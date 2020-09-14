package websocket

import (
	"bufio"
	"bytes"
	"fmt"
	"crypto/tls"
	"log"
	"net/http"

	"github.com/costinm/wpgate/pkg/mesh"
	"github.com/costinm/wpgate/pkg/auth"
	"github.com/costinm/wpgate/pkg/msgs"
	"github.com/costinm/wpgate/pkg/transport/eventstream"
	"github.com/costinm/wpgate/pkg/transport/ssh"
	ws "golang.org/x/net/websocket"
)

// Client and server for messaging over websocket
// Uses VAPID or TLS authentication for client, TLS auth for server
// Both ends identify with their public key and/or cert.

func WSTransport(gate *msgs.Mux, mux *http.ServeMux) {
	ws := &ws.Server{
		Config:    ws.Config{},
		Handshake: nil,
		Handler: func(conn *ws.Conn) {
			h2ctx := auth.AuthContext(conn.Request().Context())
			websocketStream(gate, conn, h2ctx, "http-"+conn.Request().RemoteAddr)
		},
	}
	mux.Handle("/ws", ws)
}

func WSTransportSSH(gate *mesh.Gateway, sshg *ssh.SSHGate, mux *http.ServeMux) {
	ws := &ws.Server{
		Config:    ws.Config{},
		Handshake: nil,
		Handler: func(conn *ws.Conn) {
			sshg.HandleServerConn(conn)
		},
	}
	mux.Handle("/ssh", ws)
}

func WSTransportMsgs(gate *mesh.Gateway, sshg *ssh.SSHGate, mux *http.ServeMux) {
	ws := &ws.Server{
		Config:    ws.Config{},
		Handshake: nil,
		Handler: func(conn *ws.Conn) {
			// TODO: get auth !
			mconn := &msgs.MsgConnection{
				SubscriptionsToSend: nil, // Don't send all messages down - only if explicit subscription.
				Conn: conn,
			}
			msgs.DefaultMux.AddConnection("", mconn)
			br := bufio.NewReader(conn)
			mconn.HandleMessageStream(nil, br, "", gate.Auth.VIP6.String())
		},
	}
	mux.Handle("/wsmsg", ws)
}

// Websocket stream - each frame is a message.
// Currently using a special protocol - derived from 'disaster radio' - since
// I'm testing LoRA and related IoT protocols.
// Will eventually use protobufs (after I fix the firmware)
func websocketStream(mux *msgs.Mux, conn *ws.Conn, h2ctx *auth.ReqContext, id string) {
	data := make([]byte, 4096)
	fr, err := conn.NewFrameReader()
	if err != nil {
		log.Println("Websocket ", err)
		return
	}
	fw, _ := conn.NewFrameWriter(conn.PayloadType)
	go func() {
		eventstream.EventStream(conn.Request().Context(), conn.Request().RemoteAddr, func(ev *msgs.Message) error {
			bo := bytes.Buffer{}
			ba := ev.MarshalJSON()
			bo.Write([]byte{0, 1, 'c', '|'})
			bo.Write(ba)
			_, err := fw.Write(bo.Bytes())
			if err != nil {
				return err
			}
			return nil
		})
	}()
	for {
		n, err := fr.Read(data)
		if err != nil {
			log.Println("Websocket ", err)
			return
		}
		if data[2] != '!' {
			fw.Write([]byte{data[0], data[1], '!'})
		}

		from := ""
		body := ""
		if data[2] == 'c' && data[3] == '|' {
			if data[4] == '<' {
				msgb := string(data[5:n])
				uidEnd := strings.Index(msgb, ">")
				from = msgb[0:uidEnd]
				body = msgb[uidEnd:]
			} else {
				body = string(data[4:n])
				from = ""
			}
			// <from> cmd params ?
			log.Printf("WS: %s %s\n", from, body)
			mux.SendMessage(&msgs.Message{
				Id:         fmt.Sprintf("%X%X", data[0], data[1]),
				To:         "/" + body,
				Subject:    "",
				Path:       nil,
				From:       from,
				Data:       nil,
				Meta:       nil,
				Connection: nil,
				Topic:      "",
			})
			log.Printf("WS: %X%X %s\n", data[0], data[1], string(data[2:n]))
		} else {
			msgb := string(data[3:n])
			log.Printf("WS: %X%X %s\n", data[0], data[1], msgb)
		}
	}
}

func WSClient(a *auth.Auth, mux *msgs.Mux, dest string) error {
	wsc, err := ws.NewConfig(dest, dest)

	wsc.Header.Add("Authorization", a.VAPIDToken(dest))
	wsc.TlsConfig = &tls.Config{
		InsecureSkipVerify: true,
	}

	ws, err := ws.DialConfig(wsc)
	if err != nil {
		return err
	}

	websocketStream(mux, ws, nil, "")

	return nil
}
