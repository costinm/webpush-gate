package websocket

import (
	"crypto/tls"
	"log"
	"net/http"

	"github.com/costinm/wpgate/pkg/auth"
	"github.com/costinm/wpgate/pkg/msgs"
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

func websocketStream(mux *msgs.Mux, conn *ws.Conn, h2ctx *auth.ReqContext, id string) {
	data := make([]byte, 4096)
	fw, _ := conn.NewFrameWriter(conn.PayloadType)

	mc := &msgs.MsgConnection{
		SubscriptionsToSend: []string{"*"},
		SendMessageToRemote: func(ev *msgs.Message) error {
			_, err := fw.Write(ev.MarshalJSON())
			return err
		},
	}

	msgs.DefaultMux.AddConnection(id, mc)

	mc.SendMessageToRemote(msgs.NewMessage("test", nil))

	log.Println("DM HTTP EVENT STREAM ", id)

	defer func() {
		msgs.DefaultMux.RemoveConnection(id, mc)
		log.Println("DM HTTP EVENT STREAM CLOSE ", id)
	}()

	fr, err := conn.NewFrameReader()
	if err != nil {
		log.Println("Websocket ", err)
		return
	}
	for {
		n, err := fr.Read(data)
		if err != nil {
			log.Println("Websocket ", err)
			return
		}
		m := mux.ProcessMessage(data[0:n], h2ctx)

		mux.SendMessage(m)
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
