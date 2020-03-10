package websocket

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/costinm/wpgate/pkg/msgs"
	"github.com/costinm/wpgate/pkg/transport/stream"
	ws "golang.org/x/net/websocket"
)

var (
	// createBuffer to get a buffer. Inspired from caddy.
	// See PooledIOCopy for example
	bufferPoolCopy = sync.Pool{New: func() interface{} {
		return make([]byte, 0, 8*1024)
	}}
)

// Client or server event-stream connection.
// Useful for debugging and sending messages to old browsers.
// This is one of the simplest protocols.

type EventStreamConnection struct {
	msgs.MsgConnection
}

func WSTransport(gate *msgs.Gateway, mux *http.ServeMux) {
	ws := &ws.Server{
		Config:    ws.Config{},
		Handshake: nil,
		Handler: func(conn *ws.Conn) {
			websocketStream(gate, conn)
		},
	}
	mux.Handle("/ws", ws)

}

// Websocket stream - each frame is a message.
// Currently using a special protocol - derived from 'disaster radio' - since
// I'm testing LoRA and related IoT protocols.
// Will eventually use protobufs (after I fix the firmware)
func websocketStream(gate *msgs.Gateway, conn *ws.Conn) {
	data := make([]byte, 4096)
	fr, err := conn.NewFrameReader()
	if err != nil {
		log.Println("Websocket ", err)
		return
	}
	fw, _ := conn.NewFrameWriter(conn.PayloadType)
	go func() {
		stream.EventStream(conn.Request().Context(), conn.Request().RemoteAddr, func(ev *msgs.Message) error {
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
			gate.Mux.SendMessage(&msgs.Message{
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

