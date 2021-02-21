package websocket

import (
	"bufio"
	"crypto/tls"
	"net"
	"net/http"

	"github.com/costinm/ugate/pkg/auth"
	"github.com/costinm/wpgate/pkg/msgs"
	ws "golang.org/x/net/websocket"
)

// Client and server for messaging over websocket
// Uses VAPID or TLS authentication for client, TLS auth for server
// Both ends identify with their public key and/or cert.

func WSTransport(gate *msgs.Mux, mux *http.ServeMux) {
	wsmsg := &ws.Server{
		Config:    ws.Config{},
		Handshake: nil,
		Handler: func(conn *ws.Conn) {
			//h2ctx := auth.AuthContext(conn.Request().Context())
			websocketStream(gate, conn, "http-"+conn.Request().RemoteAddr)
		},
	}
	mux.Handle("/ws", wsmsg)
	//if sshg != nil {
	//	wsssh := &ws.Server{
	//		Config:    ws.Config{},
	//		Handshake: nil,
	//		Handler: func(conn *ws.Conn) {
	//			sshg.HandleServerConn(conn)
	//		},
	//	}
	//	mux.Handle("/ssh", wsssh)
	//}
}

func websocketStream(gate *msgs.Mux, conn *ws.Conn, s string) {
	// TODO: get auth !
	mconn := &msgs.MsgConnection{
		SubscriptionsToSend: nil, // Don't send all messages down - only if explicit subscription.
		Conn: conn,
	}
	msgs.DefaultMux.AddConnection("", mconn)
	br := bufio.NewReader(conn)
	mconn.HandleMessageStream(nil, br, "")

}

func WSGateClient(a *auth.Auth, dest string) (net.Conn, error) {
	wsc, err := ws.NewConfig(dest, dest)

	wsc.Header.Add("Authorization", a.VAPIDToken(dest))

	wsc.TlsConfig = &tls.Config{
		InsecureSkipVerify: true,
	}

	ws, err := ws.DialConfig(wsc)
	if err != nil {
		return nil, err
	}

	return ws, nil
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

	websocketStream(mux, ws, "")

	return nil
}
