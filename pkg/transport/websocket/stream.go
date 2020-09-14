package websocket

import (
	"bufio"
	"crypto/tls"
	"net/http"

	"github.com/costinm/wpgate/pkg/auth"
	"github.com/costinm/wpgate/pkg/mesh"
	"github.com/costinm/wpgate/pkg/msgs"
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

func websocketStream(gate *msgs.Mux, conn *ws.Conn, ctx *auth.ReqContext, s string) {
	// TODO: get auth !
	mconn := &msgs.MsgConnection{
		SubscriptionsToSend: nil, // Don't send all messages down - only if explicit subscription.
		Conn: conn,
	}
	msgs.DefaultMux.AddConnection("", mconn)
	br := bufio.NewReader(conn)
	mconn.HandleMessageStream(nil, br, "")

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
