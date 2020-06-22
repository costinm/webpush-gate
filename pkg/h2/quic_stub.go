// +build NOQUIC

package h2

import (
	"net"
	"net/http"
)

const (
	UseQuic = false
)

func (h2 *H2) InitQuicServer(port int, handler http.Handler) error {
	return nil
}

// InitQuicServerConn starts a QUIC server, using H2 certs, on a connection.
func (h2 *H2) InitQuicServerConn(port int, conn net.PacketConn, handler http.Handler) error {
	return nil
}

func (h2 *H2) InitQuicClient() *http.Client {
	return nil
}
