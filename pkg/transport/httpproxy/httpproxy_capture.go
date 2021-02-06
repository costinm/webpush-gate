package httpproxy

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/costinm/ugate"
	"github.com/costinm/wpgate/pkg/h2"
	"github.com/costinm/wpgate/pkg/mesh"
)

// Used for HTTP_PROXY=localhost:port, to intercept outbound traffic using http proxy protocol.
// CONNECT too.

// Experimental, not the main capture mode - TUN and SOCKS should be used if possible.

func NewHTTPGate(gw *mesh.Gateway, h2 *h2.H2) *HTTPGate {
	return &HTTPGate{
		gw: gw,
		h2: h2,
	}
}

// Start listening on the addr, as a HTTP_PROXY
// Handles CONNECT and PROXY requests using the gateway
// for streams.
func (gw *HTTPGate) HttpProxyCapture(addr string) error {
	// For http proxy we need a dedicated plain HTTP port
	nl, err := net.Listen("tcp", addr)
	if err != nil {
		log.Println("Failed to listen", err)
		return err
	}
	go http.Serve(nl, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "CONNECT" {
			gw.handleConnect(w, r)
			return
		}
		// This is a real HTTP proxy
		if r.URL.IsAbs() {
			log.Println("HTTPPRX", r.Method, r.Host, r.RemoteAddr, r.URL)
			gw.captureHttpProxyAbsURL(w, r)
			return
		}
	}))
	return nil
}

// WIP: HTTP proxy with absolute address, to a QUIC server (or sidecar)`
func (gw *HTTPGate) captureHttpProxyAbsURL(w http.ResponseWriter, r *http.Request) {
	// HTTP proxy mode - uses the QUIC client to connect to the node
	// TODO: redirect via VPN, only root VPN can do plaintext requests

	// parse r.URL, follow the same steps as TCP - if mesh use Client/mtls, if VPN set forward to VPN, else use H2 client

	// r.Host is populated from the absolute URL.
	// Typical headers (curl):
	// User-Agent, Acept, Proxy-Connection:Keep-Alive

	if gw.proxy(w, r) {
		return
	}

	ht := &http.Transport{
		DialContext: gw.gw.DialContext,
	}
	hc := &http.Client{Transport: ht}

	// TODO: use VPN to Dial !!!
	//
	resp, err := hc.Transport.RoundTrip(r)
	if err != nil {
		log.Println("XXX ", err)
		http.Error(w, err.Error(), 500)
		return
	}
	origBody := resp.Body
	defer origBody.Close()
	ugate.CopyResponseHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)

	log.Println("PHTTP: ", r.URL)

}

// WIP: If method is CONNECT - operate in TCP proxy mode. This can be used to proxy
// a TCP UdpNat to a mesh node, from localhost or from a net node.
// Only used to capture local traffic - should be bound to localhost only, like socks.
// It speaks HTTP/1.1, no QUIC
func (gw *HTTPGate) handleConnect(w http.ResponseWriter, r *http.Request) {
	hij, ok := w.(http.Hijacker)
	if !ok {
		w.WriteHeader(503)
		w.Write([]byte("Error - no hijack support"))
		return
	}

	host := r.URL.Host
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}

	proxyClient, _, e := hij.Hijack()
	if e != nil {
		w.WriteHeader(503)
		w.Write([]byte("Error - no hijack support"))
		return
	}

	ra := proxyClient.RemoteAddr().(*net.TCPAddr)

	_, pf , err := gw.gw.DialProxy(context.Background(),
		stringAddr(host), ra, "CHP")

	if err != nil {
		w.WriteHeader(503)
		w.Write([]byte("Dial error" + err.Error()))
		return
	}

	proxyClient.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))

	// Blocking.
	pf(proxyClient)
}

type stringAddr string
func(s stringAddr) Network() string {
	return "addr"
}
func(s stringAddr) String() string {
	return string(s)
}

