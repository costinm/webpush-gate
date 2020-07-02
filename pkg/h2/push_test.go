package h2

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/net/http2"
)

func newLocalListener(t *testing.T) net.Listener {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err == nil {
		return ln
	}
	ln, err = net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

var tlsConfigInsecure = &tls.Config{InsecureSkipVerify: true}

// Used by a H2 server to 'fake' a secure connection.
type fakeTLSConn struct {
	net.Conn
}

func (c *fakeTLSConn) ConnectionState() tls.ConnectionState {
	return tls.ConnectionState{
		Version:     tls.VersionTLS12,
		CipherSuite: 0xC02F,
	}
}

// Start a H2 server with fake TLS
func startH2cServer(t *testing.T) net.Listener {
	h2Server := &http2.Server{}
	l := newLocalListener(t)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			t.Error(err)
			return
		}
		h2Server.ServeConn(
			&fakeTLSConn{conn},
			&http2.ServeConnOpts{
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					fmt.Fprintf(w, "Hello, %v, http: %v", r.URL.Path, r.TLS == nil)
				})})
	}()
	return l
}

func TestTransportH2c(t *testing.T) {
	l := startH2cServer(t)
	defer l.Close()
	req, err := http.NewRequest("GET", "http://"+l.Addr().String()+"/foobar", nil)
	if err != nil {
		t.Fatal(err)
	}
	tr := &http2.Transport{
		AllowHTTP: true,
		DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
			return net.Dial(network, addr)
		},
	}
	res, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.ProtoMajor != 2 {
		t.Fatal("proto not h2c")
	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(body), "Hello, /foobar, http: true"; got != want {
		t.Fatalf("response got %v, want %v", got, want)
	}
}

func Test_Service(t *testing.T) {
	mux := http.NewServeMux()

	// Real TLS server listener, httptest.Server
	srv := httptest.NewUnstartedServer(mux)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	http2.ConfigureServer(srv.Config, &http2.Server{})
	log.Println(srv.URL)

	url := srv.URL

	// h2 - inspired from h2demo
	http2.VerboseLogs = true

	tr := &http.Transport{
		TLSClientConfig: tlsConfigInsecure,
	}
	hc := http.Client{
		Transport: tr,
	}
	res, err := hc.Get(url + "/subscribe")
	if err != nil {
		t.Fatal("subscribe", err)
	}
	loc := res.Header.Get("location")
	if len(loc) == 0 {
		t.Fatal("location", res)
	}
}
