package h2_test

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"testing"

	"github.com/costinm/wpgate/pkg/auth"
	"github.com/costinm/wpgate/pkg/h2"
	"github.com/costinm/wpgate/pkg/tests"
	"golang.org/x/net/http2"
)

// Verify mutual cert authentication
func TestCerts(t *testing.T) {
	gw := tests.TestGateway(16000)
	defer gw.Close()

	bCerts := auth.NewAuth(nil, "bob", "m.webinf.info")
	bH2, _ := h2.NewTransport(bCerts)

	bH2.InitMTLSServer(16009, http.HandlerFunc(func(writer http.ResponseWriter, r *http.Request) {
		ac := auth.AuthContext(r.Context())
		log.Println("Client VIP: ", ac.VIP)
		if len(r.TLS.PeerCertificates) > 0 {
			log.Println("Client cert", r.TLS.PeerCertificates[0].DNSNames,
				len(r.TLS.PeerCertificates))
			writer.WriteHeader(200)
		} else {
			writer.WriteHeader(501)
		}
	}))

	aCerts := auth.NewAuth(nil, "alice", "m.webinf.info")
	aH2, _ := h2.NewTransport(aCerts)

	res, err := aH2.Client("localhost:16009").Get("https://localhost:16009/hello")
	if err != nil {
		t.Fatal("Get error ", err)
	}

	if len(res.TLS.PeerCertificates) == 0 {
		t.Error("Missing server certs")
	}
	log.Println("Server cert", res.TLS.PeerCertificates[0].DNSNames)

	if res.StatusCode != 200 {
		t.Error("Missing client certs")
	}
}

func TestTransportH2c(t *testing.T) {
	l := tests.StartH2cServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, %v, http: %v", r.URL.Path, r.TLS == nil)
	}))
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



