package h2_test

import (
	"log"
	"net/http"
	"testing"

	"github.com/costinm/wpgate/pkg/auth"
	"github.com/costinm/wpgate/pkg/h2"
	"github.com/costinm/wpgate/pkg/tests"
)

// Verify mutual cert authentication
func TestCerts(t *testing.T) {
	gw := tests.TestGateway(16000)
	defer gw.Close()

	bCerts := auth.NewAuth(nil, "bob", "m.webinf.info")
	bH2, _ := h2.NewTransport(bCerts)

	http.HandleFunc("/hello", func(writer http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) > 0 {
			log.Println("Client cert", r.TLS.PeerCertificates)
			writer.WriteHeader(200)
		} else {
			writer.WriteHeader(501)
		}
	})
	bH2.InitMTLSServer(16009, http.DefaultServeMux)

	aCerts := auth.NewAuth(nil, "alice", "m.webinf.info")
	aH2, _ := h2.NewTransport(aCerts)

	res, err := aH2.Client("localhost:16009").Get("https://localhost:16009/hello")
	if err != nil {
		t.Fatal("Get error ", err)
	}

	if len(res.TLS.PeerCertificates) == 0 {
		t.Error("Missing server certs")
	}
	log.Println("Server cert", res.TLS.PeerCertificates)

	if res.StatusCode != 200 {
		t.Error("Missing client certs")
	}

}
