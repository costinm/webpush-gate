package h2_test

import (
	"log"
	"net/http"
	"testing"

	"github.com/costinm/wpgate/pkg/h2"
)

func TestCerts(t *testing.T) {
	h2srv, _ := h2.NewH2("")
	http.HandleFunc("/hello", func(writer http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) > 0 {
			log.Println("Client cert", r.TLS.PeerCertificates)
			writer.WriteHeader(200)
		} else {
			writer.WriteHeader(501)
		}
	})
	h2srv.InitMTLSServer(16009, http.DefaultServeMux)

	h2c, _ := h2.NewH2("")
	res, err := h2c.Client("localhost:16009").Get("https://localhost:16009/hello")
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
