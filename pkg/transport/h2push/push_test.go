package h2push

import (
	"crypto/tls"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/net/http2"
)

var tlsConfigInsecure = &tls.Config{InsecureSkipVerify: true}


func Test_Service(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", HTTPHandlerPushPromise)

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

	hc := srv.Client()
	//tr := &http.Transport{
	//	TLSClientConfig: tlsConfigInsecure,
	//}
	//hc := http.Client{
	//	Transport: tr,
	//}
	res, err := hc.Get(url + "/")
	if err != nil {
		t.Fatal("subscribe", err)
	}
	loc := res.Header.Get("location")
	if len(loc) == 0 {
		t.Fatal("location", res)
	}
}
