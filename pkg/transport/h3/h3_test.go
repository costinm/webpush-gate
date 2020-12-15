package h3

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/costinm/wpgate/pkg/auth"
	"github.com/costinm/wpgate/pkg/tests"
	"github.com/costinm/wpgate/pkg/h2"
	"github.com/costinm/wpgate/pkg/mesh"
	"github.com/costinm/wpgate/pkg/transport/ssh"
	quic "github.com/lucas-clemente/quic-go"
	"golang.org/x/net/http2"
)

/*
Low level quic:
- stream: StreamID, reader, cancelRead, SetReadDeadline
          writer+closer, CancelWrite, SetWriteDeadline
-

 */

const addr = "localhost:4242"

const message = "foobar"


// ================ TCP/streams tests

func TestSSH(t *testing.T) {
	bA := auth.NewAuth(nil, "bob", "m.webinf.info")

	bTls := bA.GenerateTLSConfigServer()
	bTls.ClientAuth = tls.RequestClientCert
	//bTls.VerifyConnection = func(state tls.ConnectionState) error {
	//	log.Println("SState; ", state)
	//	return nil
	//}
	bTls.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		return nil
	}

	go func() {
		gw := mesh.New(bA, nil)
		sshg := ssh.NewSSHGate(gw, bA)
		sshg.InitServer()
		sshg.ListenSSH("localhost:4243")

	}()

	err := clientMain()
	if err != nil {
		t.Fatal(err)
	}
}

func TestQ(t *testing.T) {
	bA := auth.NewAuth(nil, "bob", "m.webinf.info")
	bTls := bA.GenerateTLSConfigServer()
	bTls.ClientAuth = tls.RequestClientCert
	//bTls.VerifyConnection = func(state tls.ConnectionState) error {
	//	log.Println("SState; ", state)
	//	return nil
	//}
	bTls.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		return nil
	}

	go func() { EchoServerQ(bTls, addr) }()

	err := clientMain()
	if err != nil {
		t.Fatal(err)
	}
}

func clientMain() error {
	aA := auth.NewAuth(nil, "alice", "m.webinf.info")

	tlsConf := aA.GenerateTLSConfigClient()
	//InsecureSkipVerify: true or set bob's root cert
	tlsConf.NextProtos = []string{"h2"}

	// QUIC specific dialer - creates a multiplexed session
	session, err := quic.DialAddr(addr, tlsConf, nil)
	if err != nil {
		return err
	}
	// Verify the other side cert
	sstate := session.ConnectionState()
	log.Println(sstate.PeerCertificates[0].DNSNames)

	stream, err := session.OpenStreamSync(context.Background())
	if err != nil {
		return err
	}
	err = testEchoClient(stream)
	if err != nil {
		return err
	}

	ss, err := session.AcceptStream(context.Background())
	if err != nil {
		log.Println(err)

	}
	buf := make([]byte, 4)
	io.ReadFull(ss, buf)

	fmt.Printf("Client: Got2 '%s'\n", buf)
	return nil
}

func testEchoClient(stream quic.Stream) error {
	_, err := stream.Write([]byte(message))
	if err != nil {
		return err
	}

	buf := make([]byte, len(message))
	_, err = io.ReadFull(stream, buf)
	if err != nil {
		return err
	}
	stream.Close()

	fmt.Printf("Client: Got '%s'\n", buf)


	return nil
}


// Start a server that echos all data on the first stream opened by the client
func EchoServerQ(bTls *tls.Config, addr string) error {
	listener, err := quic.ListenAddr(addr, bTls, nil)
	if err != nil {
		return err
	}

	for {
		sess, err := listener.Accept(context.Background())
		if err != nil {
			return err
		}

		sstate := sess.ConnectionState()
		log.Println(sstate.PeerCertificates[0].DNSNames)

		go func() {
			for {
				stream, err := sess.AcceptStream(context.Background())
				if err != nil {
					log.Println("Accept done ", err)
					return
				}

				go tests.EchoHandler(stream, stream)
			}
		}()

		ss, err := sess.OpenStreamSync(context.Background())
		if err != nil {
			log.Println(err)
		}
		_, err = ss.Write([]byte("ping"))
		if err != nil {
			log.Println(err)
		}

		ss.Close()
	}
	return err
}


// =================== HTTP tests

func TestH3(t *testing.T) {
	bCerts := auth.NewAuth(nil, "bob", "m.webinf.info")
	bH2, _ := h2.NewTransport(bCerts)

	InitQuicServer(bH2, 15099, http.DefaultServeMux)

	http.DefaultServeMux.HandleFunc("/test",
		func(writer http.ResponseWriter, request *http.Request) {
			log.Println(request)
			writer.Write([]byte("hi"))
		})

	// Client
	aCerts := auth.NewAuth(nil, "alice", "m.webinf.info")
	aH2, _ := h2.NewTransport(aCerts)

	hc := InitQuicClient(aH2, "bob.m.webinf.info")
	res, err := hc.Get("https://127.0.0.1:15099/test")
	if err != nil {
		t.Fatal(err)
	}

	log.Println(res)
}


func NewLocalListener() net.Listener {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err == nil {
		return ln
	}
	ln, err = net.Listen("tcp6", "[::1]:0")
	if err != nil {
		log.Fatal(err)
	}
	return ln
}

var tlsConfigInsecure = &tls.Config{InsecureSkipVerify: true}

// Start a H2 server with fake TLS
func startH2cServer(t *testing.T) net.Listener {
	h2Server := &http2.Server{}

	l := NewLocalListener()
	go func() {
		conn, err := l.Accept()
		if err != nil {
			t.Error(err)
			return
		}
		h2Server.ServeConn(
			&tests.FakeTLSConn{conn},
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
