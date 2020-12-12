package tests

import "C"
import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"

	_ "net/http/pprof"

	"github.com/costinm/wpgate/pkg/h2"
	"github.com/costinm/wpgate/pkg/mesh"
	"github.com/costinm/wpgate/pkg/transport/accept"
	"golang.org/x/net/http2"
)

var (
	TestEnv1 *TestEnv

	// client side gateway under test on 5357 (mesh), 16004(socks), 16005(http)
	ClientGW   *mesh.Gateway
	HSClientGW *http.Client
	HPClientGW *http.Client

	// Remote(central) gateway on 14000
	VpnGW   *mesh.Gateway
	HSVpnGW *http.Client
	HPVpnGW *http.Client
)

// Used by a H2 server to 'fake' a secure connection.
type FakeTLSConn struct {
	net.Conn
}

func (c *FakeTLSConn) ConnectionState() tls.ConnectionState {
	return tls.ConnectionState{
		Version:     tls.VersionTLS12,
		CipherSuite: 0xC02F,
	}
}


// Init a Gateway, with a new set of private keys:
// - basePort - H2/QUIC MTLS DMesh port
// - +1 SOCKS
// - +2 HTTP PROXY
// - +22 SSHClientConn
func TestGateway(baseport int) *mesh.Gateway {
	h2c, _ := h2.NewH2("")
	h2c.InitMTLSServer(baseport, h2c.MTLSMux)

	gw := mesh.New(h2c.Certs,
		&mesh.GateCfg{})

	// /tcp ingress circuits
	// ingress only via SSHClientConn and accepted connections
	//gw.InitMux(h2c.MTLSMux)

	accept.NewForwarder(gw, &mesh.ListenerConf{
		Local:  fmt.Sprintf(":%d", baseport+3),
		Remote: "localhost:8000",
	})

	return gw
}

// Init common (fixed) est env.
//
// - ClientGW on 16000(DM), 16001(SOCKS), 16002(HPROXY), 16003(SSHClientConn)
// - HSClientGW and HPClientGW clients set to use ClientGW
//
// - VPNGW on 14000(DM), 14001, 14002
// - HSVpnGW, HPVpnGW
//
// - TCP echo on 3000
// - UDP echo on 3001
// - test http server on 3002, https on 3003
//
func InitCommonGateways() {
	if ClientGW != nil {
		return
	}
	ClientGW = TestGateway(16000)
	HSClientGW = h2.NewSocksHttpInsecure("127.0.0.1:" + strconv.Itoa(16001))
	HPClientGW = h2.ProxyHttp("127.0.0.1:" + strconv.Itoa(16002))

	TestEnv1 = NewTestEnv(3000)

	// VPN server on 14000(mesh)
	VpnGW = TestGateway(14000)
	HSVpnGW = h2.NewSocksHttpInsecure("127.0.0.1:" + strconv.Itoa(14001))
	HPVpnGW = h2.ProxyHttp("127.0.0.1:" + strconv.Itoa(14002))

}

// Small env for testing / probers
type TestEnv struct {
	udpListener  *net.UDPConn
	echoListener *net.TCPListener
	httpListener *net.TCPListener
	httpsSrv     *h2.H2

	NextStatus int
}

// TODO: close
// TODO: auto-alloc ports, configure clients
// TODO: control close, send, pause
// TODO: run test servers as standalone app
// TODO: run test GW as stadndalone app, including test servers (gate ?)

// HTTP echo/info
func (te *TestEnv) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sc := 200
	if te.NextStatus != 0 {
		sc = te.NextStatus
	}
	w.WriteHeader(sc)
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		log.Printf("SERVER: %V", r.TLS.PeerCertificates[0])
		fmt.Fprintf(w, "TLS_SERVER: %V", r.TLS.PeerCertificates[0])
	}

	w.Write([]byte("Hello"))
}

// UDP Echo server
func InitEchoUdp(port int) error {
	l, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
	if err != nil {
		return err
	}
	go func() {
		for {
			b := make([]byte, 1600)
			n, addr, _ := l.ReadFromUDP(b)
			l.WriteToUDP(b[0:n], addr)
		}
	}()
	return nil
}

// TCP Echo server on port
func InitEchoServer(port string) {
	nl, err := net.Listen("tcp", port)
	if err != nil {
		log.Println("Failed to listen", err)
		return
	}

	go func() {
		for {
			conn, _ := nl.Accept()
			go EchoHandler(conn, conn)
		}
	}()
}

func EchoHandler(r io.Reader, w io.Writer) {
	_, _ = io.Copy(w, r)
	if c, ok := w.(io.Closer); ok {
		c.Close()
	}
}

// Start test servers
func NewTestEnv(basePort int) *TestEnv {
	te := &TestEnv{}

	InitEchoServer(fmt.Sprintf(":%d", basePort))

	InitEchoUdp(basePort + 1)

	te.startHTTPTestServer(basePort)
	return te
}

// Http test server on +2, https on +3
func (te *TestEnv) startHTTPTestServer(basePort int) {
	mux := &http.ServeMux{}

	// Plain text http
	// For http proxy we need a dedicated plain HTTP port
	mux.Handle("/hello", te)
	mux.Handle("/", te)

	nl, err := net.Listen("tcp", fmt.Sprintf(":%d", basePort+2))
	if err != nil {
		log.Println("Failed to listen", err)
		return
	}
	go http.Serve(nl, mux)

	// H2/https
	testEnvH2, _ := h2.NewH2("")
	testEnvH2.InitH2Server(fmt.Sprintln(":%d", basePort+3), mux, false)
}

// tests on the 'echo' server. c1 is an established connection to the echo server, possibly
// using intermediaries.
func TcpEchoTest(c1 net.Conn) {

	c1.Write([]byte("GET / HTTP/1.1\n\n"))

	data := make([]byte, 1024)
	n, _ := c1.Read(data[0:])
	log.Println("Recv: ", string(data[:n]))

	c1.Close()

	//tcpClient(t)
}

func NewLocalListener() (net.Listener) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err == nil {
		return ln
	}
	ln, err = net.Listen("tcp6", "[::1]:0")
	if err != nil {
		return nil
	}
	return ln
}

// Start a H2 server over plain text
func StartH2cServer(handler http.Handler) net.Listener {
	h2Server := &http2.Server{}
	l := NewLocalListener()
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		h2Server.ServeConn(
			conn, // &h2.FakeTLSConn{conn},
			&http2.ServeConnOpts{
				Handler: handler})
	}()
	return l
}

