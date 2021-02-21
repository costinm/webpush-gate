package h2

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/costinm/ugate/pkg/auth"
	"github.com/costinm/wpgate/pkg/streams"
	"golang.org/x/net/http2"
	"google.golang.org/grpc"
)

// H2 provides network communication over HTTP/2, QUIC, SSH
// It also handles the basic config loading - in particular certificates.
//
type H2 struct {
	quicClientsMux sync.RWMutex
	quicClients    map[string]*http.Client
	// HttpsClient with mesh certificates, H2.
	// Call Client() to get it - or the Quic one
	httpsClient *http.Client

	// Local mux is exposed on 127.0.0.1:5227
	// Status, UI.
	LocalMux *http.ServeMux

	// MTLS mux.
	// In DMesh it exposes register, tcp, admin
	MTLSMux *http.ServeMux

	// Client tls config, shared
	tlsConfig *tls.Config

	//GrpcServer http.Handler

	Certs *auth.Auth

	GRPC *grpc.Server
}

var (
	// Set to the address of the AP master
	AndroidAPMaster string
	//AndroidAPIface  *net.Interface
	//AndroidAPLL     net.IP
)

// Deprecated, test only
func NewH2(confdir string) (*H2, error) {
	name, _ := os.Hostname()
	certs := auth.NewAuth(nil, name, "m.webinf.info")
	return NewTransport(certs)
}

// NewTransport initialized the H2 transport. Requires auth information for
// setting up TLS. Same certificate can be used for both server or client, like in Istio.
// This will also initialize a GRPC server and 2 Mux, one for localhost and one for ingress.
//
// Verification is disabled in transport, but implemented in a wrapper, using authz.
func NewTransport(authz *auth.Auth) (*H2, error) {
	h2 := &H2{
		MTLSMux:     &http.ServeMux{},
		LocalMux:    &http.ServeMux{},
		quicClients: map[string]*http.Client{},
		GRPC:        grpc.NewServer(),
	}

	h2.Certs = authz

	ctls := h2.Certs.GenerateTLSConfigClient()
	ctls.VerifyPeerCertificate = verify("")
	h2.tlsConfig = ctls

	t := &http.Transport{
		// This is enough to disable h2 automatically.
		TLSClientConfig: ctls,
	}

	// Will modify t to add NPN. If H2, t1.TLSNextProto will be set so it upgrades.
	// The H2 dial will return t2 as RoundTripper. Requires the server to have TLS.
	// The resulting transport will be used as roundtripper to servers using SSH-style
	// auth.
	http2.ConfigureTransport(t)
	rtt := http.RoundTripper(t)

	if streams.MetricsClientTransportWrapper != nil {
		rtt = streams.MetricsClientTransportWrapper(rtt)
	}

	h2.httpsClient = &http.Client{
		Timeout: 15 * time.Minute,
		//Timeout:   5 * time.Second,
		Transport: rtt,
	}

	return h2, nil
}

func CleanQuic(httpClient *http.Client) {
	//hrt, ok := httpClient.Transport.(*h2quic.RoundTripper)
	hrt, ok := httpClient.Transport.(io.Closer)
	if ok {
		hrt.Close()
	}
}

//// Used by a H2 server to 'fake' a secure connection.
//// Testing.
//type FakeTLSConn struct {
//	net.Conn
//}
//
//func (c *FakeTLSConn) ConnectionState() tls.ConnectionState {
//	return tls.ConnectionState{
//		Version:     tls.VersionTLS12,
//		CipherSuite: 0xC02F,
//	}
//}

//// Multiplexed plaintext server, using MTLSMux and GRPCServer
//func (h2 *H2) InitPlaintext(port string) {
//	l, err := net.Listen("tcp", port)
//	if err != nil {
//		log.Fatal(err)
//	}
//	m := cmux.New(l)
//
//	grpcL := m.Match(cmux.HTTP2HeaderField("content-type", "application/grpc"))
//	// TODO: MTLS should probably be disabled in this case, but it's using Handle so may be ok
//	go h2.GRPC.Serve(grpcL)
//
//	httpL := m.Match(cmux.HTTP1Fast())
//	hs := &http.Server{
//		Handler: h2.HandlerWrapper(h2.MTLSMux),
//	}
//	go hs.Serve(httpL)
//
//	h2L := m.Match(cmux.HTTP2())
//
//	go func() {
//		conn, err := h2L.Accept()
//		if err != nil {
//			return
//		}
//
//		h2Server := &http2.Server{}
//		h2Server.ServeConn(
//			conn, //&FakeTLSConn{conn},
//			&http2.ServeConnOpts{
//				Handler: h2.HandlerWrapper(h2.MTLSMux)})
//	}()
//
//	go m.Serve()
//}

// Start QUIC and HTTPS servers on port, using handler.
func (h2 *H2) InitMTLSServer(port int, handler http.Handler) error {
	if streams.MetricsHandlerWrapper != nil {
		handler = streams.MetricsHandlerWrapper(handler)
	}
	err := h2.InitH2Server(":"+strconv.Itoa(port), handler, true)
	if err != nil {
		return err
	}
	//if UseQuic {
	//	err = h2.InitQuicServer(port, handler)
	//}
	return err
}

func (h2 *H2) InitH2Server(port string, handler http.Handler, mtls bool) error {
	tcpAddr, err := net.ResolveTCPAddr("tcp", port)
	if err != nil {
		log.Println("Failed to resolve ", port)
		return err
	}
	tcpConn, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		log.Println("Failed to listen https ", port)
		return err
	}

	return h2.InitH2ServerListener(tcpConn, handler, mtls)
}

// Init a HTTPS server on a given listener.
// Will add TLS transport and certs !
//
func (h2 *H2) InitH2ServerListener(tcpConn *net.TCPListener, handler http.Handler, requestTLSClient bool) error {

	tlsServerConfig := h2.Certs.GenerateTLSConfigServer()
	if requestTLSClient {
		// only option supported by mint?
		//tlsServerConfig.ClientAuth = tls.RequireAnyClientCert
		tlsServerConfig.ClientAuth = tls.RequestClientCert
	}
	hw := h2.HandlerWrapper(handler)
	// Self-signed cert
	s := &http.Server{
		TLSConfig: tlsServerConfig,
		Handler:   hw,
	}

	// Regular TLS
	tlsConn := tls.NewListener(tcpConn, tlsServerConfig)
	go s.Serve(tlsConn)

	return nil
}

// Verify a server cert. Not enough context to verify name at this point
func verify(pub string) func(der [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(der [][]byte, verifiedChains [][]*x509.Certificate) error {
		var err error
		x509Cert := make([]*x509.Certificate, len(der))
		for i, b := range der {
			// err already checked
			x509Cert[i], _ = x509.ParseCertificate(b)
		}

		// verify the leaf is not expired
		leaf := x509Cert[0]
		now := time.Now()
		if now.Before(leaf.NotBefore) {
			return errors.New("certificate is not valid yet")
		}
		if now.After(leaf.NotAfter) {
			return errors.New("expired certificate")
		}

		// TODO: match the pub key against the trust DB
		// certs are self-signed, and domain name is not trusted - just the pub key

		// Use the equivalent of SSH known-hosts as database.

		return err
	}
}

func traceMap(r *http.Request) string {
	p := r.URL.Path
	// TODO: move to main
	if strings.HasPrefix(p, "/tcp/") {
		return "/tcp"
	}
	if strings.HasPrefix(p, "/dm/") {
		return "/dm"
	}

	return r.URL.Path
}

// handler wrapper wraps a Handler, adding MTLS checking, recovery, metrics.
type handlerWrapper struct {
	handler http.Handler
	h2      *H2
}

func (h2 *H2) HandlerWrapper(h http.Handler) *handlerWrapper { // http.Handler {
	return &handlerWrapper{handler: h, h2: h2}
}

func (hw *handlerWrapper) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t0 := time.Now()
	h2c := &auth.ReqContext{
		T0: t0,
	}


	vapidH := r.Header["Authorization"]
	if len(vapidH) > 0 {
		tok, pub, err := auth.CheckVAPID(vapidH[0], time.Now())
		if err == nil {
			h2c.Pub = pub
			h2c.VAPID = tok
		}
	}

	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		pk1 := r.TLS.PeerCertificates[0].PublicKey
		h2c.Pub = auth.MarshalPublicKey(pk1)
		// TODO: Istio-style, signed by a trusted CA. This is also for SSH-with-cert
		h2c.SAN, _ = auth.GetSAN(r.TLS.PeerCertificates[0])
	}
	if h2c.Pub == nil {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Missing VAPID or mTLS"))
		return
	}

	h2c.VIP = auth.Pub2VIP(h2c.Pub)
	// ssh-style, known pub leaf
	var role string
	if role = hw.h2.Certs.Authorized[string(h2c.Pub)]; role == "" {
		role = "guest"
	}
	h2c.Role = role

	ctx := auth.ContextWithAuth(r.Context(), h2c)
	if hw.h2.GRPC != nil && r.ProtoMajor == 2 && strings.HasPrefix(
		r.Header.Get("Content-Type"), "application/grpc") {
		hw.h2.GRPC.ServeHTTP(w, r.WithContext(ctx))
		return
	}

	hw.handler.ServeHTTP(w, r.WithContext(ctx))
}

// Common RBAC/Policy
//
// Input: context - VIP6 src/dest, ports, etc.
// For HTTP: path
//
// Map to 'group'
//
// Use Authorized_keys or groups to match

var (
	accessLogs = true
)

