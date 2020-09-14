package h2

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/costinm/wpgate/pkg/auth"
	"github.com/costinm/wpgate/pkg/streams"
	"github.com/soheilhy/cmux"
	"golang.org/x/net/http2"
	"google.golang.org/grpc"
)

// H2 provides network communication over HTTP/2, QUIC, SSH
// It also handles the basic config loading - in particular certificates.
//
type H2 struct {

	// HttpsClient with mesh certificates, H2.
	// Call Client() to get it - or the Quic one
	httpsClient *http.Client

	Vpn string

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
	AndroidAPIface  *net.Interface
	AndroidAPLL     net.IP
)

// Deprecated, test only
func NewH2(confdir string) (*H2, error) {
	name, _ := os.Hostname()
	certs := auth.NewAuth(nil, name, "m.webinf.info")
	return NewTransport(certs)
}

// Return a tls.Config to be used in a TLS client ( or HTTP client)
// for a specific host.
// This is needed if hosts don't use a common root CA.
func (h2 *H2) TlsClientConfig(hn string) *tls.Config {
	ctls := h2.Certs.GenerateTLSConfigClient()
	ctls.VerifyPeerCertificate = verify(hn)
	return ctls
}

func NewTransport(authz *auth.Auth) (*H2, error) {
	h2 := &H2{
		MTLSMux:     &http.ServeMux{},
		LocalMux:    &http.ServeMux{},
		GRPC:        grpc.NewServer(),
	}

	h2.Certs = authz

	ctls := h2.Certs.GenerateTLSConfigClient()
	ctls.VerifyPeerCertificate = verify("")
	h2.tlsConfig = ctls

	t := &http.Transport{
		// This is enough to disable h2 automatically - need explicit
		// config
		TLSClientConfig: ctls,
	}

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

// Start QUIC and HTTPS servers on port, using handler.
func (h2 *H2) InitMTLSServer(port int, handler http.Handler) error {
	if streams.MetricsHandlerWrapper != nil {
		handler = streams.MetricsHandlerWrapper(handler)
	}
	err := h2.InitH2Server(":"+strconv.Itoa(port), handler, true)
	if err != nil {
		return err
	}
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
	hw := h2.HandlerAuthWrapper(handler)
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

func (h2 *H2) InitPlaintext(port string) {
       l, err := net.Listen("tcp", port)
       if err != nil {
               log.Fatal(err)
       }
       m := cmux.New(l)

       grpcL := m.Match(cmux.HTTP2HeaderField("contenttype", "application/grpc"))
       // TODO: MTLS should probably be disabled in this case, but it's using Handle so may be ok
       go h2.GRPC.Serve(grpcL)

       httpL := m.Match(cmux.HTTP1Fast())
       hs := &http.Server{
               Handler: h2.HandlerAuthWrapper(h2.MTLSMux),
       }
       go hs.Serve(httpL)

       h2L := m.Match(cmux.HTTP2())

       go func() {
               conn, err := h2L.Accept()
               if err != nil {
                       return
               }

               h2Server := &http2.Server{}
               h2Server.ServeConn(
                       conn,
                       &http2.ServeConnOpts{
                               Handler: h2.HandlerAuthWrapper(h2.MTLSMux)})
       }()

       go m.Serve()
}

// Verify a server
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

// handler wrapper wraps a Handler, adding MTLS checking, recovery, metrics.
type HandlerAuthWrapper struct {
	handler http.Handler
	h2      *H2
}

func (h2 *H2) HandlerAuthWrapper(h http.Handler) *HandlerAuthWrapper { // http.Handler {
	return &HandlerAuthWrapper{handler: h, h2: h2}
}

func (hw *HandlerAuthWrapper) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t0 := time.Now()
	h2c := &auth.ReqContext{
		T0: t0,
	}

	defer func() {
		// TODO: add it to an event buffer
		if accessLogs && h2c != nil && !strings.Contains(r.URL.Path, "/dns") {
			log.Println("HTTP", h2c.SAN, h2c.ID(), r.RemoteAddr, r.URL, time.Since(t0))
		}
		if r := recover(); r != nil {
			fmt.Println("Recovered in f", r)

			debug.PrintStack()

			// find out exactly what the error was and set err
			var err error

			switch x := r.(type) {
			case string:
				err = errors.New(x)
			case error:
				err = x
			default:
				err = errors.New("Unknown panic")
			}
			if err != nil {
				fmt.Println("ERRROR: ", err)
			}
		}
	}()

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
		h2c.Pub = auth.KeyBytes(pk1)
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


