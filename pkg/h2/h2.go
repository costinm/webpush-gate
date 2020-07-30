package h2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/costinm/wpgate/pkg/auth"
	"github.com/costinm/wpgate/pkg/mesh"
	"github.com/soheilhy/cmux"
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

	VIP6 net.IP

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

func NewTransport(authz *auth.Auth) (*H2, error) {
	h2 := &H2{
		MTLSMux:     &http.ServeMux{},
		LocalMux:    &http.ServeMux{},
		quicClients: map[string]*http.Client{},
		GRPC:        grpc.NewServer(),
	}

	h2.Certs = authz

	h2.VIP6 = auth.Pub2VIP(h2.Certs.Pub)

	ctls := h2.Certs.GenerateTLSConfigClient()
	ctls.VerifyPeerCertificate = verify("")
	h2.tlsConfig = ctls

	t := &http.Transport{
		// This is enough to disable h2 automatically.
		TLSClientConfig: ctls,
	}

	http2.ConfigureTransport(t)
	rtt := http.RoundTripper(t)

	if mesh.MetricsClientTransportWrapper != nil {
		rtt = mesh.MetricsClientTransportWrapper(rtt)
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

// Multiplexed plaintext server, using MTLSMux and GRPCServer
func (h2 *H2) InitPlaintext(port string) {
	l, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatal(err)
	}
	m := cmux.New(l)

	grpcL := m.Match(cmux.HTTP2HeaderField("content-type", "application/grpc"))
	// TODO: MTLS should probably be disabled in this case, but it's using Handle so may be ok
	go h2.GRPC.Serve(grpcL)

	httpL := m.Match(cmux.HTTP1Fast())
	hs := &http.Server{
		Handler: h2.handlerWrapper(h2.MTLSMux),
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
			&fakeTLSConn{conn},
			&http2.ServeConnOpts{
				Handler: h2.handlerWrapper(h2.MTLSMux)})
	}()

	go m.Serve()
}

// Start QUIC and HTTPS servers on port, using handler.
func (h2 *H2) InitMTLSServer(port int, handler http.Handler) error {
	if mesh.MetricsHandlerWrapper != nil {
		handler = mesh.MetricsHandlerWrapper(handler)
	}
	err := h2.InitH2Server(":"+strconv.Itoa(port), handler, true)
	if err != nil {
		return err
	}
	if UseQuic {
		err = h2.InitQuicServer(port, handler)
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
	hw := h2.handlerWrapper(handler)
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

func (h2 *H2) handlerWrapper(h http.Handler) *handlerWrapper { // http.Handler {
	return &handlerWrapper{handler: h, h2: h2}
}

func (hw *handlerWrapper) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
		h2c.SAN, _ = GetSAN(r.TLS.PeerCertificates[0])
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

func GetPeerCertBytes(r *http.Request) []byte {
	if r.TLS != nil {
		if len(r.TLS.PeerCertificates) > 0 {
			pke, ok := r.TLS.PeerCertificates[0].PublicKey.(*ecdsa.PublicKey)
			if ok {
				return elliptic.Marshal(auth.Curve256, pke.X, pke.Y)
			}
			rsap, ok := r.TLS.PeerCertificates[0].PublicKey.(*rsa.PublicKey)
			if ok {
				return x509.MarshalPKCS1PublicKey(rsap)
			}
		}
	}
	return nil
}

func GetResponseCertBytes(r *http.Response) []byte {
	if r.TLS != nil {
		if len(r.TLS.PeerCertificates) > 0 {
			pke, ok := r.TLS.PeerCertificates[0].PublicKey.(*ecdsa.PublicKey)
			if ok {
				return elliptic.Marshal(auth.Curve256, pke.X, pke.Y)
			}
			rsap, ok := r.TLS.PeerCertificates[0].PublicKey.(*rsa.PublicKey)
			if ok {
				return x509.MarshalPKCS1PublicKey(rsap)
			}
		}
	}
	return nil
}

var (
	oidExtensionSubjectAltName = []int{2, 5, 29, 17}
)

const (
	nameTypeEmail = 1
	nameTypeDNS   = 2
	nameTypeURI   = 6
	nameTypeIP    = 7
)

func getSANExtension(c *x509.Certificate) []byte {
	for _, e := range c.Extensions {
		if e.Id.Equal(oidExtensionSubjectAltName) {
			return e.Value
		}
	}
	return nil
}

func GetSAN(c *x509.Certificate) ([]string, error) {
	extension := getSANExtension(c)
	dns := []string{}
	// RFC 5280, 4.2.1.6

	// SubjectAltName ::= GeneralNames
	//
	// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
	//
	// GeneralName ::= CHOICE {
	//      otherName                       [0]     OtherName,
	//      rfc822Name                      [1]     IA5String,
	//      dNSName                         [2]     IA5String,
	//      x400Address                     [3]     ORAddress,
	//      directoryName                   [4]     Name,
	//      ediPartyName                    [5]     EDIPartyName,
	//      uniformResourceIdentifier       [6]     IA5String,
	//      iPAddress                       [7]     OCTET STRING,
	//      registeredID                    [8]     OBJECT IDENTIFIER }
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(extension, &seq)
	if err != nil {
		return dns, err
	} else if len(rest) != 0 {
		return dns, errors.New("x509: trailing data after X.509 extension")
	}
	if !seq.IsCompound || seq.Tag != 16 || seq.Class != 0 {
		return dns, asn1.StructuralError{Msg: "bad SAN sequence"}
	}

	rest = seq.Bytes
	for len(rest) > 0 {
		var v asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &v)
		if err != nil {
			return dns, err
		}

		if v.Tag == nameTypeDNS {
			dns = append(dns, string(v.Bytes))
		}
	}

	return dns, nil
}

// NewSocksHttpClient returns a new client using SOCKS5 server.
func NewSocksHttpClient(socksAddr string) *http.Client {
	if socksAddr == "" {
		socksAddr = "127.0.0.1:15004"
	}
	//os.Setenv("HTTP_PROXY", "socks5://"+socks5Addr)
	// Localhost is not accepted by environment.
	//hc := &http.Client{Transport: &http.Transport{Gateway: http.ProxyFromEnvironment}}

	// Configure a hcSocks http client using localhost SOCKS
	socksProxy, _ := url.Parse("socks5://" + socksAddr)
	return &http.Client{
		Timeout: 15 * time.Minute,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(socksProxy),
			//TLSClientConfig: &tls.Config{
			//	InsecureSkipVerify: true,
			//},
		},
	}
}
