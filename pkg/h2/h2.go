package h2

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
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
	"golang.org/x/net/http2"
)

// H2 provides network communication over HTTP/2, QUIC, SSH
// It also handles the basic config loading - in particular certificates.
//
//
type H2 struct {
	*H2Conf

	quicClientsMux sync.RWMutex
	quicClients    map[string]*http.Client

	// HttpsClient with mesh certificates.
	HttpsClient *http.Client

	VIP6 net.IP

	Vpn string

	// Local mux is exposed on 127.0.0.1:5227
	LocalMux *http.ServeMux

	// MTLS mux.
	// In DMesh it exposes register, tcp, admin
	MTLSMux *http.ServeMux

	// Client tls config, shared
	tlsConfig *tls.Config

	//GrpcServer http.Handler

	Certs *auth.Auth
}

// Params:
// dest - data passed when the acceptor was created.
// acceptAddr - the port where the connection was accepted.
// con - the accepted stream.
type InHandler func(dest string, acceptAddr string, conn io.ReadWriteCloser) error

type OutHandler interface {
	Dial(dest string, localIn io.ReadCloser, clientMeta string, ctype string) (TcpProxy, error)
}

// TcpProxy is an interface for proxying to a remote address.
// The input and output are a local reader or writer.
// The proxy is created using Dial()
type TcpProxy interface {
	// Blocking method, will return when both sides have finished.
	ProxyConn(localIn io.ReadCloser, localOut io.Writer)
}

var (
	// Set to the address of the AP master
	AndroidAPMaster string
	AndroidAPIface  *net.Interface
	AndroidAPLL     net.IP
)

type Host struct {
	// Address and port of a HTTP server to forward the domain.
	Addr string

	// Directory to serve static files. Used if Addr not set.
	Dir string
	Mux http.Handler `json:"-"`
}

// Conf that can be saved to disk to preserve h2 settings.
// This is a compact form for listeners, ports, etc.
//
type H2Conf struct {
	// Must include leading ., used as a suffix
	Domain string

	// Name is the base64-encoded form of the ID or a local name (hostname)
	Name string

	// HTTP address to listen on. Defaults to :2080 or :80 if running as root.
	// Will act as an inbound gateway
	//GatewayHTTPAddr  string
	//GatewayHTTPSAddr string

	// Set of hosts with certs to configure in the h2 server.
	// The cert is expected in CertDir/HOSTNAME.[key,crt]
	// The server will terminate TLS and HTTP, forward to the host as plain text.
	Hosts map[string]*Host `json:"Hosts,omitempty"`

	// Conf is configured from Android side with the config (settings)
	// ssid, pass, vpn_ext
	Conf map[string]string `json:"Conf,omitempty"`
}

// NewH2 will load config dir. If missing, will initiate a config.
// If the parameter is empty, new in-memory config will be created (for tests or apps that save
// config in their own format)
// Deprecated
func NewH2(confdir string) (*H2, error) {
	return NewTransport(nil, &H2Conf{})
}

func NewTransport(config auth.ConfStore, h2Cfg *H2Conf) (*H2, error) {

	h2 := &H2{
		H2Conf:      h2Cfg,
		MTLSMux:     &http.ServeMux{},
		LocalMux:    &http.ServeMux{},
		quicClients: map[string]*http.Client{},
	}

	if h2.Domain == "" {
		h2.Domain = "m.webinf.info"
	}
	if h2.Conf == nil {
		h2.Conf = map[string]string{}
	}

	name, _ := os.Hostname()
	h2.Certs = auth.NewAuth(config, name, h2.Domain)

	h2.VIP6 = auth.Pub2VIP(h2.Certs.Pub)

	h2.Name = hex.EncodeToString(h2.VIP6[8:])

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

	h2.HttpsClient = &http.Client{
		Timeout: 15 * time.Minute,
		//Timeout:   5 * time.Second,
		Transport: rtt,
	}

	return h2, nil
}

var (
	useQuic = false // os.Getenv("VPN_QUIC") != "0"
)

func CleanQuic(httpClient *http.Client) {
	//hrt, ok := httpClient.Transport.(*h2quic.RoundTripper)
	hrt, ok := httpClient.Transport.(io.Closer)
	if ok {
		hrt.Close()
	}
}

func (h2 *H2) Client(host string) *http.Client {
	if strings.Contains(host, "/") {
		parts := strings.Split(host, "/")
		host = parts[2] // http(0)/(1)/HOST(2)/...
	}
	if UseQuic {
		if strings.Contains(host, "p2p") ||
			(strings.Contains(host, "wlan") && strings.HasPrefix(host, AndroidAPMaster)) {
			h2.quicClientsMux.RLock()
			if c, f := h2.quicClients[host]; f {
				h2.quicClientsMux.RUnlock()
				return c
			}
			h2.quicClientsMux.RUnlock()

			h2.quicClientsMux.Lock()
			if c, f := h2.quicClients[host]; f {
				h2.quicClientsMux.Unlock()
				return c
			}
			c := h2.InitQuicClient()
			h2.quicClients[host] = c
			h2.quicClientsMux.Unlock()

			log.Println("TCP-H2 QUIC", host)
			return c
		}
	}

	return h2.HttpsClient
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

func (h2 *H2) InitH2ServerListener(tcpConn *net.TCPListener, handler http.Handler, mtls bool) error {

	tlsServerConfig := h2.Certs.GenerateTLSConfigServer()
	if mtls {
		tlsServerConfig.ClientAuth = tls.RequireAnyClientCert // only option supported by mint?
	}
	hw := h2.handlerWrapper(handler)
	hw.mtls = mtls
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
	mtls    bool
}

func (h2 *H2) handlerWrapper(h http.Handler) *handlerWrapper { // http.Handler {
	return &handlerWrapper{handler: h, h2: h2, mtls: true}
}

func (hw *handlerWrapper) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t0 := time.Now()
	// TODO: authenticate first, either localhost (for proxy) or JWT/clientcert
	// TODO: split localhost to different method ?
	defer func() {
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

	var vip net.IP
	var san []string
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		if hw.mtls {
			log.Println("403 NO_MTLS", r.RemoteAddr, r.URL)
			w.WriteHeader(403)
			return
		}
	}
	pk1 := r.TLS.PeerCertificates[0].PublicKey
	pk1b := auth.KeyBytes(pk1)
	vip = auth.Pub2VIP(pk1b)
	var role string

	// ssh-style, known pub leaf
	if role = hw.h2.Certs.Authorized[string(pk1b)]; role == "" {
		role = "guest"
	}

	// TODO: Istio-style, signed by a trusted CA. This is also for SSH-with-cert

	san, _ = GetSAN(r.TLS.PeerCertificates[0])

	// TODO: check role

	ctx := context.WithValue(r.Context(), H2Info, &H2Context{
		SAN:  san,
		Role: role,
		T0:   t0,
	})
	//if hw.h2.GrpcServer != nil && r.ProtoMajor == 2 && strings.HasPrefix(
	//	r.Header.Get("Content-Type"), "application/grpc") {
	//	hw.h2.GrpcServer.ServeHTTP(w, r)
	//}
	hw.handler.ServeHTTP(w, r.WithContext(ctx))

	// TODO: add it to an event buffer
	if accessLogs && !strings.Contains(r.URL.Path, "/dns") {
		log.Println("HTTP", san, vip, r.RemoteAddr, r.URL, time.Since(t0))
	}
}

// Common RBAC/Policy
//
// Input: context - VIP6 src/dest, ports, etc.
// For HTTP: path
//
// Map to 'group'
//
// Use Authorized_keys or groups to match

type H2Key int

var (
	H2Info     = H2Key(1)
	accessLogs = false
)

type H2Context struct {
	// Auth role
	Role string

	// SAN list from the certificate, or equivalent auth method.
	SAN []string

	// Request start time
	T0 time.Time
}

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

func InitServer(port string) (err error) {
	lis, err := net.Listen("tcp", port)
	if err != nil {
		return
	}
	for {
		conn, err := lis.Accept()
		if err != nil {
			return err
		}
		go handleCon(conn)
	}
}

// Special handler for receipts and poll, which use push promises
func handleCon(con net.Conn) {
	defer con.Close()
	// writer: bufio.NewWriterSize(conn, http2IOBufSize),
	f := http2.NewFramer(con, con)
	settings := []http2.Setting{}

	if err := f.WriteSettings(settings...); err != nil {
		return
	}

	frame, err := f.ReadFrame()
	if err != nil {
		log.Println(" failed to read frame", err)
		return
	}
	sf, ok := frame.(*http2.SettingsFrame)
	if !ok {
		log.Printf("wrong frame %T from client", frame)
		return
	}
	log.Println(sf)
	//hDec := hpack.NewDecoder()

	for {
		select {}

	}
}
