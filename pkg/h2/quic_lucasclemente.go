// +build !NOQUIC

package h2

import (
	"crypto/tls"
	"crypto/x509"
	"expvar"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/costinm/wpgate/pkg/mesh"
	"github.com/lucas-clemente/quic-go"
	h2quic "github.com/lucas-clemente/quic-go/http3"
	"github.com/zserge/metric"
)

// Modified QUIC, using a hack specific to Android P2P to work around its limitations.
// Also adds instrumentation (expvar)

// v2: if wifi connection is DIRECT-, client will listen on 0xFF.. multicast on port+1.
//     AP: if destination zone is p2p, will use the MC address and port+1 when dialing
//         multiple connections may use different ports - MC is next port. Requires knowing
//         the dest is the AP - recorded during discovery.
//     AP: as server, if zone is p2p, use port+1 an MC.
//     AP: as client, same process - the GW will have a port+1

// v3: bypass QUIC and avoid the hack, create a dedicated UDP bridge.
//     should work with both h2 and QUIC, including envoy.
//     AP-client: connect to localhost:XXXX (one port per client). Ap client port different.
//     Client-AP: connect localhost:5221 (reserved).
//     AP listens on UDP:5222, Client on TCP/UDP 127.0.0.1:5221 and UDP :5220
// Need to implement wifi-like ACK for each packet - this seems to be the main problem
// with broadcast. A second problem is the power/bw.

const (
	UseQuic = true
)

/*
env variable for debug:
Mint:
- MINT_LOG=*|crypto,handshake,negotiation,io,frame,verbose

Client:
- QUIC_GO_LOG_LEVEL=debug|info|error
*/

/*
 Notes on the mint library:
 - supports AES-GCM with 12-bytes TAG, required by QUIC (aes12 packet)
 - fnv-1a hash - for older version (may be used in chrome), unprotected packets hash
 - quic-go-certificates - common compressed certs
 - buffer_pool.go - receive buffer pooled. Client also uses same
 -

	Code:
  - main receive loop server.go/serve() ->


  Packet:
   0x80 - long header = 1
	0x40 - has connection id, true in all cases for us


  Includes binaries for client-linux-debug from chrome (quic-clients)

  Alternative - minimal, also simpler: https://github.com/bifurcation/mint
  No h2, but we may not need this.
*/

var (
	QuicDebugClient = false
	QuicDebugServer = false
	//quicClientRead    = expvar.NewInt("quicClientRead")
	//quicClientReadPk  = expvar.NewInt("quicClientReadPk")
	//quicClientReadErr = expvar.NewMap("quicClientReadErr")
	//
	//quicClientWrite   = expvar.NewInt("quicClientWrite")
	//quicClientWritePk = expvar.NewInt("quicClientWritePk")
	//
	//quicSRead    = expvar.NewInt("quicSrvRead")
	//quicSReadPk  = expvar.NewInt("quicSrvReadPk")
	//quicSWrite   = expvar.NewInt("quicSrvWrite")
	//quicSWritePk = expvar.NewInt("quicSrvWritePk")
	//
	//quicDialCnt       = expvar.NewInt("quicClientDial")
	//quicDialErrListen = expvar.NewInt("quicClientDialListen")
	//quicDialErrDial   = expvar.NewInt("quicClientDialErr")

	quicDialErrs = expvar.NewMap("quicDialErr")
)

var (
	quicClientRead       = metric.NewGauge("15m10s", "1h1m")
	quicClientReadPk     = metric.NewGauge("15m10s")
	quicClientReadErrCnt = metric.NewCounter("15m10s")
	quicClientReadErr    = expvar.NewMap("quicClientReadErr")

	quicClientWrite   = metric.NewCounter("15m10s")
	quicClientWritePk = metric.NewCounter("15m10s")

	quicSRead    = metric.NewCounter("15m10s")
	quicSReadPk  = metric.NewCounter("15m10s")
	quicSWrite   = metric.NewCounter("15m10s")
	quicSWritePk = metric.NewCounter("15m10s")

	quicDialCnt       = metric.NewGauge("15m10s")
	quicDialErrListen = metric.NewCounter("15m10s")
	quicDialErrDial   = metric.NewCounter("15m10s")
)

func init() {
	expvar.Publish("quicClientRead", quicClientRead)
	expvar.Publish("quicClientReadPk", quicClientReadPk)
	expvar.Publish("quicClientReadErrCnt", quicClientReadErrCnt)

	expvar.Publish("quicClientWrite", quicClientWrite)
	expvar.Publish("quicClientWritePk", quicClientWritePk)

	expvar.Publish("quicSrvRead", quicSRead)
	expvar.Publish("quicSrvReadPk", quicSReadPk)
	expvar.Publish("quicSrvWrite", quicSWrite)
	expvar.Publish("quicSrvWritePk", quicSWritePk)

	expvar.Publish("quicClientDial", quicDialCnt)
	expvar.Publish("quicClientDialErr", quicDialErrDial)
}

var qport int

// InitQuicServer starts a regular QUIC server, bound to a port, using the H2 certificates.
func (h2 *H2) InitQuicServer(port int, handler http.Handler) error {
	c, err := net.ListenUDP("udp",
		&net.UDPAddr{
			Port: port,
		})
	if err != nil {
		log.Println("H2: Failed to listen quic ", err)
		return err
	}

	err = h2.InitQuicServerConn(port, c, handler)
	if err != nil {
		log.Println("H2: Failed to start server ", err)
		return err
	}
	log.Printf("QUIC/H2 server :%d", port)
	return nil
}

// InitQuicServerConn starts a QUIC server, using H2 certs, on a connection.
func (h2 *H2) InitQuicServerConn(port int, conn net.PacketConn, handler http.Handler) error {
	conn = &PacketConnWrapper{
		PacketConn: conn,
		useApHack:  h2.Conf["p2p_multicast"] == "true",
	}

	mtlsServerConfig := h2.Certs.GenerateTLSConfigServer()

	// called with ClientAuth is RequestClientCert or RequireAnyClientCert
	mtlsServerConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		certs := make([]*x509.Certificate, len(rawCerts))
		for i, certEntry := range rawCerts {
			certs[i], _ = x509.ParseCertificate(certEntry)
		}
		//if len(certs) > 0 {
		//	pub := certs[0].PublicKey.(*ecdsa.PublicKey)
		//	log.Println("SERVER TLS: ", len(certs), certs[0].DNSNames, pub)
		//}
		return nil
	}
	mtlsServerConfig.ClientAuth = tls.RequireAnyClientCert // only one supported by mint?

	quicServer := &h2quic.Server{
		QuicConfig: &quic.Config{
			MaxIdleTimeout: 60 * time.Second, // should be very large - but need to test recovery
			KeepAlive:      true,             // 1/2 idle timeout
			//Versions:    []quic.VersionNumber{101},

			MaxIncomingStreams:    30000,
			MaxIncomingUniStreams: 30000,
		},

		Server: &http.Server{
			Addr:        ":" + strconv.Itoa(port),
			Handler:     h2.handlerWrapper(handler),
			TLSConfig:   mtlsServerConfig,
			ReadTimeout: 5 * time.Second,
		},
	}
	go quicServer.Serve(conn)

	return nil
}

// Close the client in case of error. This actually closes all clients for any error - may
// need a separte wrapper per host. Original fix was to close only the bad client.
// h2quic implements Closer
type quicWrapper struct {
	Transport *h2quic.RoundTripper
}

func (qw *quicWrapper) RoundTrip(req *http.Request) (*http.Response, error) {
	res, err := qw.Transport.RoundTrip(req)
	if err != nil {
		//	slock.RLock()
		//	s, f := sessions[req.Host]
		//	slock.RUnlock()
		//	if f {
		//		log.Println("CLOSE SESSION HTTP error, closing client ", req.Host, req.URL, err)
		//		s.Close()
		//	} else {
		if err1, ok := err.(net.Error); ok && !err1.Timeout() {
			cl := io.Closer(qw.Transport) //.(io.Closer)
			if cl != nil {
				//slock.Lock()
				//delete(sessions, req.Host)
				//slock.Unlock()
				cl.Close()
				log.Println("HTTP error, closing client ", req.Host, req.URL, err)
			}
		} else if strings.Contains(err.Error(), "Crypto handshake did not") {
			cl := io.Closer(qw.Transport) //.(io.Closer)
			if cl != nil {
				//slock.Lock()
				//delete(sessions, req.Host)
				//slock.Unlock()
				cl.Close()
				log.Println("HTTP error, closing client ", err)
			}
		}
		//	}
	}

	return res, err
}

// QUIC_GO_LOG_LEVEL
// InitQuicClient will configure h2.QuicClient as mtls
// using the h2 private key
func (h2 *H2) InitQuicClient() *http.Client {
	/*
		May 2018 - quic uses mint. client-state-machine implements the handshake.

		- without insecureSkipVerify, uses RootCAs, ServerName in x509 cert.Verify(VerifyOptions)
		- either way, calls VerifyPeerCertificate

	*/
	// tlsconfig.hostname can override the SNI

	qtorig := &h2quic.RoundTripper{
		//		Dial: h2.QuicDialer,

		TLSClientConfig: h2.tlsConfig,

		QuicConfig: &quic.Config{
			//RequestConnectionIDOmission: false,
			// should be very large - but need to test recovery

			MaxIdleTimeout: 15 * time.Minute, // default 30s

			HandshakeTimeout: 4 * time.Second, // default 10

			// make sure we don't get 0.
			ConnectionIDLength: 4,

			MaxIncomingStreams:    30000,
			MaxIncomingUniStreams: 30000,

			KeepAlive: true, // 1/2 idle timeout
			//Versions:  []quic.VersionNumber{101},
		},
		// holds a map of clients by hostname
	}
	qt1 := &quicWrapper{Transport: qtorig}
	qrtt := http.RoundTripper(qt1)

	if mesh.MetricsClientTransportWrapper != nil {
		qrtt = mesh.MetricsClientTransportWrapper(qrtt)
	}

	return &http.Client{
		Timeout: 5 * time.Second,

		Transport: qrtt,
	}
}

var (
	// TODO: debug, clean, check, close
	// has a Context
	// ConnectionState - peer cert, ServerName
	slock sync.RWMutex

	// Key is Host of the request
	sessions map[string]quic.Session = map[string]quic.Session{}
)

// Used for p2p interface.
// Client on p2p:
//
// Server on p2p:
// - client listens and sends from a random port - won't be able to get response back
//   on same port
//   The MC port will need to get the answers, with a dispatcher
type UDPMux struct {
}

var (
	UDPMap map[string]*UDPMux
)

//// Special dialer, using a custom port range, friendly to firewalls. From h2quic.RT -> client.dial()
//// This includes TLS handshake with the remote peer, and any TLS retry.
//func (h2 *H2) QuicDialer(network, addr string, tlsConf *tls.Config, config *quic.Config) (quic.EarlySession, error) {
//	udpAddr, err := net.ResolveUDPAddr("udp", addr)
//	if err != nil {
//		log.Println("QUIC dial ERROR RESOLVE ", qport, addr, err)
//		return nil, err
//	}
//
//	var udpConn *net.UDPConn
//	var udpConn1 *net.UDPConn
//
//	// We are calling the AP. Prepare a local address
//	if AndroidAPMaster == addr {
//		//// TODO: pool of listeners, etc
//		for i := 0; i < 10; i++ {
//			udpConn, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
//			if err != nil {
//				continue
//			}
//			port := udpConn.LocalAddr().(*net.UDPAddr).Port
//			udpConn1, err = net.ListenMulticastUDP("udp6", AndroidAPIface,
//				&net.UDPAddr{
//					IP:   AndroidAPLL,
//					Port: port + 1,
//					Zone: AndroidAPIface.Name,
//				})
//			if err == nil {
//				break
//			} else {
//				udpConn.Close()
//			}
//		}
//
//		log.Println("QC: dial remoteAP=", addr, "local=", udpConn1.LocalAddr(), AndroidAPLL)
//
//	}
//
//	qport = 0
//	if udpConn == nil {
//		udpConn, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
//	}
//
//	log.Println("QC: dial remote=", addr, "local=", udpConn.LocalAddr(), AndroidAPMaster, AndroidAPLL)
//	quicDialCnt.Add(1)
//
//	cw := &ClientPacketConnWrapper{
//		PacketConn: udpConn,
//		addr:       addr,
//		start:      time.Now(),
//	}
//	cw.useApHack = h2.Conf["p2p_multicast"] == "true"
//	if udpConn1 != nil {
//		cw.PacketConnAP = udpConn1
//	}
//	qs, err := quic.Dial(cw, udpAddr, addr, tlsConf, config)
//	if err != nil {
//		quicDialErrDial.Add(1)
//		quicDialErrs.Add(err.Error(), 1)
//		udpConn.Close()
//		if udpConn1 != nil {
//			udpConn1.Close()
//		}
//		return qs, err
//	}
//	slock.Lock()
//	sessions[addr] = qs
//	slock.Unlock()
//
//	go func() {
//		m := <-qs.Context().Done()
//		log.Println("QC: session close", addr, m)
//		slock.Lock()
//		delete(sessions, addr)
//		slock.Unlock()
//		udpConn.Close()
//		if udpConn1 != nil {
//			udpConn1.Close()
//		}
//	}()
//	return qs, err
//}

// --------  Wrappers around quic structs to intercept and modify the routing using multicast -----------

// Wrap a packet conn, display messages and adjust addresses.
type ClientPacketConnWrapper struct {
	PacketConn   net.PacketConn
	PacketConnAP net.PacketConn

	// Address - set in client mode
	addr string

	start time.Time
	sent  int
	rcv   int

	useApHack bool
}

func (c *ClientPacketConnWrapper) ReadFrom(b []byte) (int, net.Addr, error) {
	con := c.PacketConn
	if c.PacketConnAP != nil {
		con = c.PacketConnAP
	}
	l, a, e := con.ReadFrom(b)
	if QuicDebugClient || e != nil {
		if e != nil && !strings.Contains(e.Error(), "use of closed network connection") {
			log.Println("QC Read: ", l, a, e, c.addr)
		}
	}
	quicClientReadPk.Add(1)
	quicClientRead.Add(float64(l))
	c.rcv += l
	if e != nil {
		quicClientReadErr.Add(e.Error(), 1)
		quicClientReadErrCnt.Add(1)
	}
	return l, a, e
}

func (c *ClientPacketConnWrapper) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	udp, ok := addr.(*net.UDPAddr)
	if ok {
		zone := udp.Zone
		if c.useApHack && strings.Contains(zone, "p2p") &&
			udp.IP[0] == 0xfe {
			udp.IP[0] = 0xff
			udp.IP[1] = 2
			udp.Port++ // TODO: maintain a port map (based on registry data) if ports are not in order
			// Normally for client connection Registry is already maintaining the right IP/port
			if true || QuicDebugClient {
				log.Println("OVERRIDE", udp, udp.IP)
			}
		} else {
			ok = false
		}
		addr = udp
	}

	n, err = c.PacketConn.WriteTo(b, addr)
	if QuicDebugClient || err != nil {
		log.Println("QC Write: ", n, err, c.addr, udp)
	}
	quicClientWritePk.Add(1)
	quicClientWrite.Add(float64(n))
	c.sent += n
	return
}
func (c *ClientPacketConnWrapper) Close() error {
	e := c.PacketConn.Close()
	if c.PacketConnAP != nil {
		c.PacketConnAP.Close()
	}
	// Can be called by establishSecureConnection for Crypto handshake did not complete...
	log.Println("QC: CloseUDP ", c.addr, time.Since(c.start), c.sent, c.rcv)
	return e
}

func (c *ClientPacketConnWrapper) LocalAddr() net.Addr {
	a := c.PacketConn.LocalAddr()
	if QuicDebugClient {
		log.Println("QC LocalAddr", a, c.addr)
	}
	return a
}

func (c *ClientPacketConnWrapper) SetDeadline(t time.Time) error {
	e := c.PacketConn.SetDeadline(t)
	log.Println("QC SetDeadline", t, c.addr)
	return e
}

func (c *ClientPacketConnWrapper) SetReadDeadline(t time.Time) error {
	e := c.PacketConn.SetReadDeadline(t)
	log.Println("QC SetReadDeadline", t, c.addr)
	return e
}

func (c *ClientPacketConnWrapper) SetWriteDeadline(t time.Time) error {
	e := c.PacketConn.SetReadDeadline(t)
	log.Println("QC SetReadDeadline", t, c.addr)
	return e
}

type PacketConnWrapper struct {
	PacketConn net.PacketConn
	useApHack  bool
}

func (c *PacketConnWrapper) ReadFrom(b []byte) (int, net.Addr, error) {
	l, a, e := c.PacketConn.ReadFrom(b)
	if QuicDebugServer {
		log.Println("SW Read: ", l, a, e)
	}
	// TODO: routing based on connection ID 1!!
	quicSReadPk.Add(1)
	quicSRead.Add(float64(l))

	return l, a, e
}

func (c *PacketConnWrapper) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	udp, ok := addr.(*net.UDPAddr)
	if ok {
		zone := udp.Zone
		if c.useApHack && strings.Contains(zone, "p2p") &&
			udp.IP[0] == 0xfe {
			udp.IP[0] = 0xff
			udp.IP[1] = 2
			udp.Port++ // TODO: maintain a port map (based on registry data) if ports are not in order
			// Normally for client connection Registry is already maintaining the right IP/port
			if QuicDebugServer {
				log.Println("SRV OVERRIDE", udp, udp.IP)
			}
		} else {
			ok = false
		}
		addr = udp
	}

	n, err = c.PacketConn.WriteTo(b, addr)
	if QuicDebugServer {
		log.Println("QS Write: ", n, err, ok, udp)
	}
	quicSWritePk.Add(1)
	quicSWrite.Add(float64(n))
	return
}

func (c *PacketConnWrapper) Close() error {
	e := c.PacketConn.Close()
	log.Println("QS CloseUDP ", e)
	return e
}

// Client only seems to call it for the debug, in server.go/Listen
func (c *PacketConnWrapper) LocalAddr() net.Addr {
	a := c.PacketConn.LocalAddr()
	//log.Println("QS LocalAddr", a)
	return a
}
func (c *PacketConnWrapper) SetDeadline(t time.Time) error {
	e := c.PacketConn.SetDeadline(t)
	log.Println("QS SetDeadline", t)
	return e
}

func (c *PacketConnWrapper) SetReadDeadline(t time.Time) error {
	e := c.PacketConn.SetReadDeadline(t)
	log.Println("QS SetReadDeadline", t)
	return e
}
func (c *PacketConnWrapper) SetWriteDeadline(t time.Time) error {
	e := c.PacketConn.SetReadDeadline(t)
	log.Println("QS SetWriteDeadline", t)
	return e

}
