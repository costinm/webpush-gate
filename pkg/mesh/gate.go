package mesh

// Package capture provide different methods to capture local traffic:
// - TUN device, using a soft tcp/dup stack (netstacktun/)
// - Istio-style iptables (iptables/)
// - socks5 (socks5_capture)
// - http proxy and connect (httpproxy_capture)
// - localhost ports (port_capture) - also used for creating reverse proxies
//
// Applications with support for http proxy or socks5 can use env variables or settings.
// Applications without support for proxies can be captured transparently- but requires root or CAP_NET.

import (
	"log"
	"net/http"
	"strings"

	"github.com/costinm/wpgate/pkg/auth"

	"net"
	"os"
	"sync"
	"time"
)

var (

	// Managed by 'NewTCPProxy' - before dial.
	tcpConTotal = Metrics.NewCounter("gate:tcp:total", "TCP connections proxied", "15m10s")

	// Managed by updateStatsOnClose - including error cases.
	tcpConActive = Metrics.NewGauge("gate:tcp:active", "Active TCP proxies", "15m10s")

	udpConTotal  = Metrics.NewCounter("gate:udph2:total", "UDP connections", "15m10s")
	udpConActive = Metrics.NewGauge("gate:udph2:active", "Active UDP", "15m10s")

	// Gateway() operations started, of all types, after Dial.
	remoteToLocal2 = Metrics.NewCounter("gate:tcpproxy:total", "TCP connections dialed and proxied", "15m10s")

	// closeWrite breakdown - numbers should add up to double remoteToLocal2 (i.e. each proxy has 2 close)
	tcpCloseTotal = Metrics.NewCounter("gate:tcpclose:total", "Debug - out close using io.Closer()", "15m10s")
	tcpCloseWrite = Metrics.NewCounter("gate:tcpcloseoutwrite:total", "Debug - out close using net.TCPConn", "15m10s")
	tcpCloseFAIL  = Metrics.NewCounter("gate:tcpclosefail:total", "Invalid out stream, no close method", "15m10s")

	tcpCloseIn   = Metrics.NewCounter("gate:tcpclosein:total", "Debug: reader close using TCPConn.CloseRead()", "15m10s")
	tcpCloseRead = Metrics.NewCounter("gate:tcpcloseinread:total", "Debug: reader close using src.Close()", "15m10s")

	// Gateway()  - with remouteOut/localIn are handled by http (client to server stream). This happens
	// for proxies using h2 client only.
	proxyOverHttpClient = Metrics.NewCounter("gate:hclientproxy:total", "TCP over HTTP Client (1-way proxy)", "15m10s")
	// For HTTP client and server. The local2remote is handled by http stack.
	// This tracks how many times we called Close() on the interception/socks/etc writer.
	remoteToLocalClose = Metrics.NewCounter("gate:closeremotetolocal:total", "TCP over H2 Client - Close http client writer", "15m10s")
)

// Gateway is the main capture API.
type Gateway struct {
	Mesh

	// H2 has configured MTLS clients for QUIC or H2
	// Used to forward the UdpNat to an upstream VPN server.
	// H2 is the Http implementation backing the gate.
	//H2 *transport.H2
	Conf auth.ConfStore

	Config *GateCfg

	//EgressVpn []string

	// TODO: multi-level circuits (tor extends the path to ~3 - we may need more)
	VpnCircuit []string

	// UDP
	// Capture return - sends packets back to client app.
	UDPWriter UdpWriter

	// Capture server. May be set in TPROXY mode.
	UDPListener *os.File

	// UDP address used for creating connections to remote hosts.
	// Set on port 0, to avoid allocating it each time
	client *net.UDPAddr

	// NAT
	udpLock   sync.RWMutex
	ActiveUdp map[string]*UdpNat
	AllUdpCon map[string]*HostStats

	tcpLock   sync.RWMutex
	ActiveTcp map[int]*TcpProxy
	AllTcpCon map[string]*HostStats

	// Set to true by Close, will result in the maintainance routines to exit
	closed bool

	// DNS forward DNS requests, may resolve local addresses
	DNS IPResolver

	Resolve func(uint64) []net.IP

	// SSHClientConn-based gateway
	SSHGate MUXDialer

	// Key is the local port. Value has info about where it is forwarded,
	// including the VIP associated with the client.
	Listeners map[int]Listener

	// Client to VPN
	SSHClient JumpHost

	JumpHosts map[string]TunDialer

	// Client to mesh expansion - not trusted, set when mesh expansion is in use.
	// Used as a jump host to connect to the next destination.
	// TODO: allow multiple addresses.
	// TODO: this can also be used as 'egressGateway'
	SSHClientUp TunDialer

	annMutex sync.RWMutex

	// Indicate if this node will listen as master, using multicast
	// Uses more battery, requires to respond and update clients.
	Master bool

	Auth *auth.Auth

	// Listening on * for signed messages
	// Source for sent messages and multicasts
	UDPMsgConn *net.UDPConn

	// Handles UDP packets (if in TPROXY or TUN capture)
	UDPGate UDPGate

	// Mesh devices visible from this device.
	VisibleDevices map[string]*MeshDevice
}

var UDPMsgPort = 5228

// UdpWriter is implemented by capture, provides a way to send back packets to
// the captured app.
type UdpWriter interface {
	WriteTo(data []byte, dstAddr *net.UDPAddr, srcAddr *net.UDPAddr) (int, error)
}

// Keyed by Hostname:port (if found in dns tables) or IP:port
type HostStats struct {
	// First open
	Open time.Time

	// Last usage
	Last time.Time

	SentBytes   int
	RcvdBytes   int
	SentPackets int
	RcvdPackets int
	Count       int

	LastLatency time.Duration
	LastBPS     int
}

// Represents on UDP 'nat' connection.
// Currently full cone, i.e. one local port per NAT.
type UdpNat struct {
	Stream
	// bound to a local port (on the real network).
	UDP *net.UDPConn

	Closed    bool
	LocalPort int

	LastRemoteIP    net.IP
	LastsRemotePort uint16
}

type TcpRemoteHost struct {
	Stream
}

type Listener interface {
	Close()
}

type ListenerConf struct {
	// Local address (ex :8080). This is the requested address - if busy :0 will be used instead, and Port
	// will be the actual port
	// TODO: UDS
	// TODO: indicate TLS SNI binding.
	Local string

	// Real port the listener is listening on, or 0 if the listener is not bound to a port (virtual, using mesh).
	Port int

	// Remote where to forward the proxied connections
	// IP:port format, where IP can be a mesh VIP
	Remote string `json:"Remote,omitempty"`
}

type Host struct {
	// Address and port of a HTTP server to forward the domain.
	Addr string

	// Directory to serve static files. Used if Addr not set.
	Dir string
	Mux http.Handler `json:"-"`
}

// Configuration for the Gateway.
//
type GateCfg struct {

	// Port proxies: will register a listener for each port, forwarding to the
	// given address.
	Listeners []*ListenerConf `json:"TcpProxy,omitempty"`

	// Set of hosts with certs to configure in the h2 server.
	// The cert is expected in CertDir/HOSTNAME.[key,crt]
	// The server will terminate TLS and HTTP, forward to the host as plain text.
	Hosts map[string]*Host `json:"Hosts,omitempty"`

	// Proxy requests to hosts (external or mesh) using the VIP of another node.
	Via map[string]string `json:"Via,omitempty"`

	// VIP of the default egress node, if no 'via' is set.
	Egress string

	// If set, all outbound requests will use the server as a proxy.
	// Similar with Istio egress gateway.
	Vpn string
}

func (gw *Gateway) ActiveTCP() map[int]*TcpProxy {
	return gw.ActiveTcp
}

func New(certs *auth.Auth, gcfg *GateCfg) *Gateway {
	if gcfg == nil {
		gcfg = &GateCfg{}
	}
	gw := &Gateway{
		closed:    false,
		Mesh:      NewMesh(),
		Conf:      certs.Config,
		ActiveUdp: make(map[string]*UdpNat),
		ActiveTcp: make(map[int]*TcpProxy),
		AllUdpCon: make(map[string]*HostStats),
		AllTcpCon: make(map[string]*HostStats),
		Listeners: make(map[int]Listener),
		JumpHosts: map[string]TunDialer{},
		//upstreamMessageChannel: make(chan packet, 100),
		Auth:           certs,
		Config:         gcfg,
		VisibleDevices: map[string]*MeshDevice{},
	}

	gw.client = &net.UDPAddr{
		Port: 0,
	}
	// TODO: add grpcserver, http mux

	NodeF = gw.Node

	return gw
}

func (gw *Gateway) Close() {
	// close all http listeners

	//s.session.Close()
}

// Used for debug/status in main app
func (gw *Gateway) Status() (int, int, int, int) {
	gw.udpLock.Lock()
	udpA := len(gw.ActiveUdp)
	udpT := len(gw.AllUdpCon)
	gw.udpLock.Unlock()
	gw.tcpLock.Lock()
	tcpA := len(gw.ActiveTcp)
	tcpT := len(gw.AllTcpCon)
	gw.tcpLock.Unlock()

	return udpA, udpT, tcpA, tcpT
}

func androidClientUnicast2MulticastAddress(ip6 net.IP) net.IP {
	b := []byte(ip6.To16())
	b[0] = 0xFF // Convert to multicast, with same interface address
	b[1] = 2
	return net.IP(b)
}

func (gw *Gateway) Node(pub []byte) *DMNode {
	dmFrom := auth.Pub2ID(pub)
	gw.MeshMutex.Lock()
	defer gw.MeshMutex.Unlock()

	node, f := gw.Nodes[dmFrom]
	if !f {
		node = NewDMNode()
		node.PublicKey = pub
		node.VIP = auth.Pub2VIP(pub)
		gw.Nodes[dmFrom] = node
	}
	node.PublicKey = pub
	node.LastSeen = time.Now()

	return node
}

// Used by the mesh router to find the GW address based on IP
func (gw *Gateway) GetNodeByID(dmFrom uint64) (*DMNode, bool) {
	gw.MeshMutex.Lock()
	defer gw.MeshMutex.Unlock()
	node, f := gw.Nodes[dmFrom]
	return node, f
}

func (gw *Gateway) IsMeshHost(hostport string) bool {
	return strings.HasPrefix(hostport, "[fd00::") || strings.HasPrefix(hostport, "fd00::")
}

func (gw *Gateway) IsMeshAddr(host net.IP) bool {
	return host.To4() == nil && host[0] == 0xFD && host[1] == 0
}

var tcpClose = 61 * time.Minute

func (gw *Gateway) FreeIdleSockets() {
	gw.tcpLock.Lock()
	t0 := time.Now()
	var tcpClientsToTimeout []int

	for client, remote := range gw.ActiveTcp {
		if t0.Sub(remote.LastClientActivity) > tcpClose &&
			t0.Sub(remote.LastRemoteActivity) > tcpClose {
			log.Printf("UDPC: %s:%d rcv=%d/%d snd=%d/%d ac=%v ra=%v op=%v la=%s",
				remote.DestIP, remote.DestPort,
				remote.RcvdPackets, remote.RcvdBytes,
				remote.SentPackets, remote.SentBytes,
				time.Since(remote.LastClientActivity), time.Since(remote.LastRemoteActivity), time.Since(remote.Open),
				client)

			tcpClientsToTimeout = append(tcpClientsToTimeout, client)
		}
	}
	for _, client := range tcpClientsToTimeout {
		tp := gw.ActiveTcp[client]

		closeWrite(tp.ServerOut, true)
		closeWrite(tp.ClientOut, false)
		closeIn(tp.ServerIn)
		closeIn(tp.ClientIn)

		if tp.RemoteCtx != nil {
			tp.RemoteCtx()
		}

		delete(gw.ActiveTcp, client)
	}

	gw.tcpLock.Unlock()

}
