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
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/costinm/ugate"
	"github.com/costinm/ugate/pkg/auth"
	ugates "github.com/costinm/ugate/pkg/ugatesvc"
	"github.com/costinm/wpgate/pkg/streams"

	"net"
	"sync"
	"time"
)

var (

	// Managed by 'NewTCPProxy' - before dial.
	tcpConTotal = streams.Metrics.NewCounter("gate:tcp:total", "TCP connections proxied", "15m10s")

	// Managed by updateStatsOnClose - including error cases.
	tcpConActive = streams.Metrics.NewGauge("gate:tcp:active", "Active TCP proxies", "15m10s")

	udpConTotal  = streams.Metrics.NewCounter("gate:udph2:total", "UDP connections", "15m10s")
	udpConActive = streams.Metrics.NewGauge("gate:udph2:active", "Active UDP", "15m10s")

	// Gateway() operations started, of all types, after Dial.
	remoteToLocal2 = streams.Metrics.NewCounter("gate:tcpproxy:total", "TCP connections dialed and proxied", "15m10s")

	// closeWrite breakdown - numbers should add up to double remoteToLocal2 (i.e. each proxy has 2 close)
	tcpCloseTotal = streams.Metrics.NewCounter("gate:tcpclose:total", "Debug - out close using io.Closer()", "15m10s")
	tcpCloseWrite = streams.Metrics.NewCounter("gate:tcpcloseoutwrite:total", "Debug - out close using net.TCPConn", "15m10s")
	tcpCloseFAIL  = streams.Metrics.NewCounter("gate:tcpclosefail:total", "Invalid out stream, no close method", "15m10s")

	tcpCloseIn   = streams.Metrics.NewCounter("gate:tcpclosein:total", "Debug: reader close using TCPConn.CloseRead()", "15m10s")
	tcpCloseRead = streams.Metrics.NewCounter("gate:tcpcloseinread:total", "Debug: reader close using src.Close()", "15m10s")

	// Gateway()  - with remouteOut/localIn are handled by http (client to server stream). This happens
	// for proxies using h2 client only.
	proxyOverHttpClient = streams.Metrics.NewCounter("gate:hclientproxy:total", "TCP over HTTP Client (1-way proxy)", "15m10s")
	// For HTTP client and server. The local2remote is handled by http stack.
	// This tracks how many times we called Close() on the interception/socks/etc writer.
	remoteToLocalClose = streams.Metrics.NewCounter("gate:closeremotetolocal:total", "TCP over H2 Client - Close http client writer", "15m10s")
)

// Gateway is the main capture API.
type Gateway struct {
	m sync.RWMutex

	*ugates.UGate

	// Vpn is the currently active VPN server. Will be selected from the list of
	// known VPN servers (in future - for now hardcoded to the test server)
	Vpn string

	// User agent - hostname or android build id or custom.
	UA string

	tcpLock   sync.RWMutex
	ActiveTcp map[int]*streams.TcpProxy

	AllTcpCon map[string]*HostStats

	// DNS forward DNS requests, may resolve local addresses
	DNS ugate.IPResolver

	// SSHClientConn-based gateway
	SSHGate ugates.Transport

	// Client to VPN
	SSHClient ugate.MuxedConn

	JumpHosts map[string]ugate.MuxedConn

	// Client to mesh expansion - not trusted, set when mesh expansion is in use.
	// Used as a jump host to connect to the next destination.
	// TODO: allow multiple addresses.
	// TODO: this can also be used as 'egressGateway'
	SSHClientUp ugate.MuxedConn

	Auth *auth.Auth
}

func (gw *Gateway) ActiveTCP() map[int]*streams.TcpProxy {
	return gw.ActiveTcp
}

func New(certs *auth.Auth, gcfg *ugate.GateCfg) *Gateway {
	if gcfg == nil {
		gcfg = &ugate.GateCfg{}
	}
	gw := &Gateway{
		//ActiveUdp: make(map[string]*UdpNat),
		ActiveTcp: make(map[int]*streams.TcpProxy),
		//AllUdpCon: make(map[string]*HostStats),
		AllTcpCon: make(map[string]*HostStats),
		JumpHosts: map[string]ugate.MuxedConn{},
		//upstreamMessageChannel: make(chan packet, 100),
		Auth:           certs,
	}

	return gw
}

func (gw *Gateway) Close() {
	// close all http listeners

	//s.session.Close()
}

// Used for debug/status in main app
func (gw *Gateway) Status() (int, int, int, int) {
	//gw.udpLock.Lock()
	//udpA := len(gw.ActiveUdp)
	//udpT := len(gw.AllUdpCon)
	//gw.udpLock.Unlock()
	gw.tcpLock.Lock()
	tcpA := len(gw.ActiveTcp)
	tcpT := len(gw.AllTcpCon)
	gw.tcpLock.Unlock()

	return 0, 0, tcpA, tcpT
}

func androidClientUnicast2MulticastAddress(ip6 net.IP) net.IP {
	b := []byte(ip6.To16())
	b[0] = 0xFF // Convert to multicast, with same interface address
	b[1] = 2
	return net.IP(b)
}

func (gw *Gateway) Node(pub []byte) *ugate.DMNode {
	dmFrom := auth.Pub2ID(pub)
	gw.m.Lock()
	defer gw.m.Unlock()

	node, f := gw.UGate.Nodes[dmFrom]
	if !f {
		node = ugates.NewDMNode()
		node.PublicKey = pub
		node.VIP = auth.Pub2VIP(pub)
		gw.UGate.Nodes[dmFrom] = node
	}
	node.PublicKey = pub
	node.LastSeen = time.Now()

	return node
}

// Used by the mesh router to find the GW address based on IP
func (gw *Gateway) GetNodeByID(dmFrom uint64) (*ugate.DMNode, bool) {
	gw.m.Lock()
	defer gw.m.Unlock()
	node, f := gw.UGate.Nodes[dmFrom]
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
		if t0.Sub(remote.LastWrite) > tcpClose &&
			t0.Sub(remote.LastRead) > tcpClose {
			log.Printf("UDPC: %s:%d rcv=%d/%d snd=%d/%d ac=%v ra=%v op=%v la=%s",
				remote.DestAddr.IP, remote.DestAddr.Port,
				remote.RcvdPackets, remote.RcvdBytes,
				remote.SentPackets, remote.SentBytes,
				time.Since(remote.LastWrite), time.Since(remote.LastRead), time.Since(remote.Open),
				client)

			tcpClientsToTimeout = append(tcpClientsToTimeout, client)
		}
	}
	for _, client := range tcpClientsToTimeout {
		tp := gw.ActiveTcp[client]

		tp.Close()

		if tp.RemoteCtx != nil {
			tp.RemoteCtx()
		}

		delete(gw.ActiveTcp, client)
	}

	gw.tcpLock.Unlock()

}

// DialMesh creates a circuit to a mesh host:
// - if a local address is known, will be used directly
// - if an IP address is known, will be used directly
// - otherwise, will send up to the parent
//
// The circuit is currently NOT encrypted E2E - each host on the path can see the content,
// similar with the ISP or a Wifi access point. After the circuit is created e2e encryption
// should be added - typically this is used for HTTPS connections. Tor-like obfuscation is not
// supported yet.
//
// dest - the destionation, in [IP6]:port format
// addr - the address.
// host - in this case will be an IPv6 - all mesh hosts are in this form
// port - is the port to use on the mesh node. The real port used is the mesh port from registry
//
func (gw *Gateway) DialMesh(tp *streams.TcpProxy) error {
	// TODO: host can also be XXXXXX.m.MESH_DOMAIN - with 16 byte hex interface address (we can also support 6)
	ip6 := tp.DestIP
	key := binary.BigEndian.Uint64(ip6[8:])

	if key == gw.Auth.VIP64 {
		// Destination is this host - forward to localhost.

		// TODO: verify caller has permissions (authorized)
		// TODO: port may be forwarded to a specific destination (configured by the control plane/node)
		tp.Type = tp.Type + "-MD"
		log.Println("DIAL: TARGET REACHED", tp.DestDNS, tp.DestPort)
		return gw.dialDirect(tp, "", []byte{127, 0, 0, 1}, tp.DestPort)
	}

	node, f := gw.GetNodeByID(key)
	if f {
		ok := gw.DialMeshLocal(tp, node)
		if ok {
			log.Println("DIAL: MESH local ", node, tp.Dest)
			return nil
		}
	}

	if gw.SSHClient != nil {
		// We have an active connection to SSHVpn - use it instead of H2.
		// TODO: for testing H2 vs SSHClientConn perf disable SSHClient
		err := gw.SSHClient.DialProxy(&tp.Stream)
		if err == nil {
			log.Println("DIAL: SSH VPN ", tp.Dest)
			tp.Type = tp.Type + "-MSSHC"
			return nil
		}
	}

	if gw.SSHClientUp != nil {
		// We have an active connection to SSHVpn - use it instead of H2.
		// TODO: reconnect
		// TODO: when net is lost, stop trying
		tp.Type = tp.Type + "-ISSHC"
		log.Println("DIAL: MESH SSHC Up OUT TO PARENT ", tp.Dest)
		err := gw.SSHClientUp.DialProxy(&tp.Stream)
		if err == nil {
			log.Println("DIAL: SSH UP ", tp.Dest)
			return nil
		}
	}

	//if g.Vpn != "" {
	//	log.Println("DIAL: HTTP VPN ", dest, addr, host, port)
	//	tp.Type = tp.Type + "-MH2VPN"
	//
	//	return tp.DialViaHTTP(g.Vpn, net.JoinHostPort(host, port))
	//}
	log.Println("PORT: node not found ", tp.Dest)
	return fmt.Errorf("No valid Gateway")
}

// DialMeshLocal will connect to a node that is locally known - has a MUX connection, local IP or
// external IP.
func (gw *Gateway) DialMeshLocal(tp *streams.TcpProxy, node *ugate.DMNode) bool {
	if node.TunSrv != nil {
		tp.Type = tp.Type + "-MSSHD"
		err := node.TunSrv.DialProxy(&tp.Stream)
		if err == nil {

			log.Println("DIAL: SSH CON REVERSE ", tp.Dest)
			return true
		}
	}

	if node.TunClient != nil {
		tp.Type = tp.Type + "-MSSHD"
		err := node.TunClient.DialProxy(&tp.Stream)
		// Err indicates failure to connect to the destination
		// If the TUN is broken, it'll be closed, resulting in SSHTunClient=nil
		if err == nil {
			log.Println("DIAL: SSH CON LOCAL ", tp.Dest)
			return true
		}
	}

	// No connection, attempt the known IPs
	if node.TunClient == nil {
		for _, ip := range node.GWs() {
			// Create a mux, as client. Will be reused as SSHTunClient
			sshVpn, err := gw.SSHGate.DialMUX(net.JoinHostPort(ip.IP.String(), "5222"), node.PublicKey, nil)
			if err == nil {
				node.TunClient = sshVpn
				go func() {

					// Blocking - will be closed when the ssh connection is closed.
					sshVpn.Wait()

					node.TunClient = nil
					log.Println("SSH PEER CLOSE ", tp.Dest)
				}()
			}
		}
	}

	if node.TunClient != nil {
		tp.Type = tp.Type + "-MSSHD"
		err := node.TunClient.DialProxy(&tp.Stream)
		// Err indicates failure to connect to the destination
		// If the TUN is broken, it'll be closed, resulting in SSHTunClient=nil
		if err == nil {
			log.Println("DIAL: SSH CON LOCAL ", tp.Dest)
			return true
		}
	}

	return false

}

// Connect the proxy to a direct IP address. Remote will be set to the connected stream.
// Note that part of the handshake the initialData may also be sent. Gateway method will handle any additional data.
//
// error returned if connection and handshake fail.
func (gw *Gateway) dialDirect(tp *streams.TcpProxy, addr string, dstIP net.IP, dstPort int) error {
	var err error

	var dstAddr *net.TCPAddr
	if dstIP == nil {
		dstAddr, err = net.ResolveTCPAddr("tcp", addr)
		if err != nil {
			return err
		}
		tp.DestIP = dstAddr.IP
	} else {
		dstAddr = &net.TCPAddr{IP: dstIP, Port: dstPort}
	}

	c1, err := net.DialTCP("tcp", nil, dstAddr)
	if err != nil {
		log.Println("TCPO: ERR", dstAddr, err)
		return err
	}

	tp.In = c1
	tp.Out = c1

	return nil
}

// dest can be:
// - hostname:port
// - [IP]:port
// - [MESHIP6]/dest
//
// "addr" is used for TUN, Iptables, SOCKS(with IP), when only destination IP is known.
// Name may be available in dns cache.
//
// addr and dest can be mesh IP6 or regular external IP.
//
// Note that DialIP may already stream bytes from localIn if the call is successful - for HTTP proxy
// it uses a Request, and the body starts getting read and streammed after headers.
// The data from the remote will need to be proxied to localOut manually.
//
// Init a connection to the destination. Will attempt to find a route, may call 'DialXXX' several times to
// find a path. Route discovery and other overhead expected.
//
// In case of error, caller should close local in/out streams
func (gw *Gateway) Dial(tp *streams.TcpProxy, dest string, addr *net.TCPAddr) error {

	// I have an IP resolved already. May be mesh or next hop.
	// Happens for iptables, tun, SOCKS/IP.
	if addr != nil {
		tp.SetDestAddr(addr)
		if gw.DNS != nil {
			dns := gw.DNS.IPResolve(addr.IP.String())
			if dns != "" {
				tp.DestDNS = dns
			} else {
				tp.DestDNS = addr.IP.String()
			}
		}
	} else {
		if err := tp.SetDest(dest); err != nil {
			return err
		}
		if tp.DestIP != nil {
			// dest is in numeric format, attempt to find the real name
			if gw.DNS != nil {
				dns := gw.DNS.IPResolve(tp.DestIP.String())
				if dns != "" {
					tp.DestDNS = dns
				}
			}
		}
	}

	host := tp.DestDNS // IP or DNS hostname from reverse lookup
	// [fd00::] addresses.
	// TODO: also support XXXX.mesh.suffix DNS format.
	if gw.IsMeshHost(host) {
		return gw.DialMesh(tp)
	}

	if tp.DestDirectNoVPN || host == "localhost" || host == "" || host == "127.0.0.1" ||
			(tp.DestIP != nil && IsRFC1918(tp.DestIP)) {
		// Direct connection to destination, should be a public address
		//log.Println("DIAL: DIRECT LOCAL ", dest, addr, host, port)
		return gw.dialDirect(tp, dest, tp.DestIP, tp.DestPort)
	}

	c, _ := gw.Auth.Config.Get("vpn_ext")
	if gw.SSHClient != nil && c != nil && (string(c) == "true") {
		// We have an active connection to SSHVpn - use it instead of H2.
		// TODO: for testing H2 vs SSHClientConn perf disable SSHClient
		tp.Type = tp.Type + "-ISSHP"
		//log.Println("DIAL: NET SSHC OUT TO PARENT ", dest, addr, host, port)
		err := gw.SSHClient.DialProxy(&tp.Stream)
		if err == nil {
			return nil
		}
	}

	if gw.SSHClientUp != nil {
		// We have an active connection to SSHVpn - use it instead of H2.
		// TODO: reconnect
		// TODO: when net is lost, stop trying
		tp.Type = tp.Type + "-ISSHU"
		//log.Println("DIAL: NET SSHC Up OUT TO PARENT ", dest, addr, host, port)
		err := gw.SSHClientUp.DialProxy(&tp.Stream)
		if err == nil {
			return nil
		}
	}

	// dest can be an IP:port or hostname:port or MESHID/[....]
	// TODO: support literal form of MESH hosts
	//if g.Vpn != "" {
	//	tp.Type = tp.Type + "-IH2"
	//	log.Println("DIAL: NET HTTP VPN ", g.Vpn, dest, addr, host, port)
	//	return tp.DialViaHTTP(g.Vpn, dest)
	//}

	// Direct connection to destination, should be a public address
	//log.Println("DIAL: DIRECT ", dest, addr, host, port)
	return gw.dialDirect(tp, dest, tp.DestIP, tp.DestPort)
}


var (
	tcpProxyId    = 0
	tcpProxyIdMux = sync.Mutex{}
)

func nextProxyId() int {
	tcpProxyIdMux.Lock()
	x := tcpProxyId
	tcpProxyId++
	tcpProxyIdMux.Unlock()
	return x
}



// Glue for interface type. Called when a new captured TCP connection
// is accepted and src/dst meta decoded.
func (gw *Gateway) NewStream(acceptClientAddr net.IP, remotePort uint16,
	ctype string,
	initialData []byte,
	clientIn io.ReadCloser, clientOut io.Writer) interface{} {
	return gw.NewTcpProxy(&net.TCPAddr{IP: acceptClientAddr, Port: int(remotePort)}, ctype, initialData, clientIn, clientOut)
}

// Implements the http.Transport.DialContext function - used for dialing requests using
// custom net.Conn.
//
// Also implements x.net.proxy.ContextDialer - socks also implements it.
func (gw *Gateway) DialContext(ctx context.Context, network, addr string) (conn net.Conn, e error) {
	// Get meta from ctx:
	// ctype ( how was the connection received )
	// directClientAddr - previous source

	tp := gw.NewTcpProxy(&net.TCPAddr{IP: gw.Auth.VIP6,
		Port: nextProxyId()},
		"DIAL", nil, nil, nil)

	err := gw.Dial(tp, addr, nil)
	if err != nil {
		return nil, err
	}

	return tp, nil
}

func (gw *Gateway) HandleTUN(conn net.Conn, target *net.TCPAddr) error {
	_, p, err := gw.DialProxy(context.Background(), conn.RemoteAddr(), conn.LocalAddr(), "tun")
	if err != nil {
		return err
	}
	return p(conn)
}

// Glue for interface type. Called when a new captured TCP connection
// is accepted and src/dst meta decoded.
func (gw *Gateway) DialProxy(ctx context.Context,
		addr net.Addr, directClientAddr net.Addr,
		ctype string, meta ...string) (net.Conn, func(client net.Conn) error, error) {
	var addrTCP *net.TCPAddr
	dest := ""
	if ta, ok := addr.(*net.TCPAddr); ok {
		addrTCP = ta
	} else {
		dest = addr.String()
	}

	tp := gw.NewTcpProxy(directClientAddr, ctype,
		nil, nil, nil)
	err := gw.Dial(tp, dest, addrTCP)
	if err != nil {
		return nil, nil, err
	}
	return tp, tp.ProxyConnClose, nil
}

func (gw *Gateway) trackTcpProxy(proxy *streams.TcpProxy) {
	gw.tcpLock.Lock()
	gw.ActiveTcp[proxy.StreamId] = proxy
	tcpConActive.Add(1)
	tcpConTotal.Add(1)
	gw.tcpLock.Unlock()
}

// Initiate and track the TcpProxy object.
// Requires an "Id" key to be set - based on the source only.
// ctype represents the type of the acceptor.
//
// src is typically the 'previous hop' - i.e. the IP address and port accepting the connection.
// The original source may be different.
//
// clientOut can be a http.ResponseWriter or net.Conn
func (gw *Gateway) NewTcpProxy(src net.Addr,
		ctype string,
		initialData []byte,
		clientIn io.ReadCloser,
		clientOut io.Writer) *streams.TcpProxy {
//	if tsrc, ok := src.(*net.TCPAddr); ok {
		//origIP = tsrc.IP
		//origPort = tsrc.Port
//	} else {
//		log.Println("UNEXPECTED SRC ", src, clientIn)
//		host, port, _ := net.SplitHostPort(src.String())
//		origPort, _ = strconv.Atoi(port)
//		origIPAddr, _ := net.ResolveIPAddr("ip", host)
//		if origIPAddr != nil {
//			origIP = origIPAddr.IP
//		}
//	}

	tp := &streams.TcpProxy{
		Stream: ugate.Stream{
			Open:       time.Now(),
			Type:       ctype,
			StreamId:   nextProxyId(),
		},
		Origin:     src.String(),
		ClientAddr:   src,
		OnProxyClose: gw.OnProxyClose,
		Initial:      initialData,
		ClientIn:     clientIn,
		ClientOut:    clientOut,
	}

	gw.trackTcpProxy(tp)

	//if Debug {
	//	log.Println("TPROXY OPEN ", tp.Type, tp.StreamId, tp.Origin, initialData, clientIn)
	//}
	return tp
}


// Local (non-internet) addresses.
// RFC1918, RFC4193, LL
func IsRFC1918(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.To4() == nil {
		// IPv6 equivalent - RFC4193, ULA - but this is used as DMesh
		if ip[0] == 0xfd {
			return true
		}
		if ip[0] == 0xfe && ip[1] == 0x80 {
			return true
		}
		return false
	}
	if ip[0] == 10 {
		return true
	}
	if ip[0] == 192 && ip[1] == 168 {
		return true
	}
	if ip[0] == 172 && ip[1]&0xF0 == 0x10 {
		return true
	}
	// Technically not 1918, but 6333
	if ip[0] == 192 && ip[1] == 0 && ip[2] == 0 {
		return true
	}

	return false
}

func (gw *Gateway) OnProxyClose(tp *streams.TcpProxy) {
	gw.tcpLock.Lock()

	_, f1 := gw.ActiveTcp[tp.StreamId]
	if !f1 {
		gw.tcpLock.Unlock()
		return
	}

	delete(gw.ActiveTcp, tp.StreamId)

	if tp.Closer != nil {
		tp.Closer()
	}
	gw.tcpLock.Unlock()

	if tp.In != nil {
		tp.In.Close()
	}
	if tp.Out != nil {
		if r, f := tp.Out.(io.Closer); f {
			r.Close()
		}
	}
	if tp.ClientIn != nil {
		tp.ClientIn.Close()
	}

	tcpConActive.Add(-1)

	gw.tcpLock.Lock()
	hs, f := gw.AllTcpCon[tp.Dest]

	if !f {
		hs = &HostStats{Open: time.Now()}
		gw.AllTcpCon[tp.Dest] = hs
	}
	hs.Last = time.Now()
	hs.SentPackets += tp.SentPackets
	hs.SentBytes += tp.SentBytes
	hs.RcvdPackets += tp.RcvdPackets
	hs.RcvdBytes += tp.RcvdBytes
	hs.Count++

	hs.LastLatency = hs.Last.Sub(tp.Open)
	hs.LastBPS = int(int64(hs.RcvdBytes) * 1000000000 / hs.LastLatency.Nanoseconds())

	gw.tcpLock.Unlock()
}

// HttpGetNodes (/dmesh/ip6) returns the list of known nodes, both direct and indirect.
// This allows nodes to sync the mesh routing table.
func (gw *Gateway) HttpGetNodes(w http.ResponseWriter, r *http.Request) {
	gw.m.RLock()
	defer gw.m.RUnlock()
	je := json.NewEncoder(w)
	je.SetIndent(" ", " ")
	je.Encode(gw.UGate.Nodes)
}

// HttpGetNodes (/dmesh/ip6) returns the list of known nodes, both direct and indirect.
// This allows nodes to sync the mesh routing table.
func (gw *Gateway) HttpNodesFilter(w http.ResponseWriter, r *http.Request) {
	gw.m.RLock()
	defer gw.m.RUnlock()
	rec := []*ugate.DMNode{}
	t0 := time.Now()
	for _, n := range gw.UGate.Nodes {
		if t0.Sub(n.LastSeen) < 6000*time.Millisecond {
			rec = append(rec, n)
		}
	}
	je := json.NewEncoder(w)
	je.SetIndent(" ", " ")
	je.Encode(rec)
}

func (gw *Gateway) HttpAllTCP(w http.ResponseWriter, r *http.Request) {
	gw.tcpLock.RLock()
	defer gw.tcpLock.RUnlock()
	json.NewEncoder(w).Encode(gw.AllTcpCon)
}

func (gw *Gateway) HttpTCP(w http.ResponseWriter, r *http.Request) {
	gw.tcpLock.RLock()
	defer gw.tcpLock.RUnlock()
	json.NewEncoder(w).Encode(gw.ActiveTcp)
}
