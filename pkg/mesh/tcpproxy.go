package mesh

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// TODO: Use DialContext pattern:
// - gateway implements DialContext, takes care of stream creation
// - return net.Conn is a TcpProxy
//
// Instead of:
// tp = new TcpProxy(clientin, clientout)
// tp.Dial(addr)
// tp.Proxy()
//
// Use:
// tpcon = dialContext.Dial(addr) - serverout/in set
// gwproxy.Proxy(tpcon, clientIn, clientOut...)

// DMesh uses H2 for registration and relay.
//
//
// Optional: SSHClientConn and SOCKS relay is also supported.
//
// Several other protocols provide relay of TCP connections.

// Syncthing: relay protocol on same port, plain TCP relay and join messages.
//   JoinRelay, Ping,SessionInvitation,ConnectRequest
//   JoinSessionRequest/Response
// TODO: we may link the library or use the relay servers. Low priority.

// SIP

// SSHClientConn

// SOCKS

// === L4/TCP common code  ===
//
// - Handles SOCKS, HTTP CONNECT, TUN captured
// - opens a connection to the remote site, proxies packets
// - keeps stats
// - buffer reuse.
// - handles accepted connections sent back over SSHClientConn or direct
//
// Implements ReadCloser over the localIn stream - so it can be passed to http.Post() or used for reading.
//
type TcpProxy struct {
	Stream

	gw *Gateway

	// Client stream reader, data from captured/local app to remote.
	// Set when the proxy is created, based on the captured stream.
	//
	// - For socks or accept capture, a TCPConnection
	// - For accept, a net.Conn
	// - for TCP-over-HTTP server - req.Body
	// - ...
	ClientIn io.Reader

	// A chunk of initial data, to be sent before localIn.
	// Currently not used - SNI proxy and other cases where data is sent along var-len header might use it.
	Initial []byte

	// Client stream writer.
	//
	// - for socks - a TCPConnection
	// - for accept, a net.Conn
	// - for TCP-over-HTTP - a http.Writer.
	//
	// When the remoteIn is closed, the appropriate CloseWrite must be called, to send the FIN to the other side.
	// Note that reading from clientIn might continue.
	ClientOut io.Writer

	// remoteCtx is a context associated with the remote side connection, for example in http cases.
	RemoteCtx context.CancelFunc

	// Track the status of the 2 FIN. If both FINs are set, the inputs are also closed and proxy is done.

	// True if the destination is local, no VPN needed
	// Used for VPN-accepted connections,
	LocalDest bool

	localAddr net.Addr
}

func (tp *TcpProxy) Write(b []byte) (n int, err error) {
	if tp.ServerOut == nil {
		return
	}
	n, err = tp.ServerOut.Write(b)
	tp.SentBytes += n
	tp.SentPackets++
	tp.LastClientActivity = time.Now()

	return
}

func (tp *TcpProxy) Read(out []byte) (int, error) {
	n, err := tp.ServerIn.Read(out)
	tp.RcvdBytes += n
	tp.RcvdPackets++
	tp.LastRemoteActivity = time.Now()
	return n, err
}

func (tp *TcpProxy) Close() error {
	// will be called 2x - probably need to make sure all proxy creation is associated with a defer close before
	// Dial() and Gateway()
	if !tp.ClientClose {
		closeWrite(tp.ClientOut, false)
		tp.ClientClose = true
	}
	if !tp.ServerClose {
		closeWrite(tp.ServerOut, true)
		tp.ServerClose = true
	}

	tp.updateStatsOnClose(tp.gw)
	return nil
}

func (tp *TcpProxy) LocalAddr() net.Addr {
	return tp.localAddr
}

func (tp *TcpProxy) RemoteAddr() net.Addr {
	// Dial doesn't set it very well...
	return tp.localAddr
}

func (tp *TcpProxy) SetDeadline(t time.Time) error {
	return nil
}

func (tp *TcpProxy) SetReadDeadline(t time.Time) error {
	return nil
}

func (tp *TcpProxy) SetWriteDeadline(t time.Time) error {
	return nil
}

// Glue for interface type. The interface is a StreamProxy
func (gw *Gateway) NewStream(addr net.IP, port uint16, ctype string, initialData []byte,
	clientIn io.ReadCloser, clientOut io.Writer) interface{} {
	return gw.NewTcpProxy(&net.TCPAddr{IP: addr, Port: int(port)}, ctype, initialData, clientIn, clientOut)
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
	clientOut io.Writer) *TcpProxy {
	var origIP net.IP
	var origPort int
	if tsrc, ok := src.(*net.TCPAddr); ok {
		origIP = tsrc.IP
		origPort = tsrc.Port
	} else {
		log.Println("UNEXPECTED SRC ", src, clientIn)
		host, port, _ := net.SplitHostPort(src.String())
		origPort, _ = strconv.Atoi(port)
		origIPAddr, _ := net.ResolveIPAddr("ip", host)
		if origIPAddr != nil {
			origIP = origIPAddr.IP
		}
	}

	tp := &TcpProxy{
		Stream: Stream{
			Open:       time.Now(),
			Type:       ctype,
			StreamId:   nextProxyId(),
			Origin:     src.String(),
			OriginIP:   origIP,
			OriginPort: origPort,
		},
		localAddr: src,
		gw:        gw,
		Initial:   initialData,
		ClientIn:  clientIn,
		ClientOut: clientOut,
	}

	gw.trackTcpProxy(tp)

	//if Debug {
	//	log.Println("TPROXY OPEN ", tp.Type, tp.StreamId, tp.Origin, initialData, clientIn)
	//}
	return tp
}

func (gw *Gateway) trackTcpProxy(proxy *TcpProxy) {
	gw.tcpLock.Lock()
	gw.ActiveTcp[proxy.StreamId] = proxy
	tcpConActive.Add(1)
	tcpConTotal.Add(1)
	gw.tcpLock.Unlock()
}

func (tp *TcpProxy) SetDestAddr(addr *net.TCPAddr) {
	var host, port string
	var dest string

	host = addr.IP.String()
	port = strconv.Itoa(addr.Port)
	dest = net.JoinHostPort(host, port)

	tp.DestAddr = addr
	tp.DestIP = addr.IP
	tp.DestPort = addr.Port

	if tp.gw.DNS != nil {
		dns := tp.gw.DNS.IPResolve(host)
		if dns != "" {
			tp.DestDNS = dns
		} else {
			tp.DestDNS = addr.IP.String()
		}
	}
	tp.Dest = dest
}

func (tp *TcpProxy) SetDest(dest string) error {
	// Port allocated to a mesh node and port
	host, port, err := net.SplitHostPort(dest)
	if err != nil {
		log.Println("Error port to host", err)
		return err
	}
	portN, _ := strconv.Atoi(port)
	tp.DestPort = portN

	addrIP := net.ParseIP(host)
	if addrIP != nil {
		tp.DestIP = addrIP
		addr := &net.TCPAddr{IP: addrIP, Port: portN}
		if tp.gw.DNS != nil {
			dns := tp.gw.DNS.IPResolve(host)
			if dns != "" {
				tp.DestDNS = dns
			}
		}
		tp.DestAddr = addr
	}
	tp.DestDNS = host
	tp.Dest = dest
	return nil

}

// Implements the http.Transport.DialContext function - used for dialing requests using
// custom net.Conn.
//
// Also implements x.net.proxy.ContextDialer - socks also implements it.
func (gw *Gateway) DialContext(ctx context.Context, network, addr string) (conn net.Conn, e error) {
	tp := gw.NewTcpProxy(&net.TCPAddr{IP: gw.Auth.VIP6, Port: nextProxyId()}, "DIAL", nil, nil, nil)
	err := tp.Dial(addr, nil)
	if err != nil {
		return nil, err
	}

	return tp, nil
}

func (gw *Gateway) DialContextTCP(ctx context.Context, network, addr *net.TCPAddr) (conn net.Conn, e error) {
	tp := gw.NewTcpProxy(&net.TCPAddr{IP: gw.Auth.VIP6, Port: nextProxyId()}, "DIAL", nil, nil, nil)
	err := tp.Dial("", addr)
	if err != nil {
		return nil, err
	}

	return tp, nil
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
func (tp *TcpProxy) Dial(dest string, addr *net.TCPAddr) error {

	// I have an IP resolved already. May be mesh or next hop.
	// Happens for iptables, tun, SOCKS/IP.
	if addr != nil {
		tp.SetDestAddr(addr)
	} else {
		if err := tp.SetDest(dest); err != nil {
			return err
		}
	}

	host := tp.DestDNS // IP or DNS hostname from reverse lookup
	// [fd00::] addresses.
	// TODO: also support XXXX.mesh.suffix DNS format.
	if tp.gw.IsMeshHost(host) {
		return tp.DialMesh()
	}

	if tp.LocalDest || host == "localhost" || host == "" || host == "127.0.0.1" ||
		(tp.DestIP != nil && IsRFC1918(tp.DestIP)) {
		// Direct connection to destination, should be a public address
		//log.Println("DIAL: DIRECT LOCAL ", dest, addr, host, port)
		return tp.dialDirect(dest, tp.DestIP, tp.DestPort)
	}

	g := tp.gw
	c, _ := tp.gw.Conf.Get("vpn_ext")
	if g.SSHClient != nil && c != nil && (string(c) == "true") {
		// We have an active connection to SSHVpn - use it instead of H2.
		// TODO: for testing H2 vs SSHClientConn perf disable SSHClient
		tp.Type = tp.Type + "-ISSHP"
		//log.Println("DIAL: NET SSHC OUT TO PARENT ", dest, addr, host, port)
		err := g.SSHClient.DialProxy(&tp.Stream)
		if err == nil {
			return nil
		}
	}

	if g.SSHClientUp != nil {
		// We have an active connection to SSHVpn - use it instead of H2.
		// TODO: reconnect
		// TODO: when net is lost, stop trying
		tp.Type = tp.Type + "-ISSHU"
		//log.Println("DIAL: NET SSHC Up OUT TO PARENT ", dest, addr, host, port)
		err := g.SSHClientUp.DialProxy(&tp.Stream)
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
	via := tp.gw.Config.Via[dest]
	if via == "" {
		dot := strings.Index(dest, ".")
		dd := dest[dot+1:]
		via = tp.gw.Config.Via[dd]
	}
	if via != "" {
		// TODO
		tcpMux := g.JumpHosts[via]
		if tcpMux == nil {
			return errors.New("Not found " + via)
		}
		log.Println("VIA: ", dest, via)
		return tcpMux.DialProxy(&tp.Stream)
	}

	if tp.gw.Config.Egress != "" {

	}

	// Direct connection to destination, should be a public address
	//log.Println("DIAL: DIRECT ", dest, addr, host, port)
	return tp.dialDirect(dest, tp.DestIP, tp.DestPort)
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
func (tp *TcpProxy) DialMesh() error {
	// TODO: host can also be XXXXXX.m.MESH_DOMAIN - with 16 byte hex interface address (we can also support 6)
	ip6 := tp.DestIP
	key := binary.BigEndian.Uint64(ip6[8:])

	g := tp.gw
	if key == g.Auth.VIP64 {
		// Destination is this host - forward to localhost.

		// TODO: verify caller has permissions (authorized)
		// TODO: port may be forwarded to a specific destination (configured by the control plane/node)
		tp.Type = tp.Type + "-MD"
		log.Println("DIAL: TARGET REACHED", tp.DestDNS, tp.DestPort)
		return tp.dialDirect("", []byte{127, 0, 0, 1}, tp.DestPort)
	}

	node, f := tp.gw.GetNodeByID(key)
	if f {
		ok := tp.DialMeshLocal(node)
		if ok {
			log.Println("DIAL: MESH local ", node, tp.Dest)
			return nil
		}
	}

	if g.SSHClient != nil {
		// We have an active connection to SSHVpn - use it instead of H2.
		// TODO: for testing H2 vs SSHClientConn perf disable SSHClient
		err := g.SSHClient.DialProxy(&tp.Stream)
		if err == nil {
			log.Println("DIAL: SSH VPN ", tp.Dest)
			tp.Type = tp.Type + "-MSSHC"
			return nil
		}
	}

	if g.SSHClientUp != nil {
		// We have an active connection to SSHVpn - use it instead of H2.
		// TODO: reconnect
		// TODO: when net is lost, stop trying
		tp.Type = tp.Type + "-ISSHC"
		log.Println("DIAL: MESH SSHC Up OUT TO PARENT ", tp.Dest)
		err := g.SSHClientUp.DialProxy(&tp.Stream)
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
func (tp *TcpProxy) DialMeshLocal(node *DMNode) bool {
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
			sshVpn, err := tp.gw.SSHGate.DialMUX(net.JoinHostPort(ip.IP.String(), "5222"), node.PublicKey, nil)
			if err == nil {
				node.TunClient = sshVpn
				go func() {

					// Blocking - will be closed when the ssh connection is closed.
					sshVpn.AcceptDial()

					node.TunClient = nil
					sshVpn.(io.Closer).Close()
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

// Connect the proxy to a direct IP address. Remote will be set to the connected stream.
// Note that part of the handshake the initialData may also be sent. Gateway method will handle any additional data.
//
// error returned if connection and handshake fail.
func (tp *TcpProxy) dialDirect(addr string, dstIP net.IP, dstPort int) error {
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

	tp.ServerIn = c1
	tp.ServerOut = c1

	return nil
}

// ----------------------------------------------------------------------------------
// Tracking and stats

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

var Debug = true

// Update the stats, log and remove from active, moving in the track.
// Make sure everything is closed
func (tp *TcpProxy) updateStatsOnClose(g *Gateway) {
	g.tcpLock.Lock()

	_, f1 := g.ActiveTcp[tp.StreamId]
	if !f1 {
		g.tcpLock.Unlock()
		return
	}

	delete(g.ActiveTcp, tp.StreamId)

	if tp.Closer != nil {
		tp.Closer()
	}
	g.tcpLock.Unlock()

	if tp.ServerIn != nil {
		tp.ServerIn.Close()
	}
	if tp.ServerOut != nil {
		if r, f := tp.ServerOut.(io.Closer); f {
			r.Close()
		}
	}
	if cl, ok := tp.ClientIn.(io.Closer); ok {
		cl.Close()
	}

	log.Printf("TCPC: %d src=%s dst=%s rcv=%d/%d snd=%d/%d la=%v ra=%v op=%v dest=%v %v %s",
		tp.StreamId,
		tp.Origin,
		tp.Dest,
		tp.RcvdPackets, tp.RcvdBytes,
		tp.SentPackets, tp.SentBytes,
		time.Since(tp.LastClientActivity),
		time.Since(tp.LastRemoteActivity),
		time.Since(tp.Open),
		tp.PrevPath, tp.NextPath, tp.Type)

	tcpConActive.Add(-1)

	g.tcpLock.Lock()
	hs, f := g.AllTcpCon[tp.Dest]

	if !f {
		hs = &HostStats{Open: time.Now()}
		g.AllTcpCon[tp.Dest] = hs
	}
	hs.Last = time.Now()
	hs.SentPackets += tp.SentPackets
	hs.SentBytes += tp.SentBytes
	hs.RcvdPackets += tp.RcvdPackets
	hs.RcvdBytes += tp.RcvdBytes
	hs.Count++

	hs.LastLatency = hs.Last.Sub(tp.Open)
	hs.LastBPS = int(int64(hs.RcvdBytes) * 1000000000 / hs.LastLatency.Nanoseconds())

	g.tcpLock.Unlock()
}

//---------------------------------------------------------------------------------
// Buffer copy and proxy. Blocking. Called after the connection was established (Dial ok).
func (tp *TcpProxy) ProxyConn(client net.Conn) error {
	tp.ClientIn = client
	tp.ClientOut = client
	return tp.Proxy()
}

func (tp *TcpProxy) ProxyHTTPInTcpOut(clientOut http.ResponseWriter, clientIn io.ReadCloser) error {
	tp.ClientIn = clientIn
	tp.ClientOut = clientOut
	// Close won't work - special.
	return tp.Proxy()
}

func Proxy(tproxy net.Conn, in io.Reader, out io.WriteCloser) {
	tp, ok := tproxy.(*TcpProxy)
	if !ok {
		return
	}
	tp.ClientIn = in
	tp.ClientOut = out
	tp.Proxy()
}

// Proxy will start forwarding the connection to the remote.
// This is a blocking call - will return when done.
func (tp *TcpProxy) Proxy() error {
	remoteToLocal2.Add(1)

	if tp.ServerOut == nil { // special case where localIn goes directly to transport ( http )
		// just need to proxy remote in to local out.
		// local in and initial data is sent in the background
		return tp.proxyHttpServerBodyToClient()
	}

	errCh := make(chan error, 2)
	if tp.DestPort == 53 {
		//h	return tp.gw.DNS.DNSOverTCP(tp.clientIn, tp.clientOut)
	}

	// Need to proxy localIn to remoteOut first.
	go tp.gw.proxyClientToServer(tp, tp.ServerOut, tp.ClientIn, errCh)

	_, err := tp.gw.proxyServerToClient(tp, tp.ClientOut, tp.ServerIn, errCh, false)

	tp.updateStatsOnClose(tp.gw)

	return err

}

func closeIn(src io.Closer) {
	if src == nil {
		return
	}
	srcT, ok := src.(*net.TCPConn)
	if ok {
		tcpCloseRead.Add(1)
		srcT.CloseRead()
	} else {
		src.Close()
		tcpCloseIn.Add(1)
	}
}

type closeWriter interface {
	CloseWrite() error
}

// Called for dst out and local out.
// - proxyRemoteToLocal
//
func closeWrite(dst io.Writer, server bool) {
	if dst == nil {
		return
	}
	dstT, ok := dst.(*net.TCPConn)
	if ok {
		tcpCloseWrite.Add(1)
		dstT.CloseWrite()
		return
	}

	dstCW, ok := dst.(closeWriter)
	if ok {
		tcpCloseWrite.Add(1)
		dstCW.CloseWrite()
		return
	}

	dstCl, ok := dst.(io.Closer)
	if ok {
		tcpCloseTotal.Add(1)
		dstCl.Close()
		return
	}

	//	log.Println("FAILED TO CLOSE OUT / FIN", server, dst)
	tcpCloseFAIL.Add(1)
}

// Copy data from the remote connection (read) to the local writer,
// closing both at the end. Used for HTTP client only.
// Blocking.
// For http, remoteIn is the responseBody, localOut is from interception.
func (tp *TcpProxy) proxyHttpServerBodyToClient() error {
	proxyOverHttpClient.Add(1)

	_, err := tp.CopyBuffered(tp.ClientOut, tp.ServerIn, true)

	// remote has closed its stream - FIN or RST.
	// TODO: wait for local to close

	// already closed, but make sure.
	tp.ServerIn.Close()

	// Attempt to close out, to propagate the FIN.
	if out1, ok := tp.ClientOut.(io.Closer); ok {
		out1.Close()
		remoteToLocalClose.Add(1)
		if Debug {
			log.Println("CLOSE remoteToLocal FIN ", tp.Dest, tp.Origin)
		}
	} else {
		//if Debug {
		log.Println("CLOSE remoteToLocal NO FIN ", tp.Dest, tp.Origin)
		//}
	}

	// remove from active, update global stats.
	tp.updateStatsOnClose(tp.gw)

	// At this point the clientIn may still have bytes to send to remoteOut.
	// This is used with HTTP, where the client is still processing data.

	return err
}

// Will copy data from remoteIn to localOut, and update stats and close at the end.
// If closeAtEnd is false, the localOut will be closed as soon as remoteIn is done.
// If it is true (http modes), localOut and remoteOut will be closed after localIn finishes reading.
// Blocking
func (gw *Gateway) proxyServerToClient(tcpProxy *TcpProxy,
	localOut io.Writer, remoteIn io.ReadCloser,
	errch chan error, httpCloseMode bool) (int64, error) {

	n := int64(0)
	var err error
	// TODO: err, n to be sent on a channel, for metrics
	if remoteIn == nil || localOut == nil {
		err = io.EOF
		log.Println("NULL ", remoteIn, localOut)
	} else {
		if n, err = tcpProxy.CopyBuffered(localOut, remoteIn, true); err != nil {
			if err1, ok := err.(*net.OpError); ok && err1.Err == syscall.EPIPE {
				// typical close
				err = io.EOF
			}
		}
	}

	//if Debug {
	//	log.Println("CLOSE remoteToLocal1 ", tcpProxy.Dest, tcpProxy.Origin)
	//}

	closeWrite(localOut, false) // send FIN ( closeWrite if localOut is TCP)
	tcpProxy.ClientClose = true

	errch <- err

	closeIn(remoteIn) // likely already closed (remoteIn.Read returned error or EOF)
	if cl, ok := tcpProxy.ClientIn.(io.Closer); ok {
		closeIn(cl)
	}

	return n, err
}

// Copy data from local (intercepted or H2/SSHClientConn client) to remote (TCP over something), notify errch at the end.
// This runs in a go-routine. May write some initial data captured before Gateway (part of handshake)
func (gw *Gateway) proxyClientToServer(proxy *TcpProxy, remoteOut io.Writer, localIn io.Reader, errch chan error) {
	//PooledIoCopy(dst, src)
	var err error

	if proxy.Initial != nil {
		_, err = proxy.ServerOut.Write(proxy.Initial)
		proxy.SentBytes += len(proxy.Initial)

	}

	// TODO: err, n to be sent on a channel, for metrics
	if err != nil {

	} else if proxy.ClientIn == nil || proxy.ServerOut == nil {
		err = io.EOF
		log.Println("NULL ", localIn, proxy.ServerOut)
	} else {
		if _, err = proxy.CopyBuffered(proxy.ServerOut, localIn, false); err != nil {
			if err1, ok := err.(*net.OpError); ok && err1.Err == syscall.EPIPE {
				// typical close
				err = io.EOF
			}
		}
	}

	//if !httpCloseMode {
	//	if Debug {
	//		log.Println("CLOSE localToRemote ", proxy.Dest, proxy.Origin, proxy.remoteOut, localIn)
	//	}
	closeWrite(proxy.ServerOut, true)
	//closeIn(localIn) - done at the end, after remoteIn has sent the FIN from the other direction
	//}
	proxy.ServerClose = true

	// Wait for the other side to finish.
	var remoteErr error
	if errch != nil {
		remoteErr = <-errch
	}

	if (err != nil && err != io.EOF) ||
		(remoteErr != nil && remoteErr != io.EOF) {
		log.Println("TCPE:", err, remoteErr)
	}

	// remoteIn is done now.
	//if httpCloseMode {
	//	closeWrite(remoteOut)
	//	closeIn(localIn)
	//	// also close localIn, remoteOut
	//	closeWrite(tcpProxy.remoteOut)
	//	closeIn(tcpProxy.clientIn)
	//}

}
