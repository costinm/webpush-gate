package streams

import (
	"context"
	"io"
	"log"
	"net"
	"strconv"
	"syscall"
	"time"

	"github.com/costinm/ugate"
)

var (
	// Gateway() operations started, of all types, after Dial.
	remoteToLocal2 = Metrics.NewCounter("gate:tcpproxy:total", "TCP connections dialed and proxied", "15m10s")

	// closeWrite breakdown - numbers should add up to double remoteToLocal2 (i.e. each proxy has 2 close)
	tcpCloseTotal = Metrics.NewCounter("gate:tcpclose:total", "Debug - out close using io.Closer()", "15m10s")
	tcpCloseWrite = Metrics.NewCounter("gate:tcpcloseoutwrite:total", "Debug - out close using net.TCPConn", "15m10s")
	tcpCloseFAIL  = Metrics.NewCounter("gate:tcpclosefail:total", "Invalid out stream, no close method", "15m10s")

	tcpCloseIn   = Metrics.NewCounter("gate:tcpclosein:total", "Debug: reader close using TCPConn.CloseRead()", "15m10s")
	tcpCloseRead = Metrics.NewCounter("gate:tcpcloseinread:total", "Debug: reader close using src.Close()", "15m10s")
)

// Stats and proxy support for proxied streams.

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
	ugate.Stream

	OnProxyClose func(proxy *TcpProxy)

	// The inbound stream.

	// Client stream reader, data from captured/local app to remote.
	// Set when the proxy is created, based on the captured stream.
	//
	// - For socks or accept capture, a TCPConnection
	// - For accept, a net.Conn
	// - for TCP-over-HTTP server - req.Body
	// - ...
	ClientIn io.ReadCloser

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

	// Address of the connected endpoint, previous hop.
	// OriginIP/OriginPort track the real client, and PrevPath
	// the path.
	ClientAddr net.Addr

	// Original client from the interception -host:port, result of net.JoinHostPort
	//
	// In the origin server it's typically 127.0.0.1:XXXX.
	// When forwarded, it should be translated to VIP : OriginStreamID
	Origin string

	// True if the destination is local, no VPN needed
	// Used for VPN-accepted connections forwarded to directly
	// reachable hosts, disables dialing through other VPNs.
	DestDirectNoVPN bool


	DestIP net.IP

	// DestPort is set
	DestPort int

}

//func (tp *TcpProxy) Write(b []byte) (n int, err error) {
//	if tp.ServerOut == nil {
//		return
//	}
//	n, err = tp.ServerOut.Write(b)
//	tp.SentBytes += n
//	tp.SentPackets++
//	tp.LastClientActivity = time.Now()
//
//	return
//}


func (tp *TcpProxy) LocalAddr() net.Addr {
	return tp.ClientAddr
}

func (tp *TcpProxy) RemoteAddr() net.Addr {
	// Dial doesn't set it very well...
	return tp.ClientAddr
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



func (tp *TcpProxy) SetDestAddr(addr *net.TCPAddr) {
	var host, port string
	var dest string

	host = addr.IP.String()
	port = strconv.Itoa(addr.Port)
	dest = net.JoinHostPort(host, port)

	tp.DestAddr = addr
	tp.DestIP = addr.IP
	tp.DestPort = addr.Port

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

		tp.DestAddr = addr
	}
	tp.DestDNS = host
	tp.Dest = dest
	return nil

}

// ----------------------------------------------------------------------------------
// Tracking and stats

var Debug = true

// Update the stats, log and remove from active, moving in the track.
// Make sure everything is closed
func (tp *TcpProxy) updateStatsOnClose() {
	if tp.OnProxyClose != nil {
		tp.OnProxyClose(tp)
	}
}

//---------------------------------------------------------------------------------


// This is the main function used with the DialProxy interface
func (tp *TcpProxy) ProxyConnClose(client net.Conn) error {
	tp.ClientIn = client
	tp.ClientOut = client
	err := tp.Proxy()
	return err
}


// Explicit close - for example for idle.
func (tp *TcpProxy) Close() error {
	// will be called 2x - probably need to make sure all proxy creation is associated with a defer close before
	// Dial() and Gateway()
	//log.Println("XXX Explicit CLOSE")
	if !tp.ClientClose {
		closeWrite(tp.ClientOut, false)
		tp.ClientClose = true
	}
	if !tp.ServerClose {
		closeWrite(tp.Out, true)
		tp.ServerClose = true
	}

	tp.updateStatsOnClose()
	return nil
}


// Proxy will start forwarding the connection to the remote.
// This is a blocking call - will return when done.
func (tp *TcpProxy) Proxy() error {
	if tp.DestPort == 53 {
		//h	return tp.gw.DNS.DNSOverTCP(tp.clientIn, tp.clientOut)
	}

	remoteToLocal2.Add(1)

	errCh := make(chan error, 2)
	// Need to proxy localIn to remoteOut first.
	go tp.proxyClientToServer(tp.Out, tp.ClientIn, errCh)

	_, err := tp.proxyServerToClient(errCh)

	tp.updateStatsOnClose()
	log.Printf("TCPC: %d src=%v dst=%s rcv=%d/%d snd=%d/%d la=%v ra=%v op=%v dest=%v %v %s",
		tp.StreamId,
		tp.RemoteAddr(),
		tp.Dest,
		tp.RcvdPackets, tp.RcvdBytes,
		tp.SentPackets, tp.SentBytes,
		time.Since(tp.LastWrite),
		time.Since(tp.LastRead),
		time.Since(tp.Open),
		tp.PrevPath, tp.NextPath, tp.Type)

	return err
}

// Will copy data from remoteIn to localOut, and update stats and close at the end.
// If closeAtEnd is false, the localOut will be closed as soon as remoteIn is done.
// If it is true (http modes), localOut and remoteOut will be closed after localIn finishes reading.
// Blocking
func (tp *TcpProxy) proxyServerToClient(errch chan error) (int64, error) {
	n := int64(0)
	var err error

	// TODO: err, n to be sent on a channel, for metrics
	if tp.In == nil || tp.ClientOut == nil {
		err = io.EOF
		log.Println("NULL ", tp.In, tp.ClientOut)
	} else {
		if n, err = tp.CopyBuffered(tp.ClientOut, tp.In, true); err != nil {
			if err1, ok := err.(*net.OpError); ok && err1.Err == syscall.EPIPE {
				// typical close
				err = io.EOF
			}
		}
	}

	// At this point, tp.ServerIn got a FIN or RST.
	// CopyBuffered doesn't cluse ClientOut - we need to
	// close so FIN is sent
	closeWrite(tp.ClientOut, false) // send FIN ( closeWrite if localOut is TCP)
	tp.ClientClose = true

	// Wait for the other side to finish
	errch <- err

	closeRead(tp.In) // likely already closed (remoteIn.Read returned error or EOF)
	closeRead(tp.ClientIn)
	// tp.ServerOut closed in the other thread, to notify FIN

	return n, err
}


func closeRead(src io.ReadCloser) {
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


// Copy data from local (intercepted or H2/SSHClientConn client) to remote (TCP over something), notify errch at the end.
// This runs in a go-routine. May write some initial data captured before Gateway (part of handshake)
func (tp *TcpProxy) proxyClientToServer(remoteOut io.Writer, localIn io.ReadCloser, errch chan error) {
	var err error

	if tp.Initial != nil {
		_, err = tp.Out.Write(tp.Initial)
	}

	// TODO: err, n to be sent on a channel, for metrics
	if err != nil {

	} else if tp.ClientIn == nil || tp.Out == nil {
		err = io.EOF
		log.Println("NULL ", localIn, tp.Out)
	} else {
		if _, err = tp.CopyBuffered(tp.Out, localIn, false); err != nil {
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
	closeWrite(tp.Out, true)
	//closeRead(localIn) - done at the end, after remoteIn has sent the FIN from the other direction
	//}
	tp.ServerClose = true

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
	//	closeRead(localIn)
	//	// also close localIn, remoteOut
	//	closeWrite(tcpProxy.remoteOut)
	//	closeRead(tcpProxy.clientIn)
	//}

}
