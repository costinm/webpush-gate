package streams

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Common to TCP and UDP proxies
// Represents an outgoing connection to a remote site, with stats.
//
// Common to TCP and UDP proxies. Results of a "Dial"
// originating a connection to a remote or local destination.
//
type Stream struct {
	// remote In - data from remote app to local.
	// May be an instance:
	// - net.Conn - for outbound TCP connections
	// - a res.Body for http-over-HTTP client. Note that remoteOut will be null in this case.
	// - a TCPConnection for socks
	// - for ssh -
	ServerIn io.ReadCloser `json:"-"`

	// remoteOut - stream sending to the server.
	// will be nil for http or cases where the API uses Read() and has its own local->remote proxy logic.
	//
	// Normally an instance of net.Conn, create directly to app or to another node.
	//
	ServerOut io.WriteCloser `json:"-"`

	Open time.Time

	// last receive from local (and send to remote)
	LastClientActivity time.Time

	// last receive from remote (and send to local)
	LastRemoteActivity time.Time

	// Original client from the interception -host:port, result of net.JoinHostPort
	//
	// In the origin server it's typically 127.0.0.1:XXXX.
	// When forwarded, it should be translated to VIP : OriginStreamID
	Origin string

	// Identifier for the 'previous hop' IP.
	// This is used to lookup connection metadata (the Stream, auth info, etc)
	// Should be based on something that the client has access to - in case of TCP it's the remote IP/port
	// If localhost capture, this will be set to the VIP.
	OriginIP net.IP

	OriginPort int

	// Original dest - hostname or IP, including port. Parameter of the orginal Dial from the captured egress stream.
	// May be a mesh IP6, host, etc. If original address was captured by IP, destIP will also be set.
	Dest string

	// Resolved destination IP. May be nil if SOCKS or forwarding is done. Final Gateway will have it set.
	// If capture is based on IP, it'll be set in all hops.
	// If set, this is the authoritiative destination, DestDNS will be a hint.
	DestAddr *net.TCPAddr

	// True if the destination is local, no VPN needed
	// Used for VPN-accepted connections,
	LocalDest bool

	// True if the destination is local, no VPN needed
	// Used for VPN-accepted connections forwarded to directly
	// reachable hosts, disables dialing through other VPNs.
	DestDirectNoVPN bool

	DestIP net.IP

	// DestPort is set
	DestPort int

	// Address of the source. For accepted/forwarded
	// stream it is the remote address of the accepted connection.
	// For local capture is localhost and the remote port.
	SrcAddr net.Addr

	// Hostname of the destination, based on DNS cache and interception.
	// Used as a key in the 'per host' stats.
	DestDNS string

	// Counter
	// Key in the Active table.
	StreamId int

	// Client type - original capture and all transport hops.
	// SOCKS, CONNECT, PROXY, SOCKSIP, PROXYIP,
	// EPROXY = TCP-over-HTTP in, direct host out
	Type string

	// Sent from client to server ( client is initiator of the proxy )
	SentBytes   int
	SentPackets int

	// Received from server to client
	RcvdBytes   int
	RcvdPackets int

	// If set, this is a circuit.
	NextPath []string

	// Set for circuits - path so far (over H2)
	PrevPath []string

	// Set if the client has sent the FIN, and gateway sent the FIN to server
	ClientClose bool

	// Set if the server has sent the FIN, and gateway forwarded it to the client.
	ServerClose bool

	// Additional closer, to be called after the proxy function is done and both client and remote closed.
	Closer func() `json:"-"`

	// remoteCtx is a context associated with the remote side connection,
	// for example in http cases.
	RemoteCtx context.CancelFunc
}

type nameAddress string

// name of the network (for example, "tcp", "udp")
func (na nameAddress) Network() string {
	return "mesh"
}
func (na nameAddress) String() string {
	return string(na)
}

var (
	// createBuffer to get a buffer. Inspired from caddy.
	// See PooledIOCopy for example
	bufferPoolCopy = sync.Pool{New: func() interface{} {
		return make([]byte, 0, 32*1024)
	}}
)

func (tp *Stream) Write(b []byte) (n int, err error) {
	if tp.ServerOut == nil {
		return
	}
	n, err = tp.ServerOut.Write(b)
	tp.SentBytes += n
	tp.SentPackets++
	tp.LastClientActivity = time.Now()

	return
}

func (tp *Stream) Read(out []byte) (int, error) {
	n, err := tp.ServerIn.Read(out)
	tp.RcvdBytes += n
	tp.RcvdPackets++
	tp.LastRemoteActivity = time.Now()
	return n, err
}



// Copy src to dst, using a pooled intermediary buffer.
//
// Will update stats about activity and data.
// Does not close dst when src is closed
//
// Blocking, returns when src returned an error or EOF/graceful close.
// May also return with error if src or dst return errors.
//
// srcIsRemote indicates that the connection is from the server to client. (remote to local)
// If false, the connection is from client to server ( local to remote )
func (stats *Stream) CopyBuffered(dst io.Writer, src io.Reader, srcIsRemote bool) (written int64, err error) {
	buf1 := bufferPoolCopy.Get().([]byte)
	defer bufferPoolCopy.Put(buf1)
	bufCap := cap(buf1)
	buf := buf1[0:bufCap:bufCap]

	// For netstack: src is a gonet.Conn, doesn't implement WriterTo. Dst is a net.TcpConn - and implements ReadFrom.
	// CopyBuffered is the actual implementation of Copy and CopyBuffer.
	// if buf is nil, one is allocated.
	// Duplicated from io

	// This will prevent stats from working.
	// If the reader has a WriteTo method, use it to do the copy.
	// Avoids an allocation and a copy.
	//if wt, ok := src.(io.WriterTo); ok {
	//	return wt.WriteTo(dst)
	//}
	// Similarly, if the writer has a ReadFrom method, use it to do the copy.
	//if rt, ok := dst.(io.ReaderFrom); ok {
	//	return rt.ReadFrom(src)
	//}

	first := false
	for {
		if srcc, ok := src.(net.Conn); ok {
			srcc.SetReadDeadline(time.Now().Add(15 * time.Minute))
		}
		nr, er := src.Read(buf)
		if er != nil && er != io.EOF {
			if strings.Contains(er.Error(), "NetworkIdleTimeout") {
				return written, nil
			}
			return written, err
		}
		if nr == 0 {
			// shouldn't happen unless err == io.EOF
			return written, nil
		}
		if nr > 0 {
			if srcIsRemote {
				stats.LastRemoteActivity = time.Now()
				stats.RcvdPackets++
				stats.RcvdBytes += int(nr)
			} else {
				stats.SentPackets++
				stats.SentBytes += int(nr)
				stats.LastClientActivity = time.Now()
			}
			if first {
				// TODO: sniff SNI
			}
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if f, ok := dst.(http.Flusher); ok {
				f.Flush()
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil { // == io.EOF
			return written, er
		}
	}
	return written, err
}

func (tp *Stream) LocalAddr() net.Addr {
	return tp.SrcAddr
}

func (tp *Stream) RemoteAddr() net.Addr {
	if tp.DestAddr != nil {
		return tp.DestAddr
	}
	return nameAddress(tp.Dest)
	// Dial doesn't set it very well...
	//return tp.SrcAddr
}

