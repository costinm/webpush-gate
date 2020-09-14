package toh

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/costinm/wpgate/pkg/h2"
	"github.com/costinm/wpgate/pkg/mesh"
)

// K8S:
// API_SERVER/api/v1/namespaces/%s/pods/%s/portforward
// Forwards a local port to the pod, using SPDY or Websocket.

// TODO: half close doesn't work well - if http client closes the req body, we detect and half close the remote
// connection. However if remote half closes, we can't close the stream going back to client without terminating
// the request, which also terminates reading from remote.
// The fix is to either tweak the QUIC stack to keep sending request body, or use the low-level APIs, or to
// packetize the response from remote to loca ( going in the response writter ).

type TcpOverH2 struct {
	gw *mesh.Gateway
}

func New(gw *mesh.Gateway, mux *http.ServeMux) *TcpOverH2 {
	toh := &TcpOverH2{
		gw: gw,
	}
	mux.HandleFunc("/tcp/", toh.HTTPTunnelTCP)

	return toh
}

// Server side 'TCP-over-H2+QUIC
//
// URL format:
// - /tcp/HOSTNAME:PORT - egress using hostname (may also be ipv4 IP)
// - /tcp/[IPADDR]:PORT - egress using IP6 address
// - /tcp/[fd00::MESHID]:port - mesh routing. Send to the port on the identified node, possibly via VPN and gateways.
//
// - WIP: /tcp/[fd00::MESHID]/.../HOSTNAME:port - mesh circuit routing. Last component is the final destination.
//
// Returns 50x errors or 200 followed by a body starting with 'OK' (to flush headers)
// Additional metadata using headers.
func (toh *TcpOverH2) HTTPTunnelTCP(w http.ResponseWriter, r *http.Request) {
	// TODO: meta: via, trace, t0, loop detection

	if r.Proto == "HTTP/1.1" {
		log.Println("HTTP-TCP", r.URL, r.Proto)
		w.WriteHeader(http.StatusBadRequest) // 400
		return
	}

	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 3 {
		log.Println("Error parsing ", parts)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	addr := parts[2] // next hop - may be a mesh node, external hostname or IP

	var err error

	// TODO: use the VIP instead of IP. Same for SSH clients.
	ra, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)

	tcpProxy := toh.gw.NewTcpProxy(ra, "HPROXY", nil, r.Body, w)
	defer tcpProxy.Close()

	if len(parts) > 3 {
		tcpProxy.NextPath = parts[3:]
	}
	oldPath := r.Header.Get(HEADER_PREV_PATH)
	if oldPath != "" {
		tcpProxy.PrevPath = strings.Split(oldPath, "/")
	}

	err = tcpProxy.Dial(addr, nil)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}

	// egress proxies the connection.
	// "proxy" wraps a TCP connection to the external host. 'remoteIn' and 'remoteOut' are the net.Conn
	// w and rbody are the clients.

	head := "OK"
	w.WriteHeader(200)

	// TODO: match SSH, use a packet.
	// This is needed to get the connection going - client must parse the first packet as well.
	w.Write([]byte(head))
	w.(http.Flusher).Flush()

	// Dial sets the remote streams

	// TODO: packetize, compat with apiserver if possible
	tcpProxy.Proxy()
	return
}

const HEADER_PREV_PATH = "x-dm-p"

func (toh *TcpOverH2) httpEgressProxy(proxy *mesh.TcpProxy, clientWriter http.ResponseWriter) {
	// like in socks, need to write some header to start the process.
}

// TcpProxy implements Read, so it can be passed to a HTTP connection while capturing stats.
// This is for using the regular http.Client - where the body must be passed as a Reader to POST.
// "Remote" is a node that handles the forwarding.
// It will return bytes normally, using a CopyBuffered method. Called from http2.clientStream.writeRequestBody
type BodyReader struct {
	Proxy *mesh.TcpProxy
}

// This is a read from the client, used by the Http request to push bytes to remote.
// We increment the counters since http library doesn't count.
func (br *BodyReader) Read(out []byte) (int, error) {
	ch := br.Proxy
	if ch.Initial != nil {
		n := len(ch.Initial)
		if n > len(out) {
			n = len(out)
		}
		copy(out, ch.Initial[0:n])

		if n == len(ch.Initial) {
			ch.Initial = nil
		} else {
			ch.Initial = ch.Initial[n:]
		}
		return n, nil
	}

	if ch.ClientIn == nil {
		return 0, io.EOF
	}
	n, err := ch.ClientIn.Read(out)
	ch.SentBytes += n
	ch.SentPackets++
	ch.LastClientActivity = time.Now()

	if err != nil {
		ch.ClientClose = true
		// Will result in sending the FIN in H2.
	}
	//if err != nil && Debug {
	//	log.Println("CLOSE httplocalToRemote ", ch.Dest, ch.Origin)
	//}
	return n, err
}

// DialContext implements the interface.
func (toh *TcpOverH2) DialContext(ctx context.Context, network, destAddr string) (net.Conn, error) {
	// t0 := time.Now()

	// tp.Stream.Dest = "TCPH2C/" + via + "/" + destAddr

	// url := "https://" + via + "/tcp/" + destAddr

	// if tp.NextPath != nil {
	// 	url = url + "/" + strings.Join(tp.NextPath, "/")
	// }
	// pp := toh.gw.Auth.VIP6.String()
	// if tp.PrevPath != nil {
	// 	pp = pp + "/" + strings.Join(tp.PrevPath, "/")
	// }

	// // The client HTTP will return a Body reader - this has the data from the remote end.
	// //
	// req, err := http.NewRequest("POST", url, &BodyReader{Proxy: tp})
	// if err != nil {
	// 	log.Println("TCP-H2 Failed to generate HTTP/TCP addr", url, err)
	// 	return nil, err
	// }
	// req.Header.Add(HEADER_PREV_PATH, pp)

	// // If the request was received over H2:
	// //  - clientIn is set to req.Body, clientOut is set to w - from the client, when tp is created
	// //  - the BodyReader passed to NewRequest will read from clientIn ( the other side ) and auto write to remote
	// //  - remoteOut is not used - since it's already wired. This method will not set remoteOut

	// // If the requeset is intercepted or created via other means, clientIn and clientOut are set.
	// // The BodyReader passed to req will read from the clientIn, and remoteOut is not set.
	// //
	// // If this is result of a local process using Dialer to get a net.Conn:
	// //  - there is no clientIn set
	// //  - we create a pipe, so http can consume clientIn and send it to the remote side. Data is added to
	// //    the pipe when the net.Conn.Write() is called - which is supposed to send to the remote side. H2 would
	// //    get the piped data and send it.
	// //  - remoteIn is used to implement Read() of the net.Conn implemented by TcpProxy
	// if tp.ClientIn == nil {
	// 	pr, pw := io.Pipe()
	// 	tp.ServerOut = pw
	// 	tp.ClientIn = pr
	// }

	// hc := h2.Client(via)

	// ctx, cancel := context.WithCancel(context.Background())
	// req = req.WithContext(ctx)
	// tp.RemoteCtx = cancel

	// res, err := hc.Do(req)
	// if err != nil {
	// 	log.Println("TCP-H2 start error ", url, time.Since(t0), err)
	// 	cleanup(nil, res)
	// 	return err
	// }
	// log.Println("TCP-H2 start", url, time.Since(t0), res.StatusCode)

	// // Handshake/metadata
	// head := make([]byte, 2)
	// _, err = io.ReadFull(res.Body, head)
	// if err != nil {
	// 	log.Println("TCP-H2 H2-CLI Res error ", url, res.StatusCode, err)
	// 	cleanup(nil, res)
	// 	return err
	// }

	// // TODO: use a H2 stream low level. res.Body would be the stream
	// tp.ServerIn = res.Body
	// // Read method of tcpp will be used, streaming of data from tcpp should have already started
	// // The proxy method will ignore remoteOut, it is hooked to "localIn" by the HTTP handler.
	// //ch.remoteOut = nil

	return nil, nil
}



// DialViaHTTP connects to 'via' as 2-way H2, and forward in/out to the remote http stream.
// Keep track of the connection using localid and ctype.
// Some initial data from client will start to be sent.
//
// destAddr is the final destination of the stream - can be:
// - hostname:port
// - [IP6]:port
// - IP4:port
// - [fd00:MESHID]:port -> route to the MESHID, then use it to connect to the given dest addr
// The proxy MUST have localIn and initialData already set, because the http connection will start streaming it.
func (toh *TcpOverH2) DialViaHTTP(h2 *h2.H2, tp *mesh.TcpProxy, via, destAddr string) error {

	t0 := time.Now()

	tp.Stream.Dest = "TCPH2C/" + via + "/" + destAddr

	url := "https://" + via + "/tcp/" + destAddr

	if tp.NextPath != nil {
		url = url + "/" + strings.Join(tp.NextPath, "/")
	}
	pp := toh.gw.Auth.VIP6.String()
	if tp.PrevPath != nil {
		pp = pp + "/" + strings.Join(tp.PrevPath, "/")
	}

	// The client HTTP will return a Body reader - this has the data from the remote end.
	//
	req, err := http.NewRequest("POST", url, &BodyReader{Proxy: tp})
	if err != nil {
		log.Println("TCP-H2 Failed to generate HTTP/TCP addr", url, err)
		return err
	}
	req.Header.Add(HEADER_PREV_PATH, pp)

	// If the request was received over H2:
	//  - clientIn is set to req.Body, clientOut is set to w - from the client, when tp is created
	//  - the BodyReader passed to NewRequest will read from clientIn ( the other side ) and auto write to remote
	//  - remoteOut is not used - since it's already wired. This method will not set remoteOut

	// If the requeset is intercepted or created via other means, clientIn and clientOut are set.
	// The BodyReader passed to req will read from the clientIn, and remoteOut is not set.
	//
	// If this is result of a local process using Dialer to get a net.Conn:
	//  - there is no clientIn set
	//  - we create a pipe, so http can consume clientIn and send it to the remote side. Data is added to
	//    the pipe when the net.Conn.Write() is called - which is supposed to send to the remote side. H2 would
	//    get the piped data and send it.
	//  - remoteIn is used to implement Read() of the net.Conn implemented by TcpProxy
	if tp.ClientIn == nil {
		pr, pw := io.Pipe()
		tp.ServerOut = pw
		tp.ClientIn = pr
	}

	hc := h2.Client(via)

	ctx, cancel := context.WithCancel(context.Background())
	req = req.WithContext(ctx)
	tp.RemoteCtx = cancel

	res, err := hc.Do(req)
	if err != nil {
		log.Println("TCP-H2 start error ", url, time.Since(t0), err)
		cleanup(nil, res)
		return err
	}
	log.Println("TCP-H2 start", url, time.Since(t0), res.StatusCode)

	// Handshake/metadata
	head := make([]byte, 2)
	_, err = io.ReadFull(res.Body, head)
	if err != nil {
		log.Println("TCP-H2 H2-CLI Res error ", url, res.StatusCode, err)
		cleanup(nil, res)
		return err
	}

	// TODO: use a H2 stream low level. res.Body would be the stream
	tp.ServerIn = res.Body
	// Read method of tcpp will be used, streaming of data from tcpp should have already started
	// The proxy method will ignore remoteOut, it is hooked to "localIn" by the HTTP handler.
	//ch.remoteOut = nil

	return nil
}

func cleanup(localIn io.ReadCloser, res *http.Response) {
	if localIn != nil {
		localIn.Close()
	}

	//if err != nil && err.Error() != "EOF" {
	//	log.Println("TCP/H2 ERRR ", url, err, time.Since(t0))
	//}

	if res != nil && res.Body != nil {
		res.Body.Close()
		//log.Println("TCP/H2 CLOSE", url, time.Since(t0))
	}
}
