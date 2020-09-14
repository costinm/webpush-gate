package accept

import (
	"io"
	"log"
	"net"
	"strconv"

	"github.com/costinm/wpgate/pkg/mesh"
)

// RemoteListener accepts connections on a remote server, and
// forwards to a local server over an existing connection,
// similar with -R in ssh.

// Docs and other options:
//https://blog.ston3o.me/how-to-expose-local-server-behind-firewall/
// - OpenVPN - easy to setup docker container
// - upnpc
// - tor
// ngrok - free 40 con/min
// pagekite - py, $3/month
// bleenco/localtunnel (go)
// localtunnel/localtunnel (js)
// yaler - commercial
// inlets / rancher remote dialer

// socks bind standard - not commonly implemented

// ssh -R remote_server_ip:12345:localhost:12345
// - multiplexed over ssh TCP con, flow control per socket

/*
			byte      SSH_MSG_CHANNEL_OPEN
      string    "forwarded-tcpip"
      uint32    sender channel

			uint32    initial window size
      uint32    maximum packet size

			string    address that was connected
      uint32    port that was connected

			string    originator IP address
      uint32    originator port
*/

// concourse TSA - uses ssh, default 2222
// 'beacon' is effectively using ssh command to forward ports
// "golang.org/x/crypto/ssh"
//https://github.com/concourse/tsa/blob/master/tsacmd/server.go

// Original implementation attempted to use http(2).
// The main problem with H2 client connections is that we lack ability to flush() on the input
// stream. This is a problem for the http interface in go, and unfortunately I'm not aware of
// any good solution.
// 1. We can use just the response stream, creating a new connection to send response.
// The new connection may go to a different replica - so some forwarding on server side
// may be needed. Ok with a single server, or if the server can be pinned (cookie, etc)
// 2. We can use the low level h2 stack, like grpc http2_client.

// Rancher 'Reverse Tunneling Dialer' and 'inlets':
// - use websocket - no multiplexing.
// - binary messages, using websocket frames

// TODO: emulate SSHClientConn protocol over H3 ( H2 connections framed )
// TODO: send a message to request client to open a reverse TCP channel for each accepted connection

func NewForwarder(gw *mesh.Gateway, cfg *mesh.ListenerConf) {
	pl, _ := NewPortListener(gw, cfg.Local)
	pl.cfg.Remote = cfg.Remote
	go pl.Run()
}

// Create a local port on listenPort, accepting connections to be forwarded to the mesh VIP or a
// defined IP address. Implements -R in ssh.
func NewPortListener(gw *mesh.Gateway, listenPort string) (*Listener, error) {
	ll := &Listener{
		cfg: &mesh.ListenerConf{
			Local: listenPort,
		},
		GW: gw,
	}

	// Not supported: RFC: address "" means all families, 0.0.0.0 IP4, :: IP6, localhost IP4/6, etc
	listener, err := net.Listen("tcp", ll.cfg.Local)
	if err != nil {
		host, _, _ := net.SplitHostPort(ll.cfg.Local)
		ll.cfg.Local = host + ":0"
		listener, err = net.Listen("tcp", ll.cfg.Local)
		if err != nil {
			log.Println("failed-to-listen", err)
			return nil, err
		}
	}

	laddr := listener.Addr().String()
	_, port, _ := net.SplitHostPort(laddr)
	portN, _ := strconv.Atoi(port)

	ll.cfg.Port = portN
	ll.Listener = listener

	ll.GW.Listeners[portN] = ll

	return ll, nil
}

// A Listener is similar with an Envoy Listener.
// It can be created by a Gateway or Sidecar resource in istio, as well as from in Service and for out capture
//
// For mesh, it is also auto-created for each device/endpoint/node for accepting messages and in connections.
//
type Listener struct {
	cfg *mesh.ListenerConf
	// Destination:
	// - sshConn if set -
	// - Remote
	// - vpn (for outbound) ?
	// - dmesh ingress gateway

	// Set if the listener forward to a ssh connection
	// used for ssh - this is the original IP:port in the -R request, might not match the actual
	// port we are listening on.
	acceptForwarder AcceptForwarder

	// Original bind host and port, as requested by client
	// May be different from actual port.
	// Used with the acceptForwarder to track the binding.
	bindHost string
	bindPort uint32

	// Real listener for the port
	Listener net.Listener

	GW *mesh.Gateway
}

// AcceptForwarder is used to tunnel accepted connections over a multiplexed stream.
// Implements -R in ssh.
// TODO: h2 implementation
// Used by acceptor.
type AcceptForwarder interface {
	// Called when a connection was accepted.
	//
	AcceptForward(in io.ReadCloser, out io.Writer,
		remoteIP net.IP, remotePort int,
		bindHost string, bindPort uint32)
}

// Accepted connections will be sent to 'con'
func (ll *Listener) SetAcceptForwarder(con AcceptForwarder, bindKey string, bindPort uint32) *Listener {
	ll.acceptForwarder = con
	ll.bindPort = bindPort
	ll.bindHost = bindKey
	return ll
}

func (ll *Listener) Close() error {
	ll.Listener.Close()
	delete(ll.GW.Listeners, ll.cfg.Port)
	return nil
}

func (ll Listener) Accept() (net.Conn, error) {
	return ll.Listener.Accept()
}

func (ll Listener) Addr() (net.Addr) {
	return ll.Listener.Addr()
}

// For -R, runs on the remote ssh server to accept connections and forward back to client, which in turn
// will forward to a port/app.
// Blocking.
func (ll Listener) Run() {
	log.Println("Gateway: open on ", ll.cfg.Local, ll.bindHost, ll.bindPort, ll.cfg.Remote)
	for {
		remoteConn, err := ll.Listener.Accept()
		if err != nil {
			return
		}
		go ll.handleAcceptedConn(remoteConn)
	}
}

func (ll *Listener) handleAcceptedConn(c net.Conn) error {
	// c is the local or 'client' connection in this case.
	// 'remote' is the configured destination.

	ra := c.RemoteAddr().(*net.TCPAddr)

	if ll.acceptForwarder != nil {
		ll.acceptForwarder.AcceptForward(c, c, ra.IP, ra.Port,
			ll.bindHost, ll.bindPort)
		return nil
	}

	defer c.Close()

	// Ingress mode, forward to an IP
	if ll.cfg.Remote != "" {
		proxy := ll.GW.NewTcpProxy(c.RemoteAddr(), "ACC-"+strconv.Itoa(ll.cfg.Port), nil, c, c)
		err := ll.GW.Dial(proxy, ll.cfg.Remote, nil)
		if err != nil {
			log.Println("Failed to connect ", ll.cfg.Remote, err)
			return err
		}

		return proxy.Proxy()
	}

	return nil
}

// port capture is the plain reverse proxy mode: it listens to a port and forwards.
//
// Clients will use "localhost:port" for TCP or UDP proxy, and http will use some DNS
// resolver override to map hostname to localhost.
// The config is static (mesh config) or it can be dynamic (http admin interface or mesh control)

// Start a port capture or forwarding.
// listenPort: port on local host, or :0. May include 127.0.0.1 or 0.0.0.0 or specific interface.
// host: destination. Any connection on listenPort will result on a TCP stream to the destination.
//       May be a chain of DMesh nodes, with an IP:port at the end.
