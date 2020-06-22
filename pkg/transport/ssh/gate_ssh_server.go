package ssh

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/costinm/wpgate/pkg/auth"
	"github.com/costinm/wpgate/pkg/mesh"
	"github.com/costinm/wpgate/pkg/msgs"
	"github.com/costinm/wpgate/pkg/transport/accept"
	"golang.org/x/crypto/ssh"
)

func (sshGate *SSHGate) authPub(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	if cert, ok := key.(*ssh.Certificate); ok {
		if cert.CertType != ssh.UserCert {
			return nil, fmt.Errorf("ssh: cert has type %d", cert.CertType)
		}
		// 1. Verify cert.SignatureKey is a CA

		// conn.User() is usually set to 'dmesh' - and ignored.
		//

		// cert.ValidPrincipals

		// for ED: 51 bytes,  19 (4 + 11 ssh-ed25519 + 4) + 32
		if cpk, ok := cert.Key.(ssh.CryptoPublicKey); ok {
			pubk := cpk.CryptoPublicKey()

			kbytes := auth.KeyBytes(pubk)
			kbs := string(kbytes)
			vip := auth.Pub2VIP(kbytes)

			var role string
			if role = sshGate.certs.Auth(kbytes, ""); role == "" {
				role = "guest"
			}
			log.Println("SSHClientConn Key ", key.Type(), role, base64.StdEncoding.EncodeToString(kbytes))

			return &ssh.Permissions{
				Extensions: map[string]string{
					"key":    kbs,
					"role":   role,
					"vip":    vip.String(),
					"user":   conn.User(),
					"remote": conn.RemoteAddr().String(),
				},
			}, nil
		}
		return nil, fmt.Errorf("key rejected for %s", key.Type())
	}

	// for ED: 51 bytes,  19 (4 + 11 ssh-ed25519 + 4) + 32
	if cpk, ok := key.(ssh.CryptoPublicKey); ok {
		pubk := cpk.CryptoPublicKey()

		kbytes := auth.KeyBytes(pubk)
		kbs := string(kbytes)
		vip := auth.Pub2VIP(kbytes)

		var role string
		if role = sshGate.certs.Auth(kbytes, ""); role == "" {
			role = "guest"
		}
		log.Println("SSHClientConn Key ", key.Type(), role, base64.StdEncoding.EncodeToString(kbytes))

		return &ssh.Permissions{
			Extensions: map[string]string{
				"key":    kbs,
				"role":   role,
				"vip":    vip.String(),
				"user":   conn.User(),
				"remote": conn.RemoteAddr().String(),
			},
		}, nil

	}

	log.Println("Unknown SSHClientConn Key, guest: ", conn.User(), conn.RemoteAddr(), key.Type(), base64.StdEncoding.EncodeToString(key.Marshal()))

	return nil, fmt.Errorf("key rejected for %s", key.Type())

}

func (sshGate *SSHGate) InitServer() error {
	// An SSHClientConn server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.
	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			return nil, fmt.Errorf("password rejected for %q", c.User())
		},
		PublicKeyCallback: sshGate.authPub,
		Config: ssh.Config{
			MACs: []string{"none", "hmac-sha2-256-etm@openssh.com", "hmac-sha2-256", "hmac-sha1", "hmac-sha1-96"},
			Ciphers: []string{
				"aes128-gcm@openssh.com",
				"chacha20-poly1305@openssh.com",
				"aes128-ctr", "none",
			},
		},
	}

	privateKey, err := ssh.NewSignerFromKey(sshGate.certs.EC256PrivateKey) // ssh.Signer
	config.AddHostKey(privateKey)

	sshGate.serverConfig = config

	return err
}

// Start listening. Typically address is :0, and the default port is 5222
// A single server is usually sufficient for a node.
func (sshGate *SSHGate) ListenSSH(address string) error {
	if address == "" {
		address = ":5222"
	}

	// Once a ServerConfig has been configured, connections can be
	// accepted.
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}

	go func() {
		for {
			nConn, err := listener.Accept()
			if err != nil {
				log.Println("failed to accept incoming connection ", err)
				time.Sleep(10 * time.Second)
				continue
			}
			go sshGate.HandleServerConn(nConn)
		}
	}()
	return nil
}

var conId int

// Handles a connection as SSH server, using a net.Conn - which might be tunneled over other transports.
// SSH handles multiplexing and packets.
func (sshGate *SSHGate) HandleServerConn(nConn net.Conn) {
	sshGate.metrics.Total.Add(1)

	t0 := time.Now()

	// Before use, a handshake must be performed on the incoming
	// net.Conn. Handshake results in conn.Permissions.
	conn, chans, globalSrvReqs, err := ssh.NewServerConn(nConn, sshGate.serverConfig)
	if err != nil {
		nConn.Close()
		log.Println("SSHD: handshake error ", err, nConn.RemoteAddr())
		sshGate.metrics.Errors.Add(1)
		return
	}

	vips := conn.Permissions.Extensions["key"]
	if vips == "" {
		conn.Close()
		nConn.Close()
		log.Println("SSHD: unexpected missing pub ", err, nConn.RemoteAddr())
		sshGate.metrics.Errors.Add(1)
		return
	}

	// conn: SendMessage,

	scon := &SSHServerConn{
		sshConn: conn,
		SSHConn: SSHConn{
			gate:    sshGate,
			Connect: time.Now(),
			Addr:    nConn.RemoteAddr().String(),
		},
	}

	vipsb := []byte(vips)
	scon.vip = auth.Pub2ID(vipsb)
	scon.VIP6 = auth.Pub2VIP(vipsb)
	scon.pubKey = vipsb
	vipHex := fmt.Sprintf("%x", scon.vip)
	//scon.key =
	sshGate.metrics.Active.Add(1)

	sshGate.mutex.Lock()
	oldSCon := sshGate.SshConn[scon.vip]
	sshGate.SshConn[scon.vip] = scon
	sshGate.mutex.Unlock()

	if oldSCon != nil {
		oldSCon.Close()
	}

	n := sshGate.gw.Node(vipsb)
	scon.Node = n
	// n.SSHTunSrv = scon - will be set when 5222 is received

	defer func() {

		sshGate.metrics.Active.Add(-1)

		sshGate.mutex.Lock()
		existing := sshGate.SshConn[scon.vip]
		if existing == scon {
			delete(sshGate.SshConn, scon.vip)
		}
		sshGate.mutex.Unlock()

		// TODO: remove from list of active
		scon.Close()
		conn.Close()
		log.Println("SSHD: CLOSE ", nConn.RemoteAddr(), auth.Pub2VIP(vipsb))
		sshGate.metrics.Latency.Add(time.Since(t0).Seconds())

		n.TunSrv = nil
	}()

	role := conn.Permissions.Extensions["role"]
	log.Println("SSHD: CONNECTION FROM ", nConn.RemoteAddr(), auth.Pub2VIP(vipsb), role)

	//msgs.Send("/gate/ssh", "remote",
	//	nConn.RemoteAddr().String(),
	//	"key", base64.StdEncoding.EncodeToString([]byte(conn.Permissions.Extensions["key"])),
	//	"role", role)

	// The incoming Request channel: accept forwarding of hosts port to the destination
	// This is for 'global requests'.
	go scon.handleServerConnRequests(globalSrvReqs, n, nConn, conn, vipHex, sshGate)

	// Service the incoming Channel channel.
	// Each channel is a stream - shell, exec, local TCP forward.
	for newChannel := range chans {
		switch newChannel.ChannelType() {
		case "direct-tcpip":
			// When remote starts with a -L PORT:host:port, and connects to port
			var req channelOpenDirectMsg
			scon.gate.localFwdS.Total.Add(1)
			err := ssh.Unmarshal(newChannel.ExtraData(), &req)
			if err != nil {
				log.Println("malformed-tcpip-request", err)
				newChannel.Reject(ssh.UnknownChannelType, "invalid data")
				continue
			}

			// TODO: allow connections to mesh VIPs
			//if role == ROLE_GUEST {
			//	newChannel.Reject(ssh.UnknownChannelType, "only authorized users can proxy")
			//	continue
			//}
			log.Println("-L: forward request", req.Laddr, req.Lport, req.Raddr, req.Rport)

			go scon.handleDirectTcpip(newChannel, req.Raddr, req.Rport, req.Laddr, req.Lport)
			conId++

		case "session":
			// session channel - the main interface for shell, exec
			scon.handleServerSessionChannel(n, newChannel, role)

		default:
			fmt.Println("SSHD: unknown channel Rejected", newChannel.ChannelType())
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
		}
	}

	log.Println("SSHD: end chans", scon.VIP6)
}

// Server connection from one SSHClientConn client - inbound
type SSHServerConn struct {
	SSHConn

	sshConn *ssh.ServerConn
	Remote  string
}

func (sshS *SSHServerConn) ForwardSocks() {
	panic("implement me")
}

func (sshS *SSHServerConn) ForwardTCP(local, remote string) error {
	panic("implement me")
}

func (sshS *SSHServerConn) Close() error {
	log.Println("SSHD: Close", sshS.VIP6, sshS.sshConn.RemoteAddr())
	return sshS.sshConn.Close()
}

// Global requests
func (scon *SSHServerConn) handleServerConnRequests(reqs <-chan *ssh.Request, n *mesh.DMNode, nConn net.Conn, conn *ssh.ServerConn, vipHex string, sshGate *SSHGate) {
	scon.Remote = nConn.RemoteAddr().String()

	for r := range reqs {
		// Global types.
		switch r.Type {
		// "-R": we expect at least one R with 0.0.0.0 and port 5222, corresponding to the main mux dispatcher.
		// SSHClientConn clients will only accept back connections with this particular host:port, and srcIP:srcPort.
		// Other reverse accept ports can be opened as well.
		case "tcpip-forward":
			var req tcpipForwardRequest
			err := ssh.Unmarshal(r.Payload, &req)
			if err != nil {
				log.Println("malformed-tcpip-request", err)
				r.Reply(false, nil)
				continue
			}
			if req.BindPort == 5222 {
				scon.handleMeshNodeForward(req, n, r, vipHex)
			} else {
				listener := scon.handleTcpipForward(req, r)
				if listener != nil {
					defer func() {
						log.Println("Listener close ", listener)
						listener.Close()
					}()
				}
			}

			continue

		case "keepalive@openssh.com":
			n.LastSeen = time.Now()
			log.Println("SSHD: client keepalive", n.VIP)
			r.Reply(true, nil)

		default:
			log.Println("SSHD: unknown global REQUEST ", r.Type)
			if r.WantReply {
				log.Println(r.Type)
				r.Reply(false, nil)
			}
		}
	}
}

// For -R on 5222, special reverse TCP mode.
//
func (scon *SSHServerConn) handleMeshNodeForward(req tcpipForwardRequest,
	clientNode *mesh.DMNode,
	r *ssh.Request, vipHex string) {
	// This is the SSHClientConn-mesh port of the connected client. Will be used as gateway
	clientNode.TunSrv = scon
	// No special listener - this is a virtual mux, using reverse SOCKS
	var res tcpipForwardResponse
	res.BoundPort = req.BindPort

	r.Reply(true, ssh.Marshal(res))

	// TODO: propagate the endpoint, reflect it in the UI
	msgs.Send("/endpoint/ssh",
		"remote", scon.Remote,
		"key", base64.StdEncoding.EncodeToString([]byte(scon.sshConn.Permissions.Extensions["key"])),
		"vip", vipHex) // TODO: configure the public addresses !

}

// -R handling - create accepting socket to forward over this conn.
func (scon *SSHServerConn) handleTcpipForward(req tcpipForwardRequest, r *ssh.Request) mesh.Listener {
	// Requested port
	forPort := req.BindPort

	// Not supported: RFC: address "" means all families, 0.0.0.0 IP4, :: IP6, localhost IP4/6, etc
	listener, err := accept.NewPortListener(scon.gate.gw, fmt.Sprintf("%s:%d", req.BindIP, forPort))
	if err != nil {
		log.Println("Error accepting ", err, forPort)
		r.Reply(false, nil)
		return nil
	}

	// BindIP and BindPort must be sent back  via ReverseForward, so client can
	// match the -R.. request
	listener.AddEndpointSSH(scon, req.BindIP, req.BindPort)
	_, port, err := net.SplitHostPort(listener.Listener.Addr().String())
	if err != nil {
		r.Reply(false, nil)
		return nil
	}

	//msgs.Send("/ssh/accept",
	//	"remote", nConn.RemoteAddr().String(),
	//	"req", fmt.Sprintf("%d", req.BindPort),
	//	"vip", vipHex,
	//	"key", base64.StdEncoding.EncodeToString([]byte(conn.Permissions.Extensions["key"])),
	//	"addr",fmt.Sprintf("%s:%d", "", forPort)) // TODO: configure the public addresses !
	var res tcpipForwardResponse
	forPort32, _ := strconv.Atoi(port)
	forPort = uint32(forPort32)
	res.BoundPort = forPort

	log.Println("SSHS: (-R) tcpip-forward ", forPort, res.BoundPort, req.BindIP)

	r.Reply(true, ssh.Marshal(res))

	//bindAddr := net.JoinHostPort(req.BindIP, fmt.Sprintf("%d", req.BindPort))
	go listener.Run()

	return listener
}

// For -R, when a remote conn is received on a TCP accept.
func (sshS *SSHServerConn) ReverseForward2(in io.ReadCloser, out io.Writer,
	ip net.IP, port int, hostKey string, portKey uint32) {

	log.Println("FWD Connection ", ip, port, portKey)
	defer func() {
		in.Close()
	}()

	var req forwardTCPIPChannelRequest
	req.ForwardIP = hostKey
	req.ForwardPort = portKey

	req.OriginIP = ip.String()
	req.OriginPort = uint32(port)

	channel, reqs, err := sshS.sshConn.OpenChannel("forwarded-tcpip", ssh.Marshal(req))
	if err != nil {
		log.Println("Failed for forward-tcpip", err)
		return
	}

	defer func() {
		channel.Close()
	}()

	go func() {
		for r := range reqs {
			log.Println("forwarded-tcpip remote request ", r)

			r.Reply(false, nil)
		}
	}()

	// Common gateway code to forward a connection.
	// Will proxy the 2 connections, with stats, etc.
	proxy := sshS.gate.gw.NewTcpProxy(&net.TCPAddr{IP: ip, Port: port}, "SSHR", nil, in, out)
	defer proxy.Close()
	proxy.ServerIn = channel
	proxy.ServerOut = channel

	// Not accurate - we don't really know where it goes after next hop
	proxy.Dest = sshS.sshConn.RemoteAddr().String()

	proxy.Proxy()
}

// DialReverse uses an existing server connection (this node accepted the request) to create
// a virtual tunnel where this node is the client.
// For SSH it relies on "forwarded-tcpip", which is typically used for -R/accept channels, with
// a custom header at the beginning (TODO: use CONNECT, and make it consistent for all channels)
func (sshS *SSHServerConn) DialProxy(tp *mesh.Stream) error {
	log.Println("SSHClientConn SOCKS Reverse Connection ", tp.Dest)

	sshS.gate.rMesh.Total.Add(1)

	var req forwardTCPIPChannelRequest
	req.ForwardIP = "0.0.0.0"
	req.ForwardPort = 5222

	orighost, origPort, _ := net.SplitHostPort(tp.Origin)
	origPortI, _ := strconv.Atoi(origPort)

	req.OriginIP = orighost
	req.OriginPort = uint32(origPortI)

	channel, reqs, err := sshS.sshConn.OpenChannel("forwarded-tcpip", ssh.Marshal(req))
	if err != nil {
		log.Println("Failed for forward-tcpip", err)
		sshS.gate.rMesh.Errors.Add(1)
		return err
	}
	sshS.gate.rMesh.Active.Add(1)

	go func() {
		for r := range reqs {
			log.Println("forwarded-tcpip remote request ", r)
			r.Reply(false, nil)
		}
	}()

	// TODO: send SOCKS-like header based on dest !!!
	head := []byte{0, 0}
	binary.BigEndian.PutUint16(head, uint16(len(tp.Dest)))

	channel.Write(head)
	channel.Write([]byte(tp.Dest))

	t0 := time.Now()
	tp.Closer = func() {
		sshS.gate.rMesh.Active.Add(-1)
		sshS.gate.rMesh.Latency.Add(time.Since(t0).Seconds())
		channel.Close()
	}
	tp.ServerOut = channel
	tp.ServerIn = channel

	return nil
}

func (sshC *SSHClientConn) ForwardSocks() error {

	// TODO: as optimization, allow an option to take the Listener and pass it to http, with a mux - make it H2, with TLS

	l, err := sshC.sshclient.Listen("tcp", "0.0.0.0:5222")
	if err != nil {
		log.Println("unable to register tcp forward", err)
		return err
	}

	sshC.gate.gw.GWAddr = sshC.Addr
	msgs.Send("./gate/sshc", "addr", sshC.Addr)

	for {
		c, err := l.Accept()
		if err != nil {
			l.Close()
			return nil
		}

		go func() {
			// TODO: reuse buffer, reuse method, use a proto ?
			head := make([]byte, 512)
			c.Read(head[0:2])
			sz := binary.BigEndian.Uint16(head)
			c.Read(head[0:sz])

			p := sshC.gate.gw.NewTcpProxy(c.RemoteAddr(), "SSHRSOCKS", nil, c, c)

			err = p.Dial(string(head[0:sz]), nil)

			p.Proxy()
		}()
	}
	// Serve HTTP with your SSHClientConn server acting as a reverse proxy.

	return nil
}

// Handles SOCKS (-D) and local fwd (-L), mapping remote ports to connections to a host:port
// It is equivalent with /dmesh/tcp/IP/port request.
func (sshS *SSHServerConn) handleDirectTcpip(newChannel ssh.NewChannel, host string, port uint32, localAddr string, localPort uint32) {
	channel, requests, err := newChannel.Accept()
	if err != nil {
		log.Println("could not accept channel.", err)
		return
	}

	go func(in <-chan *ssh.Request) {
		for req := range in {
			log.Println("direct-tcpip session request ", req.Type, string(req.Payload))
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}(requests)

	sshS.gate.localFwdS.Active.Add(1)
	t0 := time.Now()
	// channel is a io.ReadWriter
	addr, _ := net.ResolveIPAddr("ip", localAddr)

	proxy := sshS.gate.gw.NewTcpProxy(&net.TCPAddr{IP: addr.IP, Port: int(localPort)}, "SSHL", nil, channel, channel)
	err = proxy.Dial(net.JoinHostPort(host, strconv.Itoa(int(port))), nil)
	if err != nil {
		channel.Close()
		sshS.gate.localFwdS.Active.Add(-1)
		sshS.gate.localFwdS.Errors.Add(1)
		log.Println("SSHD: -L  ERR ", sshS.vip, err, host, port, localAddr, localPort)
		return
	}
	log.Println("SSHD: -L ", sshS.vip, host, port, localAddr, localPort)
	proxy.Proxy()
	sshS.gate.localFwdS.Active.Add(-1)
	sshS.gate.localFwdS.Latency.Add(time.Since(t0).Seconds())
}

const ROLE_GUEST = "guest"

// Channel contains 'exec' and 'shell' sessions.
// We use this as interface to the messaging system. On stock SSH servers we expect an app called 'dmeshMsg'
// that is execed, using stdin and stdout for communication.
// TODO: reuse UDS protocol parsing (or eventing)
// TODO: ACL (possibly reused from eventing) - command messages only from trusted sources, forwarding, etc
func (sshS *SSHServerConn) handleServerSessionChannel(node *mesh.DMNode, newChannel ssh.NewChannel, role string) {
	channel, requests, err := newChannel.Accept()
	if err != nil {
		log.Println("could not accept channel.")
		return
	}

	sshS.msgChannel = channel

	// Sessions have out-of-band requests such as "shell",
	// "pty-req" and "env".  Here we handle only the
	// "shell" request.
	go sshS.handleServerRequestChan(node, requests)

	// ssh: pty-req, shell session req
	// exec - command passed when env and exec is received.
	// We use this just for one command right now - dmeshMsg

	mconn := &msgs.MsgConnection{
		SubscriptionsToSend: nil, // Don't send all messages down - only if explicit subscription.
		SendMessageToRemote: sshS.SendMessageToRemote,
	}

	//if role != ROLE_GUEST {
	msgs.DefaultMux.AddConnection("sshs-"+sshS.VIP6.String(), mconn)
	//}

	br := bufio.NewReader(channel)

	go handleMessageStream(node, br, sshS.VIP6.String(), sshS.gate.certs.VIP6.String(), mconn, true)

	mconn.SendMessageToRemote(msgs.NewMessage("/endpoint/sshs", map[string]string{
		//"remote", nConn.RemoteAddr().String(),
		//"key": base64.StdEncoding.EncodeToString(sshC.gate.certs.Pub),
		//"vip": sshC.gate.certs.VIP6.String(), // TODO: configure the public addresses !
		"ua": sshS.gate.gw.UA,
	}))
}

// As a server, handle out-of-band requests on a session.
// server may have multiple sessions
func (sshS *SSHServerConn) handleServerRequestChan(n *mesh.DMNode, in <-chan *ssh.Request) {
	for req := range in {
		switch req.Type {
		case "shell":
			log.Println("shell request, closing ", sshS.vip, req.Type, string(req.Payload))
			if len(req.Payload) > 0 {
				// We don't accept any
				// commands, only the
				// default shell.
			}
			req.Reply(true, nil)
		case "exec":
			sshExec := execRequest{}
			if len(req.Payload) > 0 {
				ssh.Unmarshal(req.Payload, &sshExec)
				// We don't accept any
				// commands, only the
				// default shell.
			}
			log.Println("exec ", sshS.vip, sshExec.Command)
			req.Reply(true, nil)
		case "pty-req":
			req.Reply(false, nil)
		case "env":
			log.Println("Env request ", req.Type, string(req.Payload))
			req.Reply(true, nil)
		case "keepalive@openssh.com":
			n.LastSeen = time.Now()
			log.Println("SSHD: client keepalive", n.VIP)
			req.Reply(true, nil)
		default:
			log.Println("Session request ", req.Type, string(req.Payload))
			req.Reply(true, nil)
		}

	}
}

// Messages received from remote, over SSH.
//
// from is the authenticated VIP of the sender.
// self is my own VIP
//
//
func handleMessageStream(node *mesh.DMNode, br *bufio.Reader, from string, self string, mconn *msgs.MsgConnection, isServer bool) {
	mconn.HandleMessageStream(func(ev *msgs.Message) {
		// Direct message from the client, with its own info
		if ev.Topic == "endpoint" {
			if node.NodeAnnounce == nil {
				node.NodeAnnounce = &mesh.NodeAnnounce{}
			}
			node.NodeAnnounce.UA = ev.Meta["ua"]
		}
		newEv, _ := json.Marshal(ev)
		fmt.Println(string(newEv))

	}, br, from, self)

	log.Println("Message mux closed")
}

// SSH client: handles the connection with the server.
//
// Messages from server are dispatched to the mux, for local forwarding
// Messages from local mux are sent to the server - sub is *.
//
// The mux is responsible for eliminating loops and forwarding.
func (sshC *SSHClientConn) handleClientMsgChannel(node *mesh.DMNode, channel ssh.Channel, subs []string) {
	mconn := &msgs.MsgConnection{
		SubscriptionsToSend: subs,
		SendMessageToRemote: sshC.SendMessageToRemote,
	}

	msgs.DefaultMux.AddConnection("sshc-"+sshC.VIP6.String(), mconn)

	// From and path will be populated by forwarder code.
	mconn.SendMessageToRemote(msgs.NewMessage("/endpoint/sshc", map[string]string{
		//"remote", nConn.RemoteAddr().String(),
		//"key": base64.StdEncoding.EncodeToString(sshC.gate.certs.Pub),
		//"vip": sshC.gate.certs.VIP6.String(), // TODO: configure the public addresses !
		"ua": sshC.gate.gw.UA,
	}))

	br := bufio.NewReader(channel)
	handleMessageStream(node, br, sshC.VIP6.String(), sshC.gate.certs.VIP6.String(), mconn, false)

	// Disconnected
	node.TunClient = nil
}

// Private SSHClientConn structs

type execRequest struct {
	Command string
}

type tcpipForwardRequest struct {
	BindIP   string
	BindPort uint32
}

type tcpipForwardResponse struct {
	BoundPort uint32
}

// "forwarded-tcp" or "-R" - reverse, ssh-server-accepted connections sent to client.
// VPN or public device will expose a port, or a dmesh client will use a local port as Gateway
// ForwardIP/ForwardPort are used as keys - to match the listener.
type forwardTCPIPChannelRequest struct {
	ForwardIP   string
	ForwardPort uint32
	OriginIP    string
	OriginPort  uint32
}

// RFC 4254 7.2 - direct-tcpip
// -L or -D, or egress. Client using VPN as an egress gateway.
// Raddr can be a string (hostname) or IP.
// Laddr is typically 127.0.0.1 (unless ssh has an open socks, and other machines use it)
//
type channelOpenDirectMsg struct {
	Raddr string
	Rport uint32

	Laddr string
	Lport uint32
}
