package ssh

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/costinm/ugate"
	"github.com/costinm/wpgate/pkg/auth"
	"github.com/costinm/wpgate/pkg/msgs"
	"golang.org/x/crypto/ssh"
)

// Server side auth
func (sshGate *SSHGate) authPub(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	// SSH certificates are different from HTTP - one layer only.
	//
	if cert, ok := key.(*ssh.Certificate); ok {
		if cert.CertType != ssh.UserCert {
			return nil, fmt.Errorf("ssh: cert has type %d", cert.CertType)
		}
		// 1. Verify cert.SignatureKey is a CA

		//cert.SignatureKey.(ssh.CryptoPublicKey)

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
		ServerVersion: version,
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

	privateKey, err := ssh.NewSignerFromKey(sshGate.certs.EC256Cert.PrivateKey) // ssh.Signer
	config.AddHostKey(privateKey)

	sshGate.serverConfig = config

	return err
}

// Start listening. Typically address is :0, and the default port is 5222
// A single server is usually sufficient for a node.
func (sshGate *SSHGate) ListenSSH(address string) error {
	if sshGate.serverConfig == nil {
		sshGate.InitServer()
	}
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

	role := conn.Permissions.Extensions["role"]
	vips := conn.Permissions.Extensions["key"]
	if vips == "" {
		conn.Close()
		nConn.Close()
		log.Println("SSHD: unexpected missing pub ", err, nConn.RemoteAddr())
		sshGate.metrics.Errors.Add(1)
		return
	}

	scon := &SSHServerConn{
		SSHConn: SSHConn{
			gate:    sshGate,
			Connect: time.Now(),
			Addr:    nConn.RemoteAddr().String(),
			open:    true,
			sshConn: conn,
		},
	}

	vipsb := []byte(vips)
	scon.vip = auth.Pub2ID(vipsb)
	scon.VIP6 = auth.Pub2VIP(vipsb)
	scon.pubKey = vipsb

	scon.role = role

	sshGate.gw.JumpHosts[scon.VIP6.String()] = scon

	vipHex := fmt.Sprintf("%x", scon.vip)
	//scon.key =
	sshGate.metrics.Active.Add(1)

	sshGate.mutex.Lock()
	oldSCon := sshGate.SshConn[scon.vip]
	sshGate.SshConn[scon.vip] = scon
	sshGate.mutex.Unlock()

	if oldSCon != nil {
		//oldSCon.Close()
	}

	n := sshGate.gw.Node(vipsb)
	scon.Node = n
	// n.SSHTunSrv = scon - will be set when 5222 is received

	if string(conn.ClientVersion()) == version {
		n.TunSrv = scon
	}

	defer func() {

		sshGate.metrics.Active.Add(-1)

		sshGate.mutex.Lock()
		existing := sshGate.SshConn[scon.vip]
		if existing == scon {
			delete(sshGate.SshConn, scon.vip)
		}
		delete(sshGate.gw.JumpHosts, scon.VIP6.String())
		sshGate.mutex.Unlock()

		// TODO: remove from list of active
		scon.Close()
		conn.Close()
		log.Println("SSHD: CLOSE ", nConn.RemoteAddr(), auth.Pub2VIP(vipsb))
		sshGate.metrics.Latency.Add(time.Since(t0).Seconds())

		n.TunSrv = nil
	}()

	log.Println("SSHD: CONNECTION FROM ", nConn.RemoteAddr(), auth.Pub2VIP(vipsb), role)

	//msgs.Send("/gate/ssh", "remote",
	//	nConn.RemoteAddr().String(),
	//	"key", base64.StdEncoding.EncodeToString([]byte(conn.Permissions.Extensions["key"])),
	//	"role", role)

	// The incoming Request channel: accept forwarding of hosts port to the destination
	// This is for 'global requests': keepalive and '-R'
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
			if role == ROLE_GUEST &&
				req.Rport != SSH_MESH_PORT && req.Rport != H2_MESH_PORT {
				newChannel.Reject(ssh.Prohibited,
					"only authorized users can proxy " +
					scon.VIP6.String())
				continue
			}
			log.Println("-L: forward request", req.Laddr, req.Lport, req.Raddr, req.Rport, role)

			go scon.handleDirectTcpip(newChannel, req.Raddr, req.Rport, req.Laddr, req.Lport)
			conId++

		case "session":
			// session channel - the main interface for shell, exec
			// Used for messages.
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
}

func (sshS *SSHServerConn) RemoteVIP() net.IP {
	return sshS.VIP6
}

func (sshS *SSHServerConn) Wait() error {
	return nil
}

func (sshS *SSHServerConn) RemoteAccept(r, f string) error {
	return nil
}
func (sshS *SSHServerConn) Close() error {
	log.Println("SSHD: Close", sshS.VIP6, sshS.sshConn.RemoteAddr())
	return sshS.sshConn.Close()
}

// Global requests
func (sshS *SSHServerConn) handleServerConnRequests(reqs <-chan *ssh.Request, n *ugate.DMNode, nConn net.Conn, conn *ssh.ServerConn, vipHex string, sshGate *SSHGate) {
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

			if req.BindPort == SSH_MESH_PORT || req.BindPort != H2_MESH_PORT {
				sshS.handleMeshNodeForward(req, n, r, vipHex)
			} else {
				if sshS.role == ROLE_GUEST && req.BindPort != SSH_MESH_PORT {
					r.Reply(false, nil)
					continue
				}
				listener := sshS.handleTcpipForward(req, r)
				if listener != nil {
					defer func() {
						log.Println("portListener close ", listener)
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

// For -R on 5222, special reverse TCP mode similar with SOCKS.
// No listener is created - this is used internally
func (sshS *SSHServerConn) handleMeshNodeForward(req tcpipForwardRequest,
	clientNode *ugate.DMNode,
	r *ssh.Request, vipHex string) {
	// This is the SSHClientConn-mesh port of the connected client. Will be used as gateway
	clientNode.TunSrv = sshS
	// No special listener - this is a virtual mux, using reverse SOCKS
	var res tcpipForwardResponse
	res.BoundPort = req.BindPort

	r.Reply(true, ssh.Marshal(res))

	// TODO: propagate the endpoint, reflect it in the UI
	msgs.Send("/endpoint/ssh",
		"remote", sshS.Addr,
		"key", base64.StdEncoding.EncodeToString([]byte(sshS.sshConn.Permissions.Extensions["key"])),
		"vip", vipHex) // TODO: configure the public addresses !
}

type fwdPort struct {
	scon     *SSHServerConn
	bindPort uint32
	bindIP   string
}

func (fp *fwdPort) DialContext(ctx context.Context, net, addr string) (net.Conn, error) {
	// TODO: get remote IP and port from ctx

	//log.Println("SSH-R FWD Connection ", ip, port, portKey)
	var req forwardTCPIPChannelRequest
	req.ForwardIP = fp.bindIP
	req.ForwardPort = fp.bindPort

	//req.OriginIP = ip.String()
	//req.OriginPort = uint32(port)

	channel, reqs, err := fp.scon.sshConn.OpenChannel("forwarded-tcpip", ssh.Marshal(req))
	if err != nil {
		log.Println("Failed for forward-tcpip", err)
		return nil, err
	}

	go func() {
		for r := range reqs {
			log.Println("forwarded-tcpip remote request ", r)

			r.Reply(false, nil)
		}
	}()
	return &netChannel{channel}, nil
}

type netChannel struct {
	c ssh.Channel
}

func (n2 netChannel) Read(b []byte) (n int, err error) {
	return n2.c.Read(b)
}

func (n2 netChannel) Write(b []byte) (n int, err error) {
	return n2.c.Write(b)
}

func (n2 netChannel) Close() error {
	return n2.c.Close()
}

func (n2 netChannel) CloseWrite() error {
	return n2.c.CloseWrite()
}

func (n2 netChannel) LocalAddr() net.Addr {
	panic("implement me")
}

func (n2 netChannel) RemoteAddr() net.Addr {
	panic("implement me")
}

func (n2 netChannel) SetDeadline(t time.Time) error {
	panic("implement me")
}

func (n2 netChannel) SetReadDeadline(t time.Time) error {
	panic("implement me")
}

func (n2 netChannel) SetWriteDeadline(t time.Time) error {
	panic("implement me")
}

// -R handling - create accepting socket to forward over this conn.
func (sshS *SSHServerConn) handleTcpipForward(req tcpipForwardRequest, r *ssh.Request) io.Closer {
	// Requested port
	forPort := req.BindPort

	k := sshS.VIP6.String()

	// TODO: remove at exit

	// Add a TCP listener that forwards specifically to the client on this
	// connection.
	// Replaced with H2R
	// - add a 'node' at connect, based on client pubkey
	// - set the node's h2r
	cl, addr, err := sshS.gate.gw.UGate.Add(&ugate.Listener{
		Address: fmt.Sprintf("0.0.0.0:%d", forPort),
		ForwardTo: k,
		// TODO: this is currently disabled, to clean the interface.
		// XXXXXXXXXXXXXXXX
	  //Dialer: &fwdPort{
		//	scon:     sshS,
		//	bindIP:   req.BindIP,
		//	bindPort: req.BindPort,
		//},
	})

	// Not supported: RFC: address "" means all families, 0.0.0.0 IP4, :: IP6, localhost IP4/6, etc
	//listener, err := accept.NewPortListener(scon.gate.gw, fmt.Sprintf("%s:%d", req.BindIP, forPort))
	if err != nil {
		log.Println("Error accepting ", err, forPort)
		r.Reply(false, nil)
		return nil
	}

	// BindIP and BindPort must be sent back  via ReverseForward, so client can
	// match the -R.. request
	//listener.SetAcceptForwarder(scon, req.BindIP, req.BindPort)
	_, port, err := net.SplitHostPort(addr.String())
	//_, port, err := net.SplitHostPort(listener.Listener.Addr().String())
	if err != nil {
		r.Reply(false, nil)
		return nil
	}

	msgs.Send("/ssh/accept",
		"remote", sshS.sshConn.RemoteAddr().String(),
		"req", fmt.Sprintf("%d", req.BindPort),
		"vip", sshS.VIP6.String(),
		"key", base64.StdEncoding.EncodeToString([]byte(sshS.sshConn.Permissions.Extensions["key"])),
		"addr", fmt.Sprintf("%s:%d", "", forPort)) // TODO: configure the public addresses !

	var res tcpipForwardResponse
	forPort32, _ := strconv.Atoi(port)
	forPort = uint32(forPort32)
	res.BoundPort = forPort

	log.Println("SSHS: (-R) tcpip-forward ", forPort, res.BoundPort, req.BindIP)

	r.Reply(true, ssh.Marshal(res))

	//bindAddr := net.JoinHostPort(req.BindIP, fmt.Sprintf("%d", req.BindPort))

	return cl
}

type netConnChannel struct {
	ssh.Channel
}

func (n *netConnChannel) LocalAddr() net.Addr {
	return nil
}

func (n *netConnChannel) RemoteAddr() net.Addr {
	return nil
}

func (n *netConnChannel) SetDeadline(t time.Time) error {
	return nil
}

func (n *netConnChannel) SetReadDeadline(t time.Time) error {
	return nil
}

func (n *netConnChannel) SetWriteDeadline(t time.Time) error {
	return nil
}

func (sshS *SSHServerConn) DialForwarded(ctx context.Context,
	remote net.Addr,
	hostKey string, portKey uint32) (net.Conn, error) {
	var req forwardTCPIPChannelRequest
	req.ForwardIP = hostKey
	req.ForwardPort = portKey

	rt := remote.(*net.TCPAddr)
	req.OriginIP = rt.IP.String()
	req.OriginPort = uint32(rt.Port)

	channel, reqs, err := sshS.sshConn.OpenChannel("forwarded-tcpip", ssh.Marshal(req))
	if err != nil {
		log.Println("Failed for forward-tcpip", err)
		return nil, err
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
	return &netConnChannel{channel}, nil
}

// For -R, when a remote conn is received on a TCP accept.
// Will open a 'forwarded-tcpip' channel from server to client, associated
// with the previous -R.
// Called from acceptor, for an explicit listen port.
func (sshS *SSHServerConn) AcceptForward(in io.ReadCloser, out io.Writer,
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
	proxy.In = channel
	proxy.Out = channel

	// Not accurate - we don't really know where it goes after next hop
	proxy.Dest = sshS.sshConn.RemoteAddr().String()

	proxy.Proxy()
}

// DialProxy uses an existing server connection (this node accepted the request) to create
// a virtual tunnel where this node is the client.
//
// For SSH it relies on "forwarded-tcpip", which is typically used for -R/accept channels, with
// a custom header at the beginning
// (TODO: use CONNECT, and make it consistent for all channels)
//
// This only works if the clients are compatible with this extension
func (sshS *SSHServerConn) DialProxy(tp *ugate.Stream) error {
	if string(sshS.sshConn.ClientVersion()) != version {
		return sshS.DialProxyLegacy(tp)
	}
	log.Println("SSHClientConn SOCKS Reverse Connection ", tp.Dest)

	sshS.gate.rMesh.Total.Add(1)

	req := dmeshChannelData {
		Dest: tp.Dest,
		RemoteAddr: "",
	}

	channel, reqs, err := sshS.sshConn.OpenChannel("dmesh",
		ssh.Marshal(req))
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

	t0 := time.Now()
	tp.Closer = func() {
		sshS.gate.rMesh.Active.Add(-1)
		sshS.gate.rMesh.Latency.Add(time.Since(t0).Seconds())
		channel.Close()
	}
	tp.Out = channel
	tp.In = channel

	return nil
}

// Attemtping to use std forward - it requires the other side
// to understand the header. This may work if remote is doing a
// -R 0:localSocks or localConnect.
//
// For now legacy is not a priority.
func (sshS *SSHServerConn) DialProxyLegacy(tp *ugate.Stream) error {
	log.Println("SSHClientConn SOCKS Reverse Connection ", tp.Dest)

	sshS.gate.rMesh.Total.Add(1)

	var req forwardTCPIPChannelRequest
	req.ForwardIP = "0.0.0.0"
	req.ForwardPort = 5222

	orighost, origPort, _ := net.SplitHostPort(tp.LocalAddr().String())
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

	marshalAddress(channel, tp.Dest)

	t0 := time.Now()
	tp.Closer = func() {
		sshS.gate.rMesh.Active.Add(-1)
		sshS.gate.rMesh.Latency.Add(time.Since(t0).Seconds())
		channel.Close()
	}
	tp.Out = channel
	tp.In = channel

	return nil
}

func marshalAddress(c io.Writer, addr string) {
	// TODO: send SOCKS-like header based on dest !!!
	head := []byte{0, 0}
	binary.BigEndian.PutUint16(head, uint16(len(addr)))

	c.Write(head)
	c.Write([]byte(addr))
}

func extractAddress(c net.Conn) string {
	head := make([]byte, 512)
	c.Read(head[0:2])
	sz := binary.BigEndian.Uint16(head)
	c.Read(head[0:sz])
	return string(head[0:sz])
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
	err = sshS.gate.gw.Dial(proxy, net.JoinHostPort(host, strconv.Itoa(int(port))), nil)
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

// As a server, handle out-of-band requests on a session.
// server may have multiple sessions
func (sshS *SSHServerConn) handleServerRequestChan(n *ugate.DMNode, in <-chan *ssh.Request) {
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
