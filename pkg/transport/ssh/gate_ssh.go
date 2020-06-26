package ssh

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/costinm/wpgate/pkg/auth"
	"github.com/costinm/wpgate/pkg/mesh"
	"github.com/costinm/wpgate/pkg/msgs"
	"golang.org/x/crypto/ssh"
)

// Using the proxy for SSH:
// ssh -o ProxyCommand='nc -x localhost:15004 %h %p' vultr

// Similar: -J (JumpProxy) - uses a TCP forward
// Example:
//  ssh -v -J v.webinf.info:5222  -N -L 14527:localhost:15020  fd00::34be:3932:b3fe:33cb -p 15022

// Direct connection to any mesh node also allows access to other nodes by VIP:
//  ssh -v -N  -L 14527:[fd00::34be:3932:b3fe:33cb]:15020 v.webinf.info -p 5222

// Remote ports also work:
// ssh -v -N  -R 0.0.0.0:14527:localhost:15020 v.webinf.info -p 5222

// SSHClientConn-based gateway.
// Uses transport.H2.SSHClientConn
// May be replaced by pure H2 gate mechanisms - but SSHClientConn is more mature and can work with clients/servers using
// plain native servers.

// SSHClientConn private key: PEM, PKCS1 (includes public)
// SSHClientConn public key format: rfc4716

// ssh -v c1.webinf.info -p 5222  -D 15014 -L 7000:127.0.0.1:5227 -R 9000:10.1.10.2:80
// On the remote (c1)
// - connections to port 9000 on the remote server will be forwarded to localhost ssh client, and from there to the dest.
//
// On local:
// - connect to 7000 will go to c1.webinf.info, and from there to the destination (admin interface)
//

// Main SSH gateway interface. Each node can have multiple client and server connections.
// Primary port is 5222, but connections may be received over tunnels.
// A SSH gateway has one key pair and set of configs.
type SSHGate struct {

	mutex        sync.RWMutex

	// Active outbound SSHClientConn tunnels. May be direct to a neighbor/reachable IP, or tunneled in sshUp.
	// Key is the host:Port or IP:port used in Dial
	// Clients typically open at least port -R :5222, so it is possible
	// to initiate 'push' connections.
	SshClients map[string]*SSHClientConn

	// Accepted connections. If the server is running as VPN server, connections from all clients.
	// If this node is an AP or mesh node, connections from immediate neighbors.
	// Key is the VIP
	SshConn map[uint64]*SSHServerConn

	// Key loaded from .ssh/ directory.
	//sshKey ssh.Signer

	gw *mesh.Gateway

	serverConfig *ssh.ServerConfig

	metrics  *mesh.ServiceMetrics
	cmetrics *mesh.ServiceMetrics
	localFwdS *mesh.ServiceMetrics
	rAccept   mesh.Metric
	rMesh     *mesh.ServiceMetrics

	certs *auth.Auth
}

const SSH_MESH_PORT = 5222

type SSHConn struct {
	gate *SSHGate

	open bool
	// Remote address (IP:port or host:port) of the directly
	// connected peer.
	Addr string

	// Key of the remote side ( received )
	pubKey              []byte
	Connect             time.Time
	SubscriptionsToSend []string

	// Role of the user making the connection or server.
	// Currently extracted from authorized_keys.
	//
	// "guest" if none of the authorizations are matching.
	// Guests can only forward to the mesh standard port, no
	// messaging.
	//
	// TODO: list
	role string

	msgChannel ssh.Channel
	vip        uint64
	VIP6       net.IP

	Node *mesh.DMNode
}


//func (sg *SSHGate) HandleMessage(ctx context2.Context, cmdS string, meta map[string]string, data []byte) {
//	// TODO: extract UA from /endpoint. Pass up any direct known connections
//
//	// TODO: wait for the /endpoint/sshc message before activating the endpoint. Check the pub key in the message
//	// TODO: don't propagate/forward /sshc messages directly - need to add the IPs and gates of this host.
//}

// Initialize the SSH gateway.
func NewSSHGate(gw *mesh.Gateway, certs *auth.Auth) *SSHGate {
	sg := &SSHGate{
		SshClients: map[string]*SSHClientConn{},
		SshConn:    map[uint64]*SSHServerConn{},
		gw:         gw,
		certs:      certs,
		metrics:    mesh.NewServiceMetrics("sshd", "ssh server"),
		cmetrics:   mesh.NewServiceMetrics("sshc", "ssh client"),
		localFwdS:  mesh.NewServiceMetrics("sshdL", "ssh server port forwards"),
		rAccept:    mesh.Metrics.NewCounter("sshdRA", "ssh server reverse accept"),
		rMesh:      mesh.NewServiceMetrics("sshdRM", "ssh server reverse mesh"),
	}

	//msgs.DefaultMux.AddHandler("endpoint", sg)
	//msgs.DefaultMux.AddHandler("endpoints", sg)

	return sg
}

const SSH_MSG = true

func (sshGate *SSHGate) DialMUX(addr string, pub []byte, subs []string) (mesh.JumpHost, error) {
	signer, err := ssh.NewSignerFromKey(sshGate.certs.EC256PrivateKey) // ssh.Signer

	user := "dmesh"

	sshGate.cmetrics.Total.Add(1)

	sshC := &SSHClientConn{
		SSHConn: SSHConn{
			Addr:                addr,
			gate:                sshGate,
			Connect:             time.Now(),
			SubscriptionsToSend: subs,
			open: true,
		},
	}

	authm := []ssh.AuthMethod{}

	authm = append(authm, ssh.PublicKeys(signer))

	if sshGate.certs.RSAPrivate != nil {
		signer1, err := ssh.NewSignerFromKey(sshGate.certs.RSAPrivate)
		if err == nil {
			authm = append(authm, ssh.PublicKeys(signer1))
		}
	}
	if sshGate.certs.EDPrivate != nil {
		signer1, err := ssh.NewSignerFromKey(sshGate.certs.EDPrivate)
		if err == nil {
			authm = append(authm, ssh.PublicKeys(signer1))
		}
	}

	// An SSHClientConn client is represented with a ClientConn.
	// TODO: save and verify public key of server
	config := &ssh.ClientConfig{
		User:    user,
		Auth:    authm,
		Timeout: 3 * time.Second,
		//Config: ssh.Config {
		//	MACs: []string{},
		//},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			if cpk, ok := key.(ssh.CryptoPublicKey); ok {
				pubk := cpk.CryptoPublicKey()

				kbytes := auth.KeyBytes(pubk)

				sshC.pubKey = kbytes

				if pub != nil && bytes.Compare(kbytes, pub) != 0 {
					log.Println("SSHC: Unexpected pub", pub, kbytes)
				}
				var role string
				if role = sshGate.certs.Auth(kbytes, ""); role == "" {
					role = ROLE_GUEST
				}
				sshC.role = role

				sshC.VIP6 = auth.Pub2VIP(kbytes)
				sshC.vip = auth.Pub2ID(kbytes)
			}
			return nil
		},
	}

	// TODO: split TCP/conn and ssh handshake, use other transports
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		sshGate.cmetrics.Errors.Add(1)
		return nil, err
	}

	sshGate.cmetrics.Active.Add(1)

	// After handshake, ssc.VIP6 and ssc.vip are set based on the
	// server public key.
	sshC.sshclient = client

	sshGate.mutex.Lock()
	sshGate.SshClients[addr] = sshC
	sshGate.mutex.Unlock()

	// Find the Node associated with the client.
	// Update the Node with the outbound channel.
	n := sshGate.gw.Node(sshC.pubKey)
	n.TunClient = sshC
	sshC.Node = n

	go sshGate.keepalive(client, n)()

	if SSH_MSG {
		host, err2 := sshClientMsgs(client, sshC, n, subs)
		if err2 != nil {
			return host, err2
		}
	}
	log.Println("/sshc/connect", sshC.Addr)

	return sshC, nil
}


func (sshGate *SSHGate) keepalive(client *ssh.Client, n *mesh.DMNode) func() {
	return func() {
		for {
			rcvd := false
			time.AfterFunc(5*time.Second, func() {
				if !rcvd {
					// Note: there are 2 reasons to fail, ssh connection error or dest is bad.
					// TODO: send a keepalive and wait it to fail
					log.Println("SSHC: Timeout keepalive ")
					client.Close()
					return
				}
			})

			if _, _, err := client.SendRequest("keepalive@openssh.com", true, nil); err != nil {
				log.Println("SSHC: Error sending request, closing")
				client.Close()
				return
			}
			rcvd = true
			n.LastSeen = time.Now()
			time.Sleep(5 * 60 * time.Second)
		}
	}
}

func (sc *SSHConn) RemoteVIP() net.IP {
	return sc.VIP6
}

// SSHClientConn client connection - outbound.
type SSHClientConn struct {
	SSHConn

	sshclient *ssh.Client
}

func (sshC *SSHClientConn) Close() error {
	if !sshC.open {
		return nil
	}
	sshC.open = false
	sshC.gate.cmetrics.Active.Add(-1)
	sshC.gate.cmetrics.Latency.Add(time.Since(sshC.Connect).Seconds())

	log.Println("SSHC: session and connection terminated")
	sshC.gate.mutex.Lock()
	delete(sshC.gate.SshClients, sshC.Addr)
	sshC.gate.mutex.Unlock()
	if sshC.Node.TunClient == sshC {
		sshC.Node.TunClient = nil
	}

	log.Println("SSHC: /sshc/close", sshC.Addr)
	if sshC.msgChannel != nil {
		sshC.msgChannel.Close()
	}
	return sshC.sshclient.Close()
}

// DialProxy will use a SSH client connection MUX to reach a remote server.
// Part of TunDialer interface used to connect to a destination
// over this connection.
// On success, tp.Server[In|Out] will be set with a connection to
//  tp.Dest:tp.DestPort
// Uses the equivalent of "-L".
func (sshC *SSHClientConn) DialProxy(tp *mesh.Stream) error {
	// Parse the address into host and numeric port.
	h, _, _ := net.SplitHostPort(tp.Dest)

	msg := channelOpenDirectMsg{
		Raddr: h,
		Rport: uint32(tp.DestPort),
	}

	if tp.OriginIP != nil && tp.OriginIP[0] != 127 && tp.OriginIP[0] != 10 {
		// Pass original 'originIP/port' - passed at creation time, from remote data.
		// Captured traffic has 127.0.0.1
		msg.Laddr = tp.OriginIP.String()
		msg.Lport = uint32(tp.OriginPort)
	} else {
		msg.Laddr = sshC.gate.certs.VIP6.String() // tp.OriginIP.String(),
		msg.Lport = uint32(tp.StreamId)
	}

	var ch ssh.Channel = nil
	time.AfterFunc(5*time.Second, func() {
		if ch == nil {
			// Note: there are 2 reasons to fail, ssh connection error or dest is bad.
			// TODO: send a keepalive and wait it to fail
			log.Println("Timeout connecting to ", tp.Dest)
			sshC.Close()
		}
	})
	ch, in, err := sshC.sshclient.OpenChannel("direct-tcpip", ssh.Marshal(&msg))
	if err != nil {
		return err
	}
	go ssh.DiscardRequests(in)

	// Use a zero address for local and remote address.
	zeroAddr := &net.TCPAddr{
		IP:   net.IPv4zero,
		Port: 0,
	}

	conn := &chanConn{
		Channel: ch,
		laddr:   zeroAddr,
		raddr:   zeroAddr,
	}

	tp.ServerOut = conn
	tp.ServerIn = conn
	return nil
}

// ForwardSocks create a virtual listener (magic port 5222) on the
// server. The server will be able to initiate connections in reverse
// to this client.
// TODO: make it work with standard ssh servers - for example
// get a dynamic port, and bounce it as an incoming ssh connection.
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
			sshC.Close()
			return nil
		}

		go func() {
			// TODO: get server role, if guess only allow in-mesh proxy
			dest := extractAddress(c)
			p := sshC.gate.gw.NewTcpProxy(c.RemoteAddr(), "SSHRSOCKS", nil, c, c)

			err = p.Dial(dest, nil)
			if err != nil {
				log.Println("SSH error: ", c.RemoteAddr(), dest)
				p.Close()
				return
			}
			p.Proxy()
		}()
	}
	// Serve HTTP with your SSHClientConn server acting as a reverse proxy.
	return nil
}

// Use the connection to a remote SSHClientConn server to listen to a port.
// Accepted connections will be handled using the handler.
//
// vpn is the address of the vpn server
// dest is the address to forward incoming listener connections, passed as parameter to handler
// handler is a function capable of 2-way forwarding.
func (sshC *SSHClientConn) ForwardTCP(remoteListenAddr string, dest string) error {

	// TODO: as optimization, allow an option to take the Listener and pass it to http, with a mux - make it H2, with TLS

	l, err := sshC.sshclient.Listen("tcp", remoteListenAddr)
	if err != nil {
		log.Println("unable to register tcp forward", err)
		return err
	}

	//log.Println("SSHC: -R ", sshC.addr, remoteListenAddr, l.Addr())

	// TODO: include all public IPs

	for {
		c, err := l.Accept()
		if err != nil {
			log.Println("SSHC: -R close ", sshC.Addr, remoteListenAddr, l.Addr(), err)
			l.Close()
			return nil
		}

		go sshC.handleRConnection(dest, c)
	}
	// Serve HTTP with your SSHClientConn server acting as a reverse proxy.

	return nil
}

// Connection accepted on the capture port or SSHClientConn or other mechanisms, now forward to the explicit
// host. Similar code with socks5, etc.
func (sshC *SSHClientConn) handleRConnection(dest string, c net.Conn) error {
	proxy := sshC.gate.gw.NewTcpProxy(c.RemoteAddr(), "SSHC-ACCEPT", nil, c, c)
	proxy.LocalDest = true

	err := proxy.Dial(dest, nil)
	if err != nil {
		log.Println("Failed to connect ", dest, err)
		c.Close()
		return err
	}

	return proxy.ProxyConn(c)
}

//func PubKeyString(key ssh.PublicKey) string {
//	oub := key.Marshal()
//	return base64.StdEncoding.EncodeToString(oub)
//}

// Other helpers

// Can parse existing openssh RSA and ed25519 private keys, from ~/.ssh
//
// - RSA PRIVATE KEY block
// - OPENSSH PRIVATE KEY block, can only parse rsa or ed
// - PRIVATE KEY - x509 PKCS8
// - EC PRIVATE KEY
// - (DSA)
func LoadPrivateOpenSSH(file string) (interface{}, error) {
	//var rsaPrivate *rsa.PrivateKey

	privatePEMBytes, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	rsaPrivateIf, err := ssh.ParseRawPrivateKey(privatePEMBytes)
	if err != nil {
		return nil, errors.New("Failed to parse private key")
	}
	// Both
	//privateKey, err = ssh.ParsePrivateKey(privatePEMBytes)
	return rsaPrivateIf, nil
}

// Maintain the keep-alive connection to the VPN master server
// receive messages from the remote, send messages to the remote and handle forwarding
// TODO: attempt to create a circuit using Up connections.
func MaintainVPNConnection(gw *mesh.Gateway) {

	// TODO: try all Vpn servers, verify the public keys ( possibly on first use )
	for {
		sshVpn, err := gw.SSHGate.DialMUX(gw.Vpn, nil, []string{"*"}) // TODO save pub
		if err != nil {
			log.Println("Error connecting to vpn SSHClientConn ", err)
			// TODO: network change to reconnect
			time.Sleep(120 * time.Second)
		} else {
			log.Println("SSH VPN OPEN")
			gw.SSHClient = sshVpn

			for _, v := range gw.Config.Listeners {
				go sshVpn.ForwardTCP(v.Local, v.Remote)
			}

			// Will not create a real listener, just SNI-based forward for the H2 port
			if os.Getenv("ANDROID_ROOT") != "" {
				go sshVpn.ForwardTCP("0.0.0.0:5555", "localhost:5555")
			} else {
				go sshVpn.ForwardTCP("0.0.0.0:2222", "localhost:22")
			}

			// Blocking - will be closed when the ssh connection is closed.
			sshVpn.ForwardSocks()
			gw.SSHClient = nil
			// TODO: shorter timeout with exponential backoff

			if c, ok := sshVpn.(io.Closer); ok {
				c.Close()
			}
			log.Println("SSH VPN CLOSED")
			time.Sleep(5 * time.Second)
		}
	}

}

// ======= Copied from SSHClientConn, to customize

// Customized: allow passing the ports and addr.
//
// chanConn fulfills the net.Conn interface without
// the tcpChan having to hold laddr or raddr directly.
type chanConn struct {
	ssh.Channel
	laddr, raddr net.Addr
}

// LocalAddr returns the local network address.
func (t *chanConn) LocalAddr() net.Addr {
	return t.laddr
}

// RemoteAddr returns the remote network address.
func (t *chanConn) RemoteAddr() net.Addr {
	return t.raddr
}

// SetDeadline sets the read and write deadlines associated
// with the connection.
func (t *chanConn) SetDeadline(deadline time.Time) error {
	if err := t.SetReadDeadline(deadline); err != nil {
		return err
	}
	return t.SetWriteDeadline(deadline)
}

// SetReadDeadline sets the read deadline.
// A zero value for t means Read will not time out.
// After the deadline, the error from Read will implement net.Error
// with Timeout() == true.
func (t *chanConn) SetReadDeadline(deadline time.Time) error {
	// for compatibility with previous version,
	// the error message contains "tcpChan"
	return errors.New("ssh: tcpChan: deadline not supported")
}

// SetWriteDeadline exists to satisfy the net.Conn interface
// but is not implemented by this type.  It always returns an error.
func (t *chanConn) SetWriteDeadline(deadline time.Time) error {
	return errors.New("ssh: tcpChan: deadline not supported")
}

// RFC 4254 Section 6.5.
type execMsg struct {
	Command string
}
