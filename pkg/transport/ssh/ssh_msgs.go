package ssh

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/costinm/ugate"
	"github.com/costinm/wpgate/pkg/msgs"
	"golang.org/x/crypto/ssh"
)

// Channel contains 'exec' and 'shell' sessions.
// We use this as interface to the messaging system. On stock SSH servers we expect an app called 'dmeshMsg'
// that is execed, using stdin and stdout for communication.
// TODO: reuse UDS protocol parsing (or eventing)
// TODO: ACL (possibly reused from eventing) - command messages only from trusted sources, forwarding, etc
func (sshS *SSHServerConn) handleServerSessionChannel(node *ugate.DMNode, newChannel ssh.NewChannel, role string) {
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
		VIP:                 node.VIP.String(),
	}

	//if role != ROLE_GUEST {
	id := "sshs-"+node.VIP.String()
	msgs.DefaultMux.AddConnection(id, mconn)
	//}

	br := bufio.NewReader(channel)

	go handleMessageStream(msgs.DefaultMux, id, node, br, sshS.VIP6.String(), sshS.gate.certs.VIP6.String(), mconn, true)

	mconn.SendMessageToRemote(msgs.NewMessage("/endpoint/sshs", map[string]string{
		//"remote", nConn.RemoteAddr().String(),
		//"key": base64.StdEncoding.EncodeToString(sshC.gate.certs.Pub),
		//"vip": sshC.gate.certs.VIP6.String(), // TODO: configure the public addresses !
		"ua": sshS.gate.gw.Auth.Name,
	}))
}

func (sc *SSHConn) SendMessageToRemote(ev *msgs.Message) error {
	if sc == nil || sc.msgChannel == nil {
		return nil
	}
	ba := ev.MarshalJSON()
	sc.msgChannel.Write(ba)
	sc.msgChannel.Write([]byte{'\n'})

	return nil
}

// Messages received from remote, over SSH, WS, etc
//
// from is the authenticated VIP of the sender.
// self is my own VIP
//
//
func handleMessageStream(mux *msgs.Mux, id string, node *ugate.DMNode,
			br *bufio.Reader, from string, self string,
			mconn *msgs.MsgConnection, isServer bool) {
	t0 := time.Now()
	mconn.HandleMessageStream(func(ev *msgs.Message) {
		// Direct message from the client, with its own info
		if ev.Topic == "endpoint" {
			if node.NodeAnnounce == nil {
				node.NodeAnnounce = &ugate.NodeAnnounce{}
			}
			node.NodeAnnounce.UA = ev.Meta["ua"]
		}
		newEv, _ := json.Marshal(ev)
		fmt.Println(string(newEv))

	}, br, from)

	mux.RemoveConnection(id, mconn)
	log.Println("Message con close", id, time.Since(t0))
}

func sshClientMsgs(client *ssh.Client, sshC *SSHConn, n *ugate.DMNode, subs []string) (ugate.MuxedConn, error) {
	// Each ClientConn can support multiple interactive sessions,
	// represented by a Session.
	// go implementation is geared toward term emulation/shell - use the raw mechanism.
	// A session is just a channel with few extra out-of-band commands.
	sessionCh, sessionServerReq, err := client.OpenChannel("session", nil)
	if err != nil {
		log.Println("Error opening session", err)
		client.Close()
		return nil, err
	}

	// serverReq will be used only to notity that the session is over, may receive keepalives
	go func() {
		for msg := range sessionServerReq {
			// TODO: exit-status, exit-signal messages
			log.Println("SSHC: /ssh/srvmsg session message from server ", msg.Type, msg)
			if msg.WantReply {
				msg.Reply(false, nil)
			}
		}

		//sshC.Close()
	}()

	// Technically we don't need the exec channel ! Just forwarding.
	// Some servers may disable exec
	// ssh -N allows clients to not use exec.
	// This can be used with low end servers, not not clear if it helps
	req := execMsg{
		Command: "/usr/local/bin/dmeshc",
	}

	ok, err := sessionCh.SendRequest("exec", true, ssh.Marshal(&req))
	if err == nil && !ok {
		log.Println("SSHC: Message channel failed", err)
	} else {
		sshC.msgChannel = sessionCh
	}

	// Incoming messages from the channel
	go sshC.handleClientMsgChannel(n, sessionCh, subs)
	return nil, nil
}

// ======= Copied from SSHClientConn, to customize

// RFC 4254 Section 6.5.
type execMsg struct {
	Command string
}

// SSH client: handles the connection with the server.
//
// Messages from server are dispatched to the mux, for local forwarding
// Messages from local mux are sent to the server - sub is *.
//
// The mux is responsible for eliminating loops and forwarding.
func (sshC *SSHConn) handleClientMsgChannel(node *ugate.DMNode, channel ssh.Channel, subs []string) {

	// TODO: get rid of the message over SSH, use a port forward
	// and H2 or the stream.
	mconn := &msgs.MsgConnection{
		SubscriptionsToSend: subs,
		SendMessageToRemote: sshC.SendMessageToRemote,
		VIP:                 node.VIP.String(),
	}

	id := "sshc-"+sshC.VIP6.String()
	msgs.DefaultMux.AddConnection(id, mconn)

	// From and path will be populated by forwarder code.
	mconn.SendMessageToRemote(msgs.NewMessage("/endpoint/sshc", map[string]string{
		//"remote", nConn.RemoteAddr().String(),
		//"key": base64.StdEncoding.EncodeToString(sshC.gate.certs.Pub),
		//"vip": sshC.gate.certs.VIP6.String(), // TODO: configure the public addresses !
		"ua": sshC.gate.gw.Auth.Name,
	}))

	br := bufio.NewReader(channel)

	handleMessageStream(msgs.DefaultMux, id, node, br, sshC.VIP6.String(),
		sshC.gate.certs.VIP6.String(), mconn, false)

	// Disconnected
	node.TunClient = nil
}
