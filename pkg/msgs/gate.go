package msgs

import (
	"bufio"
	"context"
	"log"
	"strings"
	"sync"
	"time"

)

// Gateway handles the incoming and outgoing connections, and adaptation between
// protocols. Messages for local pod are handled by Mux.
type Gateway struct {
	mutex sync.RWMutex

	// MessageSenders tracks all connections that support SendMessageDirect() to send to the remote end.
	// For example UDS connections, SSH, etc.
	connections map[string]*MsgConnection

	// technically we could handle multiple mux and ids in a gateway - but
	// not clear use case (besides tests)
	NodeId string
	mux *Mux
}


// One connection - incoming or outgoing. Can send messages to the remote end, which may in turn forward
// messages for other nodes.
//
// Incoming messages are dispatched to the mux, which may deliver locally or forward.
//
type MsgConnection struct {

	gate *Gateway

	// Key used in mux to track this connection
	Name string

	// Vip associated with the connection. Messages will not be forwarded if the VIP is in Path or From of the
	// message.
	vip string

	// Broadcast subscriptions to forward to the remote. Will have a 'From' set to current node.
	// VPN and upstream server use "*" to receive/pass up all events.
	// TODO: keep some messages local, by using To=., and indicate broadcasts as *.
	SubscriptionsToSend []string

	// OnMessage is called when a message for this connection is dispatched.
	// The message should be either a broadcast, have as To the vip of the connection or
	// another vip reachable from the connection.
	//
	// The topic of the message should be in the Subscription list if the destination is this vip.
	//
	// Internal handlers may use the same interface.
	SendMessageToRemote func(ev *Message) error
}

// id - remote id. "uds" for the primary upstream uds connection to host (android app or wifi/root app)
//
func (mux *Mux) AddConnection(id string, cp *MsgConnection) {
	cp.Name = id
	cp.gate = mux.Gate
	mux.mutex.Lock()
	mux.Gate.connections[id] = cp
	mux.mutex.Unlock()

	// Notify any handler of a new connection
	if h, f := mux.handlers["/open"]; f {
		h.HandleMessage(context.Background(), "/open", map[string]string{"id": id}, nil)
	}
}

func (gate *Gateway) RemoveConnection(id string, cp *MsgConnection) {
	gate.mux.mutex.Lock()
	delete(gate.connections, id)
	gate.mux.mutex.Unlock()

	if h, f := gate.mux.handlers["/close"]; f {
		h.HandleMessage(context.Background(), "/close", map[string]string{"id": id}, nil)
	}
}

func (mc *MsgConnection) Close() {
	mc.gate.RemoveConnection(mc.Name, mc)
}

// Message from a remote, will be forwarded to subscribed connections.
func (mux *Gateway) OnRemoteMessage(ev *Message, from, self string, connName string) error {
	// Local handlers first
	parts := strings.Split(ev.To, "/")
	if len(parts) < 2 {
		return nil
	}
	if parts[0] == self {
		mux.mux.HandleMessageForNode(ev)
		return nil
	}
	if parts[1] == "I" || parts[1] == "SYNC" {
		return nil
	}

	for k, ms := range mux.connections {
		if k == ev.From || k == connName {
			continue
		}
		ms.maybeSend(parts, ev, k)
	}
	return nil
}

// Send a message to one or more connections.
func (gate *Gateway) Send(ev *Message) error {
	parts := strings.Split(ev.To, "/")

	if parts[0] == "." {
		return nil
	}

	if parts[1] == "I" {
		return nil
	}

	for k, ms := range gate.connections {
		if k == ev.From { // Exclude the connection where this was received on.
			continue
		}
		ms.maybeSend(parts, ev, k)
	}
	return nil

}

func (ms *MsgConnection) maybeSend(parts []string, ev *Message, k string) {
	// TODO: check the path !
	if parts[0] != "" {
		// TODO: send if the peer ID matches, or if peer has sent a (signed) event message that the node
		// is connected
	}

	if ms.SubscriptionsToSend == nil {
		return
	}
	if Debug {
		log.Println("MSG: fwd to connection ", ev.To, k, ms.Name)
	}
	topic := parts[1]
	if topic == "I" {
		return
	}
	hasSub := false
	for _, s := range ms.SubscriptionsToSend {
		if topic == s || s == "*" {
			hasSub = true
			break
		}
	}
	if !hasSub {
		return
	}

	ms.SendMessageToRemote(ev)
}

// Messages received from remote, over SSH.
//
// from is the authenticated VIP of the sender.
// self is my own VIP
//
//
func (mconn *MsgConnection) HandleMessageStream(cb func(message *Message), br *bufio.Reader, from string, self string) {
	//defer channel.Close()
	for {
		line, _, err := br.ReadLine()
		if err != nil {
			break
		}
		//if role == ROLE_GUEST {
		//	continue
		//}
		if len(line) > 0 && line[0] == '{' {
			ev := ParseJSON(line)

			// TODO: if a JWT is present and encrypted or signed binary - use the original from.

			if ev.Time == "" {
				ev.Time = time.Now().Format("01-02T15:04:05")
			}
			if ev.From == "" {
				ev.From = from
			}

			parts := strings.Split(ev.To, "/")
			if len(parts) < 2 {
		 		log.Println("Invalid To", parts)
				continue
			}
			top := parts[1]
			ev.Topic = top
			if top == "sub" {
				mconn.SubscriptionsToSend = append(mconn.SubscriptionsToSend, parts[2])
				continue
			}

			// TODO: forwarded 'endpoint' messages, for children and peers

			if cb != nil {
				cb(ev)
			}

			loop := false
			for _, s := range ev.Path {
				if s == self {
					loop = true
					break
				}
				if s == from {
					loop = true
					break
				}
			}
			if loop {
				continue
			}
			ev.Path = append(ev.Path, from)
			ev.Connection = mconn

			mconn.gate.OnRemoteMessage(ev, from, self, mconn.Name)
		}
	}
}

