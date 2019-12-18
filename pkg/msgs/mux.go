//go:generate protoc --gogofaster_out=$GOPATH/src webpush.proto
package msgs

import (
	"container/list"
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)


// Local processing of messages. Interface doesn't use any specific struct,
// to avoid creating deps.
type MessageHandler interface {
	// Handle a message. Context may provide access to the actual message object
	// and mux.
	HandleMessage(ctx context.Context, cmdS string, meta map[string]string, data []byte)
}

// TODO: map by Uri, to keep track of last status.

// Mux handles processing messages for this node, and sending messages from
// local code.
type Mux struct {
	Gate  *Gateway
	mutex sync.RWMutex

	// Handlers by path, for processing incoming messages.
	// Messages are received from a remote connection (like UDS or ssh or http), or created locally.
	handlers map[string]MessageHandler
}

func NewMux() *Mux {
	mux := &Mux{
		Gate: &Gateway{
			connections: map[string]*MsgConnection{},
		},
		handlers:    map[string]MessageHandler{},
	}

	mux.Gate.mux = mux

	return mux
}

var DefaultMux = NewMux()

// Send a message to the default mux. Will serialize the event and save it for debugging.
//
// Local handlers and debug tools/admin can subscribe.
func Send(msgType string, meta ...string) {
	DefaultMux.Send(msgType, meta...)
}

//
func (mux *Mux) Send(msgType string, meta ...string) error {
	ev := &Message{To: msgType, Meta: map[string]string{}}
	for i := 0; i < len(meta); i += 2 {
		ev.Meta[meta[i]] = meta[i+1]
	}
	return mux.SendMessage(ev)
}

var (
	id int
	mutex sync.Mutex
)

// Publish a message. Will be distributed to remote listeners.
// TODO: routing for directed messages (to specific destination)
// TODO: up/down indication for multicast, subscription
func (mux *Mux) SendMessage(ev *Message) error {
	_ = context.Background()
	// Local handlers first
	if ev.Id == "" {
		mutex.Lock()
		ev.Id = fmt.Sprintf("%d", id)
		id++
		mutex.Unlock()
	}
	mux.HandleMessageForNode(ev)


	return mux.Gate.Send(ev)
}

// Called for local events (host==. or empty).
// Called when a message is received from one of the local streams ( UDS, etc ), if
// the final destination is the current node.
//
// Message will be passed to one or more of the local handlers, based on type.
//
// TODO: authorization (based on identity of the caller)
func (mux *Mux) HandleMessageForNode(ev *Message) error {
	if ev.TS.IsZero() {
		ev.TS = time.Now()
	}

	// Temp: debug
	mux.save(ev)

	//log.Println("EV: ", ev.To, ev.From)
	if ev.To == "" {
		return nil
	}

	argv := strings.Split(ev.To, "/")

	if len(argv) < 2 {
		return nil
	}

	toNode := argv[0]
	if toNode != "" {
		// Currently local handlers only support local originated messages.
		// Use a connection for full support.
		return nil
	}
	topic := argv[1]

	payload := ev.Binary()
	log.Println("MSG: ", argv, ev.Meta, ev.From, ev.Data, len(payload))

	if h, f := mux.handlers[topic]; f {
		h.HandleMessage(context.Background(), ev.To, ev.Meta, payload)
	} else if h, f = mux.handlers[""]; f {
		log.Println("UNHANDLED: ", ev.To)
		h.HandleMessage(context.Background(), ev.To, ev.Meta, payload)
	}
	if h, f := mux.handlers["*"]; f {
		h.HandleMessage(context.Background(), ev.To, ev.Meta, payload)
	}
	return nil
}


// Add a local handler for a specific message type or *
// This is a local function.
func (mux *Mux) AddHandler(path string, cp MessageHandler) {
	mux.mutex.Lock()
	mux.handlers[path] = cp
	mux.mutex.Unlock()
}

// TODO: circular buffer, poll event, for debug
const EV_BUFFER = 200

var events = list.New()
// debug
func (mux *Mux) save(ev *Message) {
	if ev.To == "SYNC/LL" ||
			ev.To == "SYNC/LLSRV" {
		//log.Println("EV:", ev.Type, ev.Msg, ev.Meta)
		return
	}

	mux.mutex.Lock()
	events.PushBack(ev)
	if events.Len() > EV_BUFFER {
		events.Remove(events.Front())
	}
	mux.mutex.Unlock()
}


// Adapter from func to interface
type HandlerCallbackFunc func(ctx context.Context, cmdS string, meta map[string]string, data []byte)

// ServeHTTP calls f(w, r).
func (f HandlerCallbackFunc) HandleMessage(ctx context.Context, cmdS string, meta map[string]string, data []byte) {
	f(ctx, cmdS, meta, data)
}

type ChannelHandler struct {
	MsgChan chan *Message
}

func NewChannelHandler() *ChannelHandler {
	return &ChannelHandler{MsgChan: make(chan *Message, 100)}
}

func (u *ChannelHandler) HandleMessage(ctx context.Context, cmdS string, meta map[string]string, data []byte) {
	log.Println("MSG: ", cmdS)
	m := NewMessage(cmdS, meta).SetDataJSON(data)
	//m.Connection = replyTo
	u.MsgChan <- m
}

func (u *ChannelHandler) WaitEvent(name string) *Message {
	tmax := time.After(20 * time.Second)

	for {
		select {
		case <-tmax:
			return nil
		case e := <-u.MsgChan:
			if e.To == name {
				return e
			}
			if strings.HasPrefix(e.To, name) {
				return e
			}
			log.Println("EVENT", e)
		}
	}

	return nil
}


