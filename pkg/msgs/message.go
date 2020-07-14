package msgs

import (
	"encoding/json"
	"fmt"
	"time"
)

// Wrapper around 'pubsub' or event based systems.

// TODO: find a proper library (or turn this into one)

// Circular buffer holding 'event logs' that can be uploaded to central server or shown in UI
// Access logs are a type of event.

// On Android side - this is a set of Messages.
// Similar: k8s events - rich interface.

// TODO: use grpc library to push, maybe to istio mixer access log

// logrus
// glog
// zapcore:
// istio:  zapcore + Infof, InfoEnabled, scopes (including default), lumberjack for rotate, grpc->zaprpc, cobra

// CloudEvents: each event is POST-ed to a URL
// ce-specversion: "0.3-wip"
// ce-type: "com.example.someevent"
// ce-time: "2018-04-05T03:56:24Z"
// ce-id: "1234-1234-1234"
// ce-source: "/mycontext/subcontext"

// Records recent received messages and broadcasts, for debug and UI
type Message struct {

	//RFC3339 "2018-04-05T17:31:00Z"
	Time string `json:"time,omitempty"`

	// ID of event, to dedup. Included as meta 'id'
	Id string `json:"id,omitempty"`

	// Can be 'topic', or destination
	To string `json:"to,omitempty"`

	Subject string `json:"subject,omitempty"`

	// VIPs in the path
	Path []string `json:"path,omitempty"`

	// Describes the event producer - VIP or public key
	From string `json:"from,omitempty"`

	// JSON-serializable payload.
	// Interface means will be serialized as base64 if []byte, as String if string or actual Json without encouding
	// otherwise.
	Data interface{} `json:"data,omitempty"`

	// TS is the timestamp, in go format. When sending over the wire, converted to Time. From time when received.
	TS time.Time `json:"-"`

	// If data is a map (common case)
	Meta map[string]string `json:"meta,omitempty"`

	// If received from a remote, the connection it was received on.
	// nil if generated locally
	Connection *MsgConnection `json:"-"`

	// Extracted from To URL
	Topic string `json:"-"`
}

// TODO: websocket to watch events
// TODO: push events to debug server

// NewMessage creates a new message, originated locally
func NewMessage(cmdS string, meta map[string]string) *Message {
	ev := &Message{Meta: map[string]string{}}
	ev.To = cmdS
	ev.Meta = meta

	ev.Id = meta["id"]
	if ev.Id == "" {
		mutex.Lock()
		ev.Id = fmt.Sprintf("%d", id)
		id++
		mutex.Unlock()
	}

	return ev
}

//func (ev *Message) SetData(data []byte) *Message {
//	ev.DataJson = data
//	return ev
//}

func ParseJSON(data []byte) *Message {
	ev := &Message{}
	json.Unmarshal(data, ev)
	return ev
}

func (ev *Message) MarshalJSON() []byte {
	dataB, _ := json.Marshal(ev)
	return dataB
}

// Return a binary representation of the data: either the []byte for raw data, or the marshalled json starting with
// {.
func (ev *Message) Binary() []byte {
	if data, ok := ev.Data.([]byte); ok {
		return data
	} else if data, ok := ev.Data.(string); ok {
		return []byte(data)
	} else if ev.Data != nil {
		ba, _ := json.Marshal(ev.Data)
		return ba
	}
	return nil
}

func (ev *Message) SetDataJSON(data interface{}) *Message {
	ev.Data = data
	//jsonB, _ := json.Marshal(data)
	//// TODO: keep data, serialize before sending (if needed)
	//ev.Data = jsonB
	return ev
}

// Propagate the event to all handlers (internal and external) that are subscribed
//func (em *Mux) SendMessageType(cmd string, meta map[string]string, data []byte) error {
//	em.SendMessageDirect(&Message{Type: cmd, Meta: meta, Data: data})
//	return nil
//}
