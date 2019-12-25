package msgs

import (
	"crypto/rand"
	"encoding/base64"
	"io/ioutil"
	"log"
	"net/http"
	"net/textproto"
	"strings"

	"github.com/costinm/wpgate/pkg/auth"
	"golang.org/x/net/websocket"
)

type Backoff interface {
	BackoffSleep()
	BackoffReset()
}

var ReceiveBaseUrl = "https://127.0.0.1:5228/"

// Mux corresponds to a server with TLS certificates.
// MTLS is optional, can be used instead of VAPID tokens.
func (gate *Gateway) InitMux(mux *http.ServeMux) {
	mux.HandleFunc("/msg/", HTTPHandlerSend)
	mux.HandleFunc("/s/", HTTPHandlerSend)
	mux.HandleFunc("/subscribe", SubscribeHandler)
	mux.HandleFunc("/p/", gate.HTTPHandlerEventStream)
	ws := &websocket.Server{
		Config:    websocket.Config{},
		Handshake: nil,
		Handler: func(conn *websocket.Conn) {
			gate.websocketStream(conn)
		},
	}
	mux.Handle("/ws", ws)
}

// Return the sticky and recent events.
func DebugEventsHandler(w http.ResponseWriter, req *http.Request) {

	w.Write([]byte("["))
	for e := events.Front(); e != nil; e = e.Next() {
		e := e
		ba := e.Value.(*Message).MarshalJSON()
		w.Write(ba)
		w.Write([]byte(",\n"))
	}
	w.Write([]byte("{}]"))
}

// Used to push a message from a remote sender.
//
// Mapped to /s/[DESTID]?...
//
//
// q or path can be used to pass command. Body and query string are sent.
// TODO: compatibility with cloud events and webpush
// TODO: RBAC (including admin check for system notifications)
//
func HTTPHandlerSend(w http.ResponseWriter, r *http.Request) {
	//transport.GetPeerCertBytes(r)

	r.ParseForm()

	var cmd string
	var parts []string
	q := r.Form.Get("q")

	if q != "" {
		parts = strings.Split(q, "/")
		cmd = q
	} else {
		parts = strings.Split(r.URL.Path, "/")
		parts = parts[2:]
		cmd = strings.Join(parts, " ")

		log.Println("MSG_SEND: ", parts, "--", cmd)
	}

	params := map[string]string{}
	for k, v := range r.Form {
		params[k] = v[0]
	}
	var err error
	var body []byte
	if r.Method == "POST" {
		body, err = ioutil.ReadAll(r.Body)
		if err != nil {
			return
		}
	}

	DefaultMux.HandleMessageForNode(NewMessage(cmd, params).SetDataJSON(body))
	w.WriteHeader(200)
}

// Currently mapped to /dmesh/uds - sends a message to a specific connection, defaults to the UDS connection
// to the android or root dmwifi app.
func (mux *Mux) HTTPUDS(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	var cmd string
	var parts []string
	q := r.Form.Get("q")
	h := r.Form.Get("h")
	if h == "" {
		h = "dmesh"
	}

	if q != "" {
		parts = strings.Split(q, " ")
		cmd = q
	} else {
		parts = strings.Split(r.URL.Path, "/")
		parts = parts[3:]
		cmd = strings.Join(parts, " ")

		log.Println("UDS: ", parts, "--", cmd)
	}

	params := map[string]string{}
	for k, v := range r.Form {
		params[k] = v[0]
	}
	var err error
	var body []byte
	if r.Method == "POST" {
		body, err = ioutil.ReadAll(r.Body)
		if err != nil {
			return
		}
	}

	ch := mux.Gate.connections[h]
	if ch != nil {
		ch.SendMessageToRemote(NewMessage(cmd, params).SetDataJSON(body))
		w.WriteHeader(200)
	} else {
		w.WriteHeader(404)
		return
	}
}

// MonitorEvents will connect to a mesh address and monitor the messages.
//
// base is used for forwarding.
//
//func (w *Mux) MonitorEvents(node Backoff, idhex string, path []string) {
//	hc := transport.NewSocksHttpClient("")
//	hc.Timeout = 1 * time.Hour
//
//	if idhex == "" {
//		hc = http.DefaultClient
//	}
//
//	for {
//		t0 := time.Now()
//
//		err := w.MonitorNode(hc, idhex, path)
//		if err != nil {
//			log.Println("WATCH_ERR", idhex, err, time.Since(t0))
//			node.BackoffSleep()
//			continue
//		}
//		node.BackoffReset()
//
//		log.Println("WATCH_CLOSE", idhex, time.Since(t0))
//		node.BackoffSleep()
//	}
//
//}

// UA represents a "user agent" - or client using the webpush protocol
type UA struct {
	// URL of the subscribe for the push service
	PushService string
}

// Create a subscription, using the Webpush standard protocol.
//
// URL is "/subscribe", no header required ( but passing a VAPID or mtls),
// response in 'location' for read and Link for sub endpoint.
func (ua *UA) Subscribe() (sub *auth.Subscription, err error) {
	res, err := http.Post(ua.PushService+"/subscribe", "text/plain", nil)

	if err != nil {
		return
	}
	sub = &auth.Subscription{}
	sub.Location = res.Header.Get("location")
	links := textproto.MIMEHeader(res.Header)["Link"]
	for _, l := range links {
		for _, link := range strings.Split(l, ",") {
			parts := strings.Split(link, ";")
			if len(parts) > 1 &&
				strings.TrimSpace(parts[1]) == "rel=\"urn:ietf:params:push\"" {
				sub.Endpoint = parts[0]
			}
		}
	}

	// generate encryption key and authenticator

	return
}

// Subscribe creates a subscription. Initial version is just a
// random - some interface will be added later, to allow sets.
func SubscribeHandler(res http.ResponseWriter, req *http.Request) {
	// For simple testing we ignore sender auth, as well as subscription sets
	token := make([]byte, 16)
	rand.Read(token)

	id := base64.RawURLEncoding.EncodeToString(token)

	res.WriteHeader(201)

	// TODO: try to use a different server, to verify UA is
	// parsing both

	// Used for send - on same server as subscribe
	res.Header().Add("Link", "</p/"+
		id+
		">;rel=\"urn:ietf:params:push\"")

	// May provide support for set: should be enabled if a
	// set interface is present, want to test without set as well
	//res.Header().Add("Link", "</p/" +
	//	"JzLQ3raZJfFBR0aqvOMsLrt54w4rJUsV" +
	//	">;rel=\"urn:ietf:params:push:set\"")

	res.Header().Add("Location", ReceiveBaseUrl+"/r/"+id)

	return
}
