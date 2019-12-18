package msgs

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// Client or server event-stream connection.
// Useful for debugging and sending messages to old browsers.
// This is one of the simplest protocols.

type EventStreamConnection struct {
	MsgConnection
}

// Used to receive (subscribe) to messages, using HTTP streaming protocol.
//
// TODO: pass the list of subscriptions, filter, 'start' message
func HTTPHandlerEventStream(w http.ResponseWriter, req *http.Request) {
	req.Header.Get("last-event-id")
	req.Header.Get("accept") // should be text/event-stream for event source, otherwise it's a GET

	h := w.Header()
	h.Add("Content-Type", "text/event-stream")
	h.Add("Cache-Control", "no-cache")

	w.WriteHeader(200)

	// Need to send an empty message first ( for strange reasons ?)
	fmt.Fprintf(w, "event: message\ndata: %s\n\n", "{}")

	eventStream(w, req, func(w http.ResponseWriter, ev *Message) {
		ba := ev.MarshalJSON()

		// TODO: id, set type in event: header ( or test if message is not required )
		//
		_, err := fmt.Fprintf(w, "event: message\ndata: %s\n\n", string(ba))
		if err != nil {
			return
		}
		w.(http.Flusher).Flush()

	})
}

// Used to receive (subscribe) to messages, as well as send messages.
//
// TODO: pass the list of subscriptions, filter, 'start' message
func eventStream(w http.ResponseWriter, req *http.Request, sender func(w http.ResponseWriter, ev *Message)) {

	ch := make(chan *Message, 10)

	id := "http-" + req.RemoteAddr
	mc := &MsgConnection{
		SubscriptionsToSend: []string{"*"},
		SendMessageToRemote: func(ev *Message) error {
			ch <- ev
			return nil
		},
	}

	// All messages sent to the channel
	DefaultMux.AddHandler("*", HandlerCallbackFunc(func(ctx context.Context, cmdS string, meta map[string]string, data []byte) {
		ch <- NewMessage(cmdS, meta).SetDataJSON(data)
	}))

	DefaultMux.AddConnection(id, mc)

	log.Println("DM HTTP EVENT STREAM ", req.RemoteAddr)

	defer func() {
		DefaultMux.Gate.RemoveConnection(id, mc)
		log.Println("DM HTTP EVENT STREAM CLOSE ", req.RemoteAddr)
	}()

	// source.addEventListener('add', addHandler, false);
	// event: add
	// data: LINE
	//
	ctx := req.Context()
	for {
		select {
		case ev := <-ch:
			sender(w, ev)
		case <-ctx.Done():
			return
		}
	}
}

func MonitorNode(w *Mux, hc *http.Client, idhex *net.IPAddr) error {
	t0 := time.Now()
	url := "http://127.0.0.1:5227/debug/eventss"
	//p := "/"
	if idhex != nil {
		//for _, pp := range path {
		//	p = p + pp + "/"
		//}
		//p = p + idhex + "/"
		//url = "http://127.0.0.1:5227/dm" + p + "127.0.0.1:5227/debug/eventss"
		url = "http://" + idhex.String() + ":5227/debug/eventss"
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	ctx, _ := context.WithTimeout(context.Background(), 600*time.Second)
	req = req.WithContext(ctx)
	res, err := hc.Do(req)
	if err != nil || res.StatusCode != 200 {
		log.Println("WATCH_ERR1", url, err, time.Since(t0), res)
		return err
	}

	rd := bufio.NewReader(res.Body)

	for {
		l, _, err := rd.ReadLine()
		if err != nil {
			if err.Error() != "EOF" {
				log.Println("WATCH_ERR2", url, err)
				return err
			} else {
				log.Println("WATCH_CLOSE", url, time.Since(t0), err)
				return nil
			}
		}
		ls := string(l)
		if ls == "" || ls == "event: message" {
			continue
		}

		if strings.HasPrefix("data:", ls) {
			ls = ls[5:]

			log.Println(idhex, ls)

		} else {

			log.Println(idhex, ls)
		}
	}
}
