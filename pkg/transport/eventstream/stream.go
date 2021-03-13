package eventstream

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/costinm/ugate/pkg/msgs"
)

// Client or server event-stream connection.
// Useful for debugging and sending messages to old browsers.
// This is one of the simplest protocols, line based.

// Used to receive (subscribe) to messages, using HTTP streaming protocol.
// TODO: pass the list of subscriptions, filter, 'start' message
func Handler(gate *msgs.Mux) func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		req.Header.Get("last-event-id")
		req.Header.Get("accept") // should be text/event-stream for event source, otherwise it's a GET

		h := w.Header()
		h.Add("Content-Type", "text/event-stream")
		h.Add("Cache-Control", "no-cache")

		w.WriteHeader(200)

		// Need to send an empty message first ( for strange reasons ?)
		fmt.Fprintf(w, "event: message\ndata: %s\n\n", "{}")

		id := "es-" + req.RemoteAddr

		mc := &msgs.MsgConnection{
			SubscriptionsToSend: []string{"*"},
			SendMessageToRemote: func(ev *msgs.Message) error {
				ba := ev.MarshalJSON()
				_, err := fmt.Fprintf(w, "event: message\ndata: %s\n\n", string(ba))
				if err != nil {
					return err
				}
				w.(http.Flusher).Flush()
				return err
			},
		}

		msgs.DefaultMux.AddConnection(id, mc)

		log.Println("DM HTTP EVENT STREAM ", id)

		defer func() {
			msgs.DefaultMux.RemoveConnection(id, mc)
			log.Println("DM HTTP EVENT STREAM CLOSE ", id)
		}()

		ctx := req.Context()
		for {
			select {
			case <-ctx.Done():
				return
			}
		}
	}
}

func MonitorNode(gate *msgs.Mux, hc *http.Client, idhex *net.IPAddr) error {
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
