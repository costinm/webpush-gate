package h2

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/costinm/wpgate/pkg/msgs"
)

// Used for monitoring, will send push promise messages.
// Messages will need to be held in a map, to be retrieved by the handler.
func HTTPHandlerPushPromise(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(200)

	ch := make(chan *msgs.Message, 10)

	id := "http-" + req.RemoteAddr
	mc := &msgs.MsgConnection{
		SubscriptionsToSend: []string{"*"},
		SendMessageToRemote: func(ev *msgs.Message) error {
			ch <- ev
			return nil
		},
	}

	// All messages sent to the channel - temp.
	msgs.DefaultMux.AddHandler("*", msgs.HandlerCallbackFunc(func(ctx context.Context, cmdS string, meta map[string]string, data []byte) {
		ch <- msgs.NewMessage(cmdS, meta).SetDataJSON(data)
	}))

	msgs.DefaultMux.AddConnection(id, mc)

	log.Println("DM HTTP EVENT STREAM ", req.RemoteAddr)

	defer func() {
		mc.Close()
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
			opt := &http.PushOptions{
				Header: http.Header{
					"User-Agent": {"foo"},
				},
			}
			// This will result in a separate handler to get the message
			if err := w.(http.Pusher).Push("/push/"+ev.Id, opt); err != nil {
				fmt.Println("error pushing", err)
				return
			}
		case <-ctx.Done():
			return
		}
	}
}
