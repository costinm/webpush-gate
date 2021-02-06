package cloudevents

import (
	"context"
	"fmt"
	"log"
	"net"
	"testing"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/cloudevents/sdk-go/v2/client"

	"github.com/costinm/wpgate/pkg/msgs"
)

func TestCE(t *testing.T) {
	cloudevents.EnableTracing(true)

	// - 8080 is default port
	// - binary encoding
	// - timeNow, UUID
	def, err := cloudevents.NewDefaultClient()
	// will use longPoll or server mux for http transport
	go def.StartReceiver(context.Background(), func(ctx context.Context, ev cloudevents.Event) {
		log.Println("RCVD-def", ev)
	})

	evch := make(chan cloudevents.Event, 8)
	ces := StartCEServer(8081, evch)
	ev1 := cloudevents.NewEvent() // will set spec version, EventContext
	ev1.SetData(cloudevents.TextPlain,  "hi")
	// Required
	ev1.Context.SetSource("8080")
	ev1.Context.SetID("123")
	ev1.Context.SetType("t1")
	// Time is added automatically
	err = ces.Send(cloudevents.ContextWithTarget(context.Background(),
		"http://localhost:8080/"),
		ev1)
	if cloudevents.IsUndelivered(err) {
		t.Fatal(err)
	}

	ev2 := cloudevents.Event{
		Context: &cloudevents.EventContextV1{
			Source: *cloudevents.ParseURIRef("8081"),
			ID: "2",
			Type: "t2",
		},
		DataEncoded: []byte("test2"),
	}
	err = def.Send(cloudevents.ContextWithTarget(context.Background(),
		"http://localhost:8081/ce"),
		ev2)
	if cloudevents.IsUndelivered(err) {
		t.Fatal(err)
	}

	ev := rcvTimeoutCE(evch)
	if ev == nil {
		t.Fatal("Not received event")
	}

}

func rcvTimeoutCE(events chan cloudevents.Event) *cloudevents.Event {
	tt := time.After(5 * time.Second)
	select {
	case ev := <- events:
		return &ev

	case <- tt: return nil
	}
}

func rcvTimeoutMsg(events chan *msgs.Message) *msgs.Message {
	tt := time.After(5 * time.Second)
	select {
	case ev := <- events:
		return ev

	case <- tt: return nil
	}
}

// Start a CE server on port.
func StartCEServer(port int, events chan cloudevents.Event) client.Client {
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Println(err)
	}
	cest, _ := cloudevents.NewHTTP(
		cloudevents.WithPath("/ce"),
		cloudevents.WithListener(l))
	ces, _ := cloudevents.NewClient(cest, cloudevents.WithTimeNow())

	go ces.StartReceiver(context.Background(), func(ctx context.Context, ev cloudevents.Event) {
		log.Println("CE-RCVD-def", port, ev)
		select {
			case events <- ev:
		}
	})

	return ces
}

