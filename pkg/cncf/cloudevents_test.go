package cncf

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"testing"
	"time"

	"github.com/cloudevents/sdk-go/pkg/cloudevents/transport"
	cenats "github.com/cloudevents/sdk-go/pkg/cloudevents/transport/nats"
	"github.com/cloudevents/sdk-go/pkg/cloudevents/transport/pubsub"
	nats "github.com/nats-io/nats-server/v2/server"

	cloudevents "github.com/cloudevents/sdk-go"
	"github.com/cloudevents/sdk-go/pkg/cloudevents/client"
	"github.com/costinm/wpgate/pkg/msgs"
)

func TestCE(t *testing.T) {
	cloudevents.EnableTracing(true)

	// - 8080 is default port
	// - binary encoding
	// - timeNow, UUID
	def, err := cloudevents.NewDefaultClient()
	// will use longPoll or server mux for http transport
	go def.StartReceiver(context.Background(), func(ctx context.Context, ev cloudevents.Event, res *cloudevents.EventResponse) {
		log.Println("RCVD-def", ev)
	})

	evch := make(chan cloudevents.Event, 8)
	ces := StartCEServer(8081, evch)
	ev1 := cloudevents.NewEvent() // will set spec version, EventContext
	ev1.Data = "hi"
	ev1.DataBinary = true
	// Required
	ev1.Context.SetSource("8080")
	ev1.Context.SetID("123")
	ev1.Context.SetType("t1")
	// Time is added automatically
	_, _, err =ces.Send(cloudevents.ContextWithTarget(context.Background(),
		"http://localhost:8080/"),
		ev1)
	if err != nil {
		t.Fatal(err)
	}

	ev2 := cloudevents.Event{
		Context: &cloudevents.EventContextV02{
			SpecVersion: "0.2",
			Source: *cloudevents.ParseURLRef("8081"),
			ID: "2",
			Type: "t2",
		},
		Data: "test2",
	}
	_, _, err = def.Send(cloudevents.ContextWithTarget(context.Background(),
		"http://localhost:8081/ce"),
		ev2)
	if err != nil {
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
	cest, _ := cloudevents.NewHTTPTransport(cloudevents.WithBinaryEncoding(),
		cloudevents.WithPath("/ce"),
		cloudevents.WithListener(l))
	ces, _ := cloudevents.NewClient(cest, cloudevents.WithTimeNow())

	go ces.StartReceiver(context.Background(), func(ctx context.Context, ev cloudevents.Event, res *cloudevents.EventResponse) {
		log.Println("CE-RCVD-def", port, ev)
		select {
			case events <- ev:
		}
	})

	return ces
}

func startTestServers(t *testing.T) {
	// Start nats.
	// Defaults: localhost:39737
	natsServer, err := nats.NewServer(&nats.Options{
		Port: 15018,
	})
	if err != nil {
		t.Fatal(err)
	}
	go natsServer.Start()
	if !natsServer.ReadyForConnections(10 * time.Second) {
		t.Fatal("Unable to start NATS Server in Go Routine")
	}

	// Start plain CloudEvents clients
	// the subject is used to "subscribe"
	natst, err := cenats.New("localhost:15018", "natssub")
	natsC, err = cloudevents.NewClient(natst)
	natsEv = make(chan cloudevents.Event, 8)
	go natsC.StartReceiver(context.Background(), func(ctx context.Context, ev cloudevents.Event, res *cloudevents.EventResponse) {
		log.Println("CE-RCVD-nats", ev)
		select {
		case natsEv <- ev:
		}
	})

	// Google
	if os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") != "" {
		//os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "/home/costin/.config/gcloud/legacy_credentials/costin@google.com/adc.json")
		gpst, err := pubsub.New(context.Background(),
			pubsub.WithProjectID("costin-istio"),
			pubsub.AllowCreateTopic(true),
			pubsub.WithTopicID("test"),
			pubsub.AllowCreateSubscription(true),
			pubsub.WithSubscriptionAndTopicID("subid3", "test"))
		if err != nil {
			t.Fatal("Failed to pubsub ", err)
		}
		gpsEv = make(chan cloudevents.Event, 8)
		gps, err = cloudevents.NewClient(gpst, cloudevents.WithConverterFn(func(ctx context.Context, message transport.Message, e error) (event *cloudevents.Event, e2 error) {
			message.(*pubsub.Message).Attributes["ce-specversion"] = "0.3"
			c3 := pubsub.CodecV03{}
			return c3.Decode(ctx, message)
		}))
		go gps.StartReceiver(context.Background(), func(ctx context.Context, ev cloudevents.Event, res *cloudevents.EventResponse) {
			log.Println("CE-RCVD-gps", ev)
			select {
			case gpsEv <- ev:
			}
		})
	}

	// Setup a 'regular' CloudEvents - will listen on http://localhost:8081/ce
	// The CE client will send to the mux, on http://localhost:15004/send
	evch = make(chan cloudevents.Event, 8)
	ces = StartCEServer(8081, evch)

}

var (
	natsEv chan cloudevents.Event
	natsC cloudevents.Client
	gpsEv chan cloudevents.Event
	gps cloudevents.Client
	evch chan cloudevents.Event
	ces cloudevents.Client

	mch chan *msgs.Message
)

func setupMux() error {
	// the subject is used to "subscribe"
	natsMuxT, err := cenats.New("localhost:15018", "natssub")
	if err != nil {
		return err
	}
	natsMuxC, err := cloudevents.NewClient(natsMuxT)
	if err != nil {
		return err
	}
	New(msgs.DefaultMux, natsMuxC)

	if os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") != "" {
		// setting only subscription doesn't add topic.
		gpstmux, err := pubsub.New(context.Background(),
			pubsub.WithProjectID("costin-istio"),
			pubsub.WithTopicID("test"),
			pubsub.AllowCreateTopic(true),
			pubsub.AllowCreateSubscription(true),
			pubsub.WithSubscriptionAndTopicID("subidmux", "test"))
		if err != nil {
			return err
		}
		gpsmux, err := cloudevents.NewClient(gpstmux, cloudevents.WithConverterFn(func(ctx context.Context, message transport.Message, e error) (event *cloudevents.Event, e2 error) {
			message.(*pubsub.Message).Attributes["ce-specversion"] = "0.3"
			c3 := pubsub.CodecV03{}
			return c3.Decode(ctx, message)
		}))
		if err != nil {
			return err
		}
		New(msgs.DefaultMux, gpsmux)
	}

	// Setup the Mux gate, with CE support.
	mux := msgs.DefaultMux
	ce, _ := NewCloudEvents(msgs.DefaultMux, 15004)
	// Add a std CE subscriber
	ce.Targets["http://localhost:8081/ce"] = ""

	// Subscribe to muxtest
	mch = make(chan *msgs.Message, 8)
	mux.AddHandler("muxtest",
		msgs.HandlerCallbackFunc(func(ctx context.Context, cmdS string,
				meta map[string]string, data []byte) {
			log.Println("Mux event", cmdS)
			mch <- msgs.NewMessage(cmdS, meta).SetDataJSON(data)
		}))

	return nil
}

func TestMux(t *testing.T) {
	startTestServers(t)

	setupMux()

	mux := msgs.DefaultMux
	var err error

	t.Run("http", func(t *testing.T) {
		// From 'plain' CE to the mux
		ce1 := cloudevents.Event{
			Context: &cloudevents.EventContextV02{
				SpecVersion: "0.2",
				Source: *cloudevents.ParseURLRef("8081"),
				ID: "2",
				Type: "muxtest",
			},
			Data: "from ce to mux",
		}
		ces.Send(cloudevents.ContextWithTarget(context.Background(),
			"http://localhost:15004/send"), ce1)

		// From mux to CE
		mux.SendMessage(&msgs.Message{
			To: "/test",
			Data: []byte("from mux to ce"),
			Meta: map[string]string{"a":"B"},
		})

		m1 := rcvTimeoutMsg(mch)
		if m1 == nil {
			t.Error("Message from CE to MUX failed")
		}
		m2 := rcvTimeoutCE(evch)
		if m2 == nil {
			t.Error("Message from MUX to CE failed")
		}
	})

	t.Run("nats", func(t *testing.T) {
		// From 'plain' CE to the mux
		ce1 := cloudevents.Event{
			Context: &cloudevents.EventContextV02{
				SpecVersion: "0.2",
				Source: *cloudevents.ParseURLRef("8081"),
				ID: "2",
				Type: "muxtest",
			},
			Data: "from nats to mux",
		}
		natsC.Send(context.Background(), ce1)

		// From mux to CE
		mux.SendMessage(&msgs.Message{
			To: "/test",
			Data: []byte("from mux to ce"),
			Meta: map[string]string{"a":"B"},
		})

		m1 := rcvTimeoutMsg(mch)
		if m1 == nil {
			t.Error("Message from nats to MUX failed")
		}
		m2 := rcvTimeoutCE(natsEv)
		if m2 == nil {
			t.Error("Message from MUX to nats failed")
		}
	})


	t.Run("goog", func(t *testing.T) {
		if gps == nil {
			return
		}
		// From 'plain' CE to the mux
		ce1 := cloudevents.Event{
			Context: &cloudevents.EventContextV02{
				SpecVersion: "0.2",
				Source: *cloudevents.ParseURLRef("8081"),
				ID: "2",
				Type: "muxtest",
			},
			Data: "from gps to mux",
		}
		_,_, err = gps.Send(context.Background(),
			ce1)
		if err != nil {
			t.Error("FAILED TO SEND pubsub", err)
		}

		// From mux to CE
		err = mux.SendMessage(&msgs.Message{
			To: "/test",
			Data: []byte("from mux to gps"),
			Meta: map[string]string{"a":"B"},
		})
		if err != nil {
			t.Error("FAILED TO SEND", err)
		}

		m1 := rcvTimeoutMsg(mch)
		if m1 == nil {
			t.Error("Message from gps to MUX failed")
		}
		m2 := rcvTimeoutCE(gpsEv)
		if m2 == nil {
			t.Error("Message from MUX to gps failed")
		}
	})

}
