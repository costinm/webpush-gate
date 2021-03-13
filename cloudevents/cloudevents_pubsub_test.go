package cloudevents

import (
	"context"
	"log"
	"os"
	"testing"
	"time"

	"github.com/cloudevents/sdk-go/pkg/cloudevents/transport/pubsub"
	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/cloudevents/sdk-go/v2/protocol"
	"github.com/costinm/ugate/pkg/msgs"

	// The server package is messed up - v2 doesn't exist.
	ps "cloud.google.com/go/pubsub"
)


func startTestServers(t *testing.T) {
	// Google
	if true || os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") != "" {
		//os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "/home/costin/.config/gcloud/legacy_credentials/costin@google.com/adc.json")
		gpst, err := pubsub.New(context.Background(),
			pubsub.WithProjectID(proj),
			pubsub.AllowCreateTopic(true),
			pubsub.WithTopicID("test"),
			pubsub.AllowCreateSubscription(true),
			pubsub.WithSubscriptionAndTopicID("subid3", "test"))
		if err != nil {
			t.Fatal("Failed to pubsub ", err)
		}
		gpsEv = make(chan cloudevents.Event, 8)
		gps, err = cloudevents.NewClient(gpst)
		//	cloudevents.WithConverterFn(func(ctx context.Context, message transport.Message, e error) (event *cloudevents.Event, e2 error) {
		//	message.(*pubsub.Message).Attributes["ce-specversion"] = "0.3"
		//	c3 := pubsub.CodecV03{}
		//	return c3.Decode(ctx, message)
		//}))
		go gps.StartReceiver(context.Background(), func(ctx context.Context, ev cloudevents.Event) {
			log.Println("CE-RCVD-gps", ev)
			select {
			case gpsEv <- ev:
			}
		})
	}
}

var (
	proj = "dmeshgate"
	gpsEv chan cloudevents.Event
	gps cloudevents.Client
	mch chan *msgs.Message
)

func setupMux() error {

	// setting only subscription doesn't add topic.
	gpstmux, err := pubsub.New(context.Background(),
		pubsub.WithProjectID(proj),
		pubsub.WithTopicID("test"),
		pubsub.AllowCreateTopic(true),
		pubsub.AllowCreateSubscription(true),
		pubsub.WithSubscriptionAndTopicID("subidmux", "test"))
	if err != nil {
		return err
	}
	gpsmux, err := cloudevents.NewClient(gpstmux)
	//	cloudevents.WithConverterFn(func(ctx context.Context, message transport.Message, e error) (event *cloudevents.Event, e2 error) {
	//	message.(*pubsub.Message).Attributes["ce-specversion"] = "0.3"
	//	c3 := pubsub.CodecV03{}
	//	return c3.Decode(ctx, message)
	//}))

	if err != nil {
		return err
	}
	New(msgs.DefaultMux, gpsmux)

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

func TestCEPS(t *testing.T) {
	ctx := context.Background()
		// setting only subscription doesn't add topic.
		gpstmux, err := pubsub.New(ctx,
		pubsub.WithProjectID(proj),
		pubsub.WithTopicID("test"),
		pubsub.AllowCreateTopic(true),
		pubsub.AllowCreateSubscription(true),
		pubsub.WithSubscriptionAndTopicID("subidmux1", "test"))
		if err != nil {
			t.Skip("Missing credentials ", err)
		}
		gpsmux, err := cloudevents.NewClient(gpstmux)

	ch := make(chan *event.Event)
	// Not supported with PubSub: returning event
	go func() {
		log.Println("Start receiver")
		err = gpsmux.StartReceiver(ctx, func(ctx context.Context, e event.Event)(protocol.Result) {
			log.Println("Received ", e)
			select {
			case ch <- &e:
			default:
			}
			return nil

		})
		if err != nil {log.Println(err)}
		log.Println("RECEIVER STARTED")
	}()
		t0 := time.Now()
		// Create an Event.
		event :=  cloudevents.NewEvent()
		event.SetSource("example/uri")
		event.SetType("example.type")
		event.SetID("ID1") // required
		event.SetData(cloudevents.ApplicationJSON, map[string]string{"hello": "world"})

		// Set a target.
		cectx := cloudevents.ContextWithTarget(context.Background(), "http://localhost:8080/")

		// Send that Event.
		if  result := gpsmux.Send(cectx, event); cloudevents.IsUndelivered(result) {
			log.Fatalf("failed to send, %v", result)
		} else {
			//log.Println("Response: ", time.Since(t0), res)
			res := <-ch
			log.Println("Response2: ", time.Since(t0), res)
		}
		if err != nil {
			t.Fatal(err)
		}

}


func TestRaw(t *testing.T) {
	ctx := context.Background()
	client, err := ps.NewClient(context.Background(), proj)
	if err != nil {
		t.Fatal(err)
	}

	top := client.Topics(context.Background())
	for {
		t, err := top.Next()
		if err != nil {
			break
		}
		it := t.Subscriptions(ctx)
		for {
			s, err := it.Next()
			if err != nil {
				break
			}
			log.Println("--- ", t.ID(), s.ID(), s.String())
		}

		log.Println(t)
	}
	subs := client.Subscriptions(ctx)
	for {
		t, err := subs.Next()
		if err != nil {
			break
		}
		log.Println(t)
	}
	topic := client.Topic("test")
	ok, err := topic.Exists(ctx)
	if !ok {
		topic, err = client.CreateTopic(ctx, "test")
		if err != nil {
			t.Fatal(err)
		}
	}
	//topic.PublishSettings.DelayThreshold = 1 * time.Second

	s := client.Subscription("subid3")
	ok, err = s.Exists(ctx)
	if !ok {
		s, err = client.CreateSubscription(ctx, "subid3", ps.SubscriptionConfig{
			Topic: topic,
			// ack(30s), retention (24h)
			// Min is 10 min.
			RetentionDuration: 10 * time.Minute,
			// Min
			ExpirationPolicy: 24 * time.Hour,
			// PushConfig: Endpoint, attributes, AuthMethod: OIDCToken
		})
	}
	t0 := time.Now()
	ch := make(chan *ps.Message)
	go s.Receive(ctx, func(ctx context.Context, message *ps.Message) {
		ch <- message
		message.Ack()
	})

	t0 = time.Now()
	res := topic.Publish(ctx, &ps.Message{Data: []byte("payload")})
	log.Println("Pub res", time.Since(t0), res)
	message :=	<-ch
	log.Println("IN ", time.Since(t0), message, string(message.Data))
	t0 = time.Now()
	res = topic.Publish(ctx, &ps.Message{Data: []byte("payload")})
	log.Println("Pub res", time.Since(t0), res)
	message =	<-ch
	log.Println("IN ", time.Since(t0), message, string(message.Data))
}

func TestMux(t *testing.T) {
	startTestServers(t)

	setupMux()

	mux := msgs.DefaultMux
	var err error

	t.Run("goog", func(t *testing.T) {
		if gps == nil {
			return
		}
		// From 'plain' CE to the mux
		// gcloud pubsub topics create subid3 --project dmeshgate
		ce1 := cloudevents.Event{
			Context: &cloudevents.EventContextV1{
				Source: *cloudevents.ParseURIRef("8081"),
				ID: "2",
				Type: "muxtest",
			},
			DataEncoded: []byte("from gps to mux"),
		}
		err = gps.Send(context.Background(),
			ce1)
		if cloudevents.IsUndelivered(err) {
			t.Error("FAILED TO SEND pubsub", err)
		}

		// From mux to CE
		err = mux.SendMessage(&msgs.Message{
			MessageData: msgs.MessageData{
				To: "/test",
				From: "foo", //*cloudevents.ParseURIRef("8081"),
				Meta: map[string]string{"a":"B"},
			},
			Data: []byte("from mux to gps"),
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
