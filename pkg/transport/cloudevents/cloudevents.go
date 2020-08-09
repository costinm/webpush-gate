package cloudevents

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/cloudevents/sdk-go"
	"github.com/cloudevents/sdk-go/pkg/cloudevents/client"
	"github.com/costinm/wpgate/pkg/msgs"
)

//

// Adapter to CloudEvents. Will receive CloudEvents via HTTP (or other sources),
// and forward them using Webpush and other gateway protocols.
//
// Will forward outgoing messages to CloudEvents.
//
// Each CloudEvents object is associated with a transport - HTTP has one
// instance, because it binds to a port.
//
// One instance can send to multiple endpoints.
type CloudEvents struct {
	client client.Client
	mux    *msgs.Mux

	Targets map[string]string
	mc      *msgs.MsgConnection
}

// TODO: separate conditional classes for AMQP, NATS, Pubsub
// As a 'messaging sidecar', this can abstract the auth.

// Adapter between the internal mux and CloudEvents.
//
// Will receive plain text cloud events - ideally from a localhost or local client.
// Also receives remote events - ideally encrypted with webpush wrapping.
//
// Messages are routed using the mux to local or remote destinations.
//
// For local->remote, the message will be encrypted
// For remote->local, message will be decrypted
// For forwarding, it is passed trough.
func New(mux *msgs.Mux, c client.Client) (*CloudEvents, error) {
	// Must use WithListener - otherwise can't control when the listening starts
	// or reuse the port.
	// Same with the mux

	//c, err := cloudevents.NewDefaultClient()
	// Default:
	// - http.New WithBinaryEncoding
	// - WithTimeNow, WithUUID
	//

	ce := &CloudEvents{
		client:  c,
		mux:     mux, // for dispatching incoming events
		Targets: map[string]string{},
	}

	go func() {

		// Receiver can take context.Context, Event
		// Or other combinations - including *EventResponse.
		// Strange...
		c.StartReceiver(context.Background(), ce.receive)
	}()

	ce.mc = &msgs.MsgConnection{
		Name:                "",
		SubscriptionsToSend: []string{"*"},
		SendMessageToRemote: ce.sendMessageToRemote,
	}
	mux.AddConnection(fmt.Sprintf("CE-%d", conid), ce.mc)
	conid++

	return ce, nil

}

var (
	conid = 1
)

func NewCloudEvents(mux *msgs.Mux, port int) (*CloudEvents, error) {
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	t, err := cloudevents.NewHTTPTransport(
		cloudevents.WithPath("/send"),
		cloudevents.WithListener(l), // can't set port
	)

	if err != nil {
		return nil, err
	}
	c, err := cloudevents.NewClient(t)
	if err != nil {
		return nil, err
	}

	return New(mux, c)
}

// Forward messages to other cloudevents servers
func (ce *CloudEvents) sendMessageToRemote(ev *msgs.Message) error {
	event := cloudevents.NewEvent()
	event.SetID(ev.Id)

	// TODO: To in dmesh was a path - in ce is a package
	// Also needs to include real destination.
	parts := strings.Split(ev.To, "/")

	event.SetType(parts[1]) // "com.cloudevents.readme.sent")
	// TODO: use the VIP6 or source
	event.SetSource("http://localhost:8080/")

	event.SetData(ev.Data)

	t, err := cloudevents.NewHTTPTransport(
		cloudevents.WithTarget("http://localhost:15004/send"),
		cloudevents.WithEncoding(cloudevents.HTTPBinaryV02),
	)

	// Alternatives: cloudevents.WithStructuredEncoding()

	//t, err := cloudevents.NewHTTPTransport(
	//	cloudevents.WithPort(8181),
	//	cloudevents.WithPath("/events/")
	//)
	//// or a custom transport: t := &custom.MyTransport{Cool:opts}

	if err != nil {
		panic("failed to create transport, " + err.Error())
	}

	c, err := cloudevents.NewClient(t)
	if err != nil {
		panic("unable to create cloudevent client: " + err.Error())
	}
	for k, _ := range ce.Targets {
		if _, _, err := c.Send(cloudevents.ContextWithTarget(context.Background(),
			k), event); err != nil {
			log.Println("failed to send cloudevent: " + err.Error())
		}
	}

	return err
}

func (ce *CloudEvents) receive(ctx context.Context, event cloudevents.Event) { //, back *cloudevents.EventResponse) {

	log.Println("MUX EVENT: ", event.Context)

	if evb, ok := event.Data.([]byte); ok {
		log.Println("MUX EVENT DATA: ", string(evb))
	}
	to := "/" + event.Type()
	if event.Subject() != "" {
		to = to + "/" + event.Subject()
	}
	// TODO: allow sending back a response ?
	m := &msgs.Message{
		Time:       event.Time().Unix(),
		Id:         event.ID(),
		To:         to,
		From:       event.Source(),
		Data:       event.Data,
		TS:         event.Time(),
		Meta:       map[string]string{},
		Connection: ce.mc,
	}
	for k, v := range event.Extensions() {
		if vs, ok := v.(string); ok {
			m.Meta[k] = vs
		}
	}
	ce.mux.HandleMessageForNode(m)
}
