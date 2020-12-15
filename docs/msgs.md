
# Event and messaging protocols

There are many apps and protocols used for events and messaging.

All messaging protocols share the basic features: a 'message'/'event' is sent/published
to one or many receivers. Each protocol and app invents its own names and terms,
but the message structure is almost universally a binary blob plus some metadata.

The implementation differences are around scale and latency, with variation
around storage/reliability. For example the number of endpoints - can be 10s of billions
for IoT/Android/Web, or 1000s for server-optimized. Number of topics can be extremely
large - or optimized for smaller use cases.

Protocols are in almost all cases based on long lived connections - using a variety
of encodings and framing mechanism.

# API

## Minimal interfaces

We need a common representation of a message, avoiding too broad dependencies.

Most cases need:
- Send
- Subscribe with a callback to receive the message

The most minimal interface seems to be:

```
interface Sender {
  Send(to string, data interface{}, meta map[string]string) (string, error)
}

interface Receiver {
  // from, etc in meta
  Receive(to string, from string, data interface{}, map[string]string)
}

```

'to' is a URL or path, last component identifies the type of the message.
The first part (host) should be empty for local or have the IP6 or host name
or a group.


For 'channels', an additional interface is needed:

```
interface Mux {
  Sender
  AddConnection(cid string, remoteAddr string, meta map[string]string, Sender)
  RemoveConnection(cid)
}
```

## HTTP style

Another convenient aproach is to use http.Handler:

- receivers implement http.Handler, the message is represented as a http.Request
- http.RoundTripper interface implemented by transports/channels
-

## Libp2p

github.com/libp2p/go-eventbus provides a basic in-process implementation,
with minimal deps (just core). The core still has a lot of deps, and the
event interface seems to be oddly specific - DHT events, etc.

However the bus is defined using 3 interfaces that can be used without
a dep to libp2p.

```
// Emitter represents an actor that emits events onto the eventbus.
type Emitter interface {
	io.Closer

	// Emit emits an event onto the eventbus. If any channel subscribed to the topic is blocked,
	// calls to Emit will block.
	//
	// Calling this function with wrong event type will cause a panic.
	Emit(evt interface{}) error
}

// Subscription represents a subscription to one or multiple event types.
type Subscription interface {
	io.Closer

	// Out returns the channel from which to consume events.
	Out() <-chan interface{}
}

// Bus is an interface for a type-based event delivery system.
type Bus interface {
	// Subscribe creates a new Subscription.
	//
	// eventType can be either a pointer to a single event type, or a slice of pointers to
	// subscribe to multiple event types at once, under a single subscription (and channel).
	//
	// Failing to drain the channel may cause publishers to block.
	//
	// If you want to subscribe to ALL events emitted in the bus, use
	// `WildcardSubscription` as the `eventType`:
	//
	//  eventbus.Subscribe(WildcardSubscription)
	//
	// Simple example
	//
	//  sub, err := eventbus.Subscribe(new(EventType))
	//  defer sub.Close()
	//  for e := range sub.Out() {
	//    event := e.(EventType) // guaranteed safe
	//    [...]
	//  }
	//
	// Multi-type example
	//
	//  sub, err := eventbus.Subscribe([]interface{}{new(EventA), new(EventB)})
	//  defer sub.Close()
	//  for e := range sub.Out() {
	//    select e.(type):
	//      case EventA:
	//        [...]
	//      case EventB:
	//        [...]
	//    }
	//  }
	Subscribe(eventType interface{}, opts ...SubscriptionOpt) (Subscription, error)

	// Emitter creates a new event emitter.
	//
	// eventType accepts typed nil pointers, and uses the type information for wiring purposes.
	//
	// Example:
	//  em, err := eventbus.Emitter(new(EventT))
	//  defer em.Close() // MUST call this after being done with the emitter
	//  em.Emit(EventT{})
	Emitter(eventType interface{}, opts ...EmitterOpt) (Emitter, error)

	// GetAllEventTypes returns all the event types that this bus knows about
	// (having emitters and subscribers). It omits the WildcardSubscription.
	//
	// The caller is guaranteed that this function will only return value types;
	// no pointer types will be returned.
	GetAllEventTypes() []reflect.Type
}
```


## CloudEvents

CloudEvents attempts to standarize a common representation and mappings, with a
decent approach. However the 'Event' is a struct, and requires a large dependency
in the SDK, so it's not a good general API.

The API are also pretty complicatd, possibly because of the goal of adapting
multiple implementations, but this gets reflected into the API.

However CloudEvents is a good bridge, that can implement the 'neutral' API and
adapt to multiple supported transports.
