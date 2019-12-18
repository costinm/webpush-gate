# TL;DR

Goal: decentralized and secure messaging, supporting multiple 'backends'

Messaging protocol: Webpush with e2e encryption, using a gRPC transport based on
Envoy XDS/UDPA. 

How: Istio-like sidecar intercepting outgoing plain text messages, 
encryption using Webpush, and delivery using CloudEvents SDK and custom code.


# Event and messaging protocols

There are many apps and protocols used for events and messaging - MQTT is one of my current favourites based on its broad
IoT adoption. I spent many years implementing C2DM/GCM/FCM so I'm still attached to them. NATS
is a nice and modern messaging implementation I like, and too many other
 interesting protocols and implementations to list.

All messaging protocols share the basic features: a 'message'/'event' is sent/published
to one or many receivers. Each invents its own names and terms, but the message 
structure is almost universally a binary blob plus some metadata. CloudEvents 
attempts to standarize a common representation and mappings, with a decent approach.

The implementation differences are around scale and latency, with variation 
around storage/reliability. For example the number of endpoints - can be 10s of billions
for IoT/Android/Web, or 1000s for server-optimized. Number of topics can be extremely
large - or optimized for smaller use cases.  

Protocols are in almost all cases based on long lived connections - using a variety
of encodings and framing mechanism. 

# Webpush

What is different about webpush is the zero-trust model and the associated encryption and authentication layers.
Another critical factor is the de-centralized model, using public keys and URLs to identify and authenticate senders 
and possibly recipients.

Most major browsers support Webpush - but using proprietary protocols, I'm not 
aware of any implementation using the official 'push promise' for delivery.
The 'send' part is well adopted, with a small number of massive servers operated
by browser vendors. 

The requirements for Webpush and most other protocols are very light: a bid-directional
pipe, capable of sending relatively small binary+metadata. GRPC is perfect for this,
so is Websocket. 

I think choosing a protocol based on H2 or Quic is ideal and would work better with
the existing infrastructure - the push promise in the spec doesn't bring any 
special value. None of the binary protocols I've seen add special value either,
and in some cases it seems there are efforts to also support Websocket for transport,
as developer realize the value of HTTP infrastructure. 

# Istio

This project can use native protocols supported by [Cloud Events](http://cloudevents.io),
or use a GRPC protocol based on the control plane protocol used by Envoy and Istio.
It extends AggregatedDiscoveryService to pass opaque encrypted/authenticated messages. 

One of the initial goals was to build a prototype for distributing Istio configs
using a messaging backend ( NATS, Google Pubsub, etc), and to experiment with 
authenticated and encrypted messages that can't be forged by the control plane.
For example the owner of a namespace would sign or encrypt the config objects,
with Istio control plane acting as a pipe distributing to Envoy. An WASM or native
Envoy component would check the signature or decrypt the control messages.

Long before Istio I did some prototyping using gRPC for Webpush - while the
naming of fields is not perfect, the Envoy XDS protocol provides all the semantic 
we need. 

## Model

- The webpush server can act as both client and server (intermediary) and supports multiple protocols, similar 
with Envoy use in Istio. Since the protocol is plain gRPC, envoy can be used for transport,
the message routing and adaptation can be either in istio-agent or envoy WASM or native.

- Each workload (endpoint/device) has a self-generated EC256 key pair - which will be used as the 'sender ID' in the 
webpush protocol, using normal JWT tokens as well as in MTLS authentication. 

- Normal discovery (K8S or other registries) store the public keys of the endpoints.

For IoT/ad-hoc/split network use:

- An IPv6 address is derived from the self-generated public key, and used as primary identifier. This is not
critical for webpush, but ties into supporting a VPN layer using webpush for control.  

- workloads may form ad-hoc exchanges using local discovery (Wifi Direct, BLE, etc), or use a control plane that 
assigns the gateways.


## Transports

### GRPC 

Implementation in xds uses a stripped down but binary compatible version of Envoy AggregatedDiscoveryService (ADS or 
XDS), with the plan to use UDPA when available.

Webpush messages, in a proto representation, are sent and received as proto.Any in the 'Resources' field, using
the rest of the XDS protocol unchanged. 

The implementation goal is to also allow proxying all other XDS resources - possibly with an encryption/decryption
or signature checking, acting as an XDS sidecar.

### Standard PUSH frames

WIP - see h2 package. Low priority, GRPC or stream will likely be more common.

### Browser 'event'

Mostly used for debugging and local delivery. Broad support in browsers, very easy to parse

## Protobuf representation

The webpush protocol defines a HTTP2 representation of webpush, using header syntax. For non-http transport
a .proto representation is defined, for both encrypted message as well as for the 'VAPID' signed message.

'VAPID' is a mechanism to generate 'voluntary' information, signed with the public key of the sender. 
It is used in subscriptions and discovery to expose minimal information about workloads, tied to the 
self-generated key pair.
 
## Gateways and adapters to other protocols

The plan is to use cloudevents SDK and adapters as much as possible. Webpush will be used on the edges, to 
encrypt and authenticate the message that will be transited via other transports. Direct integrations are also
possible - in particular the 'browser event' is useful for adding support for older browsers. 

Applications would make a HTTP post to localhost:15004 with a plain-text JSON.

## Routing 

WIP

## Code organization

- auth - key pairs, encryption, VAPID JWT, certificates, simple authorization. Because an older version 
of this was using SSH, it also has support for reading and reusing SSH authorized_keys and known_hosts, and
may use the ssh keys. Message transport over SSH and streams are in a different repo.

- cncf - integration with cloudevents SDS

- h2 - WIP for real standard PUSH_PROMISE delivery of messages. H3 will also be here.

- msgs - basic interfaces - Mux, Message, protos

- send - code for sending standard encrypted webpush messages.

- xds - GRPC transport, using minimal Envoy proto subset. 


