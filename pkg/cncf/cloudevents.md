# Terms

CloudEvents:
- Source (required): URI reference of the source. May be used to send messages back ? 
- Type (required): domain name format
- ID (required), unique for source
- Context - metadata, can be used for routing. Clear text, headers. Limits on key (20 char, a-z0-9)
Limits value - bool, int32, string, binary/base64, URI, URI ref, RFC3339 time

Tricky/optional:
- subject - instance of the type, for example file name, container id, etc.
For NATS it's used to subscribe, as equivalent with topic. CE is quite different.
Note that NATS is hierarchical, with prefix and component wildcard support. 
">" is the prefix.

# Mapping CloudEvents to Webpush

The CloudEvents spec:

"Domain specific event data SHOULD be encrypted to restrict visibility to trusted parties. The mechanism employed for 
such encryption is an agreement between producers and consumers and thus outside the scope of this specification."

The mapping to webpush defines such an agreement. 

It is recommended for webpush implementations to identify Producers and Consumers using IPv6 VIPs derived 
from the webpush public key. If this is not possible, a https:// URL should be used, using the webpush
provider domain.

It is assumed a Webpush Producer is an implementation of Webpush, providing subscribe and send handlers. 
Consumers are also WebPush clients, receiving encrypted messages. Webpush Producer and Consumer may also support
native CloudEvent protocol as plain text and integrate with other pubsub systems. 

When external pubsub systems are used, the data may either be plaintext or webpush. A webpush intermediary
will encrypt plaintext messages if possible (destination public key can be determined).  


## Encrypted messages - keys

Webpush requires knowing the EC256 public key of the destination. 

An additional context attribute 'to', is defined. It will be a string:
- EC256 public key - if the webpush system is able to use the key as primary identifier.
- VIP6 - if the system uses IPs derived from the public key.
- Webpush subscription (https URL) - if the webpush system can retrieve the public key 

If the 'to' attribute is missing, a webpush-CloudEvents intermediary may determine it based on
the destination it is forwarding to, and sign with its own keys. For example 

## Context signing and sender authentication

Mapping to Webpush uses the VAPID JWT to encode the context. 

## Context

- Context == metadata, sent as headers in the 'binary' encodings.

Seems desirable to encode the producer context in the JWT VAPID token, to make sure they are not modified.

Additional attributes added by intemrmediaries should also be encoded as JWT VAPID tokens, signed by the
intermediary. This also provides path information within multi-hop webpush systems operated by independent
entities. 



Required fields:
- id - source+id unique, used for dup detection. Source+id will be the URL of the message.
- source - URI reference, absolute URI recommended
- type - reverse DNS

URLs of type: [VIP6]/type/id or URLBASE/type/id can be used to identify the message. 


Boilerplate - may be ignored while transitioning trough webpush, but must be restored when sending to final 
CloudEvent destination:
- specversion=1.0

Optional:
- datacontenttype - may be mapped to content-type, default application/json. 
- dataschema - seems useless
- subject - identifies the resource (filename for example) associated with producing the event/message. Note it may
have privacy implications.
- time, RFC3339. May be added by intermediaries if missing - to allow expiration.

The spec defines limits on message size: 64K. Webpush may have lower limit. If a message is above the 
webpush limit, as indicated by the response code, only the message URL will be sent, and the receiver or the 
intermediary between webpush and CloudEvents system will use the URL formed by source + id to retrieve the full body.

Note that CloudEvents size is defined based on total encoding size, webpush may be defined based on data only.


# Example

CloudEvents spec:

```json
{
    "specversion" : "1.0",
    "type" : "com.github.pull.create",
    "source" : "https://github.com/cloudevents/spec/pull",
    "subject" : "123",
    "id" : "A234-1234-1234",
    "time" : "2018-04-05T17:31:00Z",
    "comexampleextension1" : "value",
    "comexampleothervalue" : 5,
    "datacontenttype" : "text/xml",
    "data" : "<much wow=\"xml\"/>"
}
```

Webpush: 
