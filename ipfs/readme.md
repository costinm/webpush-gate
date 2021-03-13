# Concepts

## Discovery

- DHT/kadelmia. Avoid 'dual' - it gets confused. LAN/local should 
  be kept separated, use auth.
- mDNS local
- also called 'signaling' in WebRTC 
- key is a SHA32 (of something), value is the address[]
- example key: sha("/libp2p/relay") - address are nodes providing relay service


## Circuits / Relay

- IPFS network provides a number of well-known and discoverable open relays
- useful for 'behind the NAT' - but should be used primarily for signaling
- IMO the use or relay for data is a major flaw in IPFS/LIBP2P. 

A better alternative is to use them only for push, with a larger set of 
nodes ( ideally all ), to initiate quic or webrtc connections. 
For fallback - standard TURN servers could be used.

This allows many home servers to get high speed ( no relay ).



## Record store

- Key is a public key - ideally ED25519 
- Value is a signed proto, typically a /ipfs address but it's a byte[]


# Transports

## webrtc

- compatible with browsers, required
- 'star' and 'direct'
- /dns4/wrtc-star1.par.dwebops.pub/tcp/443/wss/p2p-webrtc-star/p2p/<your-peer-id>
- start not supported in go, protocol not documented/clear
- 

## ws + mplex + noise|secio

- primarily for use with browser-based nodes, without RTC
- requires DNS certs (apparently for wss)

## quic

- not compatible with browsers
- flow control on streams
- mostly standards based

# Interfaces

## API

https://docs.ipfs.io/reference/http/api/

http://localhost:5001/api/v0/swarm/peers
query: arg (repeated), rest are flags.

Response: JSON


## Gateway

/p2p/${PEER_ID}/http/${PATH}

/p2p/${PEER_ID}/x/${PROTO}/http/${PATH}

