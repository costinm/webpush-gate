DMesh intent is to interoperate and 'mesh' with
other protocols and systems. Where standards
emerge, they would replace the initial implementation.

Few common characteristics:
- identity based on the public key
- multiplexed protocols
- security: most reinvent TLS or SSH protocols
- relay and tunneling
- discovery based on discovery servers or kademlia

# Kademlia

Needed for very large networks. Alternative to sharded
and federated central servers.

Noise: tied to the protocol. No infrastructure.
IPFS: seems extremely chatty, also used for files and name server.
BT: larger infra.

https://github.com/nictuku/dht - bittorent version
'5000 msg/s per core, 1G'. Use 10 peers.
bootstrap from: "router.magnets.im:6881,router.bittorrent.com:6881,dht.transmissionbt.com:6881"

## Implementation

- IPFS - used for everything
- Bittorrent BEP-5
- https://github.com/prettymuchbryce/kademlia - tied to utp, unmaintained
- https://github.com/nictuku/dht - BEP-5, UDP, bencode
-

# Federated discovery

Syncthing: infrstructure operated by volunteers.
K8S: etcd or sql databases scale to large numbers.



# Syncthing

- Focused on syncing directories across machines
- Operates a set of volunteer discovery and proxy servers
- Similar Identity and Auth with dmesh, IPFS, etc
- Maintains a database of file SHAs, for easy replication -
so it can be significantly faster than rsync.
- Android client

Interop:
- run syncthing on the same node as DMesh
- localhost:xxx expose other nodes.

Uses:
- Shared filesystem across nodes belonging to same user
- "Public sites", users can keep a local copy
- Tool to inspect and operate on the fs DB
- Share/use the relay and discovery infra

Features:
- EnableRelayHop - a node can be used as a relay. Currently no auth
- EnableAutoRelay - auto-adevertise and use relays
- Experimental.Libp2pStreamMounting - TCP proxy.
listen NAME appport, forward NAME clport PEER
- Experimental.P2pHttpProxy: /p2p/$SERVER_ID/http/$FORWARDED_PATH

# Bittorrent

- largest infrastructure for discovery
- lots of implementations and clients for files
- Kademlia DHT - Mainline - invents its own KRPC-over-UDP. Light.

# Libp2p (part of IPFS)

A small subset of libp2p, simplified and moved back to standards can be used.

To some extent, it can interoperate with regular IPFS, at least with nodes that support
the standard based protocols.

In particular:
1. Low level transport based on standard QUIC, WS over H1, with TLS+SPDY and H2 POST or CONNECT.
An alternative mux using WS+SSH is possible, since WS+SPDY might not be broadly available on JS/browsers,
while SSH has many implementations. This interoperate with IPFS when QUIC is used.
No negotiation used - the protocol is included in the discovery URL

2. Map 'multi addr' to URL, multiformat to standard HTTP negotiation and format.





# IPFS

TL;DR: its 'proprietary' protocols don't add a lot of value. Using the DHT only may be worth it
from larger nodes, but too expensive to use directly from devices. Interesting ideas, and some
adoption of 'standard' protocols - QUIC, TLS. Interesting HTT/Gateway API, worth implementing over
other random APIs, in particular the streaming and addressing.

Implementation: interesting event bus, modular, good interfaces.

- LibP2P - generic library for P2P
- port 4001, UpNP, NAT, TCP, QUIC
- port 8081 - Websocket
- 5001 - internal debug + well-defined HTTP API
- 8080 - HTTP/1.0 Proxy to IPFS
- public servers for discovery, bootstrap
- Example: /ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ
- includes distributed file storage (in the full app)

IPFS server uses about 5GB/day transfer with default ipfs options, 15% 1CPU

https://github.com/hsanjuan/ipfs-lite
https://github.com/textileio/android-ipfs-lite
https://github.com/textileio/grpc-ipfs-lite - grpc proto

Concepts are very similar:
- identity based on the public key. Also all naming is based on pubkey.
- relay protocol
- multiplexed, over multiple transports - but standards (H2, QUIC, SSH) are better.
- support WS / QUIC as 'core' protocols.


Downsides:
- size: xxx
- NIH and associated complexity - reinventing TLS, URLs. Can be avoided by using
a subset, ignoring propaganda.
- no e2e security ?
- shared key for private net is a joke. Can be replaced with a proper
ACL, authn is good.
- authz is mostly missing
- mixing the DHT for peers and files and mutable keys and pubsub.
- Bittorrent may have better file exchange protocol or net size. Can BT
be implemented over IPFS ?
- SyncThing has a more interesting tracking of file changes. Could
be implemented on same protocol ( it also has a strong NIH on protocols)


Core concept: MerkleDAG is used to verify the object based on the hashes.
Objects are immutable, identified by content SHA.
The IPNS is based instead of signing - each object is 'owned' by a keypair,
which allows a hierarchical naming starting with the pubkey. This allows
arbitrary names, with signature instead of MerkleDAG to validated.



Benefits:
- runs an infrastructure, seems to have business support (paid pinning)
- reusing code

Docker image:
- 'make IPFS_PLUGINS=...'
- su-exec, tini binary
- busybox-glibc image
-

```
IPFS_LOGGING env
ipfs log level '*' WARN/DEBUG/INFO/NOTICE
dht engine net/identity mplex swarm2(quic,listen)
mdns


ipfs id 12D3KooWLePVbQbv3PqsDZt6obMcWa99YyqRWjeiCtStSydQ6zjH
{
	"ID": "12D3KooWLePVbQbv3PqsDZt6obMcWa99YyqRWjeiCtStSydQ6zjH",
	"PublicKey": "CAESIKDiPwvGLhme8Hl8CGT3GqD0NDufr/9REulmjSfiRQXQ",
	"Addresses": [
		"/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWLePVbQbv3PqsDZt6obMcWa99YyqRWjeiCtStSydQ6zjH",
		"/ip4/127.0.0.1/udp/4001/quic/p2p/12D3KooWLePVbQbv3PqsDZt6obMcWa99YyqRWjeiCtStSydQ6zjH",
		"/ip4/149.28.196.14/tcp/4001/p2p/12D3KooWLePVbQbv3PqsDZt6obMcWa99YyqRWjeiCtStSydQ6zjH",
		"/ip4/149.28.196.14/udp/4001/quic/p2p/12D3KooWLePVbQbv3PqsDZt6obMcWa99YyqRWjeiCtStSydQ6zjH",
		"/ip6/2001:19f0:ac01:137e:5400:1ff:febe:4856/tcp/4001/p2p/12D3KooWLePVbQbv3PqsDZt6obMcWa99YyqRWjeiCtStSydQ6zjH",
		"/ip6/2001:19f0:ac01:137e:5400:1ff:febe:4856/udp/4001/quic/p2p/12D3KooWLePVbQbv3PqsDZt6obMcWa99YyqRWjeiCtStSydQ6zjH",
		"/ip6/::1/tcp/4001/p2p/12D3KooWLePVbQbv3PqsDZt6obMcWa99YyqRWjeiCtStSydQ6zjH",
		"/ip6/::1/udp/4001/quic/p2p/12D3KooWLePVbQbv3PqsDZt6obMcWa99YyqRWjeiCtStSydQ6zjH"
	],
	"AgentVersion": "go-ipfs/0.8.0-dev/0401f6097",
	"ProtocolVersion": "ipfs/0.1.0",
	"Protocols": [
		"/ipfs/bitswap",
		"/ipfs/bitswap/1.0.0",
		"/ipfs/bitswap/1.1.0",
		"/ipfs/bitswap/1.2.0",
		"/ipfs/id/1.0.0",
		"/ipfs/id/push/1.0.0",
		"/ipfs/kad/1.0.0",
		"/ipfs/lan/kad/1.0.0",
		"/ipfs/ping/1.0.0",
		"/libp2p/autonat/1.0.0",
		"/libp2p/circuit/relay/0.1.0",
		"/p2p/id/delta/1.0.0",
		"/x/"
	]
}


```

## Libp2p

- eventbus - similar with dmesh internal bus. No deps. Emit(interface), Sub Out() channel, Subscribe to interface.
- webrtc-direct - browser-to-server without signaling servers !
- circuit
- conmgr - maintain min/max connections (muxed)
-

Others/interop:
- utp (bittorrent) transport - UDP based, QUIC more standard
- noise crypto
- discovery - mdns
- relay - a protocol for relay via other hots. 'HOP' option enables this host to allow others to proxy. Only to
IPFS nodes. Can listen on a relay address - AddRelayTransport() !
- http and gostream interfaces/wrappers. net.Conn == network.Stream
- daemon - run p2p, with a local API - good examples for 'api' style


# Noise

- generic library for P2P
- IPFS experimental feature to use Noise instead of their
custom protocol (secio) and TLS
- includes a Kademlia implementation
- includes a node messaging protocol
- clean interface
- IPFS seems a more complete solution - but larger

After an initial attempt, it doesn't seem very useful
compared with ipfs.

Kademlia handles routing table, finding nodes.
You send messages to each node, by public key.

- FindNodeRequest - return 16 close nodes for this node.
- track visited, search all nodes using buckets
-


# CJDNS

- IP6, DHT
- message path


# BATMAN

- L2 protocol
- kernel implementation, openwrt
- ALFRED for sharing a small file ( dhcp leases, etc )
-


# BMX7


# Slirp

TUN + capture, IP stack, like netstack.
