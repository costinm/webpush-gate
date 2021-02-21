module github.com/costinm/wpgate

go 1.16

// replace github.com/costinm/go-ws-transport => ../go-ws-transport
replace github.com/costinm/ugate => ../ugate

require (
	cloud.google.com/go v0.56.0
	cloud.google.com/go/pubsub v1.3.1
	github.com/cloudevents/sdk-go/protocol/pubsub/v2 v2.3.1
	github.com/cloudevents/sdk-go/v2 v2.3.1
	github.com/costinm/go-libp2p-h2-transport v0.0.0-20201214154101-77015f9e2b0c
	github.com/costinm/go-ws-transport v0.3.2-0.20201108210539-68fbbde6ea68
	github.com/costinm/ugate v0.0.0-20201222193743-8b69aff0e277
	github.com/gogo/protobuf v1.3.1
	github.com/golang/protobuf v1.4.3
	github.com/golang/snappy v0.0.1 // indirect
	github.com/hsanjuan/ipfs-lite v1.1.17
	github.com/ipfs/go-cid v0.0.7
	github.com/ipfs/go-datastore v0.4.5
	github.com/ipfs/go-ipfs v0.7.0
	github.com/ipfs/go-ipfs-config v0.10.0
	github.com/ipfs/go-ipfs-files v0.0.8
	github.com/ipfs/go-ipns v0.0.2
	github.com/ipfs/go-log v1.0.4
	github.com/ipfs/interface-go-ipfs-core v0.4.0
	github.com/libp2p/go-libp2p v0.12.0
	github.com/libp2p/go-libp2p-blankhost v0.2.0
	github.com/libp2p/go-libp2p-connmgr v0.2.4
	github.com/libp2p/go-libp2p-core v0.7.0
	github.com/libp2p/go-libp2p-kad-dht v0.11.0
	github.com/libp2p/go-libp2p-peerstore v0.2.6
	github.com/libp2p/go-libp2p-quic-transport v0.9.2
	github.com/libp2p/go-libp2p-record v0.1.3
	github.com/libp2p/go-libp2p-swarm v0.3.1
	github.com/libp2p/go-libp2p-tls v0.1.3
	github.com/lucas-clemente/quic-go v0.19.2
	github.com/miekg/dns v1.1.31
	github.com/multiformats/go-multiaddr v0.3.1
	github.com/pion/datachannel v1.4.21
	github.com/pion/logging v0.2.2
	github.com/pion/sctp v1.7.11
	github.com/pion/stun v0.3.5
	github.com/pion/turn/v2 v2.0.5
	github.com/pion/webrtc/v3 v3.0.8
	github.com/zserge/metric v0.1.0
	go.opencensus.io v0.22.5
	golang.org/x/crypto v0.0.0-20201221181555-eec23a3978ad
	golang.org/x/net v0.0.0-20210119194325-5f4716e94777
	golang.org/x/sys v0.0.0-20201201145000-ef89a241ccb3
	google.golang.org/api v0.24.0
	google.golang.org/genproto v0.0.0-20200806141610-86f49bd18e98
	google.golang.org/grpc v1.34.0
	google.golang.org/grpc/examples v0.0.0-20201212000604-81b95b1854d7 // indirect
	google.golang.org/protobuf v1.25.0
)
