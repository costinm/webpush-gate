module github.com/costinm/wpgate

go 1.16

// replace github.com/costinm/go-ws-transport => ../go-ws-transport
replace github.com/costinm/ugate => ../ugate

replace github.com/costinm/wpgate/cloudevents => ./cloudevents

replace github.com/costinm/wpgate/dns => ./dns

replace github.com/costinm/wpgate/ipfs => ./ipfs

require (
	cloud.google.com/go/pubsub v1.3.1
	github.com/cloudevents/sdk-go/protocol/pubsub/v2 v2.3.1
	github.com/cloudevents/sdk-go/v2 v2.3.1
	github.com/costinm/go-libp2p-h2-transport v0.0.0-20201214154101-77015f9e2b0c // indirect
	github.com/costinm/go-ws-transport v0.3.2-0.20201108210539-68fbbde6ea68 // indirect
	github.com/costinm/ugate v0.0.0-20201222193743-8b69aff0e277
	github.com/costinm/wpgate/dns v0.0.0-00010101000000-000000000000
	github.com/costinm/wpgate/ipfs v0.0.0-00010101000000-000000000000
	github.com/gogo/protobuf v1.3.1
	github.com/golang/protobuf v1.4.3
	github.com/golang/snappy v0.0.1 // indirect
	github.com/hsanjuan/ipfs-lite v1.1.17
	github.com/ipfs/go-cid v0.0.7
	github.com/ipfs/go-datastore v0.4.5
	github.com/ipfs/go-ipfs v0.7.0 // indirect
	github.com/libp2p/go-libp2p-core v0.7.0
	github.com/libp2p/go-libp2p-kad-dht v0.11.0 // indirect
	github.com/libp2p/go-libp2p-quic-transport v0.9.2 // indirect
	github.com/lucas-clemente/quic-go v0.19.2
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
	golang.org/x/net v0.0.0-20210226172049-e18ecbb05110
	golang.org/x/sys v0.0.0-20210220050731-9a76102bfb43
	google.golang.org/grpc v1.35.0
	google.golang.org/grpc/examples v0.0.0-20201212000604-81b95b1854d7 // indirect
	google.golang.org/protobuf v1.25.0
)
