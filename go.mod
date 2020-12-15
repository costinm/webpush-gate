module github.com/costinm/wpgate

go 1.15

// replace github.com/costinm/go-ws-transport => ../go-ws-transport

require (
	github.com/costinm/go-ws-transport v0.3.2-0.20201108210539-68fbbde6ea68
	github.com/gogo/protobuf v1.3.1
	github.com/golang/protobuf v1.4.3
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
	github.com/perlin-network/noise v1.1.3
	github.com/soheilhy/cmux v0.1.4
	github.com/zserge/metric v0.1.0
	go.opencensus.io v0.22.5
	go.uber.org/zap v1.16.0
	golang.org/x/crypto v0.0.0-20200820211705-5c72a883971a
	golang.org/x/net v0.0.0-20201110031124-69a78807bb2b
	golang.org/x/sys v0.0.0-20201201145000-ef89a241ccb3
	google.golang.org/grpc v1.34.0
	google.golang.org/grpc/examples v0.0.0-20201212000604-81b95b1854d7 // indirect
	google.golang.org/protobuf v1.25.0
)
