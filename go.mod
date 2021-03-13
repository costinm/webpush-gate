module github.com/costinm/wpgate

go 1.16

// replace github.com/costinm/go-ws-transport => ../go-ws-transport
// replace github.com/costinm/ugate => ../ugate

//replace github.com/costinm/wpgate/cloudevents => ./cloudevents
//
//replace github.com/costinm/wpgate/dns => ./dns
//
//replace github.com/costinm/wpgate/ipfs => ./ipfs

require (
	github.com/costinm/ugate v0.0.0-20210221155556-10edd21fadbf
	github.com/gogo/protobuf v1.3.1
	github.com/golang/groupcache v0.0.0-20200121045136-8c9f03a8e57e // indirect
	github.com/golang/protobuf v1.4.3
	github.com/lucas-clemente/quic-go v0.19.3
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
	golang.org/x/sync v0.0.0-20200317015054-43a5402ce75a // indirect
	golang.org/x/sys v0.0.0-20210220050731-9a76102bfb43
	google.golang.org/genproto v0.0.0-20200806141610-86f49bd18e98 // indirect
	google.golang.org/grpc v1.35.0
	google.golang.org/protobuf v1.25.0
)
