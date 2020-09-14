module github.com/costinm/wpgate

go 1.15

require (
	github.com/cloudevents/sdk-go v0.10.1
	github.com/gogo/protobuf v1.3.1
	github.com/hashicorp/consul v1.8.0
	github.com/hashicorp/golang-lru v0.5.3 // indirect
	github.com/lucas-clemente/quic-go v0.18.0
	//github.com/marten-seemann/qpack v0.1.0
	// Not compatible with latest go, must match
	github.com/marten-seemann/qtls v0.10.0
	github.com/miekg/dns v1.1.29
	github.com/mjibson/esc v0.2.0 // indirect
	github.com/nats-io/nats-server/v2 v2.0.0
	github.com/perlin-network/noise v1.1.2
	github.com/pkg/errors v0.9.1 // indirect
	github.com/zserge/metric v0.1.0
	go.opencensus.io v0.22.2
	go.uber.org/zap v1.13.0
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
	golang.org/x/lint v0.0.0-20200130185559-910be7a94367 // indirect
	golang.org/x/mod v0.3.0 // indirect
	golang.org/x/net v0.0.0-20200707034311-ab3426394381
	golang.org/x/sync v0.0.0-20190911185100-cd5d95a43a6e // indirect
	golang.org/x/sys v0.0.0-20200519105757-fe76b779f299
	golang.org/x/tools v0.0.0-20200626171337-aa94e735be7f // indirect
	google.golang.org/grpc v1.24.0
)
