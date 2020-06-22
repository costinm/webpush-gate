package bootstrap

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/costinm/wpgate/pkg/auth"
	"github.com/costinm/wpgate/pkg/conf"
	"github.com/costinm/wpgate/pkg/dns"
	"github.com/costinm/wpgate/pkg/mesh"
	"github.com/costinm/wpgate/pkg/msgs"
	"github.com/costinm/wpgate/pkg/transport/accept"
	"github.com/costinm/wpgate/pkg/transport/cloudevents"
	"github.com/costinm/wpgate/pkg/transport/noise"
	"github.com/costinm/wpgate/pkg/transport/sni"
	"github.com/costinm/wpgate/pkg/transport/socks"
	sshgate "github.com/costinm/wpgate/pkg/transport/ssh"
	"github.com/costinm/wpgate/pkg/transport/websocket"
	"github.com/costinm/wpgate/pkg/transport/xds"
	"google.golang.org/grpc"
)

// bootstrap loads all the components of wpgate together
// Used for tests and full-functional binary.
// Mostly boilerplate - functions can be copied to standalone
// binaries for smaller footprint and reduce functionality.

var (
	GRPC = 12

	SOCKS        = 4
	SSH          = 22
	NOISE        = 19
	CLOUD_EVENTS = 21
	HTTP_DEBUG   = 20

	DNS = 13
)

// A set of transport and servers, and associated ports/settings.
type AllWPGate struct {
	BasePort int
	ConfDir  string

	GW *mesh.Gateway

	Socks5 net.Listener
}

func StartAll(a *AllWPGate) {
	config := conf.NewConf(a.ConfDir)

	addrN := auth.ConfInt(config, "PORT", 15000)
	meshH := auth.Conf(config, "MESH", "v.webinf.info:5222")

	// Init or load certificates/keys
	authz := auth.NewAuth(config, os.Getenv("HOSTNAME"), "")

	// Gateway - common structures
	a.GW = mesh.New(authz, nil)

	// GRPC XDS transport
	s := grpc.NewServer()
	wp := &xds.GrpcService{}
	xds.RegisterAggregatedDiscoveryServiceServer(s, wp)

	// Server GRPC
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", addrN+GRPC))
	if err != nil {
		log.Fatal(err)
	}
	go s.Serve(lis)

	// Experimental: noise transport
	go noise.New(uint16(addrN + NOISE))

	// SSH transport + reverse streams.
	sshg := sshgate.NewSSHGate(a.GW, authz)
	a.GW.SSHGate = sshg
	sshg.InitServer()
	sshg.ListenSSH(a.addr(SSH))

	// Init SOCKS - on localhost, for outbound

	// TODO: init socks on TLS, for inbound

	// Connect to a mesh node
	if meshH != "" {
		a.GW.Vpn = meshH
		go sshgate.MaintainVPNConnection(a.GW)
	}

	// Non-critical, for testing
	a.StartExtra()

	a.StartMsg()
}

func (a *AllWPGate) laddr(off int) string {
	return fmt.Sprintf("127.0.0.1:%d", a.BasePort+off)
}
func (a *AllWPGate) addr(off int) string {
	return fmt.Sprintf("0.0.0.0:%d", a.BasePort+off)
}

func (a *AllWPGate) StartMsg() {
	// Server - accept from other sources
	cloudevents.NewCloudEvents(msgs.DefaultMux, a.BasePort+CLOUD_EVENTS)
	// TODO: list of sinks, add NATS in-process

	// TODO: eventstream client (MonitorNode)

	msgs.DefaultMux.AddHandler(mesh.TopicConnectUP, msgs.HandlerCallbackFunc(func(ctx context.Context, cmdS string, meta map[string]string, data []byte) {
		log.Println(cmdS, meta, data)
	}))

	msgs.DefaultMux.AddHandler("net", msgs.HandlerCallbackFunc(func(ctx context.Context, cmdS string, meta map[string]string, data []byte) {
		// net/status
		log.Println(cmdS, meta, data)
	}))
}

func (a *AllWPGate) StartExtra() {
	var err error
	// accept: used for SSH -R

	s5, err := socks.Socks5Capture(a.addr(SOCKS), a.GW)
	if err != nil {
		log.Print("Error: ", err)
	}
	log.Println("Start SOCKS, use -x socks5://" + s5.Listener.Addr().String())
	a.Socks5 = s5.Listener

	go sni.SniProxy(a.GW, a.addr(7))

	// Local DNS resolver. Can forward up.
	dns, err := dns.NewDmDns(a.BasePort + DNS)
	go dns.Serve()
	a.GW.DNS = dns

	for _, t := range a.GW.Config.Listeners {
		accept.NewForwarder(a.GW, t)
	}

	// TODO: also on h2s
	websocket.WSTransport(msgs.DefaultMux, http.DefaultServeMux)

}
