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
	"github.com/costinm/wpgate/pkg/h2"
	"github.com/costinm/wpgate/pkg/mesh"
	"github.com/costinm/wpgate/pkg/msgs"
	"github.com/costinm/wpgate/pkg/transport/accept"
	"github.com/costinm/wpgate/pkg/transport/cloudevents"
	"github.com/costinm/wpgate/pkg/transport/eventstream"
	"github.com/costinm/wpgate/pkg/transport/httpproxy"
	"github.com/costinm/wpgate/pkg/transport/iptables"
	"github.com/costinm/wpgate/pkg/transport/local"
	"github.com/costinm/wpgate/pkg/transport/sni"
	"github.com/costinm/wpgate/pkg/transport/socks"
	sshgate "github.com/costinm/wpgate/pkg/transport/ssh"
	"github.com/costinm/wpgate/pkg/transport/websocket"
	"github.com/costinm/wpgate/pkg/transport/xds"
	"github.com/costinm/wpgate/pkg/ui"
	"google.golang.org/grpc"
)

// bootstrap loads all the components of wpgate together
// Used for tests and full-functional binary.
// Mostly boilerplate - functions can be copied to standalone
// binaries for smaller footprint and reduce functionality.

var (
	// Port range: (22...28)

	// External exposed ports

	// Primary port for H2/H3/HTTPS
	// - gRPC
	// - message receive - CloudEvents style
	// - Jump host
	// - accept host
	H2 = 28

	// Jump Gate - temp (goal is to use H2)
	SSH = 22

	// Localhost bound ports

	// local debug :5227
	// - local capture for HTTP proxy
	// - "/m/VIP/" is a forward proxy to other mesh hosts
	// - message send (no auth required, will add creds)
	HTTP_DEBUG = 27

	// DNS server - local capture
	DNS = 23

	//  -x socks5://127.0.0.1:5224
	SOCKS = 24

	// ---- Other pors ----
	// XDS, etc - istiod port
	GRPC = 12

	// curl -x http://127.0.0.10.0.0.0:15003
	HTTP_PROXY = 3

	NOISE        = 19
	CLOUD_EVENTS = 21

	// ISTIO ports - base 15000

	ISTIO_ADMIN = 0

	ISTIO_OUTBOUND = 1

	ISTIO_D = 12

	ISTIO_STATS_ENVOY = 20
	ISTIO_HEALTHZ     = 21
	ISTIO_STATS       = 90
)

// A set of transport and servers, and associated ports/settings.
type ServerAll struct {
	BasePort int
	ConfDir  string

	GW *mesh.Gateway

	Socks5 net.Listener
	hgw    *httpproxy.HTTPGate
	H2     *h2.H2

	// UI interface Handler for localhost:5227
	UI *ui.DMUI
}

func (sa *ServerAll) Close() {

}

func StartAll(a *ServerAll) {
	// File-based config
	config := conf.NewConf(a.ConfDir, "./var/lib/dmesh/")

	// Default matching Istio range.
	addrN := a.BasePort
	meshH := auth.Conf(config, "MESH", "v.webinf.info:5222")

	// Init or load certificates/keys
	hn, _ := os.Hostname()
	authz := auth.NewAuth(config, hn, "m.webinf.info")
	msgs.DefaultMux.Auth = authz

	gcfg := &mesh.GateCfg{}
	conf.Get(config, "gate.json", gcfg)

	// HTTPGate - common structures
	a.GW = mesh.New(authz, gcfg)

	h2s, err := h2.NewTransport(authz)
	if err != nil {
		log.Fatal(err)
	}
	a.H2 = h2s

	// GRPC XDS transport
	s := grpc.NewServer()
	wp := &xds.GrpcService{}
	xds.RegisterAggregatedDiscoveryServiceServer(s, wp)

	// ServerAll GRPC
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", addrN+GRPC))
	if err != nil {
		log.Fatal(err)
	}
	go s.Serve(lis)

	// Experimental: noise transport
	// bring dep no compiling on arm
	//go noise.New(uint16(addrN + NOISE))

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
	a.StartDebug()

	// Local discovery interface - multicast, local network IPs
	ld := local.NewLocal(a.GW, authz)
	go ld.PeriodicThread()

	// Start a basic UI on the debug port
	a.UI, _ = ui.NewUI(a.GW, h2s, a.hgw, ld)

	a.StartMsg()

	h2s.InitMTLSServer(a.BasePort+H2, h2s.MTLSMux)
}

func (a *ServerAll) laddr(off int) string {
	return fmt.Sprintf("127.0.0.1:%d", a.BasePort+off)
}
func (a *ServerAll) addr(off int) string {
	return fmt.Sprintf("0.0.0.0:%d", a.BasePort+off)
}

func (a *ServerAll) StartDebug() {
	mux := http.DefaultServeMux

	mux.HandleFunc("/debug/eventss", eventstream.Handler(msgs.DefaultMux))
}

func (a *ServerAll) StartMsg() {
	// ServerAll - accept from other sources
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

func (a *ServerAll) StartExtra() {
	var err error
	// accept: used for SSH -R

	s5, err := socks.Socks5Capture(a.addr(SOCKS), a.GW)
	if err != nil {
		log.Print("Error: ", err)
	}
	log.Println("Start SOCKS, use -x socks5://" + s5.Listener.Addr().String())
	a.Socks5 = s5.Listener

	// Outbound capture using Istio config
	iptables.StartIstioCapture(a.GW, "127.0.0.1:15002")

	go sni.SniProxy(a.GW, a.addr(7))

	a.hgw = httpproxy.NewHTTPGate(a.GW, a.H2)
	a.hgw.HttpProxyCapture(a.laddr(HTTP_PROXY))

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
