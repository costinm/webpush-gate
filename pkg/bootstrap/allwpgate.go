package bootstrap

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/costinm/wpgate/pkg/auth"
	"github.com/costinm/wpgate/pkg/conf"
	"github.com/costinm/wpgate/pkg/dns"
	"github.com/costinm/wpgate/pkg/h2"
	"github.com/costinm/wpgate/pkg/mesh"
	"github.com/costinm/wpgate/pkg/msgs"
	"github.com/costinm/wpgate/pkg/transport/accept"
	"github.com/costinm/wpgate/pkg/transport/eventstream"
	"github.com/costinm/wpgate/pkg/transport/httpproxy"
	"github.com/costinm/wpgate/pkg/transport/ipfs"
	"github.com/costinm/wpgate/pkg/transport/iptables"
	"github.com/costinm/wpgate/pkg/transport/local"
	"github.com/costinm/wpgate/pkg/transport/sni"
	"github.com/costinm/wpgate/pkg/transport/socks"
	sshgate "github.com/costinm/wpgate/pkg/transport/ssh"
	"github.com/costinm/wpgate/pkg/transport/udp"
	"github.com/costinm/wpgate/pkg/transport/uds"
	"github.com/costinm/wpgate/pkg/transport/websocket"
	"github.com/costinm/wpgate/pkg/transport/xds"
	"github.com/costinm/wpgate/pkg/ui"
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

	//  sni based router - could be multiplexed on 443
	SNI = 25

	// ---- Other ports ----
	// XDS, etc - istiod port
	GRPC = 12

	// curl -x http://127.0.0.10.0.0.0:15003
	// can be added to 27/debug
	HTTP_PROXY = 3

	NOISE = 19

	// on H2 and HTTP_DEBUG
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
	UI     *ui.DMUI
	UDPNat *udp.UDPGate
	Local  *local.LLDiscovery
	Conf   *conf.Conf
	sshg   *sshgate.SSHGate
	IPFS   *ipfs.IPFS
}

func (sa *ServerAll) Close() {

}

func StartAll(a *ServerAll) {
	// File-based config
	config := conf.NewConf(a.ConfDir, "./var/lib/dmesh/")
	a.Conf = config

	// Init or load certificates/keys
	authz := auth.NewAuth(config, "", "m.webinf.info")
	authz.Dump()

	// Init Auth on the DefaultMux, for messaging
	msgs.DefaultMux.Auth = authz

	gcfg := &mesh.GateCfg{}
	err := conf.Get(config, "gate.json", gcfg)
	if err != nil {
		log.Println("Use default config ", err)
	} else {
		log.Println("Cfg: ", gcfg)
	}

	// HTTPGate - common structures
	a.GW = mesh.New(authz, gcfg)

	// Create the H2
	h2s, err := h2.NewTransport(authz)
	if err != nil {
		log.Fatal(err)
	}
	a.H2 = h2s

	// GRPC XDS transport
	wp := &xds.GrpcService{}
	xds.RegisterAggregatedDiscoveryServiceServer(h2s.GRPC, wp)

	// Experimental: noise transport
	// bring dep no compiling on arm
	//go noise.New(uint16(addrN + NOISE))

	// SSH transport + reverse streams.
	sshg := sshgate.NewSSHGate(a.GW, authz)
	a.sshg = sshg
	a.GW.SSHGate = sshg
	sshg.InitServer()
	sshg.ListenSSH(a.addr(SSH))

	// TODO: init socks on TLS, for inbound

	// Connect to a mesh node
	meshH := auth.Conf(config, "MESH", "v.webinf.info:5222")
	if meshH != "" && meshH != "OFF" {
		a.GW.Vpn = meshH
		go sshgate.MaintainVPNConnection(a.GW)
	}

	// Non-critical, for testing
	a.StartExtra()

	// Local discovery interface - multicast, local network IPs
	ld := local.NewLocal(a.GW, authz)
	local.ListenUDP(ld)
	go ld.PeriodicThread()
	local.ListenUDP(ld)
	a.Local = ld

	// Start a basic UI on the debug port
	a.UI, _ = ui.NewUI(a.GW, h2s, a.hgw, ld)

	a.StartMsg()

	a.H2.MTLSMux.HandleFunc("/push/", msgs.DefaultMux.HTTPHandlerWebpush)
	a.H2.MTLSMux.HandleFunc("/subscribe", msgs.SubscribeHandler)
	a.H2.MTLSMux.HandleFunc("/p/", eventstream.Handler(msgs.DefaultMux))
	h2s.InitMTLSServer(a.BasePort+H2, h2s.MTLSMux)
}

func (a *ServerAll) laddr(off int) string {
	return fmt.Sprintf("127.0.0.1:%d", a.BasePort+off)
}
func (a *ServerAll) addr(off int) string {
	return fmt.Sprintf("0.0.0.0:%d", a.BasePort+off)
}

func (a *ServerAll) StartMsg() {
	// TODO: list of sinks, add NATS in-process

	// TODO: eventstream client (MonitorNode)
	a.H2.LocalMux.HandleFunc("/s/", msgs.HTTPHandlerSend)

	// /ws - registered on the HTTPS server
	websocket.WSTransport(msgs.DefaultMux, a.sshg, a.H2.MTLSMux)

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

	s5, err := socks.Socks5Capture(a.laddr(SOCKS), a.GW)
	if err != nil {
		log.Print("Error: ", err)
	}
	log.Println("Start SOCKS, use -x socks5://" + s5.Listener.Addr().String())
	a.Socks5 = s5.Listener

	// Outbound capture using Istio config
	iptables.StartIstioCapture(a.GW, "127.0.0.1:15002")

	sniAddr := os.Getenv("SNI_ADDR")
	if sniAddr != "" {
		go sni.SniProxy(a.GW, sniAddr)
	}

	a.hgw = httpproxy.NewHTTPGate(a.GW, a.H2)
	a.hgw.HttpProxyCapture(a.laddr(HTTP_PROXY))

	// Local DNS resolver. Can forward up.
	dnss, err := dns.NewDmDns(a.BasePort + DNS)
	dnss.Start(a.H2.MTLSMux)
	a.GW.DNS = dnss

	// Explicit TCP forwarders.
	for _, t := range a.GW.Config.Listeners {
		accept.NewForwarder(a.GW, t)
	}

	udpNat := udp.NewUDPGate(a.GW)
	a.UDPNat = udpNat

	a.IPFS = ipfs.InitIPFS(a.GW.Auth, 5231, a.H2.MTLSMux)
	a.H2.LocalMux.Handle("/ipfs/", a.IPFS)
}

func ServerUDSConnection(gw *mesh.Gateway, ld *local.LLDiscovery, cfg *conf.Conf) {
	srv, err := uds.NewServer("lproxy", msgs.DefaultMux)
	if err != nil {
		log.Println("Can't start lproxy UDS", err)
		return
	}

	srv.Start()
}

func ClientUDSConnection(gw *mesh.Gateway, ld *local.LLDiscovery, cfg *conf.Conf) {
	// Attempt to connect to local UDS socket, to communicate with android app.
	for i := 0; i < 5; i++ {
		ucon, err := uds.Dial("dmesh", msgs.DefaultMux, map[string]string{})
		if err != nil {
			time.Sleep(1 * time.Second)
		} else {
			//lmnet.NewWifi(ld, &ucon.MsgConnection, ld)

			// Special messages:
			// - close - terminate program, java side dead
			// - KILL - explicit request to stop
			ucon.Handler = msgs.HandlerCallbackFunc(func(ctx context.Context, cmdS string, meta map[string]string, data []byte) {
			})
			go func() {
				for {
					ucon.HandleStream()
					// Connection closes if the android side is dead.
					// TODO: this is only for the UDS connection !!!
					log.Printf("UDS: parent closed, exiting ")
					os.Exit(4)
				}
			}()

			break
		}
	}
	log.Println("Failed to initialize UDS to root app")
}
