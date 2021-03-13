package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/costinm/ugate"
	"github.com/costinm/ugate/pkg/auth"
	"github.com/costinm/ugate/pkg/msgs"
	"github.com/costinm/ugate/pkg/udp"
	"github.com/costinm/ugate/pkg/uds/uds"
	ugates "github.com/costinm/ugate/pkg/ugatesvc"
	"github.com/costinm/wpgate/dns"
	"github.com/costinm/wpgate/pkg/h2"
	"github.com/costinm/wpgate/pkg/mesh"
	"github.com/costinm/wpgate/pkg/transport/eventstream"
	"github.com/costinm/wpgate/pkg/transport/httpproxy"
	sshgate "github.com/costinm/wpgate/pkg/transport/ssh"
	"github.com/costinm/wpgate/pkg/transport/websocket"
	"github.com/costinm/wpgate/pkg/transport/xds"
	"github.com/costinm/wpgate/pkg/ui"
	rtc2 "github.com/costinm/wpgate/rtc"
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

	hgw    *httpproxy.HTTPGate
	H2     *h2.H2

	// UI interface Handler for localhost:5227
	UI     *ui.DMUI
	UDPNat *udp.UDPGate
	Conf   ugate.ConfStore
	sshg   *sshgate.SSHGate
}

func (sa *ServerAll) Close() {

}

func StartAll(a *ServerAll) {
	// File-based config
	config := ugates.NewConf(a.ConfDir, "./var/lib/dmesh/")
	a.Conf = config

	cfg := &ugate.GateCfg{
		BasePort: 15000,
		Domain: "h.webinf.info",
	}
	data, err := config.Get("ugate.json")
	if err == nil && data != nil {
		err = json.Unmarshal(data, cfg)
		if err != nil {
			log.Println("Error parsing json ", err, string(data))
		}
	}

	authz := auth.NewAuth(config, cfg.Name, cfg.Domain)
	// By default, pass through using net.Dialer
	ug := ugates.NewGate(&net.Dialer{}, authz, cfg, nil)


	// Init Auth on the DefaultMux, for messaging
	msgs.DefaultMux.Auth = authz

	// HTTPGate - common structures
	a.GW = mesh.New(authz, cfg)
	a.GW.UGate = ug

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
	meshH := ugate.ConfStr(config,"MESH", "v.webinf.info:5222")
	if meshH != "" && meshH != "OFF" {
		a.GW.Vpn = meshH
		go sshgate.MaintainVPNConnection(a.GW)
	}

	// Non-critical, for testing
	a.StartExtra()

	//// Local discovery interface - multicast, local network IPs
	//ld := local.NewLocal(a.GW, authz)
	//local.ListenUDP(ld)
	//go ld.PeriodicThread()
	//local.ListenUDP(ld)
	//a.Local = ld

	// Start a basic UI on the debug port
	a.UI, _ = ui.NewUI(a.GW, h2s, a.hgw)

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
	websocket.WSTransport(msgs.DefaultMux, a.H2.MTLSMux)

	msgs.DefaultMux.AddHandler(mesh.TopicConnectUP, msgs.HandlerCallbackFunc(func(ctx context.Context, cmdS string, meta map[string]string, data []byte) {
		log.Println(cmdS, meta, data)
	}))

	msgs.DefaultMux.AddHandler("net", msgs.HandlerCallbackFunc(func(ctx context.Context, cmdS string, meta map[string]string, data []byte) {
		// net/status
		log.Println(cmdS, meta, data)
	}))
}

func (a *ServerAll) StartExtra() {
	a.hgw = httpproxy.NewHTTPGate(a.GW, a.H2)
	a.hgw.HttpProxyCapture(a.laddr(HTTP_PROXY))

	// Local DNS resolver. Can forward up.
	dnss, _ := dns.NewDmDns(a.BasePort + DNS)
	dnss.Start(a.H2.MTLSMux)
	a.GW.DNS = dnss


	udpNat := udp.NewUDPGate(dnss, dnss)
	a.UDPNat = udpNat

	rtcg := &rtc2.RTC{
		UGate: a.GW.UGate,
	}

	a.GW.UGate.Mux.HandleFunc("/wrtc/direct/", rtcg.RTCDirectHandler)
}

func ServerUDSConnection(gw *mesh.Gateway, cfg ugate.ConfStore) {
	srv, err := uds.NewServer("lproxy", msgs.DefaultMux)
	if err != nil {
		log.Println("Can't start lproxy UDS", err)
		return
	}

	go srv.Start()
}

func ClientUDSConnection(gw *mesh.Gateway, cfg ugate.ConfStore) {
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
