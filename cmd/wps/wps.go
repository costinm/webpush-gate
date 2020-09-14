package main

import (
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/costinm/wpgate/pkg/auth"
	"github.com/costinm/wpgate/pkg/conf"
	"github.com/costinm/wpgate/pkg/dns"
	"github.com/costinm/wpgate/pkg/h2"
	"github.com/costinm/wpgate/pkg/mesh"
	"github.com/costinm/wpgate/pkg/msgs"
	"github.com/costinm/wpgate/pkg/transport/accept"
	"github.com/costinm/wpgate/pkg/transport/httpproxy"
	"github.com/costinm/wpgate/pkg/transport/sni"
	"github.com/costinm/wpgate/pkg/transport/socks"
	sshgate "github.com/costinm/wpgate/pkg/transport/ssh"
	"github.com/costinm/wpgate/pkg/transport/websocket"
	"github.com/costinm/wpgate/pkg/transport/xds"
)

// Basic server, with core features:
// Ingress:
// - H2+GRPC server on 5228
// - SSH gateway (until equivalent H2 is available) on 5222
//
// Messages:
// - webpush
// - SSH transport
//
// For egress:
// - socks
// - local http proxy
func main() {
	// Set if running in a knative env.
	knativePort := os.Getenv("PORT")

	bp := 5200
	base := os.Getenv("BASE_PORT")
	if base != "" {
		bp, _ = strconv.Atoi(base)
	}

	cfgDir := os.Getenv("HOME") + "/.ssh/"

	// File-based config, load identity and auth
	config := conf.NewConf(cfgDir, "./var/lib/dmesh/")

	authz := auth.NewAuth(config, "", "m.webinf.info")
	authz.Dump()
	// Init Auth on the DefaultMux, for messaging
	msgs.DefaultMux.Auth = authz

	// Create the gate
	gcfg := &mesh.GateCfg{}
	err := conf.Get(config, "gate.json", gcfg)
	if err != nil {
		log.Println("Use default config ", err)
	} else {
		log.Println("Cfg: ", gcfg)
	}
	GW := mesh.New(authz, gcfg)

	// Create the H2
	h2s, err := h2.NewTransport(authz)
	if err != nil {
		log.Fatal(err)
	}

	sshg := sshgate.NewSSHGate(GW, authz)
	GW.SSHGate = sshg
	sshg.InitServer()
	sshg.ListenSSH(addr(bp, 22))

	// Connect to a mesh node
	// - will accept reverse connections
	// - will send mesh connections
	// - messaging
	meshH := auth.Conf(config, "MESH", "v.webinf.info:5222")
	if meshH != "" && meshH != "OFF" {
		GW.Vpn = meshH
		go sshgate.MaintainVPNConnection(GW)
	}

	// HTTPS server - grpc, messaging.
	wp := &xds.GrpcService{}
	xds.RegisterAggregatedDiscoveryServiceServer(h2s.GRPC, wp)
	h2s.MTLSMux.HandleFunc("/push/", msgs.DefaultMux.HTTPHandlerWebpush)
	h2s.MTLSMux.HandleFunc("/subscribe", msgs.SubscribeHandler)

	// Messages and streams over websocket - HTTP/1.1 compatible
	websocket.WSTransport(msgs.DefaultMux, h2s.MTLSMux)

	// Egress - SOCKS, HTTP and
	s5, err := socks.Socks5Capture(laddr(bp, 24), GW)
	if err != nil {
		log.Print("Error: ", err)
	}
	log.Println("Start SOCKS, use -x socks5://" + s5.Listener.Addr().String())

	hgw := httpproxy.NewHTTPGate(GW, h2s)
	hgw.HttpProxyCapture(laddr(bp, 3))

	//// Local DNS resolver. Can forward up.
	dns, _ := dns.NewDmDns(bp + 23)
	go dns.Serve()

	GW.DNS = dns

	if knativePort == "" {
		//UI, _ := ui.NewUI(GW, h2s, nil, nil)
		//http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", bp+27), UI)

		// Ingress with SNI sniffing. Anyone can connect to reach mesh nodes
		// or explicit configured destinations. Typically exposed on 443.
		sniAddr := os.Getenv("SNI_ADDR")
		if sniAddr != "" {
			go sni.SniProxy(GW, sniAddr)
		}
		// TODO: same, on port 80

		for _, t := range GW.Config.Listeners {
			accept.NewForwarder(GW, t)
		}
		h2s.InitMTLSServer(bp+28, h2s.MTLSMux)
	} else {
		h2s.InitPlaintext(":" + knativePort)
	}

	select {}
}

func addr(bp, off int) string {
	return fmt.Sprintf("0.0.0.0:%d", bp+off)
}
func laddr(bp, off int) string {
	return fmt.Sprintf("127.0.0.1:%d", bp+off)
}
