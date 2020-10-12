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
	"github.com/costinm/wpgate/pkg/transport/httpproxy"
	"github.com/costinm/wpgate/pkg/transport/socks"
	sshgate "github.com/costinm/wpgate/pkg/transport/ssh"
	"github.com/costinm/wpgate/pkg/transport/websocket"
	"github.com/costinm/wpgate/pkg/transport/xds"
)

// Basic server, with only minimal core features:
// Ingress:
// - H2+GRPC server on 5228
// - SSH gateway (until equivalent H2 is available) on 5222
//
// Messages:
// - webpush
// - SSH transport
// - WSS transport
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

	GW := mesh.New(authz, nil)

	// Create the H2
	h2s, err := h2.NewTransport(authz)
	if err != nil {
		log.Fatal(err)
	}

	sshg := sshgate.NewSSHGate(GW, authz)
	sshg.ListenSSH(addr(bp, 22))
	// Set the ssh gate as default egress protocol
	// This will be used to maintain connections with VPN
	// and upstream servers.
	GW.SSHGate = sshg

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
	websocket.WSTransport(msgs.DefaultMux, sshg, h2s.MTLSMux)

	// Egress - SOCKS, HTTP
	s5, err := socks.Socks5Capture(laddr(bp, 24), GW)
	if err != nil {
		log.Print("Error: ", err)
	}
	log.Println("Start SOCKS, use -x socks5://" + s5.Listener.Addr().String())

	hgw := httpproxy.NewHTTPGate(GW, h2s)
	hgw.HttpProxyCapture(laddr(bp, 3))

	// Local DNS resolver. Can forward up, tracks requests
	dns, _ := dns.NewDmDns(bp + 23)
	dns.Start(h2s.MTLSMux)
	GW.DNS = dns

	if knativePort == "" {
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
