package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/costinm/wpgate/pkg/auth"
	"github.com/costinm/wpgate/pkg/conf"
	"github.com/costinm/wpgate/pkg/mesh"
	"github.com/costinm/wpgate/pkg/transport/noise"
	sshgate "github.com/costinm/wpgate/pkg/transport/ssh"
	"github.com/costinm/wpgate/pkg/transport/xds"
	"google.golang.org/grpc"
)

// WIP: Start a webpush/messaging gateway server, exposing common transports.
// - 9000: noise (kadelmia)
// - 9001: gRPC - XDS, etc
// - 9002: SSH
// - 9003: H2S
// - 9004: HTTP (debug, local)
func main() {
	cfgDir := os.Getenv("HOME") + "/.ssh/"
	config := conf.NewConf(cfgDir)

	addrN := auth.ConfInt(config, "PORT", 9000)
	meshH := auth.Conf(config, "MESH", "v.webinf.info:5222")

	// Init or load certificates/keys
	authz := auth.NewAuth(config, os.Getenv("HOSTNAME"), "")

	// Gateway - common structures
	gw := mesh.New(authz, nil)

	// GRPC XDS transport
	s := grpc.NewServer()
	wp := &xds.GrpcService{}
	xds.RegisterAggregatedDiscoveryServiceServer(s, wp)

	// Server GRPC
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", addrN+1))
	if err != nil {
		log.Fatal(err)
	}
	go s.Serve(lis)

	// Experimental: noise transport
	go noise.New(uint16(addrN))

	// SSH transport + reverse streams.
	sshg := sshgate.NewSSHGate(gw, authz)
	gw.SSHGate = sshg
	sshg.InitServer()
	sshg.ListenSSH("")

	// Connect to a mesh node
	if meshH != "" {
		gw.Vpn = meshH
		go sshgate.MaintainVPNConnection(gw)
	}

	// Debug interface
	log.Println("Starting WPS server on ", addrN)
	http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", addrN+4), nil)
}
