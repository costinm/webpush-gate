package main

import (
	"github.com/costinm/wpgate/pkg/transport/noise"
	"github.com/costinm/wpgate/pkg/transport/xds"
	"google.golang.org/grpc"
	"log"
	"net"
	"net/http"
	"os"
)

// WIP: Start a webpush server, exposing common transports.
// - 8080: gRPC
// - 8000: HTTP (debug)
// - 9000: noise (kadelmia)
func main() {
	s := grpc.NewServer()
	wp := &xds.GrpcService{}
	xds.RegisterAggregatedDiscoveryServiceServer(s, wp)

	addr := os.Getenv("PORT")
	if addr == "" {
		addr = "8080"
	}
	lis, err := net.Listen("tcp", ":"+addr)
	if err != nil {
		log.Fatal(err)
	}
	go s.Serve(lis)

	go noise.New()

	log.Println("Starting WPS server on 8001, hi4", addr)
	http.ListenAndServe("127.0.0.1:8000", nil)

}
