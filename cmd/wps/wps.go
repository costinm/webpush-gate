package main

import (
	"github.com/costinm/wpgate/pkg/xds"
	"google.golang.org/grpc"
	"log"
	"net"
	"net/http"
	"os"
)

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

	log.Println("Starting WPS server ", addr)
	http.ListenAndServe("127.0.0.1:8000", nil)

}
