package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/costinm/wpgate/pkg/bootstrap"
)

// WIP: Start a webpush/messaging gateway server, exposing common transports.
// - 9000: noise (kadelmia)
// - 9001: gRPC - XDS, etc
// - 9002: SSH
// - 9003: H2S
// - 9004: HTTP (debug, local)
func main() {
	bp := 5200
	base := os.Getenv("BASE_PORT")
	if base != "" {
		bp, _ = strconv.Atoi(base)
	}

	cfgDir := os.Getenv("HOME") + "/.ssh/"
	all := &bootstrap.ServerAll{
		ConfDir:  cfgDir,
		BasePort: bp,
	}
	bootstrap.StartAll(all)

	// Debug interface
	log.Println("Starting WPS server on ", all.BasePort)

	http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", all.BasePort+bootstrap.HTTP_DEBUG), all.UI)
}
