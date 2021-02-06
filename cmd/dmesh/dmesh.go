package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/costinm/wpgate/pkg/bootstrap"
)

// Full: all features. Has a UDS connection, similar with the Android package.
func main() {
	log.Print("Starting native process pwd=", os.Getenv("PWD"))
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

	go bootstrap.ClientUDSConnection(all.GW, all.Conf)
	go bootstrap.ServerUDSConnection(all.GW, all.Conf)

	//// Periodic registrations.
	//m.Registry.RefreshNetworksPeriodic()

	http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", all.BasePort+bootstrap.HTTP_DEBUG), all.UI)
}

