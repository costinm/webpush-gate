package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/costinm/wpgate/pkg/conf"
	"github.com/costinm/wpgate/pkg/mesh"
	"github.com/costinm/wpgate/pkg/msgs"
	"github.com/costinm/wpgate/pkg/transport/local"
	uds2 "github.com/costinm/wpgate/pkg/transport/uds"
)

// Full: all features. Has a UDS connection, similar with the Android package.
func main() {
	log.Print("Starting native process pwd=", os.Getenv("PWD"), os.Environ())
	bp := 5200
	base := os.Getenv("BASE_PORT")
	if base != "" {
		bp, _ = strconv.Atoi(base)
	}

	cfgDir := os.Getenv("HOME") + "/.ssh/"
	all := &ServerAll{
		ConfDir:  cfgDir,
		BasePort: bp,
	}
	StartAll(all)

	// Debug interface
	log.Println("Starting WPS server on ", all.BasePort)

	initUDSConnection(all.GW, all.Local, all.Conf)

	//// Periodic registrations.
	//m.Registry.RefreshNetworksPeriodic()

	http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", all.BasePort+HTTP_DEBUG), all.UI)
}

func initUDSConnection(gw *mesh.Gateway, ld *local.LLDiscovery, cfg *conf.Conf) {
	// Attempt to connect to local UDS socket, to communicate with android app.
	for i := 0; i < 5; i++ {
		ucon, err := uds2.Dial("dmesh", msgs.DefaultMux, map[string]string{})
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
