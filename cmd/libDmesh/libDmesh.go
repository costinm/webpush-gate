package main

import (
	"encoding/base64"
	"log"
	"net/http"
	"os"

	"github.com/costinm/wpgate/pkg/auth"
	"github.com/costinm/wpgate/pkg/conf"
	"github.com/costinm/wpgate/pkg/h2"
	"github.com/costinm/wpgate/pkg/mesh"
	"github.com/costinm/wpgate/pkg/msgs"
	"github.com/costinm/wpgate/pkg/transport/httpproxy"
	"github.com/costinm/wpgate/pkg/transport/local"
	sshgate "github.com/costinm/wpgate/pkg/transport/ssh"
	"github.com/costinm/wpgate/pkg/ui"
)

func main() {
	log.Print("Starting native process pwd=", os.Getenv("PWD"))

	// SYSTEMSERVERCLASSPATH=/system/framework/services.jar:/system/framework/ethernet-service.jar:/system/framework/wifi-service.jar:/system/framework/com.android.location.provider.jar
	// PATH=/sbin:/system/sbin:/system/bin:/system/xbin:/odm/bin:/vendor/bin:/vendor/xbin
	// STORAGE=/storage/emulated/0/Android/data/com.github.costinm.dmwifi/files
	// ANDROID_DATA=/data
	// ANDROID_SOCKET_zygote_secondary=12
	// ASEC_MOUNTPOINT=/mnt/asec
	// EXTERNAL_STORAGE=/sdcard
	// ANDROID_BOOTLOGO=1
	// ANDROID_ASSETS=/system/app
	// BASE=/data/user/0/com.github.costinm.dmwifi/files
	// ANDROID_STORAGE=/storage
	// ANDROID_ROOT=/system
	// DOWNLOAD_CACHE=/data/cache
	// BOOTCLASSPATH=/system/framework/core-oj.jar:/system/framework/core-libart.jar:/system/framework/conscrypt.jar:/system/framework/okhttp.jar:/system/framework/bouncycastle.jar:/system/framework/apache-xml.jar:/system/framework/ext.jar:/system/framework/framework.jar:/system/framework/telephony-common.jar:/system/framework/voip-common.jar:/system/framework/ims-common.jar:/system/framework/android.hidl.base-V1.0-java.jar:/system/framework/android.hidl.manager-V1.0-java.jar:/system/framework/framework-oahl-backward-compatibility.jar:/system/framework/android.test.base.jar:/system/framework/com.google.vr.platform.jar]

	cfgf := os.Getenv("BASE")
	if cfgf == "" {
		cfgf = os.Getenv("HOME")
		if cfgf == "" {
			cfgf = os.Getenv("TEMPDIR")
		}
		if cfgf == "" {
			cfgf = os.Getenv("TMP")
		}
		if cfgf == "" {
			cfgf = "/tmp"
		}
	}

	cfgf += "/"

	// File-based config
	config := conf.NewConf(cfgf)

	meshH := auth.Conf(config, "MESH", "v.webinf.info:5222")

	// Init or load certificates/keys
	authz := auth.NewAuth(config, os.Getenv("HOSTNAME"), "v.webinf.info")
	authz.Dump()
	msgs.DefaultMux.Auth = authz

	// HTTPGate - common structures
	GW := mesh.New(authz, nil)

	// SSH transport + reverse streams.
	sshg := sshgate.NewSSHGate(GW, authz)
	GW.SSHGate = sshg
	sshg.InitServer()
	sshg.ListenSSH(":5222")

	// Connect to a mesh node
	if meshH != "" {
		GW.Vpn = meshH
		go sshgate.MaintainVPNConnection(GW)
	}

	// Local discovery interface - multicast, local network IPs
	ld := local.NewLocal(GW, authz)
	go ld.PeriodicThread()

	h2s, err := h2.NewTransport(authz)
	if err != nil {
		log.Fatal(err)
	}

	hgw := httpproxy.NewHTTPGate(GW, h2s)
	hgw.HttpProxyCapture("localhost:5204")

	// Start a basic UI on the debug port
	u, _ := ui.NewUI(GW, h2s, hgw, ld)

	//// Periodic registrations.
	//m.Registry.RefreshNetworksPeriodic()

	log.Printf("Loading with VIP6: %v ID64: %s %s\n", h2s.VIP6,
		base64.RawURLEncoding.EncodeToString(h2s.Certs.VIP6[8:]))

	http.ListenAndServe("localhost:5227", u)
}
