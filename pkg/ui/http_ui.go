package ui

import (
	"encoding/hex"
	"encoding/json"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/costinm/wpgate/pkg/conf"
	"github.com/costinm/wpgate/pkg/dns"
	"github.com/costinm/wpgate/pkg/h2"
	"github.com/costinm/wpgate/pkg/mesh"
	"github.com/costinm/wpgate/pkg/msgs"
	"github.com/costinm/wpgate/pkg/transport/eventstream"
	"github.com/costinm/wpgate/pkg/transport/httpproxy"
	"github.com/costinm/wpgate/pkg/transport/local"
	"golang.org/x/net/websocket"
)

// curl -v http://s6.webinf.info:5227/status
// curl -v http://s6.webinf.info:5227/debug/vars
// curl -v http://s6.webinf.info:5227/debug/pprof

// UI and admin interface.
// Exposed via localhost only.
// TODO: add a random password and cookie
type DMUI struct {
	dm *mesh.Gateway
	h2 *h2.H2

	ws  *websocket.Server
	ld  *local.LLDiscovery
}

// Default handler - operating as main admin handlers.
//
// Host headers:
// - NODEID.dm -> forwarded to node, using connected client or parent.
// - configured host -> forwarded via HTTP/1.1 or H2, local named hosts
func (dm *DMUI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// TODO: authenticate first, either localhost (for proxy) or JWT/clientcert
	// TODO: split localhost to different method ?

	_, pattern := http.DefaultServeMux.Handler(r)
	if len(pattern) > 0 {
		log.Println("DHTTP: ", r.Method, r.Host, r.RemoteAddr, r.URL)
		http.DefaultServeMux.ServeHTTP(w, r)
		return
	}

	_, pattern = dm.h2.LocalMux.Handler(r)
	if len(pattern) > 0 {
		dm.h2.LocalMux.ServeHTTP(w, r)
		log.Println("LMHTTP: ", pattern, r.Method, r.Host, r.RemoteAddr, r.URL)
		return
	}

	_, pattern = dm.h2.MTLSMux.Handler(r)
	if len(pattern) > 0 {
		dm.h2.MTLSMux.ServeHTTP(w, r)
		log.Println("SMHTTP: ", pattern, r.Method, r.Host, r.RemoteAddr, r.URL)
		return
	}

	dm.h2.LocalMux.ServeHTTP(w, r)
}

func NewUI(dm *mesh.Gateway, h2 *h2.H2, hgate *httpproxy.HTTPGate, ld *local.LLDiscovery) (*DMUI, error) {
	dmui := &DMUI{
		dm: dm,
		h2: h2,
		ld: ld,
	}

	var err error
	var fs http.FileSystem

	f := "/status.html"
	_, err = FSString(true, f)
	if err == nil {
		fs = FS(true)
	} else {
		fs = FS(false)
	}

	//dm.Registry.InitHttp(dm.H2.MTLSMux)
	//dm.Registry.InitHttpAdm(dm.H2.LocalMux)

	for _, mux := range []*http.ServeMux{h2.LocalMux} {
		mux.HandleFunc("/xtcp/", dmui.Merge("tcpall.html"))
		mux.HandleFunc("/peers", dmui.Merge("peers.html"))
		mux.HandleFunc("/events", dmui.Merge("events.html"))
		mux.HandleFunc("/status", dmui.Merge("status.html"))
		mux.HandleFunc("/wifi", dmui.Merge("wifi.html"))
		mux.HandleFunc("/active", dmui.Merge("active.html"))
		mux.HandleFunc("/info", dmui.Merge("info.html"))

		mux.HandleFunc("/quitquitquit", QuitHandler)

		//		mux.HandleFunc("/debug/scan", dm.Wifi.JsonScan)
		//		mux.HandleFunc("/wifi/con", dm.Wifi.HTTPCon)

		mux.HandleFunc("/dmesh/uds/", msgs.DefaultMux.HTTPUDS)
		if dmui.dm.DNS != nil {
			mux.HandleFunc("/dmesh/dns", dmui.dm.DNS.(*dns.DmDns).HttpDebugDNS)
		}
		mux.HandleFunc("/debug/eventslog", msgs.DebugEventsHandler)
		mux.HandleFunc("/debug/eventss", eventstream.Handler(msgs.DefaultMux))

		mux.Handle("/static/", http.FileServer(http.Dir("pkg/ui/www/")))

		mux.Handle("/debug/", http.DefaultServeMux)
		mux.HandleFunc("/dm/", hgate.HttpForwardPath)
		mux.HandleFunc("/dm2/", hgate.HttpForwardPath2)

		mux.HandleFunc("/dmesh/tcpa", dmui.dm.HttpTCP)
		mux.HandleFunc("/dmesh/tcp", dmui.dm.HttpAllTCP)

		mux.HandleFunc("/dmesh/rd", dmui.HttpRefreshAndRegister)
		mux.HandleFunc("/dmesh/ip6", dmui.dm.HttpGetNodes)

		//mux.HandleFunc("/dmesh/rr", lm.HttpGetRoutes)
		if dmui.ld != nil {
			mux.HandleFunc("/dmesh/ll/if", dmui.ld.HttpGetLLIf)
		}
	}

	h2.LocalMux.Handle("/", http.FileServer(fs))
	return dmui, nil
}

// HttpRefreshAndRegister (/dmesh/rd) will initiate a multicast UDP, asking for local masters.
// After a small wait it'll return the list of peers. Debugging only.
func (lm *DMUI) HttpRefreshAndRegister(w http.ResponseWriter, r *http.Request) {
	lm.ld.RefreshNetworks()
	lm.ld.AnnounceMulticast()

	time.Sleep(5000 * time.Millisecond)

	lm.dm.HttpNodesFilter(w, r)
}

// TODO: authentication (random generated from java or local, auth=, cookie)
// TODO: handlers need to be on the admin interface as well, with admin mtls auth
// TODO: subset of handlers for status ( not all )
// TODO: use separate admin mux
// TODO: remove dep on dm

func QuitHandler(writer http.ResponseWriter, request *http.Request) {
	os.Exit(0)
}

func NodeID(n *mesh.DMNode) string {
	return hex.EncodeToString(n.VIP[8:])
}
func IP6(n *mesh.DMNode) net.IP {
	return n.VIP
}
func ToJson(n interface{}) string {
	bytes, _ := json.MarshalIndent(n, "", "  ")
	return string(bytes)
}
func Since(n time.Time) string {
	d := time.Since(n)
	return d.String()
}

// Render a template s.
// Will merge a base.html template first.
func (ui *DMUI) Merge(s string) func(http.ResponseWriter, *http.Request) {
	return func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Add("Content-Type", "text/html")

		tmpl := template.New(s).Funcs(template.FuncMap{
			"IP6":    IP6,
			"NodeID": NodeID,
			"ToJson": ToJson,
			"Since":  Since,
			//"ScanStatus": ui.dm.Wifi.ScanStatus,
		})
		tmplTxt := readTemplate("/base.html")
		tmplTxt += readTemplate("/" + s)

		t, err := tmpl.Parse(tmplTxt)
		if err != nil {
			log.Println("failed to set template", err)
			return
		}

		tmpl = t
		xp := request.Header.Get("x-dm")
		if xp != "" {
			xp = xp + "/"
		}

		conf := ui.dm.Auth.Config.(*conf.Conf)

		err = tmpl.ExecuteTemplate(writer, s, struct {
			Local *local.LLDiscovery
			Conf  map[string]string
			GW    *mesh.Gateway
			H2    *h2.H2
			Req   *http.Request
			XPath string
		}{Local: ui.ld,
			GW:    ui.dm,
			H2:    ui.h2,
			Conf:  conf.Conf,
			Req:   request,
			XPath: xp,
		})
		if err != nil {
			log.Println("failed to run template ", tmpl, err)
		}

		//writer.Write(f)
		writer.Write([]byte("</body></html>"))
	}
}

func readTemplate(f string) string {
	status_htmls, err := FSString(true, f)
	if err != nil {
		status_htmls, _ = FSString(false, f)
	}
	return status_htmls
}
