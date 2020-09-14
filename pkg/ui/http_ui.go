package ui

import (
	"container/list"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/costinm/wpgate/pkg/conf"
	"github.com/costinm/wpgate/pkg/dns"
	"github.com/costinm/wpgate/pkg/h2"
	"github.com/costinm/wpgate/pkg/mesh"
	"github.com/costinm/wpgate/pkg/msgs"
	"github.com/costinm/wpgate/pkg/transport/eventstream"
	"github.com/costinm/wpgate/pkg/transport/httpproxy"
	"github.com/costinm/wpgate/pkg/transport/local"
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

	ld *local.LLDiscovery

	// Debug recent events
	mutex  sync.Mutex
	events *list.List
}

// Default handler - operating as main admin handlers, on localhost
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

	_, pattern = dm.h2.MTLSMux.Handler(r)
	if len(pattern) > 0 {
		dm.h2.MTLSMux.ServeHTTP(w, r)
		log.Println("SMHTTP: ", pattern, r.Method, r.Host, r.RemoteAddr, r.URL)
		return
	}

	dm.h2.LocalMux.ServeHTTP(w, r)
	log.Println("LMHTTP: ", pattern, r.Method, r.Host, r.RemoteAddr, r.URL)
}

func NewUI(dm *mesh.Gateway, h2 *h2.H2, hgate *httpproxy.HTTPGate, ld *local.LLDiscovery) (*DMUI, error) {
	dmui := &DMUI{
		dm:     dm,
		h2:     h2,
		ld:     ld,
		events: list.New(),
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

	h2.LocalMux.HandleFunc("/xtcp/", dmui.Merge("tcpall.html"))
	h2.LocalMux.HandleFunc("/peers", dmui.Merge("peers.html"))
	h2.LocalMux.HandleFunc("/events", dmui.Merge("events.html"))
	h2.LocalMux.HandleFunc("/status", dmui.Merge("status.html"))
	h2.LocalMux.HandleFunc("/wifi", dmui.Merge("wifi.html"))
	h2.LocalMux.HandleFunc("/active", dmui.Merge("active.html"))
	h2.LocalMux.HandleFunc("/info", dmui.Merge("info.html"))

	// Streaming message using 'eventstream' - mostly for UI
	// SSH, gRPC and websocket are better options
	h2.LocalMux.HandleFunc("/debug/eventss", eventstream.Handler(msgs.DefaultMux))
	if dmui.dm.DNS != nil {
		h2.LocalMux.HandleFunc("/dmesh/dns", dmui.dm.DNS.(*dns.DmDns).HttpDebugDNS)
	}

	h2.LocalMux.HandleFunc("/quitquitquit", QuitHandler)

	h2.LocalMux.HandleFunc("/dmesh/uds/", msgs.DefaultMux.HTTPUDS)

	// Saved event history
	h2.LocalMux.HandleFunc("/debug/eventslog", dmui.DebugEventsHandler)

	h2.LocalMux.Handle("/static/", http.FileServer(http.Dir("pkg/ui/www/")))

	mux.HandleFunc("/dmesh/tcpa", dmui.dm.HttpTCP)
	mux.HandleFunc("/dmesh/tcp", dmui.dm.HttpAllTCP)

	mux.HandleFunc("/dmesh/rd", dmui.HttpRefreshAndRegister)
	mux.HandleFunc("/dmesh/ip6", dmui.dm.HttpGetNodes)

	//mux.HandleFunc("/dmesh/rr", lm.HttpGetRoutes)
	if dmui.ld != nil {
		mux.HandleFunc("/dmesh/ll/if", dmui.ld.HttpGetLLIf)
	}

	h2.LocalMux.Handle("/debug/", http.DefaultServeMux)
	if hgate != nil {
		h2.LocalMux.HandleFunc("/dm/", hgate.HttpForwardPath)
		h2.LocalMux.HandleFunc("/dm2/", hgate.HttpForwardPath2)
	}

	h2.LocalMux.HandleFunc("/dmesh/rd", dmui.HttpRefreshAndRegister)
	h2.LocalMux.HandleFunc("/dmesh/ip6", dmui.HttpGetNodes)
	//h2.LocalMux.HandleFunc("/dmesh/rr", lm.HttpGetRoutes)
	h2.LocalMux.HandleFunc("/dmesh/ll/if", dmui.HttpGetLLIf)
	h2.LocalMux.Handle("/", http.FileServer(fs))

	msgs.DefaultMux.OnMessageForNode = append(msgs.DefaultMux.OnMessageForNode, dmui.onmessage)

	// Add handlers to the messaging serve mux.
	msgs.DefaultMux.ServeMux = h2.LocalMux
	return dmui, nil
}

// TODO: circular buffer, poll event, for debug
const EV_BUFFER = 200

func (lm *DMUI) onmessage(ev *msgs.Message) {
	if ev.To == "SYNC/LL" ||
		ev.To == "SYNC/LLSRV" {
		//log.Println("EV:", ev.Type, ev.Msg, ev.Meta)
		return
	}

	lm.mutex.Lock()
	lm.events.PushBack(ev)
	if lm.events.Len() > EV_BUFFER {
		lm.events.Remove(lm.events.Front())
	}
	lm.mutex.Unlock()
}

// Return the sticky and recent events.
func (lm *DMUI) DebugEventsHandler(w http.ResponseWriter, req *http.Request) {

	w.Write([]byte("["))
	for e := lm.events.Front(); e != nil; e = e.Next() {
		e := e
		ba := e.Value.(*msgs.Message).MarshalJSON()
		w.Write(ba)
		w.Write([]byte(",\n"))
	}
	w.Write([]byte("{}]"))
}

func (lm *DMUI) HttpGetLLIf(w http.ResponseWriter, r *http.Request) {
	if lm.ld == nil {
		return
	}
	lm.ld.RefreshNetworks()

	lm.dm.MeshMutex.Lock()
	defer lm.dm.MeshMutex.Unlock()
	je := json.NewEncoder(w)
	je.SetIndent(" ", " ")
	je.Encode(lm.ld.DirectActiveInterfaces)
}

// HttpGetNodes (/dmesh/ip6) returns the list of known nodes, both direct and indirect.
// This allows nodes to sync the mesh routing table.
func (lm *DMUI) HttpGetNodes(w http.ResponseWriter, r *http.Request) {
	lm.dm.MeshMutex.Lock()
	defer lm.dm.MeshMutex.Unlock()
	je := json.NewEncoder(w)
	je.SetIndent(" ", " ")
	je.Encode(lm.dm.Nodes)
}

// HttpRefreshAndRegister (/dmesh/rd) will initiate a multicast UDP, asking for local masters.
// After a small wait it'll return the list of peers. Debugging only.
func (lm *DMUI) HttpRefreshAndRegister(w http.ResponseWriter, r *http.Request) {
	if lm.ld == nil {
		return
	}
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
