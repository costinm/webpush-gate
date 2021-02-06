package httpproxy

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/costinm/ugate"
	"github.com/costinm/wpgate/pkg/h2"
	"github.com/costinm/wpgate/pkg/mesh"
)

// Reverse proxy for HTTP requests.
//
// The request will be sent to target host via TCP-TUN (SSH or other transport).
// - A node can open a TCP accept port on a node with public IP
// - A HTTPGate/VPN may open 80/443 and terminate TLS, than forward via TCP-TUN
// - TODO: 443 can be forwarded using SNI sniffing
//
// Gateways terminates HTTP/HTTPS/QUIC, and forward to other hosts.

/*
Terms:
- Envoy: cluster
- Caddy: upstream - policy to select from a set
- Istio: ServiceEntry / DestinationPolicy

Typical params:
- retry interval, count
- list of hosts
- headers to add/remove
- keep alive
- timeouts
- health checks
- prefix path removal
- websocket (upstream headers Connection, Upgrade)
- transparent - X-Forwarded-Proto, X-Real-IP, Host
*/

// HTTPGate handles HTTP requests
type HTTPGate struct {
	// H2 used to create HttpClient with mesh credentials
	h2 *h2.H2

	//Auth *auth.Auth
	gw *mesh.Gateway
}

// ReverseForward a request to a normal HTTP host.
// Used if the Host header found is configured explicitly to forward to a specific address.
func (gw *HTTPGate) ForwardHTTP(w http.ResponseWriter, r *http.Request, pathH string) {
	r.Host = pathH
	r1, cancel := ugate.CreateUpstreamRequest(w, r)
	defer cancel()

	r1.URL.Scheme = "http"

	// will be used by RoundTrip.
	r1.URL.Host = pathH

	// can add more headers
	// can add headers to the response

	res, err := gw.h2.Client(r1.URL.Host).Transport.RoundTrip(r1)
	ugate.SendBackResponse(w, r, res, err)
}

// HTTP proxy.
// Host headers:
// - NODEID.dm -> forwarded to node, using connected client or parent.
// - configured host -> forwarded via HTTP/1.1 or H2, local named hosts
//func (gw *HTTPGate) Forward443(w http.ResponseWriter, r *http.Request) {
//	gw.proxy(w, r)
//}
//
//func (gw *HTTPGate) Forward80(w http.ResponseWriter, r *http.Request) {
//	gw.proxy(w, r)
//}

// Http proxy to a configured HTTP host. Hostname to HTTP address explicitly
// configured. Also hostnmae to file serving.
func (gw *HTTPGate) proxy(w http.ResponseWriter, r *http.Request) bool {
	// TODO: if host is XXXX.m.SUFFIX -> forward to node.

	host, found := gw.gw.Config.Hosts[r.Host]
	if !found {
		return false
	}
	if len(host.Addr) > 0 {
		log.Println("FWDHTTP: ", r.Method, r.Host, r.RemoteAddr, r.URL)
		gw.ForwardHTTP(w, r, host.Addr)
	}
	return true
}

// Mapped to /dm/[NODEID]/[NODEID]/HOST:PORT]/c/[REALPATH]. ReverseForward a GET via a full path.
// Will use the H2 ports of the node. This was used for debugging.
//
// Mapped to /dm/[NODEID]/[NODEID]/HOST:PORT]/d/[REALPATH]. Will create a direct path (circuit) using
// the nodes. Exit node will initiate a HTTP(s) connection
//
// Exposed only on the loopback interface.
func (gw *HTTPGate) HttpForwardPath(w http.ResponseWriter, r *http.Request) {
	newPath := r.Header.Get("x-dm-p")
	if newPath == "" {
		if newPathC, err := r.Cookie("x-dm-p"); err == nil {
			newPath = newPathC.Value
		}
	}
	if newPath == "" {
		newPath = r.RequestURI
	}
	oldPath := r.Header.Get("x-dm")

	next := strings.SplitN(newPath, "/", 32)

	if len(next) < 4 {
		w.WriteHeader(500)
		w.Write([]byte("Invalid prefix"))
		return
	}

	// NextHop should be a mesh node hex address. Will be added to the request we send
	nextHop := next[2]
	id, err := hex.DecodeString(nextHop)
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte("Invalid device ID"))
		return
	}
	//key := binary.BigEndian.Uint64(id)

	ip6 := make([]byte, 16)
	copy(ip6[8:], id)
	ip6[0] = 0xfd

	url := ""

	ht := &http.Transport{
		DialContext: gw.gw.DialContext,
	}
	hc := &http.Client{Transport: ht}

	if len(next) > 3 && next[3] == "c" {
		// Special case: accessing a URL on the next hop

		url = fmt.Sprintf("http://%s/%s",
			net.JoinHostPort(net.IP(ip6).String(), "5227"), strings.Join(next[4:], "/"))

	} else if nextHop == "c" {
		// Exit the mesh - remote is an external IP address
		// TODO: authenticate, don't allow local network or localhost unless admin-priv
		url = "127.0.0.1:5227/" + strings.Join(next[3:], "/")
		if strings.HasPrefix(url, "https:") {
			url = "https://" + url[6:]
		} else {
			url = "http://" + url
		}
		gw.ProxyHttp(gw.h2.Client(""), r, w, url, oldPath)
		return
	}

	// Connect to next mesh node using one of the discovered endpoint IPs.
	if len(oldPath) > 0 {
		oldPath += "/"
	}
	oldPath += nextHop

	// Continue
	if url == "" {
		url = "dm/" + strings.Join(next[3:], "/")
	}

	log.Println("HTTP-PROXY: next=" + url)
	gw.ProxyHttp(hc, r, w, url, oldPath)

	//w.WriteHeader(503)
	//w.Write([]byte("Invalid gateway"))
	return
}

func (gw *HTTPGate) HttpForwardPath2(w http.ResponseWriter, r *http.Request) {
	newPath := r.Header.Get("x-dm-p")
	if newPath == "" {
		if newPathC, err := r.Cookie("x-dm-p"); err == nil {
			newPath = newPathC.Value
		}
	}
	if newPath == "" {
		newPath = r.RequestURI
	}
	oldPath := r.Header.Get("x-dm")

	next := strings.SplitN(newPath, "/", 32)

	if len(next) < 4 {
		w.WriteHeader(500)
		w.Write([]byte("Invalid prefix"))
		return
	}

	// NextHop should be a mesh node hex address. Will be added to the request we send
	nextHop := next[2]
	id, err := hex.DecodeString(nextHop)
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte("Invalid device ID"))
		return
	}
	key := binary.BigEndian.Uint64(id)

	//if key == gw.Auth.VIP64 {
	//
	//}
	url := ""

	if len(next) > 3 && next[3] == "c" {
		// Special case: accessing a URL on the next hop

		url = "/dm" + strings.Join(next[3:], "/")

	} else if strings.Contains(nextHop, ":") || nextHop == "c" {
		// Exit the mesh - remote is an external IP address
		// TODO: authenticate, don't allow local network or localhost unless admin-priv

		url = nextHop + "/" + strings.Join(next[3:], "/")
		if nextHop == "c" {
			url = "127.0.0.1:5227/" + strings.Join(next[3:], "/")
		}
		if strings.HasPrefix(url, "https:") {
			url = "https://" + url[6:]
		} else {
			url = "http://" + url
		}
		gw.ProxyHttp(gw.h2.Client(""), r, w, url, oldPath)
		return
	}

	// Connect to next mesh node using one of the discovered endpoint IPs.
	if len(oldPath) > 0 {
		oldPath += "/"
	}
	oldPath += nextHop

	node, f := gw.gw.GetNodeByID(key)
	if !f {
		w.Header().Add("X-DM-ERR", "NF")
		w.WriteHeader(404)
		w.Write([]byte("Not found"))
		return
	}

	// Continue
	if url == "" {
		url = "dm/" + strings.Join(next[3:], "/")
	}

	gws := node.GWs()
	if gws != nil && len(gws) > 0 {
		for _, ip := range gws {
			oldPathIp := r.Header.Get("x-dm-ip")
			b := gw.DMNodeHttpRequestViaNeighbor(r, w, oldPath, oldPathIp, ip, url)
			if b == nil {
				return
			} else {
				// TODO: remove if next not found.
			}
		}
	} else if node.TunSrv != nil {
		// TODO:
	}

	w.WriteHeader(503)
	w.Write([]byte("Invalid gateway"))
	return
}

func BaseURL(gw *net.UDPAddr) string {
	if gw == nil {
		return ""
	}
	return "https://" + strings.Replace(gw.String(), "%", "%25", 1)
}

// ReverseForward the request to a DMESH host, using a neighbor address.
//
// path is either a URL on the destination host or a forward.
//
func (gw *HTTPGate) DMNodeHttpRequestViaNeighbor(or *http.Request, w http.ResponseWriter,
	oldPath, oldPathIp string,
	neighborLocalAddr *net.UDPAddr, path string) error {
	var nurl string

	if neighborLocalAddr.IP.To4() != nil {
		nurl = fmt.Sprintf("https://%s:%d/%s", neighborLocalAddr.IP, neighborLocalAddr.Port, path)
	} else if neighborLocalAddr.Zone == "" {
		nurl = fmt.Sprintf("https://[%s]:%d/%s", neighborLocalAddr.IP.String(), neighborLocalAddr.Port, path)
	} else {
		nurl = fmt.Sprintf("https://[%s%%25%s]:%d/%s", neighborLocalAddr.IP.String(), neighborLocalAddr.Zone, neighborLocalAddr.Port, path)
	}

	var r *http.Request
	var err error
	if or.Method == http.MethodGet || or.Method == http.MethodHead {
		r, err = http.NewRequest(or.Method, nurl, nil)
	} else {
		r, err = http.NewRequest(or.Method, nurl, or.Body)
	}
	r.Header.Add("x-dm", oldPath)
	r.Header.Add("x-dm-ip", oldPathIp+","+neighborLocalAddr.IP.String())

	cl := gw.h2.Client(r.URL.Host)
	res, err := cl.Do(r)
	if err != nil {
		h2.CleanQuic(cl)
		log.Println("HFWD-FAIL ", nurl, err)
		return err
	}

	ugate.SendBackResponse(w, r, res, err)
	log.Println("HFWD-VIA", nurl, oldPath, oldPathIp, res.StatusCode)

	return nil
}

func (gw *HTTPGate) ProxyHttp(cl *http.Client, or *http.Request, w http.ResponseWriter, nurl, oldPath string) error {

	var r *http.Request
	var err error
	if or.Method == http.MethodGet || or.Method == http.MethodHead {
		r, err = http.NewRequest(or.Method, nurl, nil)
	} else {
		r, err = http.NewRequest(or.Method, nurl, or.Body)
	}
	r.Header.Add("x-dm", oldPath)

	//cl := hc.Client(r.URL.Host)
	res, err := cl.Do(r)
	if err != nil {
		//transport.CleanQuic(cl)
		log.Println("HFWD-DIRECT-FAIL ", nurl, err)
		w.WriteHeader(500)
		//res.Status = err.Error()
		return err
	}

	ugate.SendBackResponse(w, r, res, err)
	log.Println("HFWD-DIRECT-OUT", nurl, oldPath, res.StatusCode)

	return nil
}

// See http.ProxyFromEnvironment(req) - using HTTP_PROXY, HTTPS_PROXY and NO_PROXY
// HTTPS_PROXY has precedence.
// HTTPGate URL can be http, https or socks5 scheme
