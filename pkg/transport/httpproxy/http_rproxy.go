package httpproxy

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/costinm/wpgate/pkg/auth"
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
	H2 h2.H2

	Auth *auth.Auth
	gw   *mesh.Gateway
}

// ReverseForward a request to a normal HTTP host.
// Used if the Host header found is configured explicitly to forward to a specific address.
func (gw *HTTPGate) ForwardHTTP(w http.ResponseWriter, r *http.Request, pathH string) {
	r.Host = pathH
	r1, cancel := createUpstreamRequest(w, r)
	defer cancel()

	r1.URL.Scheme = "http"

	// will be used by RoundTrip.
	r1.URL.Host = pathH

	// can add more headers
	// can add headers to the response

	res, err := gw.H2.HttpsClient.Transport.RoundTrip(r1)
	SendBackResponse(w, r, res, err)
}

// HTTP proxy.
// Host headers:
// - NODEID.dm -> forwarded to node, using connected client or parent.
// - configured host -> forwarded via HTTP/1.1 or H2, local named hosts
func (gw *HTTPGate) Forward443(w http.ResponseWriter, r *http.Request) {
	gw.proxy(w, r)
}

func (gw *HTTPGate) Forward80(w http.ResponseWriter, r *http.Request) {
	gw.proxy(w, r)
}

// Http proxy to a configured HTTP host. Hostname to HTTP address explicitly
// configured. Also hostnmae to file serving.
func (gw *HTTPGate) proxy(w http.ResponseWriter, r *http.Request) bool {
	// TODO: if host is XXXX.m.SUFFIX -> forward to node.

	host, found := gw.H2.Hosts[r.Host]
	if !found {
		return false
	}
	if len(host.Addr) > 0 {
		log.Println("FWDHTTP: ", r.Method, r.Host, r.RemoteAddr, r.URL)
		gw.ForwardHTTP(w, r, host.Addr)
	}
	if host.Dir != "" {
		if host.Mux == nil {
			host.Mux = http.FileServer(http.Dir(host.Dir))
		}
		host.Mux.ServeHTTP(w, r)
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
	key := binary.BigEndian.Uint64(id)

	ip6 := make([]byte, 16)
	copy(ip6[8:], id)
	ip6[0] = 0xfd

	//	newUrl := fmt.Sprintf("https://%v:%d/%s", ip6,)

	if key == gw.Auth.VIP64 {

	}
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
		gw.ProxyHttp(gw.H2.Client(""), r, w, url, oldPath)
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

	if key == gw.Auth.VIP64 {

	}
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
		gw.ProxyHttp(gw.H2.Client(""), r, w, url, oldPath)
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

// createUpstremRequest shallow-copies r into a new request
// that can be sent upstream.
//
// Derived from reverseproxy.go in the standard Go httputil package.
// Derived from caddy
func createUpstreamRequest(rw http.ResponseWriter, r *http.Request) (*http.Request, context.CancelFunc) {
	// Original incoming DmDns request may be canceled by the
	// user or by std lib(e.g. too many idle connections).
	ctx, cancel := context.WithCancel(r.Context())
	if cn, ok := rw.(http.CloseNotifier); ok {
		notifyChan := cn.CloseNotify()
		go func() {
			select {
			case <-notifyChan:
				cancel()
			case <-ctx.Done():
			}
		}()
	}

	outreq := r.WithContext(ctx) // includes shallow copies of maps, but okay

	// We should set body to nil explicitly if request body is empty.
	// For DmDns requests the Request Body is always non-nil.
	if r.ContentLength == 0 {
		outreq.Body = nil
	}

	// We are modifying the same underlying map from req (shallow
	// copied above) so we only copy it if necessary.
	copiedHeaders := false

	// Remove hop-by-hop headers listed in the "Connection" header.
	// See RFC 2616, section 14.10.
	if c := outreq.Header.Get("Connection"); c != "" {
		for _, f := range strings.Split(c, ",") {
			if f = strings.TrimSpace(f); f != "" {
				if !copiedHeaders {
					outreq.Header = make(http.Header)
					copyHeader(outreq.Header, r.Header)
					copiedHeaders = true
				}
				outreq.Header.Del(f)
			}
		}
	}

	// Remove hop-by-hop headers to the backend. Especially
	// important is "Connection" because we want a persistent
	// connection, regardless of what the client sent to us.
	for _, h := range hopHeaders {
		if outreq.Header.Get(h) != "" {
			if !copiedHeaders {
				outreq.Header = make(http.Header)
				copyHeader(outreq.Header, r.Header)
				copiedHeaders = true
			}
			outreq.Header.Del(h)
		}
	}

	if clientIP, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		// If we aren't the first proxy, retain prior
		// X-Forwarded-For information as a comma+space
		// separated list and fold multiple headers into one.
		if prior, ok := outreq.Header["X-Forwarded-For"]; ok {
			clientIP = strings.Join(prior, ", ") + ", " + clientIP
		}
		outreq.Header.Set("X-Forwarded-For", clientIP)
	}

	return outreq, cancel
}

// Hop-by-hop headers. These are removed when sent to the backend in createUpstreamRequest
// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
var hopHeaders = []string{
	"Alt-Svc",
	"Alternate-Protocol",
	"Connection",
	"Keep-Alive",
	"HTTPGate-Authenticate",
	"HTTPGate-Authorization",
	"HTTPGate-Connection", // non-standard but still sent by libcurl and rejected by e.g. google
	"Te",                  // canonicalized version of "TE"
	"Trailer",             // not Trailers per URL above; http://www.rfc-editor.org/errata_search.php?eid=4522
	"Transfer-Encoding",
	"Upgrade",
}

// used in createUpstreamRequetst to copy the headers to the new req.
func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		if _, ok := dst[k]; ok {
			// skip some predefined headers
			// see https://github.com/mholt/caddy/issues/1086
			if _, shouldSkip := skipHeaders[k]; shouldSkip {
				continue
			}
			// otherwise, overwrite to avoid duplicated fields that can be
			// problematic (see issue #1086) -- however, allow duplicate
			// Server fields so we can see the reality of the proxying.
			if k != "Server" {
				dst.Del(k)
			}
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// skip these headers if they already exist.
// see https://github.com/mholt/caddy/pull/1112#discussion_r80092582
var skipHeaders = map[string]struct{}{
	"Content-Type":        {},
	"Content-Disposition": {},
	"accept-Ranges":       {},
	"Set-Cookie":          {},
	"Cache-Control":       {},
	"Expires":             {},
}

// ------ End 'createUpstreamRequest' --------

// Used by both ForwardHTTP and ForwardMesh, after RoundTrip is done.
// Will copy response headers and body
func SendBackResponse(w http.ResponseWriter, r *http.Request,
	res *http.Response, err error) {

	if err != nil {
		if res != nil {
			CopyHeaders(w.Header(), res.Header)
			w.WriteHeader(res.StatusCode)
			io.Copy(w, res.Body)
			log.Println("Got ", err, res.Header)
		} else {
			http.Error(w, err.Error(), 500)
		}
		return
	}

	origBody := res.Body
	defer origBody.Close()

	CopyHeaders(w.Header(), res.Header)
	w.WriteHeader(res.StatusCode)

	stats := &mesh.Stream{}
	n, err := stats.CopyBuffered(w, res.Body, true)

	log.Println("Done: ", r.URL, res.StatusCode, n, err)
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

	cl := gw.H2.Client(r.URL.Host)
	res, err := cl.Do(r)
	if err != nil {
		h2.CleanQuic(cl)
		log.Println("HFWD-FAIL ", nurl, err)
		return err
	}

	SendBackResponse(w, r, res, err)
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

	SendBackResponse(w, r, res, err)
	log.Println("HFWD-DIRECT-OUT", nurl, oldPath, res.StatusCode)

	return nil
}

// See http.ProxyFromEnvironment(req) - using HTTP_PROXY, HTTPS_PROXY and NO_PROXY
// HTTPS_PROXY has precedence.
// HTTPGate URL can be http, https or socks5 scheme

// Also used in httpproxy_capture, for forward http proxy
func CopyHeaders(dst, src http.Header) {
	for k, _ := range dst {
		dst.Del(k)
	}
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}
