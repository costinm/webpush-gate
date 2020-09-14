package h2

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Helpers for using H2/H3 clients

// Return a http.Client configured for the host.
func (h2 *H2) Client(host string) *http.Client {
	if strings.Contains(host, "/") {
		parts := strings.Split(host, "/")
		if len(parts) > 2 {
			host = parts[2] // http(0)/(1)/HOST(2)/...
		}
	}

	return h2.httpsClient
}

// Returns a HTTP client using SOCKS gateway on the requested
// port.
func SocksHttp(socksAddr string) *http.Client {
	// Configure a hcSocks http client using localhost SOCKS
	socksProxy, _ := url.Parse("socks5://" + socksAddr)
	return &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(socksProxy),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
}

func InsecureHttp() *http.Client {
	return &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
}

// NewSocksHttpClient returns a new client using SOCKS5 server.
func NewSocksHttpClient(socksAddr string) *http.Client {
	if socksAddr == "" {
		socksAddr = "127.0.0.1:15004"
	}
	//os.Setenv("HTTP_PROXY", "socks5://"+socks5Addr)
	// Localhost is not accepted by environment.
	//hc := &http.Client{Transport: &http.Transport{Gateway: http.ProxyFromEnvironment}}

	// Configure a hcSocks http client using localhost SOCKS
	socksProxy, _ := url.Parse("socks5://" + socksAddr)
	return &http.Client{
		Timeout: 15 * time.Minute,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(socksProxy),
			//TLSClientConfig: &tls.Config{
			//	InsecureSkipVerify: true,
			//},
		},
	}
}


// Returns a HTTP client using HTTP PROXY and CONNECT
func ProxyHttp(addr string) *http.Client {
	// Configure a HTTP CONNECT client to be used against the clientGW
	proxyUrl, _ := url.Parse("http://" + addr)
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			Proxy: http.ProxyURL(proxyUrl),
		},
	}
}
