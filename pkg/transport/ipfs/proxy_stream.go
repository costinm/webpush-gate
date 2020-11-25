package ipfs

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"strings"

	//"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
)

// Adds about 8 M to the binary size.

// The http proxy is based on the example - you can
// use the example as a local proxy. This will be the
// egress server.
// TODO: auth
const Protocol = "/proxy-example/0.0.1"

// streamHandler is our function to handle any libp2p-net streams that belong
// to our protocol. The streams should contain an HTTP request which we need
// to parse, make on behalf of the original node, and then write the response
// on the stream, before closing it.
func streamHandler(stream network.Stream) {
	// Remember to close the stream when we are done.
	defer stream.Close()

	log.Println("NEW STREAM: ", stream.Conn().RemotePeer(), stream.Conn().RemotePublicKey())

	// Create a new buffered reader, as ReadRequest needs one.
	// The buffered reader reads from our stream, on which we
	// have sent the HTTP request (see ServeHTTP())
	buf := bufio.NewReader(stream)
	// Read the HTTP request from the buffer
	req, err := http.ReadRequest(buf)
	if err != nil {
		stream.Reset()
		log.Println(err)
		return
	}
	defer req.Body.Close()

	// We need to reset these fields in the request
	// URL as they are not maintained.
	req.URL.Scheme = "http"
	hp := strings.Split(req.Host, ":")
	if len(hp) > 1 && hp[1] == "443" {
		req.URL.Scheme = "https"
	} else {
		req.URL.Scheme = "http"
	}
	req.URL.Host = req.Host

	outreq := new(http.Request)
	*outreq = *req

	if !strings.Contains(req.URL.Host, "google") {
		return
	}

	// We now make the request
	fmt.Printf("Making request to %s\n", req.URL)
	resp, err := http.DefaultTransport.RoundTrip(outreq)
	if err != nil {
		stream.Reset()
		log.Println(err)
		return
	}

	// resp.Write writes whatever response we obtained for our
	// request back to the stream.
	resp.Write(stream)
}
