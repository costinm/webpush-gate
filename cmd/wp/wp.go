// Command line tool to generate VAPID keys and tokens
// The subscription can be provided as JSON, or as separate flags
// The message to be sent must be provided as stdin or 'msg'
// The VAPID key pair should be set as environment variables, not in commaond line.
package main

import (
	"bytes"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"os"

	"github.com/costinm/wpgate/pkg/auth"
	"github.com/costinm/wpgate/pkg/conf"
	"github.com/costinm/wpgate/pkg/h2"
)

var (
	// vapid  = flag.NewFlagSet("vapid", flag.ExitOnError)
	// sub = vapid.String("sub", "", "Optional email or URL identifying the sender")
	// vapid.Parse(os.Args[2:])

	to = flag.String("to", "", "Destination, if not set will print info. A VIP6 or known hostname")

	// Mesh: currently use .ssh/authorized_keys, known_hosts
	// Webpush: file under .ssh/webpush/NAME or TO. Inside
	sub = flag.String("sub", "",
		"Optional email or URL identifying the sender, to look up the subscription")

	aud  = flag.String("aud", "", "Generate a VAPID key with the given domain. Defaults to https://fcm.googleapis.com")
	curl = flag.Bool("curl", false, "Show curl request")

	dump      = flag.Bool("dump", false, "Dump id and authz")
	dumpKnown = flag.Bool("k", false, "Dump known hosts and keys")

	sendVerbose = flag.Bool("v", false, "Show request and response body")

	pushService = flag.String("server", "", "Base URL for the push service")
)

const (
	Subscription = "TO"
)

type Keys struct {
	P256dh string ``
	Auth   string ``
}

type Sub struct {
	Endpoint string ``
}

// Send the message.
func sendMessage(toS string, vapid *auth.Auth, show bool, msg string) {
	//msg, err := ioutil.ReadAll(os.Stdin)
	//if err != nil {
	//	fmt.Println("Failed to read message")
	//	os.Exit(3)
	//}

	destURL := ""
	var destPubK []byte
	var authk []byte

	// browser sub: real webpush
	wpSub := os.Getenv(Subscription)
	if len(wpSub) > 0 {
		to, err := auth.SubscriptionFromJSON([]byte(wpSub))
		if err != nil {
			fmt.Println("Invalid endpoint "+flag.Arg(1), err)
			os.Exit(3)
		}
		destURL = to.Endpoint
		destPubK = to.Key
		authk = to.Auth
	} else {
		subs := auth.Conf(vapid.Config, "sub_"+toS+".json", "")
		if subs != "" {
			to, err := auth.SubscriptionFromJSON([]byte(subs))
			if err != nil {
				fmt.Println("Invalid endpoint "+flag.Arg(1), err)
				os.Exit(3)
			}
			destURL = to.Endpoint
			destPubK = to.Key
			authk = to.Auth
			if len(authk) == 0 {
				authk = []byte{1}
			}
		} else {
			// DMesh nodes - we only have the public key, auth is not sent !
			az := vapid.Known[toS]
			if az == nil {
				az = vapid.Authz[toS]
			}
			if az == nil {
				log.Println("Not found ", toS)
				return
			}
			destPubK = az.Public
			vip := auth.Pub2VIP(destPubK).String()
			destURL = "https://[" + vip + "]:5228/push/"
			authk = []byte{1}
		}
	}
	var hc *http.Client

	if *pushService != "" {
		destURL = *pushService + "/push/"
		hc = h2.InsecureHttp()
	} else {
		hc = h2.NewSocksHttpClient("127.0.0.1:5224")
	}

	ec := auth.NewContextSend(destPubK, authk)
	c, _ := ec.Encrypt([]byte(msg))

	ah := vapid.VAPIDToken(destURL)

	if show {
		payload64 := base64.StdEncoding.EncodeToString(c)
		cmd := "echo -n " + payload64 + " | base64 -d > /tmp/$$.bin; curl -XPOST --data-binary @/tmp/$$.bin"
		cmd += " -proxy 127.0.0.1:5224"
		cmd += " -Httl:0"
		cmd += " -H\"authorization:" + ah + "\""
		fmt.Println(cmd + " " + destURL)

		return
	}

	req, _ := http.NewRequest("POST", destURL, bytes.NewBuffer(c))
	req.Header.Add("ttl", "0")
	req.Header.Add("authorization", ah)
	req.Header.Add("Content-Encoding", "aes128gcm")

	//hc := h2.ProxyHttp("127.0.0.1:5203")
	res, err := hc.Do(req)

	if res == nil {
		fmt.Println("Failed to send ", err)

	} else if err != nil {
		fmt.Println("Failed to send ", err)

	} else if res.StatusCode != 201 {
		//dmpReq, err := httputil.DumpRequest(req, true)
		//fmt.Printf(string(dmpReq))
		dmp, _ := httputil.DumpResponse(res, true)
		fmt.Println(string(dmp))
		fmt.Println("Failed to send ", err, res.StatusCode)

	} else if *sendVerbose {
		dmpReq, _ := httputil.DumpRequest(req, true)
		fmt.Printf(string(dmpReq))
		dmp, _ := httputil.DumpResponse(res, true)
		fmt.Printf(string(dmp))
	}
}

func main() {
	flag.Parse()

	// Using the SSH directory for keys and target.
	cfgDir := os.Getenv("HOME") + "/.ssh/"
	// File-based config
	config := conf.NewConf(cfgDir, "./var/lib/dmesh/")
	hn, _ := os.Hostname()

	authz := auth.NewAuth(config, hn, "m.webinf.info")

	if *dump {
		authz.Dump()
		return
	}
	if *dumpKnown {
		authz.DumpKnown()
		return
	}

	sendMessage(*to, authz, *curl, flag.Args()[0])
}
