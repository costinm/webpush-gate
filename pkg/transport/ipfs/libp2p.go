// +build !IPFS !IPFSLITE

package ipfs

import (
	"context"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"fmt"

	"github.com/costinm/ugate/pkg/auth"
	"github.com/ipfs/go-datastore"

	config "github.com/ipfs/go-ipfs-config"

	"github.com/ipfs/go-ipns"

	"github.com/libp2p/go-libp2p"

	connmgr "github.com/libp2p/go-libp2p-connmgr"

	"github.com/libp2p/go-libp2p-core/control"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/event"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/routing"

	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p-kad-dht/dual"

	ws "github.com/costinm/go-libp2p-h2-transport"
	libp2pquic "github.com/libp2p/go-libp2p-quic-transport"

	record "github.com/libp2p/go-libp2p-record"
	libp2ptls "github.com/libp2p/go-libp2p-tls"
	"github.com/multiformats/go-multiaddr"
)

// ConnectionGater, Server
type IPFS struct {
	Host host.Host
	DHT  *dual.DHT
}

func (p2p *IPFS) InterceptPeerDial(p peer.ID) (allow bool) {
	log.Println("IPFS: peerDial", p)
	return true
}

func (p2p *IPFS) InterceptAddrDial(id peer.ID, m multiaddr.Multiaddr) (allow bool) {
	log.Println("IPFS: addrDial", id, m)
	return true
}

func (p2p *IPFS) InterceptAccept(multiaddrs network.ConnMultiaddrs) (allow bool) {
	t, _ := multiaddrs.RemoteMultiaddr().MarshalText()
	t1, _ := multiaddrs.LocalMultiaddr().MarshalText()
	log.Println("IPFS: accept", string(t), string(t1))
	return true
}

func (p2p *IPFS) InterceptSecured(direction network.Direction, id peer.ID, multiaddrs network.ConnMultiaddrs) (allow bool) {
	t, _ := multiaddrs.RemoteMultiaddr().MarshalText()
	log.Println("IPFS: secured", direction, id, string(t))
	return true
}

func (p2p *IPFS) InterceptUpgraded(conn network.Conn) (allow bool, reason control.DisconnectReason) {
	t, _ := conn.RemoteMultiaddr().MarshalText()
	log.Println("IPFS: secured", conn.RemotePeer(), string(t))
	return true, 0
}

func P2PAddrFromString(c string) (*peer.AddrInfo, error) {
	ma, err := multiaddr.NewMultiaddr(c)
	if err != nil {
		fmt.Printf("Error %v", err)
		return nil, err
	}
	//"/ip4/149.28.196.14/tcp/4001/p2p/12D3KooWLePVbQbv3PqsDZt6obMcWa99YyqRWjeiCtStSydQ6zjH"
	pi, err := peer.AddrInfoFromP2pAddr(ma)
	if err != nil {
		fmt.Printf("Error %v", err)
		return nil, err
	}
	return pi, nil
}

func (p2p *IPFS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	q := r.Form.Get("q")
	if q != "" {
		p2p.DHT.GetValue(context.Background(), q)
		return
	}
	h := p2p.Host

	c := r.Form.Get("c")
	if q != "" {
		//"/ip4/149.28.196.14/tcp/4001/p2p/12D3KooWLePVbQbv3PqsDZt6obMcWa99YyqRWjeiCtStSydQ6zjH"
		pi, err := P2PAddrFromString(c)
		if err != nil {
			return
		}
		err = h.Connect(context.Background(), *pi)
		if err != nil {
			fmt.Printf("Error %v", err)
			return
		}
		return
	}

	log.Println("Peers: ", h.Peerstore().Peers())
	for _, p := range h.Peerstore().Peers() {
		log.Println(h.Peerstore().PeerInfo(p))
	}

	log.Println("Conns: ", h.Network().Conns())
}

func InitIPFS(auth *auth.Auth, p2pport int, mux *http.ServeMux) *IPFS {
	p2p := &IPFS{}
	ctx := context.Background()

	// Bootstrappers are using 1024 keys. See:
	// https://github.com/ipfs/infra/issues/378
	crypto.MinRsaKeyBits = 1024

	//ds, err := ipfslite.BadgerDatastore("test")
	//if err != nil {
	//	panic(err)
	//}
	ds := datastore.NewMapDatastore()

	var sk crypto.PrivKey
	// Set your own keypair
	bif, err := auth.Config.Get("ipfs_pkey")
	if bif != nil {
		sk, err = crypto.UnmarshalPrivateKey(bif)
		if err != nil {
			log.Print(err)
		}

	} else {
		sk, _, _ := crypto.GenerateKeyPair(
			crypto.Ed25519, // Select your key type. Ed25519 are nice short
			-1,             // Select key length when possible (i.e. RSA).
		)
		b, _ := crypto.MarshalPrivateKey(sk)
		auth.Config.Set("ipfs_pkey", b)
	}

	la := []multiaddr.Multiaddr{}
	listen, _ := multiaddr.NewMultiaddr("/ip4/0.0.0.0/tcp/4004/ws")
	la = append(la, listen)
	listen, _ = multiaddr.NewMultiaddr("/ip6/::/tcp/4004/ws")
	la = append(la, listen)
	listen, _ = multiaddr.NewMultiaddr("/ip6/::/udp/4005/quic")
	la = append(la, listen)
	listen, _ = multiaddr.NewMultiaddr("/ip4/0.0.0.0/udp/4005/quic")
	la = append(la, listen)

	// TODO: set a ConnectionGater !
	// TODO: equivalent StreamGater ?
	// TODO: create a ssh proxy
	// TODO: SSH transport

	finalOpts := []libp2p.Option{
		libp2p.Identity(sk),
		libp2p.ListenAddrs(la...),
		libp2p.ChainOptions(
			libp2p.Transport(libp2pquic.NewTransport),
			libp2p.Transport(ws.NewH2Transport),
			//libp2p.Transport(ws.NewMux(mux, "/ipfs/ws/")),
		),

		// After adding ACL
		//libp2p.EnableAutoRelay(),
		//libp2p.DisableRelay(),
		libp2p.EnableRelay(), // no circuit.OptHop

		libp2p.NATPortMap(),
		//libp2p.PrivateNetwork(secret),

		libp2p.ConnectionManager(connmgr.NewConnManager(
			10,          // Lowwater
			20,          // HighWater,
			time.Minute, // GracePeriod
		)),

		// Used for the /ws/ transport - QUIC is 'capable', has own security
		// TODO: ssh over ws built in.
		// https://docs.libp2p.io/concepts/stream-multiplexing/#implementations
		// Defaults: mplex - no flow control
		// yamux - based on h2, but not the same. Problems closing. No JS.
		// spdystream - h2, has JS, based on docker/spdystream. Out of date, not core
		//
		//libp2p.Muxer("/yamux/1.0.0", yamux.DefaultTransport),
		// Default: noise, tls
		libp2p.Security(libp2ptls.ID, libp2ptls.New),


		libp2p.AddrsFactory(func(src []multiaddr.Multiaddr) []multiaddr.Multiaddr {
			res := []multiaddr.Multiaddr{}
			for _, s := range src {
				if strings.HasPrefix(s.String(), "/ip6/fd") {
					continue
				}
				if strings.HasPrefix(s.String(), "/ip4/10.") {
					continue
				}
				res = append(res, s)
			}
			return src
		}),
		libp2p.ConnectionGater(p2p),

		// Set the 'official' relays.
		// TODO: replace with 'root' as StaticRelay
		libp2p.DefaultStaticRelays(),
	}

	if os.Getenv("DHT") != "" {
		var ddht *dual.DHT
		finalOpts = append(finalOpts, libp2p.Routing(func(h host.Host) (routing.PeerRouting, error) {
			ddht, err = newDHT(ctx, h, ds)
			p2p.DHT = ddht
			return ddht, err
		}))
	} else {
		// In-memory peer store

		finalOpts = append(finalOpts, libp2p.DefaultPeerstore)
	}

	var pi *peer.AddrInfo
	if rt := os.Getenv("IPFS_ROOT"); rt != "" {
		pi, err = P2PAddrFromString(rt)
		if err != nil {
			log.Println("Invalid ", rt, err)
		} else {
			finalOpts = append(finalOpts, libp2p.StaticRelays([]peer.AddrInfo{*pi}))
		}
	}

	h, err := libp2p.New(
		ctx,
		finalOpts...,
	)
	p2p.Host = h

	if err != nil {
		panic(err)
	}

	ps := NewPeeringService(h)

	h.SetStreamHandler(Protocol, streamHandler)

	if false {
		cp, _ := config.DefaultBootstrapPeers()
		for _, addr := range cp {
			h.Connect(context.Background(), addr)
		}
	} else {
		if pi != nil {
			ps.AddPeer(*pi)

			err = h.Connect(context.Background(), *pi)
			if err != nil {
				log.Println("IPFS: Failed to connect to ", *pi)
			} else {
				log.Println("IPFS: Connected to ", *pi)
			}
		}
	}

	ps.Start()

	log.Println(h.EventBus().GetAllEventTypes())
	sub, err := h.EventBus().Subscribe(event.WildcardSubscription)
	go func() {
		defer sub.Close()
		for e := range sub.Out() {
			log.Println("IPFS Event: ", e)
		}

	}()

	log.Println("IPFS ID: ", h.ID().String())
	log.Println("IPFS Addr: ", h.Addrs())
	return p2p
}

func newDHT(ctx context.Context, h host.Host, ds datastore.Batching) (*dual.DHT, error) {
	dhtOpts := []dual.Option{
		dual.DHTOption(dht.NamespacedValidator("pk", record.PublicKeyValidator{})),
		dual.DHTOption(dht.NamespacedValidator("ipns", ipns.Validator{KeyBook: h.Peerstore()})),
		dual.DHTOption(dht.Concurrency(10)),
		dual.DHTOption(dht.Mode(dht.ModeAuto)),
	}
	if ds != nil {
		dhtOpts = append(dhtOpts, dual.DHTOption(dht.Datastore(ds)))
	}

	return dual.New(ctx, h, dhtOpts...)
}
