// +build IPFSLITE

package ipfslite

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/costinm/wpgate/pkg/auth"
	ipfslite "github.com/hsanjuan/ipfs-lite"
	"github.com/ipfs/go-cid"
	"github.com/ipfs/go-datastore"
	crypto "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/multiformats/go-multiaddr"
)

type IPFS struct {
	Host host.Host
}

func (*IPFS) Close() {

}

func InitIPFS(auth *auth.Auth, p2pport int) *IPFS {
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

	listen, _ := multiaddr.NewMultiaddr("/ip6/::/tcp/4005")

	h, dht, err := ipfslite.SetupLibp2p(
		ctx,
		sk,
		nil,
		[]multiaddr.Multiaddr{listen},
		ds,
		ipfslite.Libp2pOptionsExtra...,
	)

	if err != nil {
		panic(err)
	}

	lite, err := ipfslite.New(ctx, ds, h, dht, nil)
	if err != nil {
		panic(err)
	}

	lite.Bootstrap(ipfslite.DefaultBootstrapPeers())

	c, _ := cid.Decode("QmWATWQ7fVPP2EFGu71UkfnqhYXDYH566qy47CnJDgvs8u")
	rsc, err := lite.GetFile(ctx, c)
	if err != nil {
		panic(err)
	}
	content, err := ioutil.ReadAll(rsc)
	if err != nil {
		panic(err)
	}
	rsc.Close()

	fmt.Println(string(content))
	return p2p
}
