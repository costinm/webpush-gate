package auth

import (
	"bytes"
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
)

// Support for ID and authn using certificates.
//
// 1. load or generate a 'primary' key pair.
// 2. load or generate a self signed certificates. Save if generated.
// 3. use the cert to sign, verify signed messages
// 4. basic authorization using a ssh-style config (to reuse authorized_keys info), with role extensions
//
// The same identity is used for both SSH and TLS.
//
// Currently the 'primary' key is EC256 - mainly for Webpush integration and to simplify the code.
//
// TODO: add rsa - mainly for Istio and dropbear
// TODO: add ed for IoT/arduino
// TODO: root CA support - if the node is a VPN master, sign keys for members.
//
// SSH config is broadly used and convenient for interop with ssh servers/clients ( and to not invent
// a new thing ). Alternatives are more complex.
//
//
type Auth struct {
	// If set, will attempt to load the key and certs from storage, and save the generated ones.
	// Config is a simple interface for blob storage.
	Config ConfStore

	// Name and domain to include in the self-signed cert.
	Name   string
	Domain string

	// Primary VIP, Created from the Pub key, will be included in the self-signed cert.
	VIP6 net.IP
	// Same as VIP6, but as uint64
	VIP64 uint64

	// Certificates associated with this node.
	tlsCerts []tls.Certificate

	// Primary public key of the node.
	// EC256: 65 bytes, uncompressed format
	// RSA: DER
	// ED25519: 32B
	Pub []byte

	// Private key to use in both server and client authentication. This is the base of the VIP of the node.
	// ED22519: 32B
	// EC256: 32
	// RSA: DER
	Priv []byte

	// Primary private keys.
	EC256PrivateKey *ecdsa.PrivateKey

	// Secondary private keys.
	RSAPrivate *rsa.PrivateKey
	EDPrivate  *ed25519.PrivateKey

	// List of authorized keys and roles, for minimal Authz.
	// Key is the string(marshalled_form). For example EC256 it's a byte[65]
	// Value is list of roles for the key.
	Authorized map[string]string

	// TODO: Root certificates to trust, keyed by domain.
	Roots map[string]*Root
}

type Root struct {
	hosts []string
}

// SSH certificates:
//
//ssh-keygen -t rsa -N '' -C 'ca' -f ca
// -N'' - no pass
// -C - comment
// Out: ca, ca.pub
//
// Client cert:
//   ssh-keygen -s ca -I test@dmesh id_rsa.pub
// Server cert:
//   ssh-keygen -s ca -h -I test.dmesh /etc/host/ssh_host_ecdsa_key.pub
// -h == host
// -I hostname
// Out: id_cert.pub
//
// ssh-keygen -L: display cert
//
// Serial, Valid, Principals, Ext, CriticalOpts, keyId
// Ext: permit pty, x11, port, user-rc
//
// .authorized:
// .known-hosts:
// @cert-authority *.dmesh.com ssh-rsa AAAA.. ca@...
//
// echo "TrustedUserCAKeys /etc/ssh/ca.pub" >> /etc/ssh/sshd_config

var (
	Curve256 = elliptic.P256()
)

// Base64-encoded prefix for SSH EC256 keys. Followed by the STD encoding of the B64 key
// 0 0 0 19 : 101 99 100 115 97 45 115 104 97 50 45 110 105 115 116 112 50 53 54 ; "ecdsa-sha2-nistp256"
// 0 0 0 8 : 110 105 115 116 112 50 53 54; "nistp256"
// 0 0 0 65 :
const SSH_ECPREFIX = "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABB"

// ConfStore abstracts config and secret storage.
type ConfStore interface {
	Get(name string) ([]byte, error)

	// keys used: ec-key.pem ec-cert.pem id_ecdsa.pub authorized_keys.save
	Set(conf string, data []byte) error
}

// Initialize the certificates, loading or generating them.
// If cfg is nil, will generate certs but not save.
//
func NewAuth(cfg ConfStore, name, domain string) *Auth {

	certs := &Auth{
		Config:     cfg,
		Domain:     domain,
		Name:       name,
		Authorized: map[string]string{},
	}

	var err error
	if cfg != nil {
		err = certs.loadCert()
	}
	if cfg == nil || err != nil || certs.EC256PrivateKey == nil {
		// Can't load the certs - generate new ones.
		certs.generateCert()
	}

	pub64 := base64.StdEncoding.EncodeToString(certs.Pub)
	certs.VIP64 = certs.NodeIDUInt()
	// Based on the primary EC256 key
	log.Println("VIP: ", certs.VIP6)
	log.Println("ID: ", base64.URLEncoding.EncodeToString(certs.NodeID()), hex.EncodeToString(certs.NodeID()), certs.NodeIDUInt())
	log.Println("PUB(std): ", pub64)
	sshPub := "ecdsa-sha2-nistp256 " + SSH_ECPREFIX + pub64 + " " + certs.Name + "@" + certs.Domain
	log.Println("PUB(SSH): ", sshPub)

	if cfg != nil {
		certs.loadKnownHosts()
		certs.loadAuth()
	}

	return certs
}

// Add or update an identity (key) with a set of permissions (roles).
// This is extending the SSH, by using the comment field as a list of roles, starting with the
// user identity.
func (certs *Auth) AddAuthorized(key interface{}, role string) {
	var keyb []byte
	if oub, ok := key.([]byte); ok {
		keyb = oub
	}

	if cp2, ok := key.(crypto.PublicKey); ok {
		oub := KeyBytes(cp2)
		key = oub
	}

	certs.Authorized[string(keyb)] = role

	// TODO: write back authorized file !!!
	bw := bytes.Buffer{}
	for k, v := range certs.Authorized {
		kb := []byte(k)
		if len(kb) == 65 {
			bw.WriteString("ecdsa-sha2-nistp256 " + base64.StdEncoding.EncodeToString(kb) + " " + v)
		}
	}

	certs.Config.Set("authorized_keys.save", bw.Bytes())
}

// Check if an identity is authorized for the role.
// The key is in the marshalled format - use KeyBytes to convert a crypto.PublicKey.
//
func (c *Auth) Auth(key []byte, role string) string {
	roles := c.Authorized[string(key)]

	return roles
}

func (c *Auth) loadKnownHosts() error {
	//
	// [h.webinf.info]:2022,[67.174.240.198]:2022 ecdsa-sha2-nistp256 AAAA...
	//  markers (optional), hostnames, keytype, base64-encoded key, comment

	authB := bytes.Buffer{}
	auth, err := c.Config.Get(".ssh/known_hosts")
	if err == nil {
		authB.Write(auth)
		authB.WriteByte('\n')
	}

	auth = authB.Bytes()
	for len(auth) > 0 {
		marker, _, pubKey, comment, rest, err := ssh.ParseKnownHosts(auth)
		if err != nil {
			return err
		}
		auth = rest

		if marker == "@cert-authority" {
			// hosts should start with *.DOMAIN

		}

		if cpk, ok := pubKey.(ssh.CryptoPublicKey); ok {
			pubk := cpk.CryptoPublicKey()
			kbytes := KeyBytes(pubk)
			if kbytes != nil {
				//if len(opts) > 0 && opts[0] == ""
				c.Authorized[string(kbytes)] = comment
				//log.Println("SSH HAUTH: ", pubKey.Type(), marker, hosts, comment, base64.StdEncoding.EncodeToString(kbytes))
				continue
			}

			continue
		} else {
			log.Println("SSH UNKNOWN ", pubKey.Type())
		}

	}

	return nil
}

// Load the authorization data.
//
// Currently using SSH formats: the original used ssh protocol and it's useful to work with existing
// ssh servers.
//
// authorized_keys is used to load KEY -> roles, using the comment field to store the roles.
// (TODO: use the options command, for locked-down accounts)
//
//
// Called at startup (and possibly refresh).
func (c *Auth) loadAuth() error {
	// TODO: load known_hosts as well

	authB := bytes.Buffer{}
	auth, err := c.Config.Get("authorized_keys")
	if err == nil {
		authB.Write(auth)
		authB.WriteByte('\n')
	}

	auth, err = c.Config.Get(".ssh/authorized_keys")
	if err == nil {
		authB.Write(auth)
		authB.WriteByte('\n')
	}

	auth, err = c.Config.Get("authorized_keys.save")
	if err == nil {
		authB.Write(auth)
		authB.WriteByte('\n')
	}

	// options:
	// SSH_ORIGINAL_COMMAND as env variable
	// no-pty,command="/usr/local/bin/dmesh"
	//
	auth = authB.Bytes()
	for len(auth) > 0 {
		pubKey, comment, opts, rest, err := ssh.ParseAuthorizedKey(auth)
		if err != nil {
			break
		}
		auth = rest

		if cpk, ok := pubKey.(ssh.CryptoPublicKey); ok {
			pubk := cpk.CryptoPublicKey()
			kbytes := KeyBytes(pubk)
			if kbytes != nil {
				//if len(opts) > 0 && opts[0] == ""
				c.Authorized[string(kbytes)] = comment
				log.Println("SSH PUBLIC AUTH256: ", pubKey.Type(), opts, comment, base64.StdEncoding.EncodeToString(kbytes))
				continue
			}

			continue
		} else {
			log.Println("SSH UNKNOWN ", pubKey.Type())
		}
	}
	return nil
}

func SSH2Pub(authkey string) ([]byte, error) {
	return nil, nil
}

// Convert a PublicKey to a marshalled format.
func KeyBytes(key crypto.PublicKey) []byte {
	if ec, ok := key.(*ecdsa.PublicKey); ok {
		// starts with 0x04 == uncompressed curve
		pubbytes := elliptic.Marshal(ec.Curve, ec.X, ec.Y)
		return pubbytes
	}
	if rsak, ok := key.(*rsa.PublicKey); ok {
		pubbytes := x509.MarshalPKCS1PublicKey(rsak)
		return pubbytes
	}
	if ed, ok := key.(ed25519.PublicKey); ok {
		return []byte(ed)
	}
	return nil
}

// Load the primary cert - expects a PEM key file
func (c *Auth) loadCert() error {
	keyPEM, err := c.Config.Get("ec-key.pem")
	if err != nil {
		return err
	}
	certPEM, err := c.Config.Get("ec-cert.pem")
	if err != nil {
		return err
	}
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}

	pk := tlsCert.PrivateKey.(*ecdsa.PrivateKey)

	c.tlsCerts = []tls.Certificate{tlsCert}
	c.EC256PrivateKey = pk
	c.Priv = pk.D.Bytes()
	c.Pub = elliptic.Marshal(Curve256, pk.X, pk.Y) // starts with 0x04 == uncompressed curve
	c.VIP6 = Pub2VIP(c.Pub)

	keyRSA, err := c.Config.Get(".ssh/id_rsa")
	if err == nil {
		c.setKey(keyRSA)
	}
	keyRSA, err = c.Config.Get(".ssh/id_ed25519")
	if err == nil {
		c.setKey(keyRSA)
	}
	return nil
}

// handle rsa and ed keys setting
func (c *Auth) setKey(keyRSA []byte) error {
	keyssh, err := ssh.ParseRawPrivateKey(keyRSA)
	switch key := keyssh.(type) {
	case *rsa.PrivateKey:
		// PRIVATE_KEY - may return RSA or ecdsa
		// RSA PRIVATE KEY
		c.RSAPrivate = key
		return nil
	case *ecdsa.PrivateKey:
		// EC PRIVATE KEY
		return nil
	case *dsa.PrivateKey:
		// DSA PRIVATE KEY
		return nil
	case *ed25519.PrivateKey:
		// OPENSSH PRIVATE KEY - may return rsa or ED25519
		c.EDPrivate = key
		return nil
	}

	return err
}

// Will initialize the privateKey from configuration (Pub, Priv must be set)
func RawToPrivate(priv, pub []byte) (*ecdsa.PrivateKey, error) {
	if len(pub) != 65 {
		return nil, errors.New("Invalid public key, size must be 65")
	}
	if len(priv) != 32 {
		return nil, errors.New("Invalid private key, size must be 32")
	}
	x := new(big.Int).SetBytes(pub[1:33])
	y := new(big.Int).SetBytes(pub[33:65])
	d := new(big.Int).SetBytes(priv[0:32])
	if !Curve256.IsOnCurve(x, y) {
		return nil, errors.New("Invalid public key, not on curve")
	}
	pk := ecdsa.PublicKey{X: x, Y: y, Curve: Curve256}
	privk := &ecdsa.PrivateKey{D: d, PublicKey: pk}
	return privk, nil
}

// generateCert will generate the keys and populate the Pub/Priv fields.
// Will set privateKey, Priv, Pub
// Pub, Priv should be saved
func (c *Auth) generateCert() {
	// d, x,y
	priv, x, y, err := elliptic.GenerateKey(Curve256, rand.Reader)
	if err != nil {
		log.Fatal("Unexpected eliptic error")
	}

	pk := ecdsa.PublicKey{X: x, Y: y, Curve: Curve256}
	d := new(big.Int).SetBytes(priv[0:32])

	c.Priv = priv
	c.EC256PrivateKey = &ecdsa.PrivateKey{D: d, PublicKey: pk}
	c.Pub = elliptic.Marshal(Curve256, x, y) // starts with 0x04 == uncompressed curve
	c.VIP6 = Pub2VIP(c.Pub)

	if c.Name == "" {
		c.Name = base64.URLEncoding.EncodeToString(c.NodeID())
	}
	keyPEM, certPEM := c.generateAndSaveSelfSigned(c.EC256PrivateKey, c.Name+"."+c.Domain)
	tlsCert, _ := tls.X509KeyPair(certPEM, keyPEM)
	c.tlsCerts = []tls.Certificate{tlsCert}

}

// Generate and save the primary self-signed Certificate
func (c *Auth) generateAndSaveSelfSigned(priv *ecdsa.PrivateKey, sans ...string) ([]byte, []byte) {
	var notBefore time.Time
	notBefore = time.Now().Add(-1 * time.Hour)

	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   sans[0],
			Organization: []string{c.Domain},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              sans,
		IPAddresses:           []net.IP{c.VIP6},
	}

	// Sign with the private key.

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		panic(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	ecb, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecb})

	if c.Config != nil {
		c.Config.Set("ec-key.pem", keyPEM)
		c.Config.Set("ec-cert.pem", certPEM)
		pub64 := base64.StdEncoding.EncodeToString(c.Pub)
		sshPub := "ecdsa-sha2-nistp256 " + SSH_ECPREFIX + pub64 + " " + c.Name + "@" + c.Domain
		c.Config.Set("id_ecdsa.pub", []byte(sshPub))
	}
	return keyPEM, certPEM
}

// Sign certificates for children.
//
func (c *Auth) GenerateDirectCert(pub crypto.PublicKey, hours time.Duration, name []string, urls []*url.URL, ips []net.IP) []byte {
	var err error

	var notBefore time.Time
	notBefore = time.Now().Add(-1 * time.Hour)
	notAfter := notBefore.Add(hours)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   name[0],
			Organization: []string{c.Domain},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              name,
		URIs:                  urls,
		IPAddresses:           ips,
	}

	// Sign with the private key of the Cert.

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, c.EC256PrivateKey)
	if err != nil {
		log.Println("Error creating cert", err)
		return nil
	}
	return certDER
}

func (c *Auth) NodeID() []byte {
	return c.VIP6[8:]
}

func (c *Auth) NodeIDUInt() uint64 {
	return Pub2ID(c.Pub)
}

// Generate a 8-byte identifier from a public key
func Pub2NodeID(pub []byte) []byte {
	// TODO: SHA ?
	return pub[len(pub)-8:]
}

// Generate a 8-byte identifier from a public key
func Pub2ID(pub []byte) uint64 {
	if len(pub) > 65 {
		sha256 := sha1.New()
		sha256.Write(pub)
		keysha := sha256.Sum([]byte{}) // 302
		return binary.BigEndian.Uint64(keysha[len(keysha)-8:])
	} else {
		// For EC256 and ED - for now just the last bytes
		return binary.BigEndian.Uint64(pub[len(pub)-8:])
	}
}

var (
	//MESH_NETWORK = []byte{0x20, 0x01, 0x04, 0x70, 0x1f, 0x04, 4, 0x29}
	MESH_NETWORK = []byte{0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0, 0x00}
)

// Convert a public key to a VIP. This is the primary ID of the nodes.
// Primary format is the 64-byte EC256 public key.
//
// For RSA, the ASN.1 format of the byte[] is used.
// For ED, the 32-byte raw encoding.
func Pub2VIP(pub []byte) net.IP {
	ip6 := make([]byte, 16)
	copy(ip6, MESH_NETWORK)

	binary.BigEndian.PutUint64(ip6[8:], Pub2ID(pub))
	return net.IP(ip6)
}

func (c *Auth) PublicKey() crypto.PublicKey {
	return c.EC256PrivateKey.Public()
}

// From a key pair, generate a tls config with cert.
// Used for Auth and Client servers.
func (c *Auth) GenerateTLSConfigServer() *tls.Config {
	var crt *tls.Certificate

	crt = &c.tlsCerts[0]

	certs := []tls.Certificate{*crt}

	certMap := c.GetCerts()
	certMap["*"] = crt

	return &tls.Config{
		Certificates: certs,
		NextProtos:   []string{"h2"},

		// Will only be called if client supplies SNI and Certificates empty
		GetCertificate: func(ch *tls.ClientHelloInfo) (*tls.Certificate, error) {
			log.Printf("ClientHello %v", ch)
			// doesn't include :5228
			c, ok := certMap[ch.ServerName]
			if ok {
				return c, nil
			}
			return crt, nil
		},
	}
}

// Get all known certificates from the config store.
// "istio" is a special name, set if istio certs are found
//
func (h2 *Auth) GetCerts() map[string]*tls.Certificate {
	certMap := map[string]*tls.Certificate{}

	// Attempt istio certs.
	if _, err := os.Stat("/etc/certs/key.pem"); !os.IsNotExist(err) {
		crt, err := tls.LoadX509KeyPair("/etc/certs/cert-chain.pem", "/etc/certs/key.pem")
		if err != nil {
			log.Println("Failed to load system istio certs", err)
		}
		certMap["istio"] = &crt
		log.Println("Loaded istio cert ", crt.Leaf.URIs)
	}

	legoBase := os.Getenv("HOME") + "/.lego/certificates"
	files, err := ioutil.ReadDir(legoBase)
	if err == nil {
		for _, ff := range files {
			s := ff.Name()
			if strings.HasSuffix(s, ".key") {
				s = s[0 : len(s)-4]
				base := legoBase + "/" + s
				cert, err := tls.LoadX509KeyPair(base+".crt",
					base+".key")
				if err != nil {
					log.Println("ACME: Failed to load ", s, err)
				} else {
					certMap[s] = &cert
					log.Println("ACME: Loaded cert for ", s)
				}
			}
		}
	}

	return certMap
}

// Generate a config to be used in a HTTP client, using the primary identity and cert.
func (c *Auth) GenerateTLSConfigClient() *tls.Config {
	// see transport.go in http onceSetNextProtoDefaults
	return &tls.Config{
		// VerifyPeerCertificate used instead
		InsecureSkipVerify: true,

		Certificates: c.tlsCerts,
		// not set on client !! Setting it also disables Auth !
		//NextProtos: nextProtosH2,
	}
}

func (c *Auth) Sign(data []byte, sig []byte) {
	for i := 0; i < 3; i++ {
		hasher := crypto.SHA256.New()
		hasher.Write(data) //[0:64]) // only public key, for debug
		hash := hasher.Sum(nil)

		r, s, _ := ecdsa.Sign(rand.Reader, c.EC256PrivateKey, hash)

		copy(sig, r.Bytes())
		copy(sig[32:], s.Bytes())

		//log.Println("SND SIG: ", hex.EncodeToString(sig))
		//log.Println("SND PUB: ", hex.EncodeToString(data[len(data)-64:]))
		//log.Println("SND HASH: ", hex.EncodeToString(hash))
		//log.Printf("SND PAYLOAD: %d %s", len(data), hex.EncodeToString(data))
		err := Verify(data, c.Pub[1:], sig)
		if err != nil {
			log.Println("Bad msg", err)
			log.Println("SIG: ", hex.EncodeToString(sig))
			log.Println("PUB: ", hex.EncodeToString(c.Pub))
			log.Println("PRIV: ", hex.EncodeToString(c.Priv))
			log.Println("HASH: ", hex.EncodeToString(hash))
		} else {
			return
		}
	}
}

func Verify(data []byte, pub []byte, sig []byte) error {
	hasher := crypto.SHA256.New()
	hasher.Write(data) //[0:64]) // only public key, for debug
	hash := hasher.Sum(nil)

	// Expects 0x4 prefix - we don't send the 4.
	//x, y := elliptic.Unmarshal(curve, pub)
	x := new(big.Int).SetBytes(pub[0:32])
	y := new(big.Int).SetBytes(pub[32:64])
	if !Curve256.IsOnCurve(x, y) {
		return errors.New("Invalid public key")
	}

	pubKey := &ecdsa.PublicKey{Curve256, x, y}
	r := big.NewInt(0).SetBytes(sig[0:32])
	s := big.NewInt(0).SetBytes(sig[32:64])
	match := ecdsa.Verify(pubKey, hash, r, s)
	if match {
		return nil
	} else {
		//log.Printf("PAYLOAD: %d %s", len(data), hex.EncodeToString(data))

		//log.Println(pubKey)

		return errors.New("Failed to validate signature ")
	}
}

//// Auth
//// Setup a bare-bones TLS config for the server
//func GenerateTLSConfigRSA() *tls.Config {
//	key, err := rsa.GenerateKey(rand.Reader, 1024)
//	if err != nil {
//		panic(err)
//	}
//	template := x509.Certificate{SerialNumber: big.NewInt(1)}
//	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
//	if err != nil {
//		panic(err)
//	}
//	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
//	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
//	//rsaFile, _ := os.Create(file)
//	//der := x509.MarshalPKCS1PrivateKey(rsaPrivate)
//	//block := pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
//	//pem.Encode(rsaFile, &block)
//	//rsaFile.Close()
//	//
//	//rsaPubFile, _ := os.Create(file + ".pub")
//	//derPub, _ := x509.MarshalPKIXPublicKey(rsaPrivate.PublicKey)
//	//blockPub := pem.Block{Type: "RSA PUBLIC KEY", Bytes: derPub}
//	//pem.Encode(rsaPubFile, &blockPub)
//	//rsaPubFile.Close()
//
//	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
//	if err != nil {
//		panic(err)
//	}
//	return &tls.Config{Certificates: []tls.Certificate{tlsCert}}
//}

// SSH equivalent:
// ssh-keygen -f server_ca -t ecdsa
// ssh-keygen -s server_ca -I keyid -n username -V +52w key.pub
// Also host keys (-h -n foo.com)
func (h2 *Auth) GetRoots() *x509.CertPool {
	caCertPool := x509.NewCertPool()

	caCert, err := h2.Config.Get("/certs/root-cert.pem")
	if err == nil {
		caCertPool.AppendCertsFromPEM(caCert)
	}

	caCertFile := "/etc/certs/root-cert.pem"
	caCert, err = ioutil.ReadFile(caCertFile)
	if err == nil {
		caCertPool.AppendCertsFromPEM(caCert)
	}

	return caCertPool
}
