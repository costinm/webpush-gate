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
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/url"
	"os"
	"strconv"
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
	Name string

	// Identifies the domain of the node.
	// Added to the 'sub' field in Vapid messages. Can be an email or domain.
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

	// base64URL encoding of the primary public key.
	// Will be added to Crypto-Keys p256ecdsa header field.
	PubKey string

	// Private key to use in both server and client authentication. This is the base of the VIP of the node.
	// ED22519: 32B
	// EC256: 32
	// RSA: DER
	Priv []byte

	// Primary private keys. This is a long-lived key, used as SSH server
	// key.
	EC256PrivateKey *ecdsa.PrivateKey

	// Secondary private keys.
	RSAPrivate *rsa.PrivateKey
	EDPrivate  *ed25519.PrivateKey

	// List of authorized keys and roles, for minimal Authz.
	// Key is the string(marshalled_form). For example EC256 it's a byte[65]
	// Value is list of roles for the key.
	Authorized map[string]string
	Known      map[string]*AuthzInfo

	Authz     map[string]*AuthzInfo
	AuthzByID map[uint64]*AuthzInfo

	// TODO: Root certificates to trust, keyed by domain.
	Roots map[string]*Root

	// cached
	pub64 string
}

// WIP: more info about authorized
type AuthzInfo struct {
	// Role - stored as comment of the SSH authz keys
	Role string

	Public []byte

	Opts map[string]string

	// key.(*ecdsa.PublicKey)
	// key.(*rsa.PublicKey)
	// key.(ed25519.PublicKey)
	Key crypto.PublicKey
}

// Subscription holds the useful values from a PushSubscription object acquired
// from the browser.
//
// https://w3c.github.io/push-api/
//
// Returned as result of /subscribe
type Subscription struct {
	// Endpoint is the URL to send the Web Push message to. Comes from the
	// endpoint field of the PushSubscription.
	Endpoint string

	// Key is the client's public key. From the getKey("p256dh") or keys.p256dh field.
	Key []byte

	// Auth is a value used by the client to validate the encryption. From the
	// keys.auth field.
	// The encrypted aes128gcm will have 16 bytes authentication tag derived from this.
	// This is the pre-shared authentication secret.
	Auth []byte

	// Used by the UA to receive messages, as PUSH promises
	Location string
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

type ConfStore interface {
	// Get a config blob by name
	Get(name string) ([]byte, error)

	// Save a config blob
	Set(conf string, data []byte) error

	// List the configs starting with a prefix, of a given type
	List(name string, tp string) ([]string, error)
}

func Conf(cs ConfStore, name, def string) string {
	if cs == nil {
		return def
	}
	b, _ := cs.Get(name)
	if b == nil {
		return def
	}
	return string(b)
}

func ConfInt(cs ConfStore, name string, def int) int {
	if cs == nil {
		return def
	}
	b, _ := cs.Get(name)
	if b == nil {
		return def
	}
	v, err := strconv.Atoi(string(b))
	if err != nil {
		return def
	}
	return v
}

// NewVapid constructs a new Vapid generator from EC256 public and private keys,
// in base64 uncompressed format.
func NewVapid(publicKey, privateKey string) (v *Auth) {
	publicUncomp, _ := base64.RawURLEncoding.DecodeString(publicKey)
	privateUncomp, _ := base64.RawURLEncoding.DecodeString(privateKey)

	x, y := elliptic.Unmarshal(curve, publicUncomp)
	d := new(big.Int).SetBytes(privateUncomp)
	pubkey := ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	pkey := ecdsa.PrivateKey{PublicKey: pubkey, D: d}

	v = _new()
	v.pub64 = publicKey
	v.Pub = publicUncomp
	v.Priv = privateUncomp
	v.PubKey = publicKey
	v.EC256PrivateKey = &pkey

	return
}

func _new() *Auth {
	return &Auth{
		Authorized: map[string]string{},
		Known:      map[string]*AuthzInfo{},
		Authz:      map[string]*AuthzInfo{},
		AuthzByID:  map[uint64]*AuthzInfo{},
	}
}

// Initialize the certificates, loading or generating them.
// If cfg is nil, will generate certs but not save.
//
func NewAuth(cfg ConfStore, name, domain string) *Auth {
	auth := _new()
	auth.Config = cfg
	auth.Domain = domain
	auth.Name = name

	// Use .ssh/ and the secondary config to load the keys.
	if cfg != nil {
		err := auth.loadCert()
		if err != nil {
			log.Println("Error loading cert: ", err)
		}
	}
	if auth.EC256PrivateKey == nil {
		// Can't load the EC256 certs - generate new ones.
		auth.generateCert()
	}

	auth.VIP64 = auth.NodeIDUInt()
	// Based on the primary EC256 key
	auth.pub64 = base64.RawURLEncoding.EncodeToString(auth.Pub)

	// Use SSH known hosts and auth to bootstrap
	if cfg != nil {
		auth.loadKnownHosts()
		auth.loadAuth()
	}
	// TODO: additional sources for root certs and identity.

	return auth
}

func (auth *Auth) DumpKnown() {
	for _, ai := range auth.Known {
		fmt.Printf("%s=%v\n", ai.Role, Pub2VIP(ai.Public))
	}
}

func (auth *Auth) Dump() {
	fmt.Println("VIP=", auth.VIP6)
	fmt.Println("ID=",
		base64.RawURLEncoding.EncodeToString(auth.NodeID()),
		hex.EncodeToString(auth.NodeID()),
		auth.NodeIDUInt())

	pub64 := base64.RawURLEncoding.EncodeToString(auth.Pub)

	fmt.Println("PUB=", pub64)
	h := strings.ReplaceAll(auth.VIP6.String()[6:], ":", "-")
	sshPub := "ecdsa-sha2-nistp256 " + SSH_ECPREFIX + pub64 + " " +
		auth.Name + "@" + h + "." + auth.Domain
	fmt.Println("SSH=", sshPub)

	for _, ai := range auth.Authz {
		fmt.Println("AUTHZ_", ai.Role, "=", Pub2VIP(ai.Public))
	}
}

// Add or update an identity (key) with a set of permissions (roles).
// This is extending the SSH, by using the comment field as a list of roles, starting with the
// user identity.
func (auth *Auth) AddAuthorized(key interface{}, role string) {
	var keyb []byte
	if oub, ok := key.([]byte); ok {
		keyb = oub
	}

	if cp2, ok := key.(crypto.PublicKey); ok {
		oub := KeyBytes(cp2)
		key = oub
	}

	auth.Authorized[string(keyb)] = role

	// TODO: write back authorized file !!!
	bw := bytes.Buffer{}
	for k, v := range auth.Authorized {
		kb := []byte(k)
		if len(kb) == 65 {
			bw.WriteString("ecdsa-sha2-nistp256 " + base64.StdEncoding.EncodeToString(kb) + " " + v)
		}
	}

	auth.Config.Set("authorized_keys.save", bw.Bytes())
}

// Check if an identity is authorized for the role.
// The key is in the marshalled format - use KeyBytes to convert a crypto.PublicKey.
//
func (auth *Auth) Auth(key []byte, role string) string {
	roles := auth.Authorized[string(key)]

	return roles
}

// Process SSH known hosts file, to keep track of hostnames
// Known hosts are not trusted - but checked for continuity
//
// - @cert-authority - declares a CA that signs hosts, wildcards.
// - @revoked
// - regular: hostnames(.), key + comment + rest
//
func (auth *Auth) loadKnownHosts() error {
	//
	// [h.webinf.info]:2022,[67.174.240.198]:2022 ecdsa-sha2-nistp256 AAAA...
	//  markers (optional), hostnames, keytype, base64-encoded key, comment
	//
	// port missing: 22
	//

	authB := bytes.Buffer{}
	khauth, err := auth.Config.Get("known_hosts")
	if err == nil && khauth != nil {
		authB.Write(khauth)
		authB.WriteByte('\n')
	}
	ksave, err := auth.Config.Get("known_hosts.save")
	if err == nil && ksave != nil {
		authB.Write(ksave)
		authB.WriteByte('\n')
	}

	authb := authB.Bytes()
	for len(authb) > 0 {
		marker, hosts, pubKey, _, rest, err := ssh.ParseKnownHosts(authb)
		if err != nil {
			return err
		}
		authb = rest

		if marker == "@cert-authority" {
			// hosts should start with *.DOMAIN

		}

		if cpk, ok := pubKey.(ssh.CryptoPublicKey); ok {
			pubk := cpk.CryptoPublicKey()
			kbytes := KeyBytes(pubk)
			if kbytes != nil { // len(kbytes) == 65 {
				for _, h := range hosts {
					// TODO: filter :5222 and extract domain
					// IP can be ignored.
					hn, p, _ := net.SplitHostPort(h)
					if p != "0" && p != "5222" {
						continue
					}

					//if len(opts) > 0 && opts[0] == ""
					auth.Known[hn] = &AuthzInfo{
						Role:   hn,
						Key:    pubk,
						Public: kbytes,
						Opts:   map[string]string{},
					}
				}
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
func (auth *Auth) loadAuth() error {
	// TODO: load known_hosts as well

	authB := bytes.Buffer{}
	authKeys, err := auth.Config.Get("authorized_keys")
	if err == nil && authKeys != nil {
		authB.Write(authKeys)
		authB.WriteByte('\n')
	}

	authKeys, err = auth.Config.Get("authorized_keys.save")
	if err == nil && authKeys != nil {
		authB.Write(authKeys)
		authB.WriteByte('\n')
	}

	// options:
	// SSH_ORIGINAL_COMMAND as env variable
	// no-pty,command="/usr/local/bin/dmesh"
	//
	authKeys = authB.Bytes()
	for len(authKeys) > 0 {
		pubKey, comment, opts, rest, err := ssh.ParseAuthorizedKey(authKeys)
		if err != nil {
			break
		}
		authKeys = rest

		if cpk, ok := pubKey.(ssh.CryptoPublicKey); ok {
			pubk := cpk.CryptoPublicKey()
			kbytes := KeyBytes(pubk)
			if kbytes != nil {
				auth.Authorized[string(kbytes)] = comment
				ai := &AuthzInfo{
					Role:   comment,
					Key:    pubk,
					Public: kbytes,
					Opts:   map[string]string{},
				}
				auth.Authz[comment] = ai
				auth.AuthzByID[Pub2ID(ai.Public)] = ai
				for _, o := range opts {
					if strings.Contains(o, "=") {
						op := strings.SplitN(o, "=", 2)
						ai.Opts[op[0]] = op[1]
					} else {
						ai.Opts[o] = ""
					}
				}
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
func (auth *Auth) loadCert() error {
	keyPEM, err := auth.Config.Get("ec-key.pem")
	if err != nil {
		return err
	}
	certPEM, err := auth.Config.Get("ec-cert.pem")
	if err != nil {
		return err
	}
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}

	pk := tlsCert.PrivateKey.(*ecdsa.PrivateKey)

	auth.tlsCerts = []tls.Certificate{tlsCert}
	auth.EC256PrivateKey = pk
	auth.Priv = pk.D.Bytes()
	auth.Pub = elliptic.Marshal(Curve256, pk.X, pk.Y) // starts with 0x04 == uncompressed curve

	auth.VIP6 = Pub2VIP(auth.Pub)

	keyRSA, err := auth.Config.Get(".ssh/id_rsa")
	if err == nil {
		auth.setKey(keyRSA)
	}
	keyRSA, err = auth.Config.Get(".ssh/id_ed25519")
	if err == nil {
		auth.setKey(keyRSA)
	}
	return nil
}

// handle rsa and ed keys setting
func (auth *Auth) setKey(keyRSA []byte) error {
	keyssh, err := ssh.ParseRawPrivateKey(keyRSA)
	switch key := keyssh.(type) {
	case *rsa.PrivateKey:
		// PRIVATE_KEY - may return RSA or ecdsa
		// RSA PRIVATE KEY
		auth.RSAPrivate = key
		return nil
	case *ecdsa.PrivateKey:
		// EC PRIVATE KEY
		return nil
	case *dsa.PrivateKey:
		// DSA PRIVATE KEY
		return nil
	case *ed25519.PrivateKey:
		// OPENSSH PRIVATE KEY - may return rsa or ED25519
		auth.EDPrivate = key
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
func (auth *Auth) generateCert() {
	// d, x,y
	priv, x, y, err := elliptic.GenerateKey(Curve256, rand.Reader)
	if err != nil {
		log.Fatal("Unexpected eliptic error")
	}

	pk := ecdsa.PublicKey{X: x, Y: y, Curve: Curve256}
	d := new(big.Int).SetBytes(priv[0:32])

	auth.Priv = priv

	auth.EC256PrivateKey = &ecdsa.PrivateKey{D: d, PublicKey: pk}
	auth.Pub = elliptic.Marshal(Curve256, x, y) // starts with 0x04 == uncompressed curve
	auth.PubKey = base64.RawURLEncoding.EncodeToString(auth.Pub)
	auth.VIP6 = Pub2VIP(auth.Pub)
	//b64 := base64.URLEncoding.WithPadding(base64.NoPadding)
	//
	//pub64 := b64.EncodeToString(pub)
	//priv64 := b64.EncodeToString(priv)

	if auth.Name == "" {
		auth.Name = base64.RawURLEncoding.EncodeToString(auth.NodeID())
	}
	keyPEM, certPEM := auth.generateAndSaveSelfSigned(auth.EC256PrivateKey, auth.Name+"."+auth.Domain)
	tlsCert, _ := tls.X509KeyPair(certPEM, keyPEM)
	auth.tlsCerts = []tls.Certificate{tlsCert}

}

// Generate and save the primary self-signed Certificate
func (auth *Auth) generateAndSaveSelfSigned(priv *ecdsa.PrivateKey, sans ...string) ([]byte, []byte) {
	var notBefore time.Time
	notBefore = time.Now().Add(-1 * time.Hour)

	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   sans[0],
			Organization: []string{auth.Domain},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              sans,
		IPAddresses:           []net.IP{auth.VIP6},
	}

	// Sign with the private key.

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		panic(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	ecb, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecb})

	if auth.Config != nil {
		auth.Config.Set("ec-key.pem", keyPEM)
		auth.Config.Set("ec-cert.pem", certPEM)
		pub64 := base64.StdEncoding.EncodeToString(auth.Pub)
		sshPub := "ecdsa-sha2-nistp256 " + SSH_ECPREFIX + pub64 + " " + auth.Name + "@" + auth.Domain
		auth.Config.Set("id_ecdsa.pub", []byte(sshPub))
	}
	return keyPEM, certPEM
}

// Sign certificates for children.
//
func (auth *Auth) GenerateDirectCert(pub crypto.PublicKey, hours time.Duration, name []string, urls []*url.URL, ips []net.IP) []byte {
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
			Organization: []string{auth.Domain},
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

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, auth.EC256PrivateKey)
	if err != nil {
		log.Println("Error creating cert", err)
		return nil
	}
	return certDER
}

func (auth *Auth) NodeID() []byte {
	return auth.VIP6[8:]
}

func (auth *Auth) NodeIDUInt() uint64 {
	return Pub2ID(auth.Pub)
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

func (auth *Auth) PublicKey() crypto.PublicKey {
	return auth.EC256PrivateKey.Public()
}

// From a key pair, generate a tls config with cert.
// Used for Auth and Client servers.
func (auth *Auth) GenerateTLSConfigServer() *tls.Config {
	var crt *tls.Certificate

	crt = &auth.tlsCerts[0]

	certs := []tls.Certificate{*crt}

	certMap := auth.GetCerts()
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
func (auth *Auth) GetCerts() map[string]*tls.Certificate {
	certMap := map[string]*tls.Certificate{}

	// Attempt istio certs.
	if _, err := os.Stat("/etc/certs/key.pem"); !os.IsNotExist(err) {
		crt, err := tls.LoadX509KeyPair("/etc/certs/cert-chain.pem", "/etc/certs/key.pem")
		if err != nil {
			log.Println("Failed to load system istio certs", err)
		} else {
			certMap["istio"] = &crt
			if crt.Leaf != nil {
				log.Println("Loaded istio cert ", crt.Leaf.URIs)
			}
		}
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
func (auth *Auth) GenerateTLSConfigClient() *tls.Config {
	// see transport.go in http onceSetNextProtoDefaults
	return &tls.Config{
		// VerifyPeerCertificate used instead
		InsecureSkipVerify: true,

		Certificates: auth.tlsCerts,
		// not set on client !! Setting it also disables Auth !
		//NextProtos: nextProtosH2,
	}
}

func (auth *Auth) Sign(data []byte, sig []byte) {
	for i := 0; i < 3; i++ {
		hasher := crypto.SHA256.New()
		hasher.Write(data) //[0:64]) // only public key, for debug
		hash := hasher.Sum(nil)

		r, s, _ := ecdsa.Sign(rand.Reader, auth.EC256PrivateKey, hash)

		copy(sig, r.Bytes())
		copy(sig[32:], s.Bytes())

		//log.Println("SND SIG: ", hex.EncodeToString(sig))
		//log.Println("SND PUB: ", hex.EncodeToString(data[len(data)-64:]))
		//log.Println("SND HASH: ", hex.EncodeToString(hash))
		//log.Printf("SND PAYLOAD: %d %s", len(data), hex.EncodeToString(data))
		err := Verify(data, auth.Pub[1:], sig)
		if err != nil {
			log.Println("Bad msg", err)
			log.Println("SIG: ", hex.EncodeToString(sig))
			log.Println("PUB: ", hex.EncodeToString(auth.Pub))
			log.Println("PRIV: ", hex.EncodeToString(auth.Priv))
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

	pubKey := &ecdsa.PublicKey{Curve: Curve256, X: x, Y: y}
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
func (auth *Auth) GetRoots() *x509.CertPool {
	caCertPool := x509.NewCertPool()

	caCert, err := auth.Config.Get("/certs/root-cert.pem")
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

// ParseKey converts the binary contents of a private key file
// to an *rsa.PrivateKey. It detects whether the private key is in a
// PEM container or not. If so, it extracts the the private key
// from PEM container before conversion. It only supports PEM
// containers with no passphrase.
func ParseKey(key []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(key)
	if block != nil {
		key = block.Bytes
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(key)
	if err != nil {
		parsedKey, err = x509.ParsePKCS1PrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("private key should be a PEM or plain PKSC1 or PKCS8; parse error: %v", err)
		}
	}
	parsed, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is invalid")
	}
	return parsed, nil
}
