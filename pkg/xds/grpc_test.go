package xds

import (
	"fmt"
	"log"
	"net"
	"testing"

	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"math/big"
	"time"

	"golang.org/x/net/context"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/jws"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	testAddr = flag.String("test.addr", "", "URL of tested server, empty for in-process")
)

func startLocalServer(t *testing.T) (*grpc.Server, string) {
	// https://github.com/grpc/grpc-go/blob/master/test/end2end_test.go
	sopts := []grpc.ServerOption{grpc.MaxConcurrentStreams(64)}
	sopts = append(sopts, grpc.MaxMsgSize(8192))

	kp, err := tls.X509KeyPair([]byte(CERT), []byte(PRIV))
	credOpt := credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{kp}})
	/*
		credOpt, err := credentials.NewServerTLSFromFile("../testdata/server1.pem", "../testdata/server1.key")
		if err != nil {
			t.Fatal("Failed to load", err)
		}*/

	sopts = append(sopts, grpc.Creds(credOpt))

	la := "localhost:0"
	lis, err := net.Listen("tcp", la)
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}

	s := grpc.NewServer(sopts...)

	t.Log(lis.Addr().String())
	addr := lis.Addr().String()

	wp := &GrpcService{}
	RegisterAggregatedDiscoveryServiceServer(s, wp)
	go s.Serve(lis)

	return s, addr
}


func TestGRpc(t *testing.T) {
	addr := *testAddr
	if len(*testAddr) == 0 {
		s, a := startLocalServer(t)
		addr = a
		fmt.Println(a)
		defer s.Stop()
	}

	conn, client, err := Connect(addr, CLIENT_PEM)
	defer conn.Close()

	res, err := client.StreamAggregatedResources(context.Background())
	if err != nil {
		log.Fatal("Subscribe fail ", err)
	}
	log.Println("Response", res)

	go func() {
		for {
			msg, err := res.Recv()
			if err != nil {
				t.Fatal("Error in receive", err)
			}
			t.Log("Received ", msg)
		}
	}()

	res.Send(&Request{})
}


// Corresponds to the GCM/webpush test account, from dev console

const priv = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDG6IaKCSJyoS2c\n7FhFWl0stSfq0h8/snEokmpyfsGIxAuW9VSiJnV+4Eph9NikYgXOupkvFlHtEtjK\nQP7lojqhva0i8VLLvbejRL1LrRTv+gTn87iimLYyqdAaIcP+4c3sACkRvkHlxBXC\nlf20Wgxlj1fR5UwAXsiks/rlO3lScTA8//ul7sbYXboIIemubrOZ/KawA6tv53fi\n4dsygW70xacgM93jL0mFSGbLUK6C9PUayhCpfHjvq+mclgutQHvO/gEf5+WfV3Lf\nDkqa/3E48Sbl59ChKfeeQJ7AY883vKxG/zVVuwNoPEhfEH8w1/RP7xXxggn2QWG+\n1ur1bU0rAgMBAAECggEBALwf8B9dxFbmWl2wq0vsy3MdY0OUuDlma+ATmtnvSNwx\nj0SXhBRYi4gUWkWLbdsLWrLLiVYfphyzVpb0IiDN7uZKnxYNaGGKbcTdnquUZ9kQ\nftNij545ERmZwlj01oqaxkgPXsiJSYomiu4fLnUFNfRYPpcmZ1tyShJ8py9nsLdm\n6K9LMcYbDoiZfMYX2bnZikA7qeVnLAYs5qS5MO5lpgarODvH8OelbRd0pxR0PDA4\nVoDtUFYQnWDiZe8ZwyzsEk2J1cluX2L4cBlIMgICBOQqG69DMgvACHknLLecUkyb\nOS852lnRf04rlxhexXZfptmokAl4NbwUIA1iQdciNgECgYEA/RVEPGceroaJzV3X\ne89nEl4eFL2FNhiXPlnpuT7PlIMch51hD2h5yD+av/Emfdrlj41+oCNCfOT3A6R/\n/Bedy12QFgph8nBvWZmc7BcOJNeuMhTgX21Z2GnyNvN8cbgN23A+SagL9blYvpxF\nZeR7VXoD/uL5CguivnyMwiI7J9kCgYEAyTNp7wRYAXC4i2UVkI6YVN6JrfYfwfDI\ntF+8LFyJ/OM/7P7shqZ+tCr5YyWmOPbgc3T1/akdF7lLiUAdyHQAyubwN6i8XV7q\nZh31OKyywbcbCy3xwxTxvW6GjPF5wtS9dkOT0D1L08wNR6m5Zd2WhPWS5a95zeAB\ngwFBgYijnqMCgYAEOIeTzlB3rqy7rRX77aCVcNZlmCeRmGVlV9CLE14Y5vrh1CEb\nRa3KRi1JiDcRIEZ113FGMHBabuMjv2mXBbnO+3d8tp2dknx47RPt6BCHUsWH9ksr\nrEI0VsgAXJ01tFEe2MdhKRlR9s5hF3Ac2+umqEtKw/RNU5ZaQO+ECVgdOQKBgGzN\nUMvgHXcp7aHz1+WENvwuG2XnYuUNwHtKCggzQqtueHNAp8do4busQZBMG8dSOa41\n4ZB6kzDxEtf1xCVSFdujZuOya6pSWY8/RAyR11jKG+W/wq0r9k3qJviw3JdvU8VQ\nZe6GNyshfUzziz56xZrA8d8jNUsPh8HAPBxAN7rhAoGBAIi2/ELz9K7nClvv4s0L\nGMK4AWpA/FN+nHkLVgt3S0xv23ccRivnPss0PhBFHKqc0vu7b+qx5ExQTWvIvob5\ndHuOHo63xWy1+X7sy9VwTtq1zHLeLQihUv6diAAdcGeBut5pwJom05867gqqb5j7\niuipzM5eRINbdYxsie/v3WCI\n-----END PRIVATE KEY-----\n"

const tokCfg = `{
  "type": "service_account",
  "project_id": "webtest-c77c7",
  "private_key_id": "d5980ebb01f252af6921423e20e331d97ab133eb",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDG6IaKCSJyoS2c\n7FhFWl0stSfq0h8/snEokmpyfsGIxAuW9VSiJnV+4Eph9NikYgXOupkvFlHtEtjK\nQP7lojqhva0i8VLLvbejRL1LrRTv+gTn87iimLYyqdAaIcP+4c3sACkRvkHlxBXC\nlf20Wgxlj1fR5UwAXsiks/rlO3lScTA8//ul7sbYXboIIemubrOZ/KawA6tv53fi\n4dsygW70xacgM93jL0mFSGbLUK6C9PUayhCpfHjvq+mclgutQHvO/gEf5+WfV3Lf\nDkqa/3E48Sbl59ChKfeeQJ7AY883vKxG/zVVuwNoPEhfEH8w1/RP7xXxggn2QWG+\n1ur1bU0rAgMBAAECggEBALwf8B9dxFbmWl2wq0vsy3MdY0OUuDlma+ATmtnvSNwx\nj0SXhBRYi4gUWkWLbdsLWrLLiVYfphyzVpb0IiDN7uZKnxYNaGGKbcTdnquUZ9kQ\nftNij545ERmZwlj01oqaxkgPXsiJSYomiu4fLnUFNfRYPpcmZ1tyShJ8py9nsLdm\n6K9LMcYbDoiZfMYX2bnZikA7qeVnLAYs5qS5MO5lpgarODvH8OelbRd0pxR0PDA4\nVoDtUFYQnWDiZe8ZwyzsEk2J1cluX2L4cBlIMgICBOQqG69DMgvACHknLLecUkyb\nOS852lnRf04rlxhexXZfptmokAl4NbwUIA1iQdciNgECgYEA/RVEPGceroaJzV3X\ne89nEl4eFL2FNhiXPlnpuT7PlIMch51hD2h5yD+av/Emfdrlj41+oCNCfOT3A6R/\n/Bedy12QFgph8nBvWZmc7BcOJNeuMhTgX21Z2GnyNvN8cbgN23A+SagL9blYvpxF\nZeR7VXoD/uL5CguivnyMwiI7J9kCgYEAyTNp7wRYAXC4i2UVkI6YVN6JrfYfwfDI\ntF+8LFyJ/OM/7P7shqZ+tCr5YyWmOPbgc3T1/akdF7lLiUAdyHQAyubwN6i8XV7q\nZh31OKyywbcbCy3xwxTxvW6GjPF5wtS9dkOT0D1L08wNR6m5Zd2WhPWS5a95zeAB\ngwFBgYijnqMCgYAEOIeTzlB3rqy7rRX77aCVcNZlmCeRmGVlV9CLE14Y5vrh1CEb\nRa3KRi1JiDcRIEZ113FGMHBabuMjv2mXBbnO+3d8tp2dknx47RPt6BCHUsWH9ksr\nrEI0VsgAXJ01tFEe2MdhKRlR9s5hF3Ac2+umqEtKw/RNU5ZaQO+ECVgdOQKBgGzN\nUMvgHXcp7aHz1+WENvwuG2XnYuUNwHtKCggzQqtueHNAp8do4busQZBMG8dSOa41\n4ZB6kzDxEtf1xCVSFdujZuOya6pSWY8/RAyR11jKG+W/wq0r9k3qJviw3JdvU8VQ\nZe6GNyshfUzziz56xZrA8d8jNUsPh8HAPBxAN7rhAoGBAIi2/ELz9K7nClvv4s0L\nGMK4AWpA/FN+nHkLVgt3S0xv23ccRivnPss0PhBFHKqc0vu7b+qx5ExQTWvIvob5\ndHuOHo63xWy1+X7sy9VwTtq1zHLeLQihUv6diAAdcGeBut5pwJom05867gqqb5j7\niuipzM5eRINbdYxsie/v3WCI\n-----END PRIVATE KEY-----\n",
  "client_email": "grpctest@webtest-c77c7.iam.gserviceaccount.com",
  "client_id": "108860539767051267871",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://accounts.google.com/o/oauth2/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/grpctest%40webtest-c77c7.iam.gserviceaccount.com"
}
`

func TestJWT(t *testing.T) {
	ts, err := google.JWTAccessTokenSourceFromJSON([]byte(tokCfg),
		"https://fcm-stream.googleapis.com")
	if err != nil {
		t.Fatal(err)
	}

	// Bearer, 1 h exp
	t.Log(ts.Token())
	tok, err := ts.Token()

	// Iss: grpctest@webtest-c77c7.iam.gserviceaccount.com
	// Aud: https://fcm-stream.googleapis.com
	// Scope: ""
	// Exp: 1484169314
	// Iat: 1484165714
	// Sub: grpctest@webtest-c77c7.iam.gserviceaccount.com
	// map[]

	// I assume Iss is used to lookup the public key in the auth DB.

	claims, _ := jws.Decode(tok.AccessToken)
	t.Logf("%+v", claims)
}


const (
	// This is a cert pool - copied from grpc tests.
	// should include the self-signed cert.
	CLIENT_PEM = `-----BEGIN CERTIFICATE-----
MIICSjCCAbOgAwIBAgIJAJHGGR4dGioHMA0GCSqGSIb3DQEBCwUAMFYxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQxDzANBgNVBAMTBnRlc3RjYTAeFw0xNDExMTEyMjMxMjla
Fw0yNDExMDgyMjMxMjlaMFYxCzAJBgNVBAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0
YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQxDzANBgNVBAMT
BnRlc3RjYTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAwEDfBV5MYdlHVHJ7
+L4nxrZy7mBfAVXpOc5vMYztssUI7mL2/iYujiIXM+weZYNTEpLdjyJdu7R5gGUu
g1jSVK/EPHfc74O7AyZU34PNIP4Sh33N+/A5YexrNgJlPY+E3GdVYi4ldWJjgkAd
Qah2PH5ACLrIIC6tRka9hcaBlIECAwEAAaMgMB4wDAYDVR0TBAUwAwEB/zAOBgNV
HQ8BAf8EBAMCAgQwDQYJKoZIhvcNAQELBQADgYEAHzC7jdYlzAVmddi/gdAeKPau
sPBG/C2HCWqHzpCUHcKuvMzDVkY/MP2o6JIW2DBbY64bO/FceExhjcykgaYtCH/m
oIU63+CFOTtR7otyQAWHqXa7q4SbCDlG7DyRFxqG0txPtGvy12lgldA2+RgcigQG
Dfcog5wrJytaQ6UA0wE=
-----END CERTIFICATE-----

	`
	// self-signed cert
	CERT = `-----BEGIN CERTIFICATE-----
MIICnDCCAgWgAwIBAgIBBzANBgkqhkiG9w0BAQsFADBWMQswCQYDVQQGEwJBVTET
MBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQ
dHkgTHRkMQ8wDQYDVQQDEwZ0ZXN0Y2EwHhcNMTUxMTA0MDIyMDI0WhcNMjUxMTAx
MDIyMDI0WjBlMQswCQYDVQQGEwJVUzERMA8GA1UECBMISWxsaW5vaXMxEDAOBgNV
BAcTB0NoaWNhZ28xFTATBgNVBAoTDEV4YW1wbGUsIENvLjEaMBgGA1UEAxQRKi50
ZXN0Lmdvb2dsZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAOHDFSco
LCVJpYDDM4HYtIdV6Ake/sMNaaKdODjDMsux/4tDydlumN+fm+AjPEK5GHhGn1Bg
zkWF+slf3BxhrA/8dNsnunstVA7ZBgA/5qQxMfGAq4wHNVX77fBZOgp9VlSMVfyd
9N8YwbBYAckOeUQadTi2X1S6OgJXgQ0m3MWhAgMBAAGjazBpMAkGA1UdEwQCMAAw
CwYDVR0PBAQDAgXgME8GA1UdEQRIMEaCECoudGVzdC5nb29nbGUuZnKCGHdhdGVy
em9vaS50ZXN0Lmdvb2dsZS5iZYISKi50ZXN0LnlvdXR1YmUuY29thwTAqAEDMA0G
CSqGSIb3DQEBCwUAA4GBAJFXVifQNub1LUP4JlnX5lXNlo8FxZ2a12AFQs+bzoJ6
hM044EDjqyxUqSbVePK0ni3w1fHQB5rY9yYC5f8G7aqqTY1QOhoUk8ZTSTRpnkTh
y4jjdvTZeLDVBlueZUTDRmy2feY5aZIU18vFDK08dTG0A87pppuv1LNIR3loveU8
-----END CERTIFICATE-----
`

	// private (and public ) RSA keys
	PRIV = `-----BEGIN PRIVATE KEY-----
MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAOHDFScoLCVJpYDD
M4HYtIdV6Ake/sMNaaKdODjDMsux/4tDydlumN+fm+AjPEK5GHhGn1BgzkWF+slf
3BxhrA/8dNsnunstVA7ZBgA/5qQxMfGAq4wHNVX77fBZOgp9VlSMVfyd9N8YwbBY
AckOeUQadTi2X1S6OgJXgQ0m3MWhAgMBAAECgYAn7qGnM2vbjJNBm0VZCkOkTIWm
V10okw7EPJrdL2mkre9NasghNXbE1y5zDshx5Nt3KsazKOxTT8d0Jwh/3KbaN+YY
tTCbKGW0pXDRBhwUHRcuRzScjli8Rih5UOCiZkhefUTcRb6xIhZJuQy71tjaSy0p
dHZRmYyBYO2YEQ8xoQJBAPrJPhMBkzmEYFtyIEqAxQ/o/A6E+E4w8i+KM7nQCK7q
K4JXzyXVAjLfyBZWHGM2uro/fjqPggGD6QH1qXCkI4MCQQDmdKeb2TrKRh5BY1LR
81aJGKcJ2XbcDu6wMZK4oqWbTX2KiYn9GB0woM6nSr/Y6iy1u145YzYxEV/iMwff
DJULAkB8B2MnyzOg0pNFJqBJuH29bKCcHa8gHJzqXhNO5lAlEbMK95p/P2Wi+4Hd
aiEIAF1BF326QJcvYKmwSmrORp85AkAlSNxRJ50OWrfMZnBgzVjDx3xG6KsFQVk2
ol6VhqL6dFgKUORFUWBvnKSyhjJxurlPEahV6oo6+A+mPhFY8eUvAkAZQyTdupP3
XEFQKctGz+9+gKkemDp7LBBMEMBXrGTLPhpEfcjv/7KPdnFHYmhYeBTBnuVmTVWe
F98XJ7tIFfJq
-----END PRIVATE KEY-----

	`
)




func genCert(cert string, key string) (*tls.Certificate, *x509.CertPool, error) {
	pair, err := tls.X509KeyPair([]byte(cert), []byte(key))
	if err != nil {
		return nil, nil, err
	}
	demoKeyPair := &pair

	demoCertPool := x509.NewCertPool()
	ok := demoCertPool.AppendCertsFromPEM([]byte(cert))
	if !ok {
		return nil, nil, errors.New("bad certs")
	}
	return demoKeyPair, demoCertPool, nil
}

func TestTLS(t *testing.T) {
	k, err := ParseKey([]byte(priv))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(k, k.Public())

	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour * 7)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{Organization: []string{"Self-Signed"}},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}

	demoCertPool := x509.NewCertPool()
	demoCertPool.AppendCertsFromPEM(derBytes)

	creds := credentials.NewServerTLSFromCert(&tls.Certificate{
		PrivateKey: k,
		Leaf:       cert,
	})

	fmt.Println(creds)

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

