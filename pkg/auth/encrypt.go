// Copyright 2016 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package webpush provides helper functions for sending encrpyted payloads
// using the Web Push protocol.
//
// Sending a message:
//   import (
//     "strings"
//     "github.com/googlechrome/webpush/webpush"
//   )
//
//   func main() {
//     // The values that make up the Subscription struct come from the browser
//     sub := &webpush.Subscription{endpoint, key, auth}
//     webpush.Send(nil, sub, "Yay! Web Push!", nil)
//   }
//
// You can turn a JSON string representation of a PushSubscription object you
// collected from the browser into a Subscription struct with a helper function.
//
//   var exampleJSON = []byte(`{"endpoint": "...", "keys": {"p256dh": "...", "auth": "..."}}`)
//   sub, err := SubscriptionFromJSON(exampleJSON)
//
// If the push service requires an authentication header (notably Google Cloud
// Messaging, used by Chrome) then you can add that as a fourth parameter:
//
//   if strings.Contains(sub.Endpoint, "https://android.googleapis.com/gcm/send/") {
//     webpush.Send(nil, sub, "A message for Chrome", myGCMKey)
//   }
package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"strings"
)

const (
	maxPayloadLength = 4078
)

var (
	authInfo = []byte("Content-Encoding: auth\x00")
	curve    = elliptic.P256()

	// Generate a random EC256 key pair. Overridable for testing.
	// Returns priv as a 16-byte point, and pub in uncompressed format, 33 bytes.
	randomKey = func() (priv []byte, pub []byte, err error) {
		priv, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, nil, err
		}

		return priv, elliptic.Marshal(curve, x, y), nil
	}

	// Generate a random salt for the encryption. Overridable for testing.
	randomSalt = func() ([]byte, error) {
		salt := make([]byte, 16)
		_, err := rand.Read(salt)
		if err != nil {
			return nil, err
		}
		return salt, nil
	}
)

// SubscriptionFromJSON is a convenience function that takes a JSON encoded
// PushSubscription object acquired from the browser and returns a pointer to a
// Subscription
func SubscriptionFromJSON(b []byte) (*Subscription, error) {
	var sub struct {
		Endpoint string
		Keys     struct {
			P256dh string
			Auth   string
		}
	}
	if err := json.Unmarshal(b, &sub); err != nil {
		return nil, err
	}

	b64 := base64.URLEncoding.WithPadding(base64.NoPadding)

	// Chrome < 52 incorrectly adds padding when Base64 encoding the values, so
	// we need to strip that out
	key, err := b64.DecodeString(strings.TrimRight(sub.Keys.P256dh, "="))
	if err != nil {
		return nil, err
	}

	auth, err := b64.DecodeString(strings.TrimRight(sub.Keys.Auth, "="))
	if err != nil {
		return nil, err
	}

	return &Subscription{sub.Endpoint, key, auth, ""}, nil
}

// TODO: rename ServerPublicKey to 'dhKey' or 'tmpKey' - to avoid confusion
// with the VAPID ServerPublicKey

// EncryptionContext stores the source and result of encrypting a message. The ciphertext is
// the actual encrypted message, while the salt and server public key are
// required to be sent to the client so that the message can be decrypted.
type EncryptionContext struct {
	// Full body of the encrypted message, including header (salt, server pub)
	// Format:
	// 16 B Salt
	// 4B rs {0,0, 16, 0} - 4k
	// 1B ID-Len {65}
	// 65B SendPublicKey
	// Up to 4k encrypted text - with 0x02 appended at the end before encryption
	// Wasted: 7 const.
	// Overhead: 16 salt, 16 sig, 64 pub. Total: 103 (64+32+7)
	Ciphertext []byte

	// 16B For encryption: must be a random generated by sender.
	Salt []byte

	// Temp EC key for encryption, 65B
	SendPublic []byte

	// UA Public bytes - from subscription
	UAPublic []byte

	// Only used for encrypt
	SendPrivate []byte
	// Only used for decrypt
	UAPrivate []byte

	// Auth - from subscription
	Auth []byte

	// Computed from public/private
	ecdh_secret []byte
}

// TODO: input should be a []byte ( proto, etc )

const debugEncrypt = false

func NewContextSend(uapub, auth []byte) *EncryptionContext {
	return &EncryptionContext{
		Auth:     auth,
		UAPublic: uapub,
	}
}

func NewContextUA(uapriv, uapub, auth []byte) *EncryptionContext {
	return &EncryptionContext{
		Auth:      auth,
		UAPublic:  uapub,
		UAPrivate: uapriv,
	}
}

// Encrypt a message such that it can be sent using the Web Push protocol.
//
// RFC8030 - message
// RFC8291 - encryption
func (er *EncryptionContext) Encrypt(plaintext []byte) ([]byte, error) {
	var err error
	if er.Salt == nil {
		er.Salt, err = randomSalt()
	}
	if er.SendPublic == nil {
		er.SendPrivate, er.SendPublic, err = randomKey()
	}

	ua_pubkey := er.UAPublic
	auth := er.Auth
	serverPrivateKey := er.SendPrivate
	serverPublicKey := er.SendPublic

	if len(plaintext) > maxPayloadLength {
		return nil, fmt.Errorf("payload is too large. The max number of bytes is %d, input is %d bytes ", maxPayloadLength, len(plaintext))
	}

	if len(ua_pubkey) == 0 {
		return nil, fmt.Errorf("subscription must include the client's public key")
	}

	if len(auth) == 0 {
		return nil, fmt.Errorf("subscription must include the client's auth value")
	}

	// Use ECDH to derive a shared secret between us and the client. We generate
	// a fresh private/public key pair at random every time we encrypt.
	secret, err := sharedSecret(curve, ua_pubkey, serverPrivateKey)
	if err != nil {
		return nil, err
	}
	er.ecdh_secret = secret
	if debugEncrypt {
		log.Println("send_pub", base64.RawURLEncoding.EncodeToString(serverPublicKey))
		log.Println("ua_pub", base64.RawURLEncoding.EncodeToString(er.UAPublic))
		log.Println("ecdh_secret", base64.RawURLEncoding.EncodeToString(secret))
	}

	var key_info []byte
	key_info = append(key_info, []byte("WebPush: info")...)
	key_info = append(key_info, 0)
	key_info = append(key_info, ua_pubkey...)
	key_info = append(key_info, serverPublicKey...)
	if debugEncrypt {
		log.Println("key_info", base64.RawURLEncoding.EncodeToString(key_info))
	}
	// Derive a Pseudo-Random Key (prk) that can be used to further derive our
	// other encryption parameters. These derivations are described in
	// https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding-00
	ikm := hkdf(auth, secret, key_info, 32)
	if debugEncrypt {
		log.Println("ikm", base64.RawURLEncoding.EncodeToString(ikm))
	}

	// Derive the Content Encryption Key and nonce
	ctx := newContext(ua_pubkey, serverPublicKey)
	cek := newCEK128(ctx, er.Salt, ikm)
	if debugEncrypt {
		log.Println("cek", base64.RawURLEncoding.EncodeToString(cek))
	}
	nonce := newNonce128(ctx, er.Salt, ikm)
	if debugEncrypt {
		log.Println("nonce", base64.RawURLEncoding.EncodeToString(nonce))
	}
	// Do the actual encryption
	pt := plaintext
	pt = append(pt, 2)
	if debugEncrypt {
		log.Println("pt_pad", base64.RawURLEncoding.EncodeToString(pt))
	}

	ciphertext, err := encrypt128(pt, cek, nonce)
	if debugEncrypt {
		log.Println("cipher", base64.RawURLEncoding.EncodeToString(ciphertext))
	}
	if err != nil {
		return nil, err
	}

	res := er.Salt
	res = append(res, 0, 0, 16, 0, 65)
	res = append(res, er.SendPublic...)

	if debugEncrypt {
		log.Println("header ", base64.RawURLEncoding.EncodeToString(res))
	}
	res = append(res, ciphertext...)

	er.Ciphertext = res
	// Return all of the values needed to construct a Web Push HTTP request.
	return res, nil
}

func (er *EncryptionContext) Decrypt(cypher []byte) ([]byte, error) {
	er.Ciphertext = cypher
	salt := er.Ciphertext[0:16]
	serverPublicKey := er.Ciphertext[21 : 21+65]
	ua_pubkey := er.UAPublic
	auth := er.Auth

	// Use ECDH to derive a shared secret between us and the client. We generate
	// a fresh private/public key pair at random every time we encrypt.
	secret, err := sharedSecret(curve, serverPublicKey, er.UAPrivate)
	if err != nil {
		return nil, err
	}
	if debugEncrypt {
		log.Println("send_pub", base64.RawURLEncoding.EncodeToString(serverPublicKey))
		log.Println("ua_pub", base64.RawURLEncoding.EncodeToString(er.UAPublic))
		log.Println("ecdh_secret", base64.RawURLEncoding.EncodeToString(secret))
	}

	var key_info []byte
	key_info = append(key_info, []byte("WebPush: info")...)
	key_info = append(key_info, 0)
	key_info = append(key_info, ua_pubkey...)
	key_info = append(key_info, serverPublicKey...)
	if debugEncrypt {
		log.Println("key_info", base64.RawURLEncoding.EncodeToString(key_info))
	}
	// Derive a Pseudo-Random Key (prk) that can be used to further derive our
	// other encryption parameters. These derivations are described in
	// https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding-00
	ikm := hkdf(auth, secret, key_info, 32)
	if debugEncrypt {
		log.Println("ikm", base64.RawURLEncoding.EncodeToString(ikm))
	}

	// Derive the Content Encryption Key and nonce
	ctx := newContext(ua_pubkey, serverPublicKey)
	cek := newCEK128(ctx, salt, ikm)
	if debugEncrypt {
		log.Println("cek", base64.RawURLEncoding.EncodeToString(cek))
	}
	nonce := newNonce128(ctx, salt, ikm)
	if debugEncrypt {
		log.Println("nonce", base64.RawURLEncoding.EncodeToString(nonce))
	}

	plain, err := decrypt128(er.Ciphertext[21+65:], cek, nonce)
	if err != nil {
		return nil, err
	}

	return plain[0 : len(plain)-1], nil
}

func newInfo128(infoType string, context []byte) []byte {
	var info []byte
	info = append(info, []byte("Content-Encoding: ")...)
	info = append(info, []byte(infoType)...)
	info = append(info, 0)
	//info = append(info, []byte("P-256")...)
	//info = append(info, context...)
	return info
}

func newCEK128(ctx, salt, prk []byte) []byte {
	info := newInfo128("aes128gcm", ctx)
	if debugEncrypt {
		log.Println("cek_info", base64.RawURLEncoding.EncodeToString(info))
	}
	return hkdf(salt, prk, info, 16)
}

func newNonce128(ctx, salt, prk []byte) []byte {
	info := newInfo128("nonce", ctx)
	if debugEncrypt {
		log.Println("nonce_info", base64.RawURLEncoding.EncodeToString(info))
	}
	return hkdf(salt, prk, info, 12)
}

// Creates a context for deriving encyption parameters, as described in
// https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding-00.
// The 'context' in this case is just the public keys of both client and server.
// The keys should always be 65 bytes each. The format of the keys is
// described in section 4.3.6 of the (sadly not freely linkable) ANSI X9.62
// specification.
func newContext(clientPublicKey, serverPublicKey []byte) []byte {
	// The context format is:
	// 0x00 || length(clientPublicKey) || clientPublicKey ||
	//         length(serverPublicKey) || serverPublicKey
	// The lengths are 16-bit, Big Endian, unsigned integers so take 2 bytes each.
	cplen := uint16(len(clientPublicKey))
	cplenbuf := make([]byte, 2)
	binary.BigEndian.PutUint16(cplenbuf, cplen)

	splen := uint16(len(serverPublicKey))
	splenbuf := make([]byte, 2)
	binary.BigEndian.PutUint16(splenbuf, splen)

	var ctx []byte
	ctx = append(ctx, 0)
	ctx = append(ctx, cplenbuf...)
	ctx = append(ctx, []byte(clientPublicKey)...)
	ctx = append(ctx, splenbuf...)
	ctx = append(ctx, []byte(serverPublicKey)...)

	return ctx
}

// HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
//
// This is used to derive a secure encryption key from a mostly-secure shared
// secret.
//
// This is a partial implementation of HKDF tailored to our specific purposes.
// In particular, for us the value of N will always be 1, and thus T always
// equals HMAC-Hash(PRK, info | 0x01). This is true because the maximum output
// length we need/allow is 32.
//
// See https://www.rfc-editor.org/rfc/rfc5869.txt
func hkdf(salt, ikm, info []byte, length int) []byte {
	// HMAC length for SHA256 is 32 bytes, so that is the maximum result length.
	if length > 32 {
		panic("Can only produce HKDF outputs up to 32 bytes long")
	}

	// Extract
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	prk := mac.Sum(nil)

	// Expand
	mac = hmac.New(sha256.New, prk)
	mac.Write(info)
	mac.Write([]byte{1})
	return mac.Sum(nil)[0:length]
}

// Encrypt the plaintext message using AES128/GCM
func encrypt128(plaintext, key, nonce []byte) ([]byte, error) {
	// Add padding. There is a uint16 size followed by that number of bytes of
	// padding.
	// TODO: Right now we leave the size at zero. We should add a padding option
	// that allows the payload size to be obscured.
	//padding := make([]byte, 2)
	//data := append(padding, plaintext...)

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	// TODO: to reduce allocations, allow out buffer to be passed in
	// (all temp buffers can be kept in a context, size is bound)
	return gcm.Seal([]byte{}, nonce, plaintext, nil), nil
}

// Decrypt the message using AES128/GCM
func decrypt128(ciphertext, key, nonce []byte) (plaintext []byte, err error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	plaintext, err = gcm.Open([]byte{}, nonce, ciphertext, nil)
	return
}

// Given the coordinates of a party A's public key and the bytes of party B's
// private key, compute a shared secret.
func sharedSecret(curve elliptic.Curve, pub, priv []byte) ([]byte, error) {
	publicX, publicY := elliptic.Unmarshal(curve, pub)
	if publicX == nil {
		return nil, fmt.Errorf("Couldn't unmarshal public key. Not a valid point on the curve.")
	}
	x, _ := curve.ScalarMult(publicX, publicY, priv)
	return x.Bytes(), nil
}
