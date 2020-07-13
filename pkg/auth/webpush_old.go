package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// Old aesgcm - with separate headers, old style. May be removed, need to confirm new is used on all browsers

// Encrypt a message such that it can be sent using the Web Push protocol.
// You can find out more about the various pieces:
//    - https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding
//    - https://en.wikipedia.org/wiki/Elliptic_curve_Diffie%E2%80%93Hellman
//    - https://tools.ietf.org/html/draft-ietf-webpush-encryption
//
// RFC8030
func Encrypt(key, auth []byte, message string) (*EncryptionContext, error) {
	plaintext := []byte(message)

	// Use ECDH to derive a shared secret between us and the client. We generate
	// a fresh private/public key pair at random every time we encrypt.
	serverPrivateKey, serverPublicKey, err := randomKey()
	if err != nil {
		return nil, err
	}

	return EncryptWithTempKey(key, auth, plaintext, serverPrivateKey, serverPublicKey)
}

// Encrypt a message using Web Push protocol, reusing the temp key.
// A new salt will be used. This is ~20% faster.
func EncryptWithTempKey(key, auth []byte, plaintext []byte,
	serverPrivateKey, serverPublicKey []byte) (*EncryptionContext, error) {

	if len(plaintext) > maxPayloadLength {
		return nil, fmt.Errorf("payload is too large. The max number of bytes is %d, input is %d bytes ", maxPayloadLength, len(plaintext))
	}

	if len(key) == 0 {
		return nil, fmt.Errorf("subscription must include the client's public key")
	}

	if len(auth) == 0 {
		return nil, fmt.Errorf("subscription must include the client's auth value")
	}
	salt, err := randomSalt()
	if err != nil {
		return nil, err
	}

	// Use ECDH to derive a shared secret between us and the client. We generate
	// a fresh private/public key pair at random every time we encrypt.
	secret, err := sharedSecret(curve, key, serverPrivateKey)
	if err != nil {
		return nil, err
	}

	// Derive a Pseudo-Random Key (prk) that can be used to further derive our
	// other encryption parameters. These derivations are described in
	// https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding-00
	prk := hkdf(auth, secret, authInfo, 32)

	// Derive the Content Encryption Key and nonce
	ctx := newContext(key, serverPublicKey)
	cek := newCEK(ctx, salt, prk)
	nonce := newNonce(ctx, salt, prk)

	// Do the actual encryption
	ciphertext, err := encrypt(plaintext, cek, nonce)
	if err != nil {
		return nil, err
	}

	// Return all of the values needed to construct a Web Push HTTP request.
	return &EncryptionContext{Ciphertext: ciphertext, Salt: salt, ServerPublicKey: serverPublicKey}, nil
}

// Decrypt an encrypted messages.
func Decrypt(sub *Subscription, crypt *EncryptionContext, subPrivate []byte) (plain []byte, err error) {
	secret, err := sharedSecret(curve, crypt.ServerPublicKey, subPrivate)
	if err != nil {
		return
	}
	prk := hkdf(sub.Auth, secret, authInfo, 32)

	// Derive the Content Encryption Key and nonce
	ctx := newContext(sub.Key, crypt.ServerPublicKey)
	cek := newCEK(ctx, crypt.Salt, prk)
	nonce := newNonce(ctx, crypt.Salt, prk)

	plain, err = decrypt(crypt.Ciphertext, cek, nonce)
	if err != nil {
		return nil, err
	}
	return
}

func newCEK(ctx, salt, prk []byte) []byte {
	info := newInfo("aesgcm", ctx)
	return hkdf(salt, prk, info, 16)
}

func newNonce(ctx, salt, prk []byte) []byte {
	info := newInfo("nonce", ctx)
	return hkdf(salt, prk, info, 12)
}

// Returns an info record. See sections 3.2 and 3.3 of
// https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding-00.
// The context argument should match what newContext creates
func newInfo(infoType string, context []byte) []byte {
	var info []byte
	info = append(info, []byte("Content-Encoding: ")...)
	info = append(info, []byte(infoType)...)
	info = append(info, 0)
	info = append(info, []byte("P-256")...)
	info = append(info, context...)
	return info
}

// Encrypt the plaintext message using AES128/GCM
func encrypt(plaintext, key, nonce []byte) ([]byte, error) {
	// Add padding. There is a uint16 size followed by that number of bytes of
	// padding.
	// TODO: Right now we leave the size at zero. We should add a padding option
	// that allows the payload size to be obscured.
	padding := make([]byte, 2)
	data := append(padding, plaintext...)

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
	return gcm.Seal([]byte{}, nonce, data, nil), nil
}

// Decrypt the message using AES128/GCM
func decrypt(ciphertext, key, nonce []byte) (plaintext []byte, err error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	plaintext, err = gcm.Open([]byte{}, nonce, ciphertext, nil)
	if err == nil && len(plaintext) >= 2 {
		// TODO: read the first 2 bytes, skip that many bytes padding
		plaintext = plaintext[2:]
	}
	return
}
