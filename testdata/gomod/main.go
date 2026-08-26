package main

import (
	"crypto/des"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"

	"golang.org/x/crypto/curve25519"
)

func useRSA() {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	_ = key
}

func useECDSA() {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	hash := make([]byte, 32)
	ecdsa.Sign(rand.Reader, key, hash)
}

func useED25519() {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	ed25519.Sign(priv, []byte("msg"))
}

func useX25519() {
	var scalar, point [32]byte
	curve25519.X25519(scalar[:], point[:])
}

// Regression fixture: crypto/x509 holds functions for two different
// primitives (ParsePKCS1PrivateKey is RSA, ParseECPrivateKey is ECDSA) —
// confirms goRulesByImport's per-import slice correctly disambiguates
// between them instead of one overwriting the other.
func useX509ParsePrivateKeys(der []byte) {
	x509.ParsePKCS1PrivateKey(der)
	x509.ParseECPrivateKey(der)
}

func use3DES() {
	key := make([]byte, 24)
	des.NewTripleDESCipher(key)
}

func useDES() {
	key := make([]byte, 8)
	des.NewCipher(key)
}

func useRC4() {
	key := make([]byte, 16)
	rc4.NewCipher(key)
}

func useMD5() {
	h := md5.New()
	_ = h
}

func useSHA1() {
	h := sha1.New()
	_ = h
}

func main() {
	useRSA()
	useECDSA()
	useED25519()
	useX25519()
	useX509ParsePrivateKeys(nil)
	use3DES()
	useDES()
	useRC4()
	useMD5()
	useSHA1()
}
