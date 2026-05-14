package testdata

import (
	"crypto/des"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/sha1"
)

// RSA key generation — quantum-vulnerable
func genRSAKey() {
	rsa.GenerateKey(rand.Reader, 1024)
}

// RSA encryption — quantum-vulnerable
func encryptRSA(pub *rsa.PublicKey, data []byte) {
	rsa.EncryptPKCS1v15(rand.Reader, pub, data)
}

// RSA signing — quantum-vulnerable
func signRSA(priv *rsa.PrivateKey, digest []byte) {
	rsa.SignPKCS1v15(rand.Reader, priv, 0, digest)
}

// ECDSA key generation — quantum-vulnerable
func genECDSA() {
	ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// ECDSA signing — quantum-vulnerable
func signECDSA(priv *ecdsa.PrivateKey, digest []byte) {
	ecdsa.SignASN1(rand.Reader, priv, digest)
}

// 3DES — deprecated
func tripleDES(key []byte) {
	des.NewTripleDESCipher(key)
}

// DES — deprecated
func desCipher(key []byte) {
	des.NewCipher(key)
}

// RC4 — broken
func rc4Cipher(key []byte) {
	rc4.NewCipher(key)
}

// MD5 — collision-broken
func hashMD5(data []byte) {
	h := md5.New()
	h.Write(data)
	md5.Sum(data)
}

// SHA-1 — deprecated
func hashSHA1(data []byte) {
	h := sha1.New()
	h.Write(data)
	sha1.Sum(data)
}
