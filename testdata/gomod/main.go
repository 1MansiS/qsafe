package main

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

func useRSA() {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	_ = key
}

func useECDSA() {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	hash := make([]byte, 32)
	ecdsa.Sign(rand.Reader, key, hash)
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
	use3DES()
	useDES()
	useRC4()
	useMD5()
	useSHA1()
}
