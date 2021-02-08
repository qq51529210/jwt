package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"math/bits"
	"strings"
)

type Alg string

func IsSupportedAlg(alg string) bool {
	switch alg {
	case "HS256", "HS384", "HS512",
		"RS256", "RS384", "RS512",
		"ES256", "ES384", "ES512",
		"PS256", "PS384", "PS512":
		return true
	default:
		return false
	}
}

const (
	HS256Alg Alg = "HS256"
	HS384Alg Alg = "HS384"
	HS512Alg Alg = "HS512"
	RS256Alg Alg = "RS256"
	RS384Alg Alg = "RS384"
	RS512Alg Alg = "RS512"
	PS256Alg Alg = "PS256"
	PS384Alg Alg = "PS384"
	PS512Alg Alg = "PS512"
	ES256Alg Alg = "ES256"
	ES384Alg Alg = "ES384"
	ES512Alg Alg = "ES512"
)

// es算法的缓存长度
const _s = bits.UintSize / 8

// es算法结果
type bigint struct {
	b    []byte
	r, s big.Int
}

// go/src/math/big/nat.go func (z nat) bytes(buf []byte) (i int)， go/src/math/big/int.go func (x *Int) Bytes() []byte
func (b *bigint) Encode(r, s *big.Int) []byte {
	sz, rz := s.Bits(), r.Bits()
	n := (len(sz) + len(rz)) * _s
	if cap(b.b) < n {
		b.b = make([]byte, n)
	} else {
		b.b = b.b[:n]
	}
	i := len(b.b)
	for _, d := range sz {
		for j := 0; j < _s; j++ {
			i--
			b.b[i] = byte(d)
			d >>= 8
		}
	}
	for i < len(b.b) && b.b[i] == 0 {
		i++
	}
	for _, d := range rz {
		for j := 0; j < _s; j++ {
			i--
			b.b[i] = byte(d)
			d >>= 8
		}
	}
	for i < len(b.b) && b.b[i] == 0 {
		i++
	}
	return b.b[i:]
}

func (b *bigint) Decode(buf []byte) {
	n := len(buf) / 2
	b.r.SetBytes(buf[:n])
	b.s.SetBytes(buf[n:])
}

func GenRSPem() (string, string) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	data := x509.MarshalPKCS1PrivateKey(key)
	block := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   data,
	}
	var pri strings.Builder
	_ = pem.Encode(&pri, &block)
	//
	data = x509.MarshalPKCS1PublicKey(&key.PublicKey)
	block = pem.Block{
		Type:    "RSA PUBLIC KEY",
		Headers: nil,
		Bytes:   data,
	}
	var pub strings.Builder
	_ = pem.Encode(&pub, &block)
	return pri.String(), pub.String()
}

func GenPSPem() (string, string) {
	return GenRSPem()
}

func genESPem(key *ecdsa.PrivateKey) (string, string) {
	data, _ := x509.MarshalECPrivateKey(key)
	block := pem.Block{
		Type:    "ES PRIVATE KEY",
		Headers: nil,
		Bytes:   data,
	}
	var pri strings.Builder
	_ = pem.Encode(&pri, &block)
	//
	data, _ = x509.MarshalPKIXPublicKey(&key.PublicKey)
	block = pem.Block{
		Type:    "ES PUBLIC KEY",
		Headers: nil,
		Bytes:   data,
	}
	var pub strings.Builder
	_ = pem.Encode(&pub, &block)
	return pri.String(), pub.String()
}

func GenES256Pem() (string, string) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return genESPem(key)
}

func GenES384Pem() (string, string) {
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	return genESPem(key)
}

func GenES512Pem() (string, string) {
	key, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	return genESPem(key)
}
