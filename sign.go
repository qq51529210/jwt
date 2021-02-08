package jwt

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"math/big"
	"strings"
	"sync"
)

var (
	signerPool sync.Pool
)

func init() {
	signerPool.New = func() interface{} {
		s := new(signer)
		s.jsonHeaderEncoder = json.NewEncoder(&s.jsonHeader)
		s.jsonPayloadEncoder = json.NewEncoder(&s.jsonPayload)
		return s
	}
}

type signer struct {
	jsonHeaderEncoder  *json.Encoder // json编码器
	jsonPayloadEncoder *json.Encoder // json编码器
	jsonHeader         bytes.Buffer  // json缓存
	jsonPayload        bytes.Buffer  // json缓存
	base64Buffer       []byte        // base64缓存
	tokenBuffer        []byte        // token缓存
	signBuffer         []byte        // 签名的缓存
	bigint                           // es算法缓存
}

// 编码header和payload，写到token缓存
func (s *signer) encode(alg Alg, header, payload Claims) (err error) {
	// header自动填充'typ'和'alg'
	header["jwt"] = "JWT"
	header["alg"] = alg
	// json(header)
	s.jsonHeader.Reset()
	err = s.jsonHeaderEncoder.Encode(header)
	if err != nil {
		return
	}
	// json(payload)
	s.jsonPayload.Reset()
	err = s.jsonPayloadEncoder.Encode(payload)
	if err != nil {
		return
	}
	s.tokenBuffer = s.tokenBuffer[:0]
	// base64(json(header))
	s.base64(s.jsonHeader.Bytes())
	s.tokenBuffer = append(s.tokenBuffer, s.base64Buffer...)
	// .
	s.tokenBuffer = append(s.tokenBuffer, '.')
	// base64(json(payload))
	s.base64(s.jsonPayload.Bytes())
	s.tokenBuffer = append(s.tokenBuffer, s.base64Buffer...)
	return
}

func (s *signer) sign(hash hash.Hash) {
	hash.Write(s.tokenBuffer)
	s.signBuffer = s.signBuffer[:0]
	s.signBuffer = hash.Sum(s.signBuffer)
}

// base64缓存b的数据
func (s *signer) base64(b []byte) {
	n := base64.RawURLEncoding.EncodedLen(len(b))
	if n <= cap(s.base64Buffer) {
		s.base64Buffer = s.base64Buffer[:n]
	} else if n > cap(s.base64Buffer) {
		s.base64Buffer = make([]byte, n)
	}
	base64.RawURLEncoding.Encode(s.base64Buffer, b)
}

func (s *signer) hs(w io.Writer, alg Alg, header, payload Claims, hash hash.Hash) (err error) {
	// header.payload
	err = s.encode(alg, header, payload)
	if err != nil {
		return
	}
	// 签名
	hash.Write(s.tokenBuffer)
	s.signBuffer = s.signBuffer[:0]
	s.signBuffer = hash.Sum(s.signBuffer)
	// .sign
	s.base64(s.signBuffer)
	s.tokenBuffer = append(s.tokenBuffer, '.')
	s.tokenBuffer = append(s.tokenBuffer, s.base64Buffer...)
	// 输出
	_, err = w.Write(s.tokenBuffer)
	return
}

func (s *signer) rs(w io.Writer, alg Alg, header, payload Claims, hash hash.Hash, sha crypto.Hash, key *rsa.PrivateKey) (err error) {
	// header.payload
	err = s.encode(alg, header, payload)
	if err != nil {
		return
	}
	// 哈希签名
	hash.Write(s.tokenBuffer)
	s.signBuffer = s.signBuffer[:0]
	s.signBuffer = hash.Sum(s.signBuffer)
	// rsa签名
	var sign []byte
	sign, err = rsa.SignPKCS1v15(rand.Reader, key, sha, s.signBuffer)
	if err != nil {
		return
	}
	// .sign
	s.base64(sign)
	s.tokenBuffer = append(s.tokenBuffer, '.')
	s.tokenBuffer = append(s.tokenBuffer, s.base64Buffer...)
	// 输出
	_, err = w.Write(s.tokenBuffer)
	return
}

func (s *signer) es(w io.Writer, alg Alg, header, payload Claims, hash hash.Hash, key *ecdsa.PrivateKey) (err error) {
	// header.payload
	err = s.encode(alg, header, payload)
	if err != nil {
		return
	}
	// 哈希签名
	hash.Write(s.tokenBuffer)
	s.signBuffer = s.signBuffer[:0]
	s.signBuffer = hash.Sum(s.signBuffer)
	// rsa签名
	var rb, sb *big.Int
	rb, sb, err = ecdsa.Sign(rand.Reader, key, s.signBuffer)
	if err != nil {
		return
	}
	// .sign
	s.base64(s.bigint.Encode(rb, sb))
	s.tokenBuffer = append(s.tokenBuffer, '.')
	s.tokenBuffer = append(s.tokenBuffer, s.base64Buffer...)
	// 输出
	_, err = w.Write(s.tokenBuffer)
	return
}

func (s *signer) ps(w io.Writer, alg Alg, header, payload Claims, hash hash.Hash, sha crypto.Hash, key *rsa.PrivateKey, opt *rsa.PSSOptions) (err error) {
	// header.payload
	err = s.encode(alg, header, payload)
	if err != nil {
		return
	}
	// 哈希签名
	hash.Write(s.tokenBuffer)
	s.signBuffer = s.signBuffer[:0]
	s.signBuffer = hash.Sum(s.signBuffer)
	// rsa签名
	var sign []byte
	sign, err = rsa.SignPSS(rand.Reader, key, sha, s.signBuffer, opt)
	if err != nil {
		return err
	}
	// .sign
	s.base64(sign)
	s.tokenBuffer = append(s.tokenBuffer, '.')
	s.tokenBuffer = append(s.tokenBuffer, s.base64Buffer...)
	// 输出
	_, err = w.Write(s.tokenBuffer)
	return
}

func SignHS256To(w io.Writer, header, payload Claims, provider Provider) error {
	s := signerPool.Get().(*signer)
	h := provider.GetHS256()
	err := s.hs(w, "HS256", header, payload, h)
	provider.PutHS256(h)
	signerPool.Put(s)
	return err
}

func SignHS384To(w io.Writer, header, payload Claims, provider Provider) error {
	s := signerPool.Get().(*signer)
	h := provider.GetHS384()
	err := s.hs(w, "HS384", header, payload, h)
	provider.PutHS384(h)
	signerPool.Put(s)
	return err
}

func SignHS512To(w io.Writer, header, payload Claims, provider Provider) error {
	s := signerPool.Get().(*signer)
	h := provider.GetHS512()
	err := s.hs(w, "HS512", header, payload, h)
	provider.PutHS512(h)
	signerPool.Put(s)
	return err
}

func SignRS256To(w io.Writer, header, payload Claims, provider Provider) error {
	s := signerPool.Get().(*signer)
	h := provider.GetSha256()
	err := s.rs(w, "RS256", header, payload, h, crypto.SHA256, provider.RS256Key())
	provider.PutSha256(h)
	signerPool.Put(s)
	return err
}

func SignRS384To(w io.Writer, header, payload Claims, provider Provider) error {
	s := signerPool.Get().(*signer)
	h := provider.GetSha384()
	err := s.rs(w, "RS384", header, payload, h, crypto.SHA384, provider.RS384Key())
	provider.PutSha384(h)
	signerPool.Put(s)
	return err
}

func SignRS512To(w io.Writer, header, payload Claims, provider Provider) error {
	s := signerPool.Get().(*signer)
	h := provider.GetSha512()
	err := s.rs(w, "RS512", header, payload, h, crypto.SHA512, provider.RS512Key())
	provider.PutSha512(h)
	signerPool.Put(s)
	return err
}

func SignES256To(w io.Writer, header, payload Claims, provider Provider) error {
	s := signerPool.Get().(*signer)
	h := provider.GetSha256()
	err := s.es(w, "ES256", header, payload, h, provider.ES256Key())
	provider.PutSha256(h)
	signerPool.Put(s)
	return err
}

func SignES384To(w io.Writer, header, payload Claims, provider Provider) error {
	s := signerPool.Get().(*signer)
	h := provider.GetSha384()
	err := s.es(w, "ES384", header, payload, h, provider.ES384Key())
	signerPool.Put(s)
	provider.PutSha384(h)
	return err
}

func SignES512To(w io.Writer, header, payload Claims, provider Provider) error {
	s := signerPool.Get().(*signer)
	h := provider.GetSha512()
	err := s.es(w, "ES512", header, payload, h, provider.ES512Key())
	provider.PutSha512(h)
	signerPool.Put(s)
	return err
}

func SignPS256To(w io.Writer, header, payload Claims, provider Provider) error {
	s := signerPool.Get().(*signer)
	h := provider.GetSha256()
	err := s.ps(w, "PS256", header, payload, h, crypto.SHA256, provider.PS256Key(), provider.PS256Opt())
	provider.PutSha256(h)
	signerPool.Put(s)
	return err
}

func SignPS384To(w io.Writer, header, payload Claims, provider Provider) error {
	s := signerPool.Get().(*signer)
	h := provider.GetSha384()
	err := s.ps(w, "PS384", header, payload, h, crypto.SHA384, provider.PS384Key(), provider.PS384Opt())
	provider.PutSha384(h)
	signerPool.Put(s)
	return err
}

func SignPS512To(w io.Writer, header, payload Claims, provider Provider) error {
	s := signerPool.Get().(*signer)
	h := provider.GetSha512()
	err := s.ps(w, "PS512", header, payload, h, crypto.SHA512, provider.PS512Key(), provider.PS512Opt())
	provider.PutSha512(h)
	signerPool.Put(s)
	return err
}

func SignTo(w io.Writer, alg Alg, header, payload Claims, provider Provider) error {
	switch alg {
	case "HS256":
		return SignHS256To(w, header, payload, provider)
	case "HS384":
		return SignHS384To(w, header, payload, provider)
	case "HS512":
		return SignHS512To(w, header, payload, provider)
	case "RS256":
		return SignRS256To(w, header, payload, provider)
	case "RS384":
		return SignRS384To(w, header, payload, provider)
	case "RS512":
		return SignRS512To(w, header, payload, provider)
	case "ES256":
		return SignES256To(w, header, payload, provider)
	case "ES384":
		return SignES384To(w, header, payload, provider)
	case "ES512":
		return SignES512To(w, header, payload, provider)
	case "PS256":
		return SignPS256To(w, header, payload, provider)
	case "PS384":
		return SignPS384To(w, header, payload, provider)
	case "PS512":
		return SignPS512To(w, header, payload, provider)
	default:
		panic(fmt.Errorf("unsupported algorithm <%s>", alg))
	}
}

func SignHS256WithSecretTo(w io.Writer, header, payload Claims, secret string) error {
	s := signerPool.Get().(*signer)
	s.tokenBuffer = s.tokenBuffer[:0]
	s.tokenBuffer = append(s.tokenBuffer, secret...)
	err := s.hs(w, "HS256", header, payload, hmac.New(crypto.SHA256.New, s.tokenBuffer))
	signerPool.Put(s)
	return err
}

func SignHS384WithSecretTo(w io.Writer, header, payload Claims, secret string) error {
	s := signerPool.Get().(*signer)
	s.tokenBuffer = s.tokenBuffer[:0]
	s.tokenBuffer = append(s.tokenBuffer, secret...)
	err := s.hs(w, "HS384", header, payload, hmac.New(crypto.SHA384.New, s.tokenBuffer))
	signerPool.Put(s)
	return err
}

func SignHS512WithSecretTo(w io.Writer, header, payload Claims, secret string) error {
	s := signerPool.Get().(*signer)
	s.tokenBuffer = s.tokenBuffer[:0]
	s.tokenBuffer = append(s.tokenBuffer, secret...)
	err := s.hs(w, "HS512", header, payload, hmac.New(crypto.SHA512.New, s.tokenBuffer))
	signerPool.Put(s)
	return err
}

func SignHS256(header, payload Claims, provider Provider) (string, error) {
	var str strings.Builder
	return str.String(), SignHS256To(&str, header, payload, provider)
}

func SignHS384(header, payload Claims, provider Provider) (string, error) {
	var str strings.Builder
	return str.String(), SignHS384To(&str, header, payload, provider)
}

func SignHS512(header, payload Claims, provider Provider) (string, error) {
	var str strings.Builder
	return str.String(), SignHS512To(&str, header, payload, provider)
}

func SignRS256(header, payload Claims, provider Provider) (string, error) {
	var str strings.Builder
	return str.String(), SignRS256To(&str, header, payload, provider)
}

func SignRS384(header, payload Claims, provider Provider) (string, error) {
	var str strings.Builder
	return str.String(), SignRS384To(&str, header, payload, provider)
}

func SignRS512(header, payload Claims, provider Provider) (string, error) {
	var str strings.Builder
	return str.String(), SignRS512To(&str, header, payload, provider)
}

func SignES256(header, payload Claims, provider Provider) (string, error) {
	var str strings.Builder
	return str.String(), SignES256To(&str, header, payload, provider)
}

func SignES384(header, payload Claims, provider Provider) (string, error) {
	var str strings.Builder
	return str.String(), SignES384To(&str, header, payload, provider)
}

func SignES512(header, payload Claims, provider Provider) (string, error) {
	var str strings.Builder
	return str.String(), SignES512To(&str, header, payload, provider)
}

func SignPS256(header, payload Claims, provider Provider) (string, error) {
	var str strings.Builder
	return str.String(), SignPS256To(&str, header, payload, provider)
}

func SignPS384(header, payload Claims, provider Provider) (string, error) {
	var str strings.Builder
	return str.String(), SignPS384To(&str, header, payload, provider)
}

func SignPS512(header, payload Claims, provider Provider) (string, error) {
	var str strings.Builder
	return str.String(), SignPS512To(&str, header, payload, provider)
}

func Sign(alg Alg, header, payload Claims, provider Provider) (string, error) {
	var str strings.Builder
	return str.String(), SignTo(&str, alg, header, payload, provider)
}

func SignHS256WithSecret(header, payload Claims, secret string) (string, error) {
	var str strings.Builder
	return str.String(), SignHS256WithSecretTo(&str, header, payload, secret)
}

func SignHS384WithSecret(header, payload Claims, secret string) (string, error) {
	var str strings.Builder
	return str.String(), SignHS384WithSecretTo(&str, header, payload, secret)
}

func SignHS512WithSecret(header, payload Claims, secret string) (string, error) {
	var str strings.Builder
	return str.String(), SignHS512WithSecretTo(&str, header, payload, secret)
}
