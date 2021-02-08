package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"hash"
	"sync"
)

// hash和key提供的接口，应该是一个缓存池
type Provider interface {
	GetHS256() hash.Hash
	GetHS384() hash.Hash
	GetHS512() hash.Hash
	PutHS256(hash.Hash)
	PutHS384(hash.Hash)
	PutHS512(hash.Hash)
	GetSha256() hash.Hash
	GetSha384() hash.Hash
	GetSha512() hash.Hash
	PutSha256(hash.Hash)
	PutSha384(hash.Hash)
	PutSha512(hash.Hash)
	RS256Key() *rsa.PrivateKey
	RS384Key() *rsa.PrivateKey
	RS512Key() *rsa.PrivateKey
	ES256Key() *ecdsa.PrivateKey
	ES384Key() *ecdsa.PrivateKey
	ES512Key() *ecdsa.PrivateKey
	PS256Key() *rsa.PrivateKey
	PS384Key() *rsa.PrivateKey
	PS512Key() *rsa.PrivateKey
	PS256Opt() *rsa.PSSOptions
	PS384Opt() *rsa.PSSOptions
	PS512Opt() *rsa.PSSOptions
}

func NewDefaultProvider(hsSecret256, hsSecret384, hsSecret512 string) *DefaultProvider {
	p := new(DefaultProvider)
	// hash
	{
		p.sha256.New = func() interface{} {
			return crypto.SHA256.New()
		}
		p.sha384.New = func() interface{} {
			return crypto.SHA384.New()
		}
		p.sha512.New = func() interface{} {
			return crypto.SHA512.New()
		}
	}
	// hs
	{
		p.hs256.New = func() interface{} {
			return hmac.New(crypto.SHA256.New, []byte(hsSecret256))
		}
		p.hs384.New = func() interface{} {
			return hmac.New(crypto.SHA384.New, []byte(hsSecret384))
		}
		p.hs512.New = func() interface{} {
			return hmac.New(crypto.SHA512.New, []byte(hsSecret512))
		}
	}
	// rs
	{
		p.GenRS256Key()
		p.GenRS384Key()
		p.GenRS512Key()
	}
	// es
	{
		p.GenES256Key()
		p.GenES384Key()
		p.GenES512Key()
	}
	// ps
	{
		p.GenPS256Key()
		p.GenPS384Key()
		p.GenPS512Key()
	}
	return p
}

type DefaultProvider struct {
	sha256   sync.Pool         // 哈希缓存
	sha384   sync.Pool         // 哈希缓存
	sha512   sync.Pool         // 哈希缓存
	hs256    sync.Pool         // hs算法的哈希缓存
	hs384    sync.Pool         // hs算法的哈希缓存
	hs512    sync.Pool         // hs算法的哈希缓存
	rs256    *rsa.PrivateKey   // rs算法私钥
	rs384    *rsa.PrivateKey   // rs算法私钥
	rs512    *rsa.PrivateKey   // rs算法私钥
	es256    *ecdsa.PrivateKey // es算法私钥
	es384    *ecdsa.PrivateKey // es算法私钥
	es512    *ecdsa.PrivateKey // es算法私钥
	ps256    *rsa.PrivateKey   // ps算法私钥
	ps384    *rsa.PrivateKey   // ps算法私钥
	ps512    *rsa.PrivateKey   // ps算法私钥
	ps256Opt *rsa.PSSOptions   // ps算法加密选项
	ps384Opt *rsa.PSSOptions   // ps算法加密选项
	ps512Opt *rsa.PSSOptions   // ps算法加密选项
}

func (p *DefaultProvider) GetHS256() hash.Hash {
	return p.hs256.Get().(hash.Hash)
}

func (p *DefaultProvider) GetHS384() hash.Hash {
	return p.hs384.Get().(hash.Hash)
}

func (p *DefaultProvider) GetHS512() hash.Hash {
	return p.hs512.Get().(hash.Hash)
}

func (p *DefaultProvider) PutHS256(hash hash.Hash) {
	hash.Reset()
	p.hs256.Put(hash)
}

func (p *DefaultProvider) PutHS384(hash hash.Hash) {
	hash.Reset()
	p.hs384.Put(hash)
}

func (p *DefaultProvider) PutHS512(hash hash.Hash) {
	hash.Reset()
	p.hs512.Put(hash)
}

func (p *DefaultProvider) GetSha256() hash.Hash {
	return p.sha256.Get().(hash.Hash)
}

func (p *DefaultProvider) GetSha384() hash.Hash {
	return p.sha384.Get().(hash.Hash)
}

func (p *DefaultProvider) GetSha512() hash.Hash {
	return p.sha512.Get().(hash.Hash)
}

func (p *DefaultProvider) PutSha256(hash hash.Hash) {
	hash.Reset()
	p.sha256.Put(hash)
}

func (p *DefaultProvider) PutSha384(hash hash.Hash) {
	hash.Reset()
	p.sha384.Put(hash)
}

func (p *DefaultProvider) PutSha512(hash hash.Hash) {
	hash.Reset()
	p.sha512.Put(hash)
}

func (p *DefaultProvider) RS256Key() *rsa.PrivateKey {
	return p.rs256
}

func (p *DefaultProvider) RS384Key() *rsa.PrivateKey {
	return p.rs384
}

func (p *DefaultProvider) RS512Key() *rsa.PrivateKey {
	return p.rs512
}

func (p *DefaultProvider) ES256Key() *ecdsa.PrivateKey {
	return p.es256
}

func (p *DefaultProvider) ES384Key() *ecdsa.PrivateKey {
	return p.es384
}

func (p *DefaultProvider) ES512Key() *ecdsa.PrivateKey {
	return p.es512
}

func (p *DefaultProvider) PS256Key() *rsa.PrivateKey {
	return p.ps256
}

func (p *DefaultProvider) PS384Key() *rsa.PrivateKey {
	return p.ps384
}

func (p *DefaultProvider) PS512Key() *rsa.PrivateKey {
	return p.ps512
}

func (p *DefaultProvider) PS256Opt() *rsa.PSSOptions {
	return p.ps256Opt
}

func (p *DefaultProvider) PS384Opt() *rsa.PSSOptions {
	return p.ps384Opt
}

func (p *DefaultProvider) PS512Opt() *rsa.PSSOptions {
	return p.ps512Opt
}

func (p *DefaultProvider) SetHS256Key(secret string) {
	p.hs256.New = func() interface{} {
		return hmac.New(crypto.SHA256.New, []byte(secret))
	}
}

func (p *DefaultProvider) SetHS384Key(secret string) {
	p.hs384.New = func() interface{} {
		return hmac.New(crypto.SHA256.New, []byte(secret))
	}
}

func (p *DefaultProvider) SetHS512Key(secret string) {
	p.hs512.New = func() interface{} {
		return hmac.New(crypto.SHA256.New, []byte(secret))
	}
}

func (p *DefaultProvider) SetRS256Key(key *rsa.PrivateKey) {
	p.rs256 = key
}

func (p *DefaultProvider) SetRS384Key(key *rsa.PrivateKey) {
	p.rs384 = key
}

func (p *DefaultProvider) SetRS512Key(key *rsa.PrivateKey) {
	p.rs512 = key
}

func (p *DefaultProvider) SetPS256Key(key *rsa.PrivateKey, opt *rsa.PSSOptions) {
	p.ps256 = key
	p.ps256Opt = opt
}

func (p *DefaultProvider) SetPS384Key(key *rsa.PrivateKey, opt *rsa.PSSOptions) {
	p.ps384 = key
	p.ps384Opt = opt
}

func (p *DefaultProvider) SetPS512Key(key *rsa.PrivateKey, opt *rsa.PSSOptions) {
	p.ps512 = key
	p.ps512Opt = opt
}

func (p *DefaultProvider) SetES256Key(key *ecdsa.PrivateKey) {
	p.es256 = key
}

func (p *DefaultProvider) SetES384Key(key *ecdsa.PrivateKey) {
	p.es384 = key
}

func (p *DefaultProvider) SetES512Key(key *ecdsa.PrivateKey) {
	p.es512 = key
}

func (p *DefaultProvider) GenRS256Key() {
	p.rs256, _ = rsa.GenerateKey(rand.Reader, 2048)
}

func (p *DefaultProvider) GenRS384Key() {
	p.rs384, _ = rsa.GenerateKey(rand.Reader, 2048)
}

func (p *DefaultProvider) GenRS512Key() {
	p.rs512, _ = rsa.GenerateKey(rand.Reader, 2048)
}

func (p *DefaultProvider) GenPS256Key() {
	p.ps256, _ = rsa.GenerateKey(rand.Reader, 2048)
}

func (p *DefaultProvider) GenPS384Key() {
	p.ps384, _ = rsa.GenerateKey(rand.Reader, 2048)
}

func (p *DefaultProvider) GenPS512Key() {
	p.ps512, _ = rsa.GenerateKey(rand.Reader, 2048)
}

func (p *DefaultProvider) GenES256Key() {
	p.es256, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func (p *DefaultProvider) GenES384Key() {
	p.es384, _ = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
}

func (p *DefaultProvider) GenES512Key() {
	p.es512, _ = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
}
