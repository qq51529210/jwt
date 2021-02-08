package jwt

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"strings"
	"sync"
)

var (
	ErrInvalidToken   = errors.New("invalid token")
	ErrUnsupportedAlg = errors.New("unsupported alg")
	verifierPool      = new(sync.Pool)
)

func init() {
	verifierPool.New = func() interface{} {
		v := new(verifier)
		v.jsonDecoder = json.NewDecoder(&v.jsonBuffer)
		return v
	}
}

// Verifier接口实现
type verifier struct {
	bigint
	headerToken        []byte        // token的header部分，base64格式
	payloadToken       []byte        // token的payload部分，base64格式
	headerPayloadToken []byte        // token的header.payload部分，base64格式
	signToken          []byte        // token的sign部分，base64格式
	jsonDecoder        *json.Decoder // json解码
	jsonBuffer         bytes.Buffer  // json缓存
	headerJsonBuffer   bytes.Buffer  // header数据json
	base64Buffer       []byte        // base64缓存
	hashBuffer         []byte        // hash(header.payload)缓存
	buffer             bytes.Buffer  // 缓存
}

func (v *verifier) base64Decode(b []byte) (err error) {
	n := base64.RawURLEncoding.DecodedLen(len(b))
	if n <= cap(v.base64Buffer) {
		v.base64Buffer = v.base64Buffer[:n]
	} else if n > cap(v.base64Buffer) {
		v.base64Buffer = make([]byte, n)
	}
	n, err = base64.RawURLEncoding.Decode(v.base64Buffer, b)
	if err != nil {
		return
	}
	v.base64Buffer = v.base64Buffer[:n]
	return
}

func (v *verifier) base64Encode(b []byte) {
	n := base64.RawURLEncoding.EncodedLen(len(b))
	if n <= cap(v.base64Buffer) {
		v.base64Buffer = v.base64Buffer[:n]
	} else if n > cap(v.base64Buffer) {
		v.base64Buffer = make([]byte, n)
	}
	base64.RawURLEncoding.Encode(v.base64Buffer, b)
}

func (v *verifier) parseToken(token string) error {
	// 第一个'.'
	i1 := strings.IndexByte(token, '.')
	if i1 < 0 {
		return ErrInvalidToken
	}
	// header
	v.headerToken = v.headerToken[:0]
	v.headerToken = append(v.headerToken, token[:i1]...)
	i1++
	// 第二个'.'
	i2 := strings.IndexByte(token[i1:], '.')
	if i2 < 0 {
		return ErrInvalidToken
	}
	i2 += i1
	// payload
	v.payloadToken = v.payloadToken[:0]
	v.payloadToken = append(v.payloadToken, token[i1:i2]...)
	// header+payload
	v.headerPayloadToken = v.headerPayloadToken[:0]
	v.headerPayloadToken = append(v.headerPayloadToken, token[:i2]...)
	// sign
	v.signToken = v.signToken[:0]
	v.signToken = append(v.signToken, token[i2+1:]...)
	return nil
}

func (v *verifier) hashHeaderPayload(h hash.Hash) {
	// hash(header.payload)
	v.hashBuffer = v.hashBuffer[:0]
	h.Write(v.headerPayloadToken)
	v.hashBuffer = h.Sum(v.hashBuffer)
}

// 验证hs算法
func (v *verifier) hs(h hash.Hash) error {
	if h == nil {
		return ErrUnsupportedAlg
	}
	// hash(header.payload)
	v.hashHeaderPayload(h)
	// base64 decode sign
	v.base64Encode(v.hashBuffer)
	// 比较
	if len(v.signToken) != len(v.base64Buffer) {
		return ErrInvalidToken
	}
	for i := 0; i < len(v.signToken); i++ {
		if v.signToken[i] != v.base64Buffer[i] {
			return ErrInvalidToken
		}
	}
	return nil
}

// 验证es算法
func (v *verifier) es(h hash.Hash, k *ecdsa.PrivateKey) error {
	if h == nil || k == nil {
		return ErrUnsupportedAlg
	}
	// hash(header.payload)
	v.hashHeaderPayload(h)
	// base64 decode sign
	err := v.base64Decode(v.signToken)
	if err != nil {
		return err
	}
	v.bigint.Decode(v.base64Buffer)
	// 验证
	if !ecdsa.Verify(&k.PublicKey, v.hashBuffer, &v.bigint.r, &v.bigint.s) {
		return ErrInvalidToken
	}
	return nil
}

// 验证rs算法
func (v *verifier) rs(h hash.Hash, c crypto.Hash, k *rsa.PrivateKey) error {
	if h == nil || k == nil {
		return ErrUnsupportedAlg
	}
	// hash(header.payload)
	v.hashHeaderPayload(h)
	// base64 decode sign
	err := v.base64Decode(v.signToken)
	if err != nil {
		return err
	}
	// 验证
	return rsa.VerifyPKCS1v15(&k.PublicKey, c, v.hashBuffer, v.base64Buffer)
}

// 验证ps算法
func (v *verifier) ps(h hash.Hash, c crypto.Hash, k *rsa.PrivateKey, o *rsa.PSSOptions) error {
	if h == nil || k == nil {
		return ErrUnsupportedAlg
	}
	// hash(header.payload)
	v.hashHeaderPayload(h)
	// base64 decode sign
	err := v.base64Decode(v.signToken)
	if err != nil {
		return err
	}
	// verify
	return rsa.VerifyPSS(&k.PublicKey, c, v.hashBuffer, v.base64Buffer, o)
}

// 使用默认的provider进行验证
func Verify(token string, provider Provider) (header, payload Claims, err error) {
	v := verifierPool.Get().(*verifier)
	// 切分token
	err = v.parseToken(token)
	if err != nil {
		return nil, nil, err
	}
	// base64(header)
	err = v.base64Decode(v.headerToken)
	if err != nil {
		return nil, nil, err
	}
	// json(base64(header))
	v.jsonBuffer.Reset()
	v.jsonBuffer.Write(v.base64Buffer)
	// header map
	header = make(map[string]interface{})
	err = v.jsonDecoder.Decode(&header)
	if err != nil {
		return nil, nil, err
	}
	// 算法
	s := header["alg"]
	alg, ok := s.(string)
	if !ok {
		return nil, nil, ErrInvalidToken
	}
	// 根据算法解析
	switch strings.ToUpper(alg) {
	case "HS256":
		h := provider.GetHS256()
		err = v.hs(h)
		provider.PutHS256(h)
	case "HS384":
		h := provider.GetHS384()
		err = v.hs(h)
		provider.PutHS384(h)
	case "HS512":
		h := provider.GetHS512()
		err = v.hs(h)
		provider.PutHS512(h)
	case "ES256":
		h := provider.GetSha256()
		err = v.es(h, provider.ES256Key())
		provider.PutSha256(h)
	case "ES384":
		h := provider.GetSha384()
		err = v.es(h, provider.ES384Key())
		provider.PutSha384(h)
	case "ES512":
		h := provider.GetSha512()
		err = v.es(h, provider.ES512Key())
		provider.PutSha512(h)
	case "RS256":
		h := provider.GetSha256()
		err = v.rs(h, crypto.SHA256, provider.RS256Key())
		provider.PutSha256(h)
	case "RS384":
		h := provider.GetSha384()
		err = v.rs(h, crypto.SHA384, provider.RS384Key())
		provider.PutSha384(h)
	case "RS512":
		h := provider.GetSha512()
		err = v.rs(h, crypto.SHA512, provider.RS512Key())
		provider.PutSha512(h)
	case "PS256":
		h := provider.GetSha256()
		err = v.ps(h, crypto.SHA256, provider.PS256Key(), provider.PS256Opt())
		provider.PutSha256(h)
	case "PS384":
		h := provider.GetSha384()
		err = v.ps(h, crypto.SHA384, provider.PS384Key(), provider.PS384Opt())
		provider.PutSha384(h)
	case "PS512":
		h := provider.GetSha512()
		err = v.ps(h, crypto.SHA512, provider.PS512Key(), provider.PS512Opt())
		provider.PutSha512(h)
	default:
		err = fmt.Errorf("unsupported algorithm <%s>", alg)
	}
	if err != nil {
		return nil, nil, err
	}
	// base64(payload)
	err = v.base64Decode(v.payloadToken)
	if err != nil {
		return nil, nil, err
	}
	// json(base64(payload))
	v.jsonBuffer.Reset()
	v.jsonBuffer.Write(v.base64Buffer)
	// payload map
	payload = make(map[string]interface{})
	err = v.jsonDecoder.Decode(&payload)
	if err != nil {
		return nil, nil, err
	}
	verifierPool.Put(v)
	return
}
