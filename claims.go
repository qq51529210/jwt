package jwt

type Claims map[string]interface{}

type Header Claims

type Payload Claims

func (h Header) SetHS256ALG() {
	h["alg"] = "HS256"
}

func (h Header) SetHS384ALG() {
	h["alg"] = "HS384"
}

func (h Header) SetHS512ALG() {
	h["alg"] = "HS512"
}

func (h Header) SetRS256ALG() {
	h["alg"] = "RS256"
}

func (h Header) SetRS384ALG() {
	h["alg"] = "RS384"
}

func (h Header) SetRS512ALG() {
	h["alg"] = "RS512"
}

func (h Header) SetES256ALG() {
	h["alg"] = "ES256"
}

func (h Header) SetES384ALG() {
	h["alg"] = "ES384"
}

func (h Header) SetES512ALG() {
	h["alg"] = "ES512"
}

func (h Header) SetPS256ALG() {
	h["alg"] = "PS256"
}

func (h Header) SetPS384ALG() {
	h["alg"] = "PS384"
}

func (h Header) SetPS512ALG() {
	h["alg"] = "PS512"
}

func (h Header) SetTYP() {
	h["typ"] = "JWT"
}

func (h Header) SetISS(iss interface{}) {
	h["iss"] = iss
}

func (h Header) SetSUB(sub interface{}) {
	h["sub"] = sub
}

func (h Header) SetAUD(aud interface{}) {
	h["aud"] = aud
}

func (h Header) SetEXP(exp interface{}) {
	h["exp"] = exp
}

func (h Header) SetNBF(nbf interface{}) {
	h["nbf"] = nbf
}

func (h Header) SetIAT(iat interface{}) {
	h["iat"] = iat
}

func (h Header) SetJTI(jti interface{}) {
	h["jti"] = jti
}
