package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/imdario/mergo"
)

// SignOption represents the options of Sign.
type SignOption struct {
	Algorithm   Algorithm
	ExpiresIn   time.Duration
	Audience    string
	Issuer      string
	JWTID       string
	Subject     string
	NoTimestamp bool
	Header      map[string]interface{}
}

// Sign encodes the given payload and serect to the JSON web token.
func Sign(payload map[string]interface{}, secretOrPrivateKey interface{}, opt *SignOption) (signed []byte, err error) {
	if payload == nil {
		return nil, ErrEmptyPayload
	}

	if secretOrPrivateKey == nil {
		return nil, ErrEmptySecretOrPrivateKey
	}

	var hj, pj, sig []byte

	if hj, err = marshalHeader(opt); err != nil {
		return nil, err
	}

	hBase64 := []byte(base64.StdEncoding.EncodeToString(hj))

	if pj, err = marshalPayload(payload, opt); err != nil {
		return nil, err
	}

	pBase64 := []byte(base64.StdEncoding.EncodeToString(pj))

	algImp, ok := algImpMap[opt.Algorithm]

	if !ok {
		return nil, ErrInvalidAlgorithm
	}

	if sig, err = algImp.sign(bytes.Join([][]byte{hBase64, pBase64}, periodBytes),
		secretOrPrivateKey); err != nil {
		return nil, err
	}

	signed = bytes.Join([][]byte{hBase64, pBase64, sig}, periodBytes)

	return
}

func marshalHeader(opt *SignOption) ([]byte, error) {
	h := map[string]interface{}{
		"alg": opt.Algorithm,
		"typ": "JWT",
	}

	if opt.Header != nil {
		if err := mergo.Map(&h, opt.Header); err != nil {
			return nil, err
		}
	}

	return json.Marshal(h)
}

func marshalPayload(payload map[string]interface{}, opt *SignOption) ([]byte, error) {
	claims := make(map[string]interface{})

	if opt.Issuer != "" {
		claims["iss"] = opt.Issuer
	}
	if opt.ExpiresIn != 0 {
		claims["exp"] = opt.ExpiresIn / 1e9
	}
	if opt.Subject != "" {
		claims["sub"] = opt.Subject
	}
	if opt.Audience != "" {
		claims["aud"] = opt.Audience
	}

	if err := mergo.Map(&claims, payload); err != nil {
		return nil, err
	}

	return json.Marshal(claims)
}
