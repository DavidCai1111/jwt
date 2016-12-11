package jwt

import (
	"bytes"
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
func Sign(payload map[string]interface{}, secretOrPrivateKey interface{}, opt *SignOption) ([]byte, error) {
	if payload == nil {
		return nil, ErrEmptyPayload
	}

	if secretOrPrivateKey == nil {
		return nil, ErrEmptySecretOrPrivateKey
	}

	hj, err := marshalHeader(opt)

	if err != nil {
		return nil, err
	}

	pj, err := marshalPayload(payload, opt)

	if err != nil {
		return nil, err
	}

	sig, err := algImpMap[opt.Algorithm].
		sign(bytes.Join([][]byte{hj, pj}, periodBytes), secretOrPrivateKey)

	if err != nil {
		return nil, err
	}

	return bytes.Join([][]byte{hj, pj, sig}, periodBytes), nil
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
