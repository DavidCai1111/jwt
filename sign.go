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

	h := header{Algorithm: opt.Algorithm, Typ: "JWT"}

	if opt.Header != nil {
		if err := mergo.Map(&h, opt.Header); err != nil {
			return nil, err
		}
	}

	hj, err := json.Marshal(h)

	if err != nil {
		return nil, err
	}

	rc := reservedClaims{
		Issuer:   opt.Issuer,
		Exp:      opt.ExpiresIn,
		Subject:  opt.Subject,
		Audience: opt.Audience,
	}

	if err := mergo.Map(&payload, rc); err != nil {
		return nil, err
	}

	pj, err := json.Marshal(payload)

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
