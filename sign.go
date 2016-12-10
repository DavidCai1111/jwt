package jwt

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/imdario/mergo"
)

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
func Sign(payload map[string]interface{}, secretOrPrivateKey []byte, opt *SignOption) ([]byte, error) {
	if payload == nil {
		return nil, ErrEmptyPayload
	}

	h := header{
		Algorithm: opt.Algorithm,
		Typ:       "JWT",
	}

	if opt.Header != nil {
		if err := mergo.Map(&h, opt.Header); err != nil {
			return nil, err
		}
	}

	headerJSON, err := json.Marshal(h)

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

	payloadJSON, err := json.Marshal(payload)

	if err != nil {
		return nil, err
	}

	sig := genSig(headerJSON, payloadJSON, secretOrPrivateKey, opt.Algorithm)

	return bytes.Join([][]byte{headerJSON, payloadJSON, sig}, []byte(".")), nil
}

func genSig(hj []byte, pj []byte, secretOrPrivateKey []byte, alg Algorithm) []byte {
	return nil
}
