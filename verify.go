package jwt

import (
	"time"
)

// VerifyOption represents the options of Verify.
type VerifyOption struct {
	Algorithm        Algorithm
	IngoreExpiration bool
	Issuer           string
	Audience         string
	Subject          string
	clockTolerance   time.Duration
}

// Verify decodes the given token and check whether the token is valid.
func Verify(token []byte, secretOrPrivateKey interface{}, opt *VerifyOption) (header Header, payload Payload, err error) {
	var (
		ok bool
		ai algorithmImplementation
	)

	if ai, ok = algImpMap[opt.Algorithm]; !ok {
		return nil, nil, ErrInvalidAlgorithm
	}

	if header, payload, err = ai.verify(token, secretOrPrivateKey); err != nil {
		return nil, nil, ErrInvalidSignature
	}

	if !header.hasValidType() {
		return nil, nil, ErrInvalidHeaderType
	}

	if !payload.checkStringClaim("aud", opt.Audience) ||
		!payload.checkStringClaim("iss", opt.Issuer) ||
		!payload.checkStringClaim("sub", opt.Subject) {
		return nil, nil, ErrInvalidReservedClaim
	}

	if !opt.IngoreExpiration {
		if ok := payload.checkExpiration(opt.clockTolerance); !ok {
			return nil, nil, ErrTokenExpired
		}
	}

	return
}
