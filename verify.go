package jwt

import (
	"time"
)

// VerifyOption represents the options of Verify.
type VerifyOption struct {
	Algorithm Algorithm
	Issuer    string
	Audience  string
	Subject   string
	// IngoreExpiration specifies whether to validate the
	// expiration of the token.
	IngoreExpiration bool
	// clockTolerance specifies the time duration to tolerate when
	// checking the expiration of the token.
	clockTolerance time.Duration
}

// Verify will return the decoded header and payload if the signature,
// optional expiration, audience, issuer and subject are valid.
// When using HMAC algorithm, secretOrPrivateKey's type should be string or []
// byte , when using RSA algorithm, secretOrPrivateKey's type should be
// rsa.PrivateKey. If the opt given is nil, it will use the defualt HS256
// algorithm.
func Verify(token []byte, secretOrPrivateKey interface{}, opt *VerifyOption) (header Header, payload Payload, err error) {
	var (
		ok bool
		ai algorithmImplementation
	)

	if opt == nil {
		opt = &VerifyOption{}
	}

	if opt.Algorithm == "" {
		opt.Algorithm = HS256
	}

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
