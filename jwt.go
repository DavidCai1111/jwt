package jwt

import (
	"errors"
	"time"
)

// Algorithm represents a supported hash algorithms.
type Algorithm string

const (
	// HS256 represents HMAC using SHA-256 hash algorithm.
	HS256 Algorithm = "HS256"
	// HS384 represents HMAC using SHA-384 hash algorithm.
	HS384 Algorithm = "HS384"
	// HS512 represents HMAC using SHA-512 hash algorithm.
	HS512 Algorithm = "HS512"
	// RS256 represents RSASSA using SHA-256 hash algorithm.
	RS256 Algorithm = "RS256"
	// RS384 represents RSASSA using SHA-384 hash algorithm.
	RS384 Algorithm = "RS384"
	// RS512 represents RSASSA using SHA-512 hash algorithm.
	RS512 Algorithm = "RS512"
)

var (
	// ErrEmptyPayload is returned when the payload given to Sign is empty.
	ErrEmptyPayload = errors.New("jwt: empty payload")
	// ErrEmptySecretOrPrivateKey is returned when the secret or private key
	// given is empy.
	ErrEmptySecretOrPrivateKey = errors.New("jwt: empty secret or private key")
	// ErrInvalidKeyType is returned when the type of given key is wrong.
	ErrInvalidKeyType = errors.New("jwt: invalid key")
	// ErrInvalidSignature is returned when the given signature is invalid.
	ErrInvalidSignature = errors.New("jwt: invalid signature")
	// ErrInvalidHeaderType is returned when "typ" not found in header and is not
	// "JWT".
	ErrInvalidHeaderType = errors.New("jwt: invalid header type")
	// ErrInvalidToken is returned when the formation of the token is not
	// "XXX.XXX.XXX".
	ErrInvalidToken = errors.New("jwt: invalid token")
	// ErrInvalidAlgorithm is returned when the algorithm is not support.
	ErrInvalidAlgorithm = errors.New("jwt: invalid algorithm")
	// ErrInvalidReservedClaim is returned when the reserved claim dose not match
	// with the given value in VerifyOption.
	ErrInvalidReservedClaim = errors.New("jwt: invalid reserved claim")
	// ErrPayloadMissingIat is returned when the payload is missing "iat".
	ErrPayloadMissingIat = errors.New("jwt: payload missing iat")
	// ErrPayloadMissingExp is returned when the payload is missing "exp".
	ErrPayloadMissingExp = errors.New("jwt: payload missing exp")
	// ErrTokenExpired is returned when the token is expired.
	ErrTokenExpired = errors.New("jwt: token expired")

	periodBytes = []byte(".")
	algImpMap   = map[Algorithm]algorithmImplementation{}
)

type algorithmImplementation interface {
	sign(content []byte, key interface{}) ([]byte, error)
	verify(signing []byte, key interface{}) (Header, Payload, error)
}

// Header represents a JWT header.
type Header map[string]interface{}

func (h Header) hasValidType() bool {
	var (
		typ      interface{}
		received string
		ok       bool
	)

	if typ, ok = h["typ"]; !ok {
		return false
	}

	if received, ok = typ.(string); !ok {
		return false
	}

	return received == "JWT"
}

// Payload represents a JWT payload.
type Payload map[string]interface{}

func (p Payload) checkStringClaim(key, expected string) bool {
	if expected == "" {
		return true
	}

	var (
		received string
		v        interface{}
		ok       bool
	)

	if v, ok = p[key]; !ok {
		return false
	}

	if received, ok = v.(string); !ok {
		return false
	}

	return expected == received
}

func (p Payload) iat() (t time.Time, err error) {
	var (
		iat float64
		ok  bool
		v   interface{}
	)

	if v, ok = p["iat"]; !ok {
		return t, ErrPayloadMissingIat
	}

	if iat, ok = v.(float64); !ok {
		return t, ErrPayloadMissingIat
	}

	return time.Unix(int64(iat), 0), nil
}

func (p Payload) expTime() (t time.Time, err error) {
	var (
		exp float64
		iat time.Time
		ok  bool
		v   interface{}
	)

	if v, ok = p["exp"]; !ok {
		return t, ErrPayloadMissingExp
	}

	if exp, ok = v.(float64); !ok {
		return t, ErrPayloadMissingExp
	}

	if iat, err = p.iat(); err != nil {
		return
	}

	return iat.Add(time.Duration(int64(exp * 1e9))), nil
}

func (p Payload) checkExpiration(tolerance time.Duration) bool {
	if exp, err := p.expTime(); err == nil {
		return time.Now().Add(tolerance).Before(exp)
	}

	return false
}
