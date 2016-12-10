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

	periodBytes = []byte(".")
	algImpMap   = map[Algorithm]algorithmImplementation{}
)

type algorithmImplementation interface {
	sign(content []byte, key interface{}) ([]byte, error)
	verify(signing []byte, key interface{}) error
}

type header struct {
	Algorithm Algorithm `json:"alg"`
	Typ       string    `json:"typ"`
}

type reservedClaims struct {
	Issuer   string        `json:"iss,omitempty"`
	Exp      time.Duration `json:"exp,omitempty"`
	Subject  string        `json:"sub,omitempty"`
	Audience string        `json:"aud,omitempty"`
}
