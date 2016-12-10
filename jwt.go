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
	// ES256 represents ECDSA using P-256 curve and SHA-256 hash algorithm.
	ES256 Algorithm = "ES256"
	// ES384 represents ECDSA using P-384 curve and SHA-384 hash algorithm.
	ES384 Algorithm = "ES384"
	// ES512 represents ECDSA using P-512 curve and SHA-512 hash algorithm.
	ES512 Algorithm = "ES512"
)

var (
	// ErrEmptyPayload is returned when the payload given to Sign is empty.
	ErrEmptyPayload = errors.New("jwt: empty payload")
	// ErrInvalidKeyType is returned when the type of given key is wrong.
	ErrInvalidKeyType = errors.New("jwt: invalid key")

	periodBytes = []byte(".")
	algImpMap   map[Algorithm]algImp
)

type algImp interface {
	sign(content []byte, key interface{}) ([]byte, error)
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