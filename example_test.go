package jwt_test

import (
	"crypto/rand"
	"crypto/rsa"
	"time"

	"github.com/DavidCai1993/jwt"
)

var (
	token   []byte
	err     error
	header  jwt.Header
	payload jwt.Payload
)

func ExampleSign() {
	payload := map[string]interface{}{"foo": "bar"}
	// Sign with default (HMAC SHA256)
	token, err = jwt.Sign(payload, "secret", nil)

	// Sign a jwt which ttl is 10s
	token, err = jwt.Sign(payload, "secret", &jwt.SignOption{
		ExpiresIn: 10 * time.Second,
	})

	privateKey, _ := rsa.GenerateKey(rand.Reader, 1024)

	// Sign with RSA SHA256
	token, err = jwt.Sign(payload, privateKey, &jwt.SignOption{
		Algorithm: jwt.RS256,
	})
}

func ExampleVerify() {
	// Verify a token symmetric
	header, payload, err = jwt.Verify(token, "secret", nil)

	// Verify audience
	header, payload, err = jwt.Verify(token, "secret", &jwt.VerifyOption{
		Audience: "fooAud",
	})

	// Verify issuer
	header, payload, err = jwt.Verify(token, "secret", &jwt.VerifyOption{
		Issuer: "fooIss",
	})

	// Verify subject and expiration
	header, payload, err = jwt.Verify(token, "secret", &jwt.VerifyOption{
		Subject:        "fooSub",
		ClockTolerance: 15 * time.Second,
	})
}
