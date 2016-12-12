package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestVerfiy(t *testing.T) {
	assert := assert.New(t)

	custom := map[string]interface{}{
		"test1k": "test1v",
		"test2k": float64(234),
	}

	signOpt := &SignOption{
		Algorithm: HS256,
		Issuer:    "testIssuer",
		Subject:   "tsetSubject",
		Audience:  "testAudience",
		ExpiresIn: time.Minute,
	}

	t.Run("Should return ErrInvalidSignature when HMAC sig is invalid", func(t *testing.T) {
		token, err := Sign(custom, "key", signOpt)

		assert.Nil(err)

		_, _, err = Verify(token, "key1", &VerifyOption{Algorithm: HS256})

		assert.Equal(ErrInvalidSignature, err)
	})

	t.Run("Should return ErrInvalidSignature when RSA sig is invalid", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 1024)

		assert.Nil(err)

		token, err := Sign(custom, key, &SignOption{
			Algorithm: RS256,
			Issuer:    "testIssuer",
			Subject:   "tsetSubject",
			Audience:  "testAudience",
			ExpiresIn: time.Minute,
		})

		assert.Nil(err)

		key2, err := rsa.GenerateKey(rand.Reader, 1024)

		assert.Nil(err)

		_, _, err = Verify(token, key2, &VerifyOption{Algorithm: RS256})

		assert.Equal(ErrInvalidSignature, err)
	})

	t.Run("Should return ErrInvalidReservedClaim when aud is miss-match", func(t *testing.T) {
		token, err := Sign(custom, "key", signOpt)

		assert.Nil(err)

		_, _, err = Verify(token, "key", &VerifyOption{
			Algorithm: HS256,
			Issuer:    "testIssuer",
			Subject:   "tsetSubject",
			Audience:  "testAudience-invalid",
		})

		assert.Equal(ErrInvalidReservedClaim, err)
	})

	t.Run("Should return ErrInvalidReservedClaim when iss is miss-match", func(t *testing.T) {
		token, err := Sign(custom, "key", signOpt)

		assert.Nil(err)

		_, _, err = Verify(token, "key", &VerifyOption{
			Algorithm: HS256,
			Issuer:    "testIssuer-invalid",
			Subject:   "tsetSubject",
			Audience:  "testAudience",
		})

		assert.Equal(ErrInvalidReservedClaim, err)
	})

	t.Run("Should return ErrInvalidReservedClaim when sub is miss-match", func(t *testing.T) {
		token, err := Sign(custom, "key", signOpt)

		assert.Nil(err)

		_, _, err = Verify(token, "key", &VerifyOption{
			Algorithm: HS256,
			Issuer:    "testIssuer",
			Subject:   "tsetSubject-invalid",
			Audience:  "testAudience",
		})

		assert.Equal(ErrInvalidReservedClaim, err)
	})

	t.Run("Should return ErrTokenExpired when token expired", func(t *testing.T) {
		token, err := Sign(custom, "key", &SignOption{
			Algorithm: HS256,
			Issuer:    "testIssuer",
			Subject:   "tsetSubject",
			Audience:  "testAudience",
			ExpiresIn: time.Second,
		})

		<-time.After(time.Second * 2)

		assert.Nil(err)

		_, _, err = Verify(token, "key", &VerifyOption{
			Algorithm: HS256,
			Issuer:    "testIssuer",
			Subject:   "tsetSubject",
			Audience:  "testAudience",
		})

		assert.Equal(ErrTokenExpired, err)
	})

	t.Run("Should pass when token expired but IngoreExpiration", func(t *testing.T) {
		token, err := Sign(custom, "key", &SignOption{
			Algorithm: HS256,
			Issuer:    "testIssuer",
			Subject:   "tsetSubject",
			Audience:  "testAudience",
			ExpiresIn: time.Second,
		})

		<-time.After(time.Second * 2)

		assert.Nil(err)

		_, _, err = Verify(token, "key", &VerifyOption{
			Algorithm:        HS256,
			Issuer:           "testIssuer",
			Subject:          "tsetSubject",
			Audience:         "testAudience",
			IngoreExpiration: true,
		})

		assert.Equal(nil, err)
	})

	t.Run("Should return original header and paylaod", func(t *testing.T) {
		token, err := Sign(custom, "key", &SignOption{
			Algorithm: HS256,
			Issuer:    "testIssuer",
			Subject:   "tsetSubject",
			Audience:  "testAudience",
			ExpiresIn: time.Second * 10,
		})

		assert.Nil(err)

		header, payload, err := Verify(token, "key", &VerifyOption{
			Algorithm: HS256,
			Issuer:    "testIssuer",
			Subject:   "tsetSubject",
			Audience:  "testAudience",
		})

		assert.Nil(err)
		assert.Equal(2, len(header))
		assert.Equal(7, len(payload))
	})
}
