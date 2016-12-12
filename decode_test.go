package jwt

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDecode(t *testing.T) {
	assert := assert.New(t)

	t.Run("Should return ErrInvalidToken when token is invalid", func(t *testing.T) {
		_, _, err := decode([]byte("a.b"))

		assert.Equal(ErrInvalidToken, err)
	})

	t.Run("Should return origin header and payload", func(t *testing.T) {
		custom := map[string]interface{}{
			"test1k": "test1v",
			"test2k": float64(234),
		}

		opt := &SignOption{
			Algorithm: HS256,
			Issuer:    "testIssuer",
			Subject:   "tsetSubject",
			Audience:  "testAudience",
			ExpiresIn: time.Minute,
		}

		signed, err := Sign(custom, "key", opt)

		header, payload, err := decode(signed)

		assert.Nil(err)
		assert.Equal(2, len(header))
		assert.Equal(7, len(payload))
		assert.Equal(string(HS256), header["alg"])
		assert.Equal("JWT", header["typ"])
		assert.Equal(opt.Subject, payload["sub"])
		assert.Equal(opt.Issuer, payload["iss"])
		assert.Equal(opt.Audience, payload["aud"])
		assert.Equal(float64(60), payload["exp"])
		assert.Equal(custom["test1k"], payload["test1k"])
		assert.Equal(custom["test2k"], payload["test2k"])
		iat, ok := payload["iat"].(float64)
		assert.True(ok)
		assert.True(time.Now().After(time.Unix(int64(iat), 0)))
	})
}
