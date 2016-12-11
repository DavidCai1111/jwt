package jwt

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestMarshalHeader(t *testing.T) {
	var unmarshaled map[string]interface{}
	assert := assert.New(t)

	t.Run("Should gen json with right default values", func(t *testing.T) {
		j, err := marshalHeader(&SignOption{Algorithm: HS256})

		assert.Nil(err)

		err = json.Unmarshal(j, &unmarshaled)

		assert.Nil(err)
		assert.Equal(2, len(unmarshaled))
		assert.Equal(string(HS256), unmarshaled["alg"])
		assert.Equal("JWT", unmarshaled["typ"])
	})

	t.Run("Should gen json with right custom values", func(t *testing.T) {
		custom := map[string]interface{}{
			"test1k": "test1v",
			"test2k": float64(234),
			"alg":    "test-alg",
		}

		j, err := marshalHeader(&SignOption{Algorithm: HS256, Header: custom})

		assert.Nil(err)

		err = json.Unmarshal(j, &unmarshaled)

		assert.Nil(err)
		assert.Equal(4, len(unmarshaled))
		assert.Equal(string(HS256), unmarshaled["alg"])
		assert.Equal("JWT", unmarshaled["typ"])
		assert.Equal(custom["test1k"], unmarshaled["test1k"])
		assert.Equal(custom["test2k"], unmarshaled["test2k"])
	})
}

func TestMarshalPayload(t *testing.T) {
	var unmarshaled map[string]interface{}
	assert := assert.New(t)

	t.Run("Should gen empty json when no given value", func(t *testing.T) {
		j, err := marshalPayload(nil, &SignOption{})

		assert.Nil(err)

		err = json.Unmarshal(j, &unmarshaled)

		assert.Nil(err)
		assert.Zero(len(unmarshaled))
	})

	t.Run("Should gen json with right default values", func(t *testing.T) {
		opt := &SignOption{
			Issuer:    "testIssuer",
			Subject:   "tsetSubject",
			Audience:  "testAudience",
			ExpiresIn: time.Minute,
		}

		j, err := marshalPayload(nil, opt)

		assert.Nil(err)

		err = json.Unmarshal(j, &unmarshaled)

		assert.Nil(err)
		assert.Equal(4, len(unmarshaled))
		assert.Equal(opt.Issuer, unmarshaled["iss"])
		assert.Equal(opt.Subject, unmarshaled["sub"])
		assert.Equal(opt.Audience, unmarshaled["aud"])
		assert.Equal(float64(60), unmarshaled["exp"])
	})

	t.Run("Should gen json with right custom values", func(t *testing.T) {
		custom := map[string]interface{}{
			"test1k": "test1v",
			"test2k": float64(234),
		}

		j, err := marshalPayload(custom, &SignOption{
			Issuer:    "testIssuer",
			Subject:   "tsetSubject",
			Audience:  "testAudience",
			ExpiresIn: time.Minute,
		})

		assert.Nil(err)

		err = json.Unmarshal(j, &unmarshaled)

		assert.Nil(err)
		assert.Equal(6, len(unmarshaled))
		assert.Equal(custom["test1k"], unmarshaled["test1k"])
		assert.Equal(custom["test2k"], unmarshaled["test2k"])
	})
}

func TestSign(t *testing.T) {
	assert := assert.New(t)

	t.Run("Should return ErrEmptyPayload when no payload given", func(t *testing.T) {
		_, err := Sign(nil, nil, nil)

		assert.Equal(ErrEmptyPayload, err)
	})

	t.Run("Should return ErrEmptySecretOrPrivateKey when no secret given", func(t *testing.T) {
		_, err := Sign(make(map[string]interface{}), nil, nil)

		assert.Equal(ErrEmptySecretOrPrivateKey, err)
	})
}
