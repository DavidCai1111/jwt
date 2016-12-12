package jwt

import (
	"testing"

	"time"

	"github.com/stretchr/testify/assert"
)

func TestHeader(t *testing.T) {
	assert := assert.New(t)

	t.Run("Should return false when miss typ in map", func(t *testing.T) {
		var h Header = map[string]interface{}{}

		assert.False(h.hasValidType())
	})

	t.Run("Should return false when typ is not string in map", func(t *testing.T) {
		var h Header = map[string]interface{}{"typ": 123}

		assert.False(h.hasValidType())
	})
}

func TestPayloadCheckStringClaim(t *testing.T) {
	assert := assert.New(t)

	t.Run("Should return true when key is empty", func(t *testing.T) {
		var p Payload = map[string]interface{}{}

		assert.True(p.checkStringClaim("test", ""))
	})

	t.Run("Should return false when key is not in map", func(t *testing.T) {
		var p Payload = map[string]interface{}{}

		assert.False(p.checkStringClaim("test", "test"))
	})

	t.Run("Should return false when value is not string", func(t *testing.T) {
		var p Payload = map[string]interface{}{"test": 123}

		assert.False(p.checkStringClaim("test", "123"))
	})
}

func TestPayloadCheckExpiration(t *testing.T) {
	assert := assert.New(t)
	var p Payload = map[string]interface{}{"test": 123}
	assert.False(p.checkExpiration(1 * time.Second))
}
