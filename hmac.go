package jwt

import (
	"crypto"
	"crypto/hmac"
	"hash"
)

func init() {
	algImpMap[HS256] = hmacAlgImp{hashFunc: crypto.SHA256.New}
	algImpMap[HS384] = hmacAlgImp{hashFunc: crypto.SHA384.New}
	algImpMap[HS512] = hmacAlgImp{hashFunc: crypto.SHA512.New}
}

type hmacAlgImp struct {
	hashFunc func() hash.Hash
}

func (ha hmacAlgImp) sign(content []byte, secret interface{}) ([]byte, error) {
	var s []byte

	switch secret.(type) {
	case []byte:
		s = secret.([]byte)
	case string:
		s = []byte(secret.(string))
	default:
		return nil, ErrInvalidKeyType
	}

	h := hmac.New(ha.hashFunc, s)

	h.Write(content)

	return h.Sum(nil), nil
}

func (ha hmacAlgImp) verify(signing []byte, secret interface{}) error {
	return nil
}
