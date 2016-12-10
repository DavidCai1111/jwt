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
	s, ok := secret.([]byte)

	if !ok {
		return nil, ErrInvalidKeyType
	}

	h := hmac.New(ha.hashFunc, s)

	if _, err := h.Write(content); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}
