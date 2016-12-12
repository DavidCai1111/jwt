package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

func init() {
	algImpMap[RS256] = rsaAlgImp{hash: crypto.SHA256}
	algImpMap[RS384] = rsaAlgImp{hash: crypto.SHA384}
	algImpMap[RS512] = rsaAlgImp{hash: crypto.SHA512}
}

type rsaAlgImp struct {
	hash crypto.Hash
}

func (ra rsaAlgImp) sign(content []byte, privateKey interface{}) ([]byte, error) {
	key, ok := privateKey.(*rsa.PrivateKey)

	if !ok {
		return nil, ErrInvalidKeyType
	}

	h := ra.hash.New()

	h.Write(content)

	return rsa.SignPKCS1v15(rand.Reader, key, ra.hash, h.Sum(nil))
}

func (ra rsaAlgImp) verify(signing []byte, key interface{}) error {
	return nil
}
