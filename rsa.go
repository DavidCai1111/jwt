package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"hash"
)

func init() {
	algImpMap[RS256] = rsaAlgImp{ch: crypto.SHA256, hh: crypto.SHA256.New()}
	algImpMap[RS384] = rsaAlgImp{ch: crypto.SHA384, hh: crypto.SHA384.New()}
	algImpMap[RS512] = rsaAlgImp{ch: crypto.SHA512, hh: crypto.SHA512.New()}
}

type rsaAlgImp struct {
	ch crypto.Hash
	hh hash.Hash
}

func (ra rsaAlgImp) sign(content []byte, privateKey interface{}) ([]byte, error) {
	pk, ok := privateKey.(*rsa.PrivateKey)

	if !ok {
		return nil, ErrInvalidKeyType
	}

	return rsa.SignPKCS1v15(rand.Reader, pk, ra.ch, ra.hh.Sum(content))
}

func (ra rsaAlgImp) verify(signing []byte, key interface{}) error {
	return nil
}
