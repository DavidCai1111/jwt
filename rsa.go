package jwt

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
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

func (ra rsaAlgImp) verify(token []byte, privateKey interface{}) (header Header, payload Payload, err error) {
	if header, payload, err = decode(token); err != nil {
		return
	}

	signatureReceive, err := base64.StdEncoding.DecodeString(string(bytes.Split(token, periodBytes)[2]))

	if err != nil {
		return
	}

	signatureExpect, err := ra.sign(token[0:bytes.LastIndexByte(token, '.')], privateKey)

	if err != nil {
		return
	}

	if !bytes.Equal(signatureReceive, signatureExpect) {
		return nil, nil, ErrInvalidSignature
	}

	return
}
