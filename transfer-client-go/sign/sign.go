package sign

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
)

func CalcHash(content []byte) []byte {
	hash := sha256.New()
	hash.Write(content)
	return hash.Sum(nil)
}

func Sign(content []byte, sk *ecdsa.PrivateKey) ([]byte, []byte, error) {
	hash := CalcHash(content)
	r, s, err := ecdsa.Sign(rand.Reader, sk, hash)
	if err != nil {
		return nil, nil, err
	}
	rText, err := r.MarshalText()
	if err != nil {
		return nil, nil, err
	}
	sText, err := s.MarshalText()
	if err != nil {
		return nil, nil, err
	}
	return rText, sText, nil
}
