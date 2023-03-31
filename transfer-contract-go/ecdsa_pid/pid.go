package ecdsa_pid

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"math/big"
	"transfer-contract-go/utils"
)

func VerifySign(pkBytes, content, rText, sText []byte) error {
	key, err := x509.ParsePKIXPublicKey(pkBytes)
	if err != nil {
		return err
	}
	publicKey := key.(*ecdsa.PublicKey)
	var r, s big.Int
	err = r.UnmarshalText(rText)
	if err != nil {
		return err
	}
	err = s.UnmarshalText(sText)
	if err != nil {
		return err
	}
	hash := utils.CalcSha256(content)
	verify := ecdsa.Verify(publicKey, hash, &r, &s)
	if !verify {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}
