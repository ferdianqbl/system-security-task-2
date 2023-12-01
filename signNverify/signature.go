package signNverify

import (
	"crypto"
	"crypto/rsa"
	"crypto/rand"
	"crypto/sha256"
)

func SignData(data []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	hashed := sha256.Sum256(data)
	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hashed[:], nil)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

func VerifySignature(data, signature []byte, publicKey *rsa.PublicKey) error {
	hashed := sha256.Sum256(data)
	return rsa.VerifyPSS(publicKey, crypto.SHA256, hashed[:], signature, nil)
}