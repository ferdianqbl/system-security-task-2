package signNverify

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func ReadRSAPrivateKeyFromFile(filename string) (*rsa.PrivateKey, error) {
	// Read the PEM-encoded private key from the file
	pemBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// Decode the PEM block
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	// Parse the RSA private key
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func ReadRSAPublicKeyFromFile(filename string) (*rsa.PublicKey, error) {
	// Read the PEM-encoded public key from the file
	pemBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// Decode the PEM block
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}

	// Parse the X.509 certificate to get the public key
	cert, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	// Extract the RSA public key from the certificate
	rsaPublicKey, ok := cert.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not an RSA key")
	}

	return rsaPublicKey, nil
}

func SavePEMPrivateKey(filename string, key *rsa.PrivateKey) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	privBytes := x509.MarshalPKCS1PrivateKey(key)

	err = pem.Encode(file, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})
	if err != nil {
		return err
	}

	fmt.Printf("Private key saved to %s\n", filename)
	return nil
}

func SavePEMPublicKey(filename string, pubkey *rsa.PublicKey) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	pubBytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return err
	}

	err = pem.Encode(file, &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	if err != nil {
		return err
	}

	fmt.Printf("Public key saved to %s\n", filename)
	return nil
}