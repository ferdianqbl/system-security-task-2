package lib

import (
	"crypto/rand"
)

// Generate nonce
func GenerateNonce() ([]byte, error) {
	// Choose an appropriate length for your nonce
	nonceLength := 16 // 16 bytes will result in a 24-character base64-encoded string

	// Create a byte slice to store the random nonce
	nonceBytes := make([]byte, nonceLength)

	// Use the crypto/rand package to generate random bytes for the nonce
	_, err := rand.Read(nonceBytes)
	if err != nil {
		return nil, err
	}

	return nonceBytes, nil
}
