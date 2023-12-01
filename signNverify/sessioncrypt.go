package signNverify

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

func GenerateSessionKey(length int) ([]byte, error) {
	key := make([]byte, length)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	// Extract the nonce from the ciphertext
	nonce := ciphertext[:12] // 96 bits
	ciphertext = ciphertext[12:]

	// Create a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create a new GCM cipher using the AES block and nonce
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Decrypt the ciphertext using GCM
	message, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return message, nil
}

func Encrypt(message []byte, key []byte) ([]byte, error) {
	// Create a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Generate a random nonce
	nonce := make([]byte, 12) // 96 bits
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Create a new GCM cipher using the AES block and nonce
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Encrypt the message using GCM
	ciphertext := aesGCM.Seal(nil, nonce, message, nil)

	// Append the nonce to the ciphertext (it will be needed for decryption)
	ciphertext = append(nonce, ciphertext...)

	return ciphertext, nil
}