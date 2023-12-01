package lib

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"io"
)

func EncryptMessage(message []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	// Generate a symmetric key
	symmetricKey := make([]byte, 32) // 256 bits for AES-256, adjust as needed
	if _, err := io.ReadFull(rand.Reader, symmetricKey); err != nil {
		return nil, err
	}

	// Encrypt the symmetric key with RSA
	encryptedSymmetricKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, symmetricKey, nil)
	if err != nil {
		return nil, err
	}

	// Encrypt the message with the symmetric key (e.g., AES-GCM)
	encryptedMessage, err := EncryptAES(message, symmetricKey)
	if err != nil {
		return nil, err
	}

	// Combine encrypted symmetric key and encrypted message
	result := append(encryptedSymmetricKey, encryptedMessage...)
	return result, nil
}

func SendEncryptedResponse(nonceA, nonceB, encryptedMessage []byte, sharedKey []byte) ([]byte, error) {
	// Combine nonceA, nonceB, and encryptedMessage into a single response
	response := append(nonceA, nonceB...)
	response = append(response, encryptedMessage...)

	// Encrypt the entire response with AES (using a pre-shared key or another secure key exchange)
	_, err := EncryptAES(response, sharedKey)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func EncryptNonce(nonce []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	encryptedNonce, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, nonce, nil)
	if err != nil {
		return nil, err
	}
	return encryptedNonce, nil
}

func EncryptSecretKey(secretKey []byte, publicKeyB *rsa.PublicKey, privateKeyA *rsa.PrivateKey) ([]byte, error) {
	// Hash the secret key
	hashedSecretKey := sha256.Sum256(secretKey)

	// Encrypt the hashed secret key using B's public key
	encryptedSecretKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKeyB, hashedSecretKey[:], nil)
	if err != nil {
		return nil, err
	}

	// Sign the hashed secret key using A's private key
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKeyA, crypto.SHA256, hashedSecretKey[:])
	if err != nil {
		return nil, err
	}

	// Combine the encrypted secret key and the signature into a single message
	message := append(encryptedSecretKey, signature...)

	return message, nil
}

func DecryptSecretKey(encryptedSecretKey []byte, publicKeyA *rsa.PublicKey, privateKeyB *rsa.PrivateKey) ([]byte, error) {

	encryptedKey := encryptedSecretKey[:len(encryptedSecretKey)-256]
	signature := encryptedSecretKey[len(encryptedSecretKey)-256:]

	hashedSecretKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKeyB, encryptedKey, nil)
	if err != nil {
		return nil, err
	}

	err = rsa.VerifyPKCS1v15(publicKeyA, crypto.SHA256, hashedSecretKey, signature)
	if err != nil {
		return nil, err
	}

	return hashedSecretKey, nil
}

// EncryptAES encrypts the message using AES-GCM with the given key
func EncryptAES(message, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, message, nil)

	result := append(nonce, ciphertext...)
	return result, nil
}
