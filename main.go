package main

import (
	"KI5_T2/lib"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

var publicKeyA *rsa.PublicKey
var privateKeyA *rsa.PrivateKey
var publicKeyB *rsa.PublicKey
var privateKeyB *rsa.PrivateKey

var sharedKey = []byte("huri83274dk98sd5")

func init() {
	privateKeyA, _ = rsa.GenerateKey(rand.Reader, 2048)
	publicKeyA = &privateKeyA.PublicKey
	privateKeyB, _ = rsa.GenerateKey(rand.Reader, 2048)
	publicKeyB = &privateKeyB.PublicKey
}

func main() {
	// Langkah 1: generate nonce dan kirim secara terenkripsi dengan public key B
	nonceA, err := lib.GenerateNonce()
	if err != nil {
		fmt.Println("Error Generating Nonce", err)
		return
	}
	fmt.Println("Nonce A:", hex.EncodeToString(nonceA))

	encryptedNonce, err := lib.EncryptNonce(nonceA, publicKeyB)
	if err != nil {
		fmt.Println("Error encrypting nonce B:", err)
		return
	}
	fmt.Println("Encrypted Nonce A:", hex.EncodeToString(encryptedNonce))

	// Langkah 2: B mengirim nonce B terenkripsi dengan public key A
	nonceB, err := lib.GenerateNonce()
	if err != nil {
		fmt.Println("Error Generating Nonce", err)
		return
	}
	fmt.Println("\n\nNonce B:", hex.EncodeToString(nonceB))

	resp, err := lib.SendEncryptedResponse(nonceA, nonceB, encryptedNonce, sharedKey)
	if err != nil {
		fmt.Println("Error sending encrypted response:", err)
		return
	}
	fmt.Println("Response:", string(resp))

	// Langkah 3: A mengirim nonce B terenkripsi dengan public key B
	encryptedNonce, err = lib.EncryptNonce(nonceB, publicKeyB)
	if err != nil {
		fmt.Println("Error encrypting nonce B:", err)
		return
	}
	fmt.Println("Encrypted Nonce B:", hex.EncodeToString(encryptedNonce))

	// Langkah 4: A mengirim secret key terenkripsi dengan private key A lalu public key B
	secretKey := []byte("hbcd9w873qr23fk")
	fmt.Println("\n\nSecret Key Before Encryption in A:", string(secretKey))

	encryptedSecretKey, err := lib.EncryptSecretKey(secretKey, publicKeyB, privateKeyA)
	if err != nil {
		fmt.Println("Error encrypting secret key:", err)
		return
	}
	fmt.Println("Secret Key After Encryption in A:", base64.StdEncoding.EncodeToString(encryptedSecretKey))

	// Langkah 5: B mendekripsi secret key dengan private key B lalu public key A
	_, err = lib.DecryptSecretKey(encryptedSecretKey, publicKeyA, privateKeyB)
	if err != nil {
		fmt.Println("Error decrypting secret key:", err)
		return
	}
	fmt.Println("\nDecrypted Secret Key in B:", string(secretKey))
}
