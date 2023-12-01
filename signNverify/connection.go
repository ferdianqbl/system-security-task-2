// https://www.sohamkamani.com/golang/rsa-encryption/
// https://gist.github.com/sohamkamani/08377222d5e3e6bc130827f83b0c073e

package signNverify

import (
	// "crypto/rand"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"net"
)

func Send(conn net.Conn, msg []byte, pubKey *rsa.PublicKey) {
	if pubKey != nil {
		// Encrypt the session key with the server's public key
		encryptedMsg, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, msg, nil)
		if err != nil {
			fmt.Println("Error encrypting message:", err)
			return
		}
		_, err = conn.Write(encryptedMsg)
		if err != nil {
			fmt.Println("Error sending encrypted session key to the server:", err)
			return
		}

	} else {
		_, err := conn.Write(msg)
		if err != nil {
			fmt.Println("Error sending encrypted session key to the server:", err)
			return
		}
	}
}

func Recv(conn net.Conn, privKey *rsa.PrivateKey) ([]byte, error) {
	data := make([]byte, 256)
	_, err := conn.Read(data)
	if privKey != nil {
		fmt.Printf("Encrypted Data: %x\n\n", data)
	}

	if err != nil {
		fmt.Println("Error reading message:", err)
		return nil, err
	}

	if privKey != nil {
		// Encrypt the session key with the server's public key
		decryptedData, err := rsa.DecryptOAEP(sha256.New(), nil, privKey, data, nil)
		if err != nil {
			fmt.Println("Error decrypting message:", err)
			return nil, err
		}
		return decryptedData, nil
	}

	return data, nil
}
