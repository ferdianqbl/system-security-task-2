// server.go
package main

import (
	"KI5/tugas1/signNverify"
	"fmt"
	"net"
)

func main() {

	// Generate RSA Key
	privateKey, publicKey, err := signNverify.GenerateRSAKeyPair(2048)
	if err != nil {
		fmt.Println("Error generating RSA key pair:", err)
		return
	}

	// Save Private key to Server
	err = signNverify.SavePEMPrivateKey("server_private.pem", privateKey)
	if err != nil {
		fmt.Println("Error saving private key:", err)
		return
	}

	// Save Public Key to Server
	err = signNverify.SavePEMPublicKey("server_public.pem", publicKey)
	if err != nil {
		fmt.Println("Error saving public key:", err)
		return
	}

	// Save Server Public Key to Client
	err = signNverify.SavePEMPublicKey("../client/server_public.pem", publicKey)
	if err != nil {
		fmt.Println("Error saving public key:", err)
		return
	}

	go func() {
		listener, err := net.Listen("tcp", ":8080")
		if err != nil {
			fmt.Println("Error starting server:", err)
			return
		}
		defer listener.Close()

		for {
			conn, err := listener.Accept()
			if err != nil {
				fmt.Println("Error accepting connection:", err)
				return
			}
			defer conn.Close()

			filename := "server_private.pem"
			privateKey, err := signNverify.ReadRSAPrivateKeyFromFile(filename)
			if err != nil {
				fmt.Println("Error reading private key:", err)
				return
			}

			//STEP 2 Decode session key
			sessionKey, _ := signNverify.Recv(conn, privateKey)
			fmt.Printf("\nDECRYPTED SESSION KEY: %x\n", sessionKey)

			//STEP 3 ok1
			data := []byte("ok1")
			signNverify.Send(conn, data, nil)

			// //BONUS
			// signature, _ := signNverify.Recv(conn, privateKey)
			// fmt.Printf("SIGNATURE: %x\n", signature)

			//STEP 5 Server terima pesan
			//Server jawab "ok2" (asumsi pasti berhasil decodenya)
			message, _ := signNverify.Recv(conn, privateKey)
			message, err = signNverify.Decrypt(message, sessionKey)
			if err != nil {
				fmt.Println("Error decrypting message from client:", err)
				return
			}
			fmt.Printf("\nDECRYPTED MESSAGE FROM CLIENT: %s\n", message)

			data = []byte("ok2")
			signNverify.Send(conn, data, nil)
		}
	}()

	fmt.Println("Server started. Waiting for connections...")
	select {}
}
