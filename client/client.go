// client.go
package main

import (
	"fmt"
	"net"
	"os"
	"KI5/tugas1/signNverify"
)

func main() {
	// privateKey, publicKey, err := signNverify.GenerateRSAKeyPair(2048)
	// if err != nil {
	// 	fmt.Println("Error generating RSA key pair:", err)
	// 	return
	// }

	// err = signNverify.SavePEMPrivateKey("client_private.pem", privateKey)
	// if err != nil {
	// 	fmt.Println("Error saving private key:", err)
	// 	return
	// }

	// err = signNverify.SavePEMPublicKey("client_public.pem", publicKey)
	// if err != nil {
	// 	fmt.Println("Error saving public key:", err)
	// 	return
	// }

	// err = signNverify.SavePEMPublicKey("../server/client_public.pem", publicKey)
	// if err != nil {
	// 	fmt.Println("Error saving public key:", err)
	// 	return
	// }

	clientConn, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		fmt.Println("Error connecting to server:", err)
		return
	}
	defer clientConn.Close()

	// Specify the desired length of the session key (in bytes)
	sessionKeyLength := 32 // Adjust the length as needed

	// Generate a session key
	sessionKey, err := signNverify.GenerateSessionKey(sessionKeyLength)
	if err != nil {
		fmt.Println("Error generating session key:", err)
		return
	}

	fmt.Printf("Generated session key: %x\n", sessionKey)


	//open server pubkey
	// Specify the filename containing the PEM-encoded PKIX public key
	filename := "server_public.pem"
	// Read and parse the RSA public key from the file
	serverPublicKey, err := signNverify.ReadRSAPublicKeyFromFile(filename)
	if err != nil {
		fmt.Println("Error reading RSA public key from file:", err)
		os.Exit(1)
	}
	
	filename = "client_private.pem"
	// Read and parse the RSA public key from the file
	
	// Step 1 Send session key encrypted with server public key 
	data := sessionKey
	signNverify.Send(clientConn, data, serverPublicKey)
	
	// // Step 3 ok1
	message, _ := signNverify.Recv(clientConn, nil)
	fmt.Printf("SERVER: %s\n", message)
	
	// //BONUS
	// privateKey, err := signNverify.ReadRSAPrivateKeyFromFile(filename)
	// if err != nil {
	// 	fmt.Println("Error reading RSA public key from file:", err)
	// 	os.Exit(1)
	// }
	// data, err = signNverify.SignData(sessionKey, privateKey)
	// if err != nil {
	// 	fmt.Println("Error signing data: ", err)
	// 	return
	// }
	// fmt.Printf("Signature: %d\n", len(data))
	// signNverify.Send(clientConn, data, serverPublicKey)
	
	//STEP 4 Klien kirim pesan ke server, 
	//data yang sudah dienkrip dengan session key.
	data = []byte("This is a secret message.")
	fmt.Printf("Raw Data: %s\n", data)
	data, _ = signNverify.Encrypt(data, sessionKey)
	fmt.Printf("Encrypted Data: %s\n", data)
	signNverify.Send(clientConn, data, serverPublicKey)
	
	//STep 6 ok2
	message, _ = signNverify.Recv(clientConn, nil)
	fmt.Printf("SERVER: %s\n", message)
	// // Verify the signature using the server's public key
	// err = VerifySignature(data, signatureBytes, serverPublicKey)
	// if err != nil {
	// 	fmt.Println("Error verifying signature:", err)
	// 	return
	// }

	// fmt.Println("Successfully received data and verified RSA-PSS signature.")
}
