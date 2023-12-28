package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
)

// import (
// 	"bufio"
// 	"crypto/aes"
// 	"crypto/cipher"
// 	"crypto/rand"
// 	"crypto/rsa"
// 	"crypto/x509"
// 	"encoding/base64"
// 	"encoding/json"
// 	"encoding/pem"
// 	"fmt"
// 	"io"
// 	"io/fs"
// 	"net"
// 	"os"
// 	"path/filepath"

// 	"../tools"
// )

const FilePath = "./File"

var goID int = 0 //Thread ID
const severhost = "localhost:8080"

type FileInfo struct {
	Name string
	Size int64
}

// Server object
type Server struct {
	listener  net.Listener
	buffer    []tools.DataPacket          //Document package
	fileCache map[string][]byte           //Daemon thread pool
	certPool  map[string]x509.Certificate //Used to store certified certificates
	// CA Certificate and private key
	caCert *x509.Certificate
	caKey  *rsa.PrivateKey
	ket    cipher.Block //temporary symmetric key
}

// NewServer Create a new server and listen for handshakes
func main() {
	server := new(Server)
	server.fileCache = make(map[string][]byte)
	//Read ca information
	server.caCert = loadCACertificate()
	server.caKey = loadCAPrivateKey()
	//Initialize server listener
	err := server.Start(severhost)
	if err != nil {
		fmt.Println("Error starting server:", err)
	}

}

// Start Initialize listener
func (s *Server) Start(address string) (err error) {

	s.listener, err = net.Listen("tcp", address)
	if err != nil {
		return err
	}
	defer s.listener.Close()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			continue
		}

		go s.handleDataPacket(conn) //handle connections
	}
}

// handleDataPacket Process incoming messages
func (s *Server) handleDataPacket(conn net.Conn) {
	//Continuous reading
	defer conn.Close()
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\x1e')
		if err != nil {
			if err == io.EOF {
				fmt.Println("Connection closed")
			} else {
				fmt.Printf("Error reading data from server: %v\n", err)
			}
			break
		}
		line = line[:len(line)-1]
		var packet tools.DataPacket
		err = json.Unmarshal([]byte(line), &packet)
		if err != nil {
			fmt.Printf("Error decoding JSON data: %v\n", err)
			continue
		}

		// Process specific business logic based on the content of the received data packet
		switch packet.Flag {
		//Return certification certificate
		case tools.RequestCert:
			//Decode base64
			contentbyte, err := base64.StdEncoding.DecodeString(packet.Content)
			// Parse CSR PEM from Content field of DataPacket
			csrBlock, _ := pem.Decode(contentbyte)
			//Compare whether to accept completely
			if uint32(len(packet.Content)) != packet.Nowsize {
				fmt.Println("Error parse CSR PEM block")
				println("The parsed length is" + string(len(packet.Content)))
				return
			}
			// Parse CSR data
			csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
			if err != nil {
				fmt.Println("Error parsing CSR:", err)
				return
			}
			// verify CSR
			err = csr.CheckSignature()
			if err != nil {
				fmt.Println("Error checking CSR signature:", err)
				return
			}
			// Process CSR, issue certificates, etc.
			certByte := tools.SignCsr(contentbyte)
			//Initialize message package
			content := base64.StdEncoding.EncodeToString(certByte)
			newpacket := tools.DataPacket{
				Flag:          tools.ReRequestCert,
				FileName:      "",
				PacketCount:   0,
				CurrentPacket: 0,
				PacketSize:    0,
				Nowsize:       uint32(len(certByte)),
				Content:       content,
				Signature:     "",
			}
			writebyte, err := json.Marshal(newpacket)
			if err != nil {
				panic("Failed to return certificate")
			}
			println("Serialization certificate successful" + string(writebyte))
			conn.Write(writebyte)
			println("Write successfully")
		//Handle link authentication
		case tools.Open:
			//Decode base64
			contentbyte, err := base64.StdEncoding.DecodeString(packet.Content)
			if err != nil {
				panic("Error parsing Open")
			}
			//If it is to say hello
			if string(contentbyte) == "Hello" {
				certByte := loadCACertificate().Raw
				content := base64.StdEncoding.EncodeToString(certByte)
				newpacket := tools.DataPacket{
					Flag:          tools.Open,
					FileName:      "cert",
					PacketCount:   0,
					CurrentPacket: 0,
					PacketSize:    0,
					Nowsize:       uint32(len(certByte)),
					Content:       content,
					Signature:     "",
				}
				writebyte, err := json.Marshal(newpacket)
				if err != nil {
					panic("Verification failed to return Sever certificate")
				}
				conn.Write(writebyte)
			}
			//If a certificate is sent, a random number encrypted by the Client's public key will be returned if the verification is successful.
			if packet.FileName == "cert" {
				//Decode base64
				contentbyte, err := base64.StdEncoding.DecodeString(packet.Content)
				if err != nil {
					panic("Decoding failed")
				}
				//Parse certificate
				cert, err := x509.ParseCertificate(contentbyte)
				if err != nil {
					panic("Failed to parse certificate")
				}
				//Verify the certificate successfully sends a random number used to generate a symmetric key
				if tools.VerifyCrt(contentbyte) == true {

					// Extract public key from certificate
					publicKey := cert.PublicKey.(*rsa.PublicKey)

					// Generate random numbers
					randomKey := make([]byte, 32) // Assuming a 256-bit symmetric key
					if _, err := io.ReadFull(rand.Reader, randomKey); err != nil {
						panic("Failed to generate random number")
					}

					// Encrypt random numbers using public key
					encryptedKey, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, randomKey)
					if err != nil {
						panic("Encrypted random number failed")
					}

					// Create symmetric key
					block, err := aes.NewCipher(randomKey)
					s.ket = block
					if err != nil {
						panic("Failed to create symmetric key")
					}

					// Send encrypted random numbers
					encryptedKeyBase64 := base64.StdEncoding.EncodeToString(encryptedKey)
					newpacket := tools.DataPacket{
						Flag:          tools.Open,
						FileName:      "key",
						PacketCount:   0,
						CurrentPacket: 0,
						PacketSize:    0,
						Nowsize:       uint32(len(encryptedKey)),
						Content:       encryptedKeyBase64,
						Signature:     "",
					}
					writebyte, err := json.Marshal(newpacket)
					if err != nil {
						panic("Verification failed to return random number")
					}
					conn.Write(writebyte)
					println("Verification returns random number successfully")
				}
			}
			//If what is sent a random number encrypted with a symmetric key
			if packet.FileName == "finish" {
				// decoding base64
				contentByte, err := base64.StdEncoding.DecodeString(packet.Content)
				if err != nil {
					panic("Base64 Decoding failed")
				}
				// Decrypt message
				decrypted := make([]byte, len(contentByte))
				stream := cipher.NewCTR(s.ket, make([]byte, s.ket.BlockSize()))
				stream.XORKeyStream(decrypted, contentByte)
				// Check whether the decrypted message is "finish"
				if string(decrypted) == "finish" {
					// Create a new DataPacket and set FileName to "finish"
					finishPacket := tools.DataPacket{
						Flag:          tools.Open, // Use appropriate logos
						FileName:      "finish",
						PacketCount:   0,
						CurrentPacket: 0,
						PacketSize:    0,
						Nowsize:       0,
						Content:       "",
						Signature:     "",
					}

					//Serialize DataPacket to JSON
					writeByte, err := json.Marshal(finishPacket)
					if err != nil {
						panic("Serialization finishPacket failed")
					}
					// Send a "finish" message to the server
					conn.Write(writeByte)
					println("Received finish")
				}
			}
		//Process incoming documents
		case tools.SendFile:
			// Decrypt file contents
			cipherText, err := base64.StdEncoding.DecodeString(packet.Content)
			if err != nil {
				panic(err)
			}
			blockSize := s.ket.BlockSize()
			plainText := make([]byte, len(cipherText))
			stream := cipher.NewCTR(s.ket, make([]byte, blockSize))
			stream.XORKeyStream(plainText, cipherText)
			// Append decrypted file contents to cache
			s.fileCache[packet.FileName] = append(s.fileCache[packet.FileName], plainText...)
			// Check if all packets are received
			if packet.CurrentPacket+1 == packet.PacketCount {
				// Open or create a file
				savePath := filepath.Join("./File", packet.FileName)
				file, err := os.OpenFile(savePath, os.O_CREATE|os.O_WRONLY, 0644)
				if err != nil {
					panic(err)
				}

				// Write file contents to file
				_, err = file.Write(s.fileCache[packet.FileName])
				if err != nil {
					panic(err)
				}
				file.Close()
				// Empty the cache
				delete(s.fileCache, packet.FileName)
			}
		//Get file directory
		case tools.GetFileList:
			File, err := ReadFileDir("./File")
			if err != nil {
				panic(err)
			}
			var Stri string
			for key, _ := range File {
				Stri += File[key].String()
			}
			println(Stri)
			packet := tools.DataPacket{
				Flag:          tools.GetFileList,
				Certname:      "",
				FileName:      "",
				PacketCount:   0,
				CurrentPacket: 0,
				PacketSize:    0,
				Nowsize:       0,
				Content:       Stri,
				Signature:     "",
			}
			byte1, _ := json.Marshal(packet)
			conn.Write(byte1)
		//Delete Files
		case tools.DeleteFile:
			os.Remove(FilePath + "/" + packet.FileName)
			println("successfully deleted")
		default:
			fmt.Println("Unknown Flag:", packet.Flag)
		}
	}

}

func (s *Server) hadleRequst(flag tools.Flag, packet tools.DataPacket) {

}
