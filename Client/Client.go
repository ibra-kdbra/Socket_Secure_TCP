package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"time"
	// "bytes"
	// "crypto/aes"
	// "crypto/cipher"
	// "crypto/rand"
	// "crypto/rsa"
	// "crypto/x509"
	// "crypto/x509/pkix"
	// "encoding/base64"
	// "encoding/json"
	// "encoding/pem"
	// "fmt"
	// "io"
	// "math"
	// "net"
	// "os"
	// "path/filepath"
	// "time"
	// "../tools"
	// "github.com/lxn/walk"
	// . "github.com/lxn/walk/declarative"
)

const serverAddress string = "localhost:8080" //server address
const clientAddress string = "localhost:8983" //c
const Maxconn int = 3                         //Maximum number of connections
// Client is  connect
type Client struct {
	address string
	name    string
	conn    []net.Conn //Connection pooling for parallelism
	buf     []byte     // First define a buf
	priKey  rsa.PrivateKey
	myCert  *x509.Certificate
	key     cipher.Block //temporary certificate
}

func main() {
	var mainWindow *walk.MainWindow
	//var openFileDialog *walk.FileDialog
	var userInfoEdit *walk.LineEdit

	//openFileDialog = new(walk.FileDialog)
	my_Client := new(Client)
	my_Client.address = clientAddress
	my_Client.name = "0"
	my_Client.conn = make([]net.Conn, Maxconn)
	// Create link
	err := my_Client.newConnect(serverAddress, 1)
	if err != nil {
		panic(err)
	}

	go my_Client.receiveconn(1)
	MainWindow{
		AssignTo: &mainWindow,
		Title:    "secure file transfer system",
		MinSize:  Size{Width: 300, Height: 200},
		Layout:   VBox{},
		Children: []Widget{
			Label{
				Text: "User Info:",
			},
			LineEdit{
				AssignTo: &userInfoEdit,
			},
			// Send certificate verification
			PushButton{
				Text: "To submit a certificate application, please enter the client name",
				OnClicked: func() {
					my_Client.name = userInfoEdit.Text()      //client name
					my_Client.SubmmitCsr(userInfoEdit.Text()) //Submit certificate request
					walk.MsgBox(mainWindow, "Success", "Submit certificate application successfully!", walk.MsgBoxIconInformation)

				},
			},
			PushButton{
				Text: "build link",
				OnClicked: func() {
					if my_Client.name == "0" {
						walk.MsgBox(mainWindow, "Failed to establish link. Please check if the certificate exists.", err.Error(), walk.MsgBoxIconError)
					} else {
						my_Client.handleRequst(tools.Open, []byte("Hello"))
					}

				},
			},
			PushButton{
				Text: "Get file directory",
				OnClicked: func() {
					// Get file directory logic
					my_Client.handleRequst(tools.GetFileList, nil)
				},
			},
			PushButton{
				Text: "Send File",
				OnClicked: func() {
					var fileName string
					InputBox(
						mainWindow,
						"Send File",
						"Please enter a file name:",
						&fileName,
					)
					// Logic for sending a file using the entered file name
					my_Client.sendFile(fileName)
				},
			},
			PushButton{
				Text: "Get file",
				OnClicked: func() {
					var fileName string
					InputBox(
						mainWindow,
						"Get file",
						"Please enter a file name:",
						&fileName,
					)
					my_Client.handleRequst(tools.GetFile, nil)

				},
			},

			PushButton{
				Text: "Delete Files",
				OnClicked: func() {
					var fileName string

					InputBox(
						mainWindow,
						"Delete Files",
						"Please enter the file name to be deleted:",
						&fileName,
					)
					// Logic to delete a file using the entered file name
					my_Client.handleRequst(tools.DeleteFile, []byte(fileName))
				},
			},
		},
	}.Run()

}

// newConnect long link
func (c *Client) newConnect(serverAddress string, id int) error {
	// Establish with server TCP connect

	conn, err := net.Dial("tcp", serverAddress)
	if err != nil {
		return fmt.Errorf("unable to connect to server: %v", err)
	}
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		fmt.Println("Connection is not a *net.TCPConn")
	}
	// set up Keepalive
	err = tcpConn.SetKeepAlive(true)
	// set up Keepalive time interval (optional)
	err = tcpConn.SetKeepAlivePeriod(30 * time.Second)
	if err != nil {
		fmt.Println("Error setting Keepalive period:", err)
	}
	c.conn[id] = tcpConn
	return nil
}

// Listen for link data
func (c *Client) receiveconn(id int) {
	for {
		println("I'm waiting to receive")
		var packet tools.DataPacket
		err := json.NewDecoder(c.conn[id]).Decode(&packet)
		if err != nil {
			fmt.Printf("Error reading data from server: %v\n", err)
			break
		}
		// Process specific business logic based on the content of the received data packet
		c.handleDataPacket(packet)
	}
}

// handleRequst  Handle client sending
func (c *Client) handleRequst(flag tools.Flag, byt []byte) error {
	switch flag {
	//Request a certificate
	case tools.RequestCert:
		// Convert byte slice to Base64 encoded string
		contentBase64 := base64.StdEncoding.EncodeToString(byt)
		len := uint32(len(contentBase64))
		packet := tools.DataPacket{
			Flag:          tools.RequestCert,
			FileName:      "",
			PacketCount:   0,
			CurrentPacket: 0,
			PacketSize:    0,
			Nowsize:       len,
			Content:       contentBase64,
			Signature:     "",
		}
		by, err := json.Marshal(packet)
		if err != nil {
			panic(err)
		}
		c.conn[1].Write(by)

		// Add a newline character
		_, err = c.conn[1].Write([]byte("\x1e"))
		if err != nil {
			panic(err)
		}
	// Create link certification
	case tools.Open:
		// Convert byte slice to Base64 encoded string
		contentBase64 := base64.StdEncoding.EncodeToString(byt)
		len := uint32(len(contentBase64))
		packet := tools.DataPacket{
			Flag:          tools.Open,
			FileName:      "",
			PacketCount:   0,
			CurrentPacket: 0,
			PacketSize:    0,
			Nowsize:       len,
			Content:       contentBase64,
			Signature:     "",
		}
		by, err := json.Marshal(packet)
		if err != nil {
			panic(err)
		}
		c.conn[1].Write(by)
		//Add a newline character
		_, err = c.conn[1].Write([]byte("\x1e"))
		if err != nil {
			panic(err)
		}
	//Get file list
	case tools.GetFileList:
		packet := tools.DataPacket{
			Flag:          tools.GetFileList,
			Certname:      "",
			FileName:      "",
			PacketCount:   0,
			CurrentPacket: 0,
			PacketSize:    0,
			Nowsize:       0,
			Content:       "",
			Signature:     "",
		}
		packetByte, err := json.Marshal(packet)
		if err != nil {
			panic("Serialization failed")
		}
		c.conn[1].Write(packetByte)
		_, err = c.conn[1].Write([]byte("\x1e"))
		if err != nil {
			panic(err)
		}
	//Delete Files
	case tools.DeleteFile:
		packet := tools.DataPacket{
			Flag:          tools.DeleteFile,
			Certname:      "",
			FileName:      string(byt),
			PacketCount:   0,
			CurrentPacket: 0,
			PacketSize:    0,
			Nowsize:       0,
			Content:       "",
			Signature:     "",
		}
		packetByte, err := json.Marshal(packet)
		if err != nil {
			panic("Serialization failed")
		}
		c.conn[1].Write(packetByte)
		_, err = c.conn[1].Write([]byte("\x1e"))
		if err != nil {
			panic(err)
		}
	}

	return nil
}

// handleDataPacket Handle incoming requests
func (c *Client) handleDataPacket(packet tools.DataPacket) {

	switch packet.Flag {
	case tools.ReRequestCert:
		cert, err := base64.StdEncoding.DecodeString(packet.Content)
		if err != nil {
			panic("Client parsing certificate error")
		}
		certBlock, _ := pem.Decode(cert)
		if certBlock == nil {
			panic("Client parsing certificate error: PEM Decoding failed")
		}

		c.myCert, err = x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			panic("Client parsing certificate error: Certificate parsing failed")
		}

		os.WriteFile("./"+c.name+"/"+c.name+".crt", certBlock.Bytes, 0644)
		println("Certificate generation successful")
	case tools.Open:
		//What was sent was the certificate from CA
		if packet.FileName == "cert" {
			encryptedKeyBase64 := base64.StdEncoding.EncodeToString(c.myCert.Raw)
			newpacket := tools.DataPacket{
				Flag:          tools.Open,
				FileName:      "cert",
				PacketCount:   0,
				CurrentPacket: 0,
				PacketSize:    0,
				Nowsize:       uint32(len(c.myCert.Raw)),
				Content:       encryptedKeyBase64,
				Signature:     "",
			}
			writebyte, err := json.Marshal(newpacket)
			if err != nil {
				panic("Failed to send certificate")
			}
			c.conn[1].Write(writebyte)
			println("Certificate sent successfully")
			_, err = c.conn[1].Write([]byte("\x1e"))
			if err != nil {
				panic(err)
			}
		}

		//What was sent was a random number.
		if packet.FileName == "key" {
			//The generated random number is now encrypted by the client's public key and needs to be decrypted by the private key.
			random, err := base64.StdEncoding.DecodeString(packet.Content)
			decryptedRandomKey, err := rsa.DecryptPKCS1v15(rand.Reader, &c.priKey, random)
			if err != nil {
				panic("Decryption of random number failed")
			}
			// Create a symmetric key using decrypted random numbers
			block, err := aes.NewCipher(decryptedRandomKey)
			c.key = block //symmetric key
			if err != nil {
				panic("Failed to create symmetric key")
			}
			println("Symmetric key generation successful")
			//  "finish"
			plaintext := []byte("finish")
			ciphertext := make([]byte, len(plaintext))

			// Encryption using symmetric keys
			stream := cipher.NewCTR(c.key, make([]byte, c.key.BlockSize()))
			stream.XORKeyStream(ciphertext, plaintext)

			// Perform the encrypted string base64 coding
			encodedCiphertext := base64.StdEncoding.EncodeToString(ciphertext)

			// create a new DataPacket, and set Content for encrypted "finish" string
			finishPacket := tools.DataPacket{
				Flag:          tools.Open,
				FileName:      "finish",
				PacketCount:   0,
				CurrentPacket: 0,
				PacketSize:    0,
				Nowsize:       uint32(len(ciphertext)),
				Content:       encodedCiphertext,
				Signature:     "", // If a signature is required, please set it here
			}
			// Serialize DataPacket to JSON
			packetBytes, err := json.Marshal(finishPacket)
			if err != nil {
				panic("Serialization finishPacket failed")
			}
			// Send "finish" message to client
			_, err = c.conn[1].Write(packetBytes)
			_, err = c.conn[1].Write([]byte("\x1e"))
			if err != nil {
				panic(err)
			}
			if err != nil {
				panic("Failed to send encrypted 'finish' message")
			}
			println("Sending encrypted 'finish' message successfully")
		}

		if packet.FileName == "finish" {
			println("Secure link established successfully")
		}
	case tools.GetFileList:
		var fileDirWindow *walk.MainWindow
		var fileDirEdit *walk.TextEdit
		MainWindow{
			AssignTo: &fileDirWindow,
			Title:    "File Directory",
			MinSize:  Size{Width: 400, Height: 300},
			Layout:   VBox{},
			Children: []Widget{
				TextEdit{
					AssignTo: &fileDirEdit,
					ReadOnly: true,
					Text:     packet.Content, // Replace with the file directory obtained from the server
				},
			},
		}.Run()
	default:
		fmt.Println("Unknown Flag received:", packet.Flag)
	}

}

// sendFile Send File
func (c *Client) sendFile(filePath string) error {
	// open a file
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Get file information
	fileInfo, err := file.Stat()
	if err != nil {
		return err
	}

	// Count the number of packets
	packetCount := uint32(math.Ceil(float64(fileInfo.Size()) / float64(tools.MaxContentSize)))

	// Read the file contents one by one and send
	for i := uint32(0); i < packetCount; i++ {
		// Read file contents
		buf := make([]byte, tools.MaxContentSize)
		n, err := file.Read(buf)
		if err != nil && err != io.EOF {
			return err
		}

		// Encrypt file contents using symmetric key
		blockSize := c.key.BlockSize()
		cipherText := make([]byte, n)
		stream := cipher.NewCTR(c.key, make([]byte, blockSize))
		stream.XORKeyStream(cipherText, buf[:n])

		// Create packet
		packet := tools.DataPacket{
			Flag:          tools.SendFile,
			FileName:      filepath.Base(filePath),
			PacketCount:   packetCount,
			CurrentPacket: i,
			PacketSize:    uint32(n),
			Nowsize:       0,
			Content:       base64.StdEncoding.EncodeToString(cipherText),
			Signature:     "",
		}

		// The serialized packet is JSON
		packetBytes, err := json.Marshal(packet)
		if err != nil {
			return err
		}

		// Send packet
		_, err = c.conn[1].Write(packetBytes)
		_, err = c.conn[1].Write([]byte("\x1e"))
		if err != nil {
			panic(err)
		}
		if err != nil {
			return err
		}
		// Add a newline character
		_, err = c.conn[1].Write([]byte("\x1e"))
		if err != nil {
			return err
		}
	}

	return nil
}

// SubmmitCsr Enter the name IP to sign the certificate and give the Client his private key.
func (c *Client) SubmmitCsr(name string) {
	//Determine whether a private key exists
	if _, err := os.Stat("./" + name); os.IsNotExist(err) {
		os.Mkdir("./"+name, 0644)
		PrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
		c.priKey = *PrivKey
		if err != nil {
			panic(err)
		}
		priPEM := new(bytes.Buffer)
		pem.Encode(priPEM, &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(PrivKey),
		})
		os.WriteFile("./"+name+"/"+name+".key", priPEM.Bytes(), 0644)
		//After saving the local private key, start transferring the certificate application
		csrTemplate := x509.CertificateRequest{
			Subject: pkix.Name{
				Country:            []string{"CN"},
				Province:           []string{"Beijing"},
				Locality:           []string{"Beijing"},
				Organization:       []string{"GKD"},
				OrganizationalUnit: []string{"GKD"},
				CommonName:         name,
			},
			PublicKey: PrivKey.PublicKey,
		}
		//Create request
		csrByte, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, PrivKey)
		//Create PEM block
		csrPEM := new(bytes.Buffer)
		pem.Encode(csrPEM, &pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csrByte,
		})
		c.handleRequst(tools.RequestCert, csrPEM.Bytes())
		println(csrTemplate.Subject.CommonName)
		if err != nil {
			panic(err)
		}
	}
}

func loadCACertificate(filePath string) *x509.Certificate {
	certPEM, err := os.ReadFile(filePath)
	if err != nil {
		return nil
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		fmt.Errorf("failed to decode PEM block containing the CAcertificate")
		return nil
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}

	return cert
}

func loadCAPrivateKey(filePath string) *rsa.PrivateKey {
	keyPEM, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Errorf("Don't have the CAprivate key")
		return nil
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		fmt.Errorf("failed to decode PEM block containing the CAprivate key")
		return nil
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil
	}

	return key
}
