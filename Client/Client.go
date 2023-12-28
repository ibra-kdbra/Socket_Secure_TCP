package main

import (
	"crypto/cipher"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
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
