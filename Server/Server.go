package main

import (
	"crypto/cipher"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"net"
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
