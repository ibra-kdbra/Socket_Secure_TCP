package main

import (
	"crypto/cipher"
	"crypto/rsa"
	"crypto/x509"
	"net"
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
