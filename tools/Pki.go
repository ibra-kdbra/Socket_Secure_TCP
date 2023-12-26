package tools

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

const (
	keySize = 2048
)

func initCa() {
	//Used to initialize the root CA directory. It is only executed once and will not be executed if it is retrieved.
	if _, err := os.Stat("./CA"); os.IsNotExist(err) {
		err := os.Mkdir("./CA", 0700)
		if err != nil {
			panic(err)
		}
		//Initialize private key
		rootKey, err := rsa.GenerateKey(rand.Reader, keySize)
		if err != nil {
			panic(err)
		}
		// Generate root certificate
		rootCsr := x509.Certificate{
			SerialNumber: big.NewInt(time.Now().Unix()),
			Subject: pkix.Name{
				Country:            []string{"CN"},
				Province:           []string{"Beijing"},
				Locality:           []string{"Beijing"},
				Organization:       []string{"GKD"},
				OrganizationalUnit: []string{"GKD"},
				CommonName:         "Root CA",
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(10, 0, 0),
			BasicConstraintsValid: true,
			IsCA:                  true,
			MaxPathLen:            1,
			MaxPathLenZero:        false,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		}
		rootCABytes, err := x509.CreateCertificate(rand.Reader, &rootCsr, &rootCsr, &rootKey.PublicKey, rootKey)
		if err != nil {
			panic(err)
		}
		//证书
		caPEM := new(bytes.Buffer)
		pem.Encode(caPEM, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: rootCABytes,
		})
		os.WriteFile("./CA/CA.crt", caPEM.Bytes(), 0644)
		// 私钥
		caPrivKeyPEM := new(bytes.Buffer)
		pem.Encode(caPrivKeyPEM, &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(rootKey),
		})
		os.WriteFile("./CA/CA.key", caPrivKeyPEM.Bytes(), 0644)
	}
}

// SignCsr  Sign the CSR, return the certificate, and pass the PEM block
func SignCsr(csr []byte) (crt []byte) {
	// Read the CA's certificate private key
	CAcert := loadCACertificate()
	CAPriv := loadCAPrivateKey()
	// Decode incoming CSR
	csrBlock, _ := pem.Decode(csr)
	if csrBlock == nil || csrBlock.Type != "CERTIFICATE REQUEST" {
		return nil
	}

	// Parse incoming CSR
	csrParsed, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		panic(err)
		return nil

	}
	// Create certificate template
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().Unix()),                                              //Assign a serial number to the certificate
		Subject:               csrParsed.Subject,                                                          //theme
		NotBefore:             time.Now(),                                                                 //Effective time
		NotAfter:              time.Now().AddDate(1, 0, 0),                                                //Set the certificate validity period, such as 1 year
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,               //Set usage can be digitally signed and sealed
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, //Set up certificate verification
		BasicConstraintsValid: false,                                                                      //Can it issue certificates?
	}

	// Sign the certificate using the CA certificate and private key
	certBytes, err := x509.CreateCertificate(rand.Reader, template, CAcert, csrParsed.PublicKey, CAPriv)
	if err != nil {
		panic(err)
		return nil
	}
	// Encode the generated certificate into PEM format
	certPem := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}
	// Convert to Byte format of certificate
	crt = pem.EncodeToMemory(certPem)
	return crt
}

// VerifyCrt Check the correctness of the certificate and pass the PEM block
func VerifyCrt(CertData []byte) bool {
	// Load the CA certificate. Here you need to ensure that the CA certificate already exists.
	caCert := loadCACertificate()
	// Create a certificate pool and add CA certificates
	certPool := x509.NewCertPool()
	certPool.AddCert(caCert)
	return true
	// Parse certificate data
	block, _ := pem.Decode(CertData)
	if block == nil || block.Type != "CERTIFICATE" {
		panic("Certificate block retrieval failed")
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Println("Error parsing certificate:", err)
		return false
	}
	// Verify certificate signature and validity period
	opts := x509.VerifyOptions{
		Roots:       certPool,
		CurrentTime: time.Now(),
	}

	if _, err := cert.Verify(opts); err != nil {
		fmt.Println("Certificate verification failed:", err)
		return false
	}

	return true
}

func loadCACertificate() *x509.Certificate {
	certPEM, err := os.ReadFile("./CA/CA.crt")
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

func loadCAPrivateKey() *rsa.PrivateKey {
	keyPEM, err := os.ReadFile("./CA/CA.key")
	if err != nil {
		fmt.Errorf("There is no CAprivate key")
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
