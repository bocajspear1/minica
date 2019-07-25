package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"
)

var mux sync.Mutex

// Paths for CA certs and files
const caCertPath = "./certs/ca.crt"
const caKeyPath = "./certs/ca.key"
const caPassPath = "./certs/ca.pass"
const caSerialPath = "./certs/lastserial"

// Paths for server certificates
const serverCertPath = "./certs/server.crt"
const serverKeyPath = "./certs/server.key"
const serverCSRPath = "./certs/server.csr"

func copyFile(src string, dst string) error {

	source, oerr := os.Open(src)
	if oerr != nil {
		return oerr
	}
	defer source.Close()

	destination, cerr := os.Create(dst)
	if cerr != nil {
		return cerr
	}
	defer destination.Close()
	_, copyerr := io.Copy(destination, source)
	return copyerr
}

func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func generateRandomPassword() (string, error) {
	b, err := generateRandomBytes(6)
	return hex.EncodeToString(b), err
}

func generateCACert() error {

	log.Println("Setting up serial")
	ioutil.WriteFile(caSerialPath, []byte(strconv.FormatInt(int64(1000), 10)), 0644)

	newSerial, err := rand.Int(rand.Reader, big.NewInt(10000))
	if err != nil {
		return err
	}

	ca := &x509.Certificate{
		SerialNumber: newSerial,
		Subject: pkix.Name{
			Organization:  []string{"FakerNet CA --FOR LAB USE ONLY-- Generated " + time.Now().String()},
			Country:       []string{"US"},
			Province:      []string{"SomeState"},
			Locality:      []string{"SomeCity"},
			StreetAddress: []string{"1 Someplace Rd"},
			PostalCode:    []string{"11111"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	log.Println("Generating CA key")
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privatekey.PublicKey

	caCert, err := x509.CreateCertificate(rand.Reader, ca, ca, publicKey, privatekey)
	if err != nil {
		return err
	}

	certOut, err := os.Create(caCertPath)
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: caCert})
	certOut.Close()

	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privatekey),
	}

	password, err := generateRandomPassword()
	if err != nil {
		return err
	}

	log.Println("Saving CA password")
	// Write out the CA password
	passwordOut, err := os.OpenFile(caPassPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	passwordOut.Write([]byte(password))
	passwordOut.Close()

	block, err = x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(password), x509.PEMCipherAES256)
	if err != nil {
		return err
	}

	log.Println("Saving CA private key")
	keyOut, err := os.OpenFile(caKeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	pem.Encode(keyOut, block)
	keyOut.Close()

	// Convert and copy the certifcate
	log.Println("Copying certs")
	copyFile(caCertPath, "./web/static/certs/fakernet-ca.crt")
	log.Println("Coverting certs")
	cmd := exec.Command("openssl", "crl2pkcs7", "-nocrl", "-certfile", "./web/static/certs/fakernet-ca.crt", "-out", "./web/static/certs/fakernet-ca.p7b")
	output, err := cmd.Output()
	if err != nil {
		return errors.New("Failed: " + string(output) + " - " + err.Error())
	}

	return nil
}

func generateServerCert(domain string, ip string) error {
	requestSubject := pkix.Name{
		Organization:  []string{"FakerNet CA Server"},
		Country:       []string{"US"},
		Province:      []string{"SomeState"},
		Locality:      []string{"SomeCity"},
		StreetAddress: []string{"1 Someplace Rd"},
		PostalCode:    []string{"11111"},
		CommonName:    domain,
	}

	rawSubject := requestSubject.ToRDNSequence()

	log.Println("Generating server key")
	// Generate keys
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	// Save private key
	log.Println("Saving server private key")
	keyOut, err := os.OpenFile(serverKeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	keyOut.Close()

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return errors.New("Invalid IP address")
	}

	asn1Subj, _ := asn1.Marshal(rawSubject)
	template := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		EmailAddresses:     []string{"fakernet@ca.fake"},
		SignatureAlgorithm: x509.SHA256WithRSA,
		IPAddresses:        []net.IP{parsedIP},
		DNSNames:           []string{domain},
	}

	log.Println("Creating server signing request")
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return err
	}

	crsOut, err := os.Create(serverCSRPath)
	if err != nil {
		return err
	}
	pem.Encode(crsOut, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	crsOut.Close()

	password, err := ioutil.ReadFile(caPassPath)
	if err != nil {
		return err
	}
	csrContents, err := ioutil.ReadFile(serverCSRPath)
	if err != nil {
		return err
	}

	log.Println("Requesting server certificate to be signed")
	certificateContents, err := signCertifcate(string(csrContents), string(password))
	if err != nil {
		return err
	}
	log.Println("Writing server certificate")
	certOut, err := os.Create(serverCertPath)
	certOut.Write(certificateContents)
	certOut.Close()

	return nil
}

func signCertifcate(csrContents string, password string) ([]byte, error) {

	pemBlock, _ := pem.Decode([]byte(csrContents))
	if pemBlock == nil {
		return nil, errors.New("Could not decode PEM format")
	}
	decodedCSR, err := x509.ParseCertificateRequest(pemBlock.Bytes)
	if err != nil {
		return nil, errors.New("Could not parse the certficate request")
	}
	if err = decodedCSR.CheckSignature(); err != nil {

		return nil, errors.New("Signature check failed")
	}

	// Load in CA key
	caKeyContents, err := ioutil.ReadFile(caKeyPath)
	if err != nil {
		return nil, errors.New("Failed to read CA key")
	}

	block, rest := pem.Decode(caKeyContents)
	if len(rest) > 0 {
		return nil, errors.New("Failed to PEM decode CA key")
	}
	der, err := x509.DecryptPEMBlock(block, []byte(password))
	if err != nil {
		return nil, errors.New("Failed to decrypt CA key with provided password")
	}

	caKeyDecrypted := pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: der})

	// Load CA cert
	caCertContents, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		return nil, errors.New("Failed to read CA certificate")
	}

	caCertBlock, rest := pem.Decode(caCertContents)
	if len(rest) > 0 {
		return nil, errors.New("Failed to PEM decode CA certificate")
	}

	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, errors.New("Failed to parse certificate")
	}

	caPair, err := tls.X509KeyPair(pem.EncodeToMemory(caCertBlock), caKeyDecrypted)

	// Get the serial number for the new certificate
	mux.Lock()
	lastSerialRaw, err := ioutil.ReadFile(caSerialPath)
	if err != nil {
		mux.Unlock()
		return nil, err
	}
	lastSerial, err := strconv.ParseInt(string(lastSerialRaw), 10, 64)
	if err != nil {
		mux.Unlock()
		return nil, err
	}
	newSerial := lastSerial + 1
	ioutil.WriteFile(caSerialPath, []byte(strconv.FormatInt(newSerial, 10)), 0644)

	mux.Unlock()

	// create client certificate template
	clientCRTTemplate := x509.Certificate{
		Signature:             decodedCSR.Signature,
		SignatureAlgorithm:    decodedCSR.SignatureAlgorithm,
		PublicKeyAlgorithm:    decodedCSR.PublicKeyAlgorithm,
		PublicKey:             decodedCSR.PublicKey,
		SerialNumber:          big.NewInt(newSerial),
		Issuer:                decodedCSR.Subject,
		Subject:               decodedCSR.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		Extensions:            decodedCSR.Extensions,
		ExtraExtensions:       decodedCSR.ExtraExtensions,
		IPAddresses:           decodedCSR.IPAddresses,
		DNSNames:              decodedCSR.DNSNames,
		IsCA:                  false,
		BasicConstraintsValid: true,
	}

	log.Println("Signing certificate for " + decodedCSR.Subject.CommonName)
	clientCRTRaw, err := x509.CreateCertificate(rand.Reader, &clientCRTTemplate, caCert, decodedCSR.PublicKey, caPair.PrivateKey)
	if err != nil {
		return nil, errors.New("Failed to sign certificate: " + err.Error())
	}

	pemOut := ""
	outWriter := bytes.NewBufferString(pemOut)

	err = pem.Encode(outWriter, &pem.Block{Type: "CERTIFICATE", Bytes: clientCRTRaw})
	if err != nil {
		return nil, errors.New("Failed to write certificate: " + err.Error())
	}

	return outWriter.Bytes(), nil
}

func mainHandler(w http.ResponseWriter, r *http.Request) {
	pageTemplate, err := template.ParseFiles("./web/templates/main.html")
	if err != nil {
		fmt.Fprintf(w, "Template failed")
		return
	}

	if r.Method == "GET" {
		pageTemplate.Execute(w, "")
	} else if r.Method == "POST" {
		var inBuffer bytes.Buffer

		r.ParseMultipartForm(32 << 20)
		csrfile, _, err := r.FormFile("csrfile")
		if err != nil {
			pageTemplate.Execute(w, err.Error())
			return
		}
		defer csrfile.Close()
		io.Copy(&inBuffer, csrfile)
		signedCert, err := signCertifcate(inBuffer.String(), r.FormValue("password"))

		if err != nil {
			http.Error(w, "500: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Disposition", "attachment; filename=newcert.crt")
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Length", strconv.FormatInt(int64(len(signedCert)), 10))
		w.Write(signedCert)
	}

}

func main() {

	args := os.Args[1:]

	if len(args) == 0 {
		log.Fatalln("No CA server domain set")
	}
	if len(args) == 1 {
		log.Fatalln("No IP set")
	}
	if len(args) == 2 {
		log.Fatalln("No port set")
	}

	caDomain := args[0]
	serverIP := args[1]
	serverPort := args[2]

	// Check for CA certs
	_, err := os.Stat(caCertPath)
	if err != nil {
		err = generateCACert()
		if err != nil {
			log.Fatalln("Failed to create CA: " + err.Error())
		}
		err = generateServerCert(caDomain, serverIP)
		if err != nil {
			log.Fatalln("Failed to create server certificate: " + err.Error())
		}
	}

	fs := http.FileServer(http.Dir("web/static/"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))
	http.HandleFunc("/", mainHandler)
	log.Fatal(http.ListenAndServeTLS(":"+serverPort, serverCertPath, serverKeyPath, nil))
}
