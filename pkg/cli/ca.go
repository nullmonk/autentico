package cli

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/eugenioenko/autentico/pkg/ca"
	"github.com/eugenioenko/autentico/pkg/ca/crypto"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/urfave/cli/v2"
	"golang.org/x/term"
)

func promptPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	bytePassword, err := term.ReadPassword(0) // 0 is stdin
	fmt.Println()
	if err != nil {
		return "", err
	}
	return string(bytePassword), nil
}

func RunCaInit(c *cli.Context) error {
	config.InitBootstrap()
	if _, err := db.InitDB(config.GetBootstrap().DbFilePath); err != nil {
		return err
	}
	defer db.CloseDB()

	ageDays := c.Int("age")
	if ageDays <= 0 {
		ageDays = 3650 // 10 years
	}

	password, err := promptPassword("Enter master password for Root CA: ")
	if err != nil {
		return err
	}

	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Autentico Root CA"},
			CommonName:   "Autentico Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(ageDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	encryptedKey, err := crypto.Encrypt(privPEM, password)
	if err != nil {
		return err
	}

	cert := ca.Certificate{
		ID:            ca.GenerateID(),
		Type:          "ca",
		CreatedAt:     time.Now(),
		CertPEM:       string(certPEM),
		KeyCiphertext: encryptedKey,
	}

	if err := ca.InsertCertificate(db.GetWriteDB(), cert); err != nil {
		return err
	}

	fmt.Printf("Root CA initialized successfully. ID: %s\n", cert.ID)
	return nil
}

func RunCaInter(c *cli.Context) error {
	config.InitBootstrap()
	if _, err := db.InitDB(config.GetBootstrap().DbFilePath); err != nil {
		return err
	}
	defer db.CloseDB()

	ageDays := c.Int("age")
	if ageDays <= 0 {
		ageDays = 1095 // 3 years
	}

	caCertRec, err := ca.GetActiveRootCA(db.GetReadDB())
	if err != nil {
		return fmt.Errorf("failed to get active root CA: %w", err)
	}
	if caCertRec == nil {
		return fmt.Errorf("no active Root CA found. Run 'autentico ca init' first.")
	}

	rootPassword, err := promptPassword("Enter master password for Root CA: ")
	if err != nil {
		return err
	}

	rootPrivPEM, err := crypto.Decrypt(caCertRec.KeyCiphertext, rootPassword)
	if err != nil {
		return fmt.Errorf("failed to decrypt root CA key (wrong password?): %w", err)
	}

	rootBlock, _ := pem.Decode(rootPrivPEM)
	if rootBlock == nil {
		return fmt.Errorf("failed to parse root CA private key PEM")
	}
	rootPrivAny, err := x509.ParsePKCS8PrivateKey(rootBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse root CA PKCS8 private key: %w", err)
	}
	rootPriv, ok := rootPrivAny.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("root CA key is not RSA")
	}

	rootCertBlock, _ := pem.Decode([]byte(caCertRec.CertPEM))
	if rootCertBlock == nil {
		return fmt.Errorf("failed to parse root CA cert PEM")
	}
	rootCert, err := x509.ParseCertificate(rootCertBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse root CA certificate: %w", err)
	}

	interPassword, err := promptPassword("Enter new password for Intermediary CA: ")
	if err != nil {
		return err
	}

	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Autentico Intermediary CA"},
			CommonName:   "Autentico Intermediary CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(ageDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, rootCert, &priv.PublicKey, rootPriv)
	if err != nil {
		return err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	encryptedKey, err := crypto.Encrypt(privPEM, interPassword)
	if err != nil {
		return err
	}

	cert := ca.Certificate{
		ID:            ca.GenerateID(),
		Type:          "intermediary",
		CreatedAt:     time.Now(),
		CertPEM:       string(certPEM),
		KeyCiphertext: encryptedKey,
	}

	if err := ca.InsertCertificate(db.GetWriteDB(), cert); err != nil {
		return err
	}

	fmt.Printf("Intermediary CA initialized successfully. ID: %s\n", cert.ID)
	return nil
}

func RunCaDelete(c *cli.Context) error {
	config.InitBootstrap()
	if _, err := db.InitDB(config.GetBootstrap().DbFilePath); err != nil {
		return err
	}
	defer db.CloseDB()

	if err := ca.DeleteAllCertificates(db.GetWriteDB()); err != nil {
		return err
	}

	fmt.Println("All certificates deleted successfully.")
	return nil
}
