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
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/urfave/cli/v2"
	"golang.org/x/term"
	"software.sslmate.com/src/go-pkcs12"
	"os"
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

	interPassword, err := promptPassword("Enter password for Intermediary CA: ")
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

	interAgeDays := 1095 // 3 years

	interPriv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	interSerialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	interTemplate := x509.Certificate{
		SerialNumber: interSerialNumber,
		Subject: pkix.Name{
			Organization: []string{"Autentico Intermediary CA"},
			CommonName:   "Autentico Intermediary CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(interAgeDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	interDerBytes, err := x509.CreateCertificate(rand.Reader, &interTemplate, &template, &interPriv.PublicKey, priv)
	if err != nil {
		return err
	}

	interCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: interDerBytes})

	interPrivBytes, err := x509.MarshalPKCS8PrivateKey(interPriv)
	if err != nil {
		return err
	}
	interPrivPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: interPrivBytes})

	interEncryptedKey, err := crypto.Encrypt(interPrivPEM, interPassword)
	if err != nil {
		return err
	}

	interCert := ca.Certificate{
		ID:            ca.GenerateID(),
		Type:          "intermediary",
		CreatedAt:     time.Now(),
		CertPEM:       string(interCertPEM),
		KeyCiphertext: interEncryptedKey,
	}

	if err := ca.InsertCertificate(db.GetWriteDB(), interCert); err != nil {
		return err
	}

	fmt.Printf("Intermediary CA initialized successfully. ID: %s\n", interCert.ID)

	return nil
}

func RunCaRefresh(c *cli.Context) error {
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

	interPassword, err := promptPassword("Enter new password for new Intermediary CA: ")
	if err != nil {
		return err
	}

	// Revoke old intermediary
	oldInter, err := ca.GetActiveIntermediaryCA(db.GetReadDB())
	if err != nil {
		return err
	}
	if oldInter != nil {
		if err := ca.RevokeCertificate(db.GetWriteDB(), oldInter.ID); err != nil {
			return err
		}
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

	fmt.Printf("New Intermediary CA generated and initialized successfully. ID: %s\n", cert.ID)
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

func RunCaMtlsBundle(c *cli.Context) error {
	if c.NArg() < 2 {
		return fmt.Errorf("usage: autentico ca mtls-bundle [-p <password>] <user> <file>")
	}
	username := c.Args().Get(0)
	filename := c.Args().Get(1)

	config.InitBootstrap()
	if _, err := db.InitDB(config.GetBootstrap().DbFilePath); err != nil {
		return err
	}
	defer db.CloseDB()

	u, err := user.UserByUsername(username)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	if u == nil {
		return fmt.Errorf("user not found: %s", username)
	}

	bundlePassword := c.String("p")
	if bundlePassword == "" {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return fmt.Errorf("bundle password not provided and stdin is not a terminal")
		}
		pw, err := promptPassword("Enter password for PKCS#12 bundle: ")
		if err != nil {
			return fmt.Errorf("failed to read bundle password: %w", err)
		}
		bundlePassword = pw
	}

	aesKey := config.GetBootstrap().DbAesKey
	if aesKey == "" {
		return fmt.Errorf("DB AES key not configured")
	}

	readDb := db.GetReadDB()
	writeDb := db.GetWriteDB()

	certRec, err := ca.GetUserCertificate(readDb, u.ID)
	if err != nil {
		return fmt.Errorf("failed to get user certificate: %w", err)
	}

	var parsedCert, parsedInter *x509.Certificate
	var priv *rsa.PrivateKey

	if certRec != nil && certRec.IntermediaryID != nil {
		// Existing certificate found
		interCertRec, err := ca.GetCertificateByID(readDb, *certRec.IntermediaryID)
		if err != nil || interCertRec == nil {
			return fmt.Errorf("failed to get intermediary cert")
		}

		privBytes, err := crypto.DecryptWithKey(certRec.KeyCiphertext, aesKey)
		if err != nil {
			return fmt.Errorf("failed to decrypt user key: %w", err)
		}
		privAny, err := x509.ParsePKCS8PrivateKey(privBytes)
		if err != nil {
			return fmt.Errorf("failed to parse user key: %w", err)
		}
		var ok bool
		priv, ok = privAny.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("user key is not RSA")
		}

		certBlock, _ := pem.Decode([]byte(certRec.CertPEM))
		if certBlock == nil {
			return fmt.Errorf("failed to decode cert pem")
		}
		parsedCert, err = x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse user cert: %w", err)
		}

		interBlock, _ := pem.Decode([]byte(interCertRec.CertPEM))
		if interBlock == nil {
			return fmt.Errorf("failed to decode inter pem")
		}
		parsedInter, err = x509.ParseCertificate(interBlock.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse inter cert: %w", err)
		}
		fmt.Printf("Using existing active certificate for user %s\n", username)

	} else {
		// Generate new certificate
		fmt.Printf("No active certificate found for user %s, generating a new one...\n", username)

		interCertRec, err := ca.GetActiveIntermediaryCA(readDb)
		if err != nil {
			return fmt.Errorf("failed to get active intermediary CA: %w", err)
		}
		if interCertRec == nil {
			return fmt.Errorf("no active intermediary CA found")
		}

		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return fmt.Errorf("cannot prompt for Intermediary CA password, stdin is not a terminal")
		}
		interPassword, err := promptPassword("Enter password for Intermediary CA: ")
		if err != nil {
			return fmt.Errorf("failed to read intermediary password: %w", err)
		}

		interPrivPEM, err := crypto.Decrypt(interCertRec.KeyCiphertext, interPassword)
		if err != nil {
			return fmt.Errorf("failed to decrypt intermediary CA key (wrong password?): %w", err)
		}

		interBlock, _ := pem.Decode(interPrivPEM)
		if interBlock == nil {
			return fmt.Errorf("failed to parse intermediary CA private key PEM")
		}
		interPrivAny, err := x509.ParsePKCS8PrivateKey(interBlock.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse intermediary CA PKCS8 private key: %w", err)
		}
		interPriv, ok := interPrivAny.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("intermediary CA key is not RSA")
		}

		interCertBlock, _ := pem.Decode([]byte(interCertRec.CertPEM))
		if interCertBlock == nil {
			return fmt.Errorf("failed to parse intermediary CA cert PEM")
		}
		parsedInter, err = x509.ParseCertificate(interCertBlock.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse intermediary CA certificate: %w", err)
		}

		priv, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return fmt.Errorf("failed to generate key: %w", err)
		}

		serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			return fmt.Errorf("failed to generate serial: %w", err)
		}

		expireDate := parsedInter.NotAfter
		template := x509.Certificate{
			SerialNumber: serialNumber,
			Subject: pkix.Name{
				Organization: []string{"Autentico User"},
				CommonName:   u.Username,
			},
			NotBefore:             time.Now(),
			NotAfter:              expireDate,
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			BasicConstraintsValid: true,
			IsCA:                  false,
		}

		derBytes, err := x509.CreateCertificate(rand.Reader, &template, parsedInter, &priv.PublicKey, interPriv)
		if err != nil {
			return fmt.Errorf("failed to sign user cert: %w", err)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

		privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return fmt.Errorf("failed to marshal user key: %w", err)
		}

		encryptedKey, err := crypto.EncryptWithKey(privBytes, aesKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt user key: %w", err)
		}

		newCert := ca.Certificate{
			ID:             ca.GenerateID(),
			Type:           "user",
			CreatedAt:      time.Now(),
			CertPEM:        string(certPEM),
			KeyCiphertext:  encryptedKey,
			UserID:         &u.ID,
			IntermediaryID: &interCertRec.ID,
			ExpireDate:     &expireDate,
		}

		if err := ca.InsertCertificate(writeDb, newCert); err != nil {
			return fmt.Errorf("failed to save user cert: %w", err)
		}

		parsedCert, err = x509.ParseCertificate(derBytes)
		if err != nil {
			return fmt.Errorf("failed to parse new cert: %w", err)
		}
	}

	pfxData, err := pkcs12.Encode(rand.Reader, priv, parsedCert, []*x509.Certificate{parsedInter}, bundlePassword)
	if err != nil {
		return fmt.Errorf("failed to create pkcs12 bundle: %w", err)
	}

	if err := os.WriteFile(filename, pfxData, 0600); err != nil {
		return fmt.Errorf("failed to write bundle file: %w", err)
	}

	fmt.Printf("Successfully wrote PKCS#12 bundle to %s\n", filename)
	return nil
}
