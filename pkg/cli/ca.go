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
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("stdin is not a terminal, cannot prompt for password interactively")
	}
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
		ageDays = 10950 // 30 years
	}

	password := c.String("ca-key-pass")
	if password == "" {
		pw, err := promptPassword("Enter master password for Root CA: ")
		if err != nil {
			return err
		}
		password = pw
	}

	interPassword := c.String("client-key-pass")
	if interPassword == "" {
		pw, err := promptPassword("Enter password for Intermediary CA: ")
		if err != nil {
			return err
		}
		interPassword = pw
	}

	serverInterPassword := config.GetBootstrap().DbAesKey
	if serverInterPassword == "" {
		return fmt.Errorf("DB AES key not configured")
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

	expireDate := template.NotAfter
	cert := ca.Certificate{
		ID:            ca.GenerateID(),
		Type:          "ca",
		CreatedAt:     time.Now(),
		CertPEM:       string(certPEM),
		KeyCiphertext: encryptedKey,
		ExpireDate:    &expireDate,
	}

	if err := ca.InsertCertificate(db.GetWriteDB(), cert); err != nil {
		return err
	}

	fmt.Printf("Root CA initialized successfully. ID: %s\n", cert.ID)

	interAgeDays := 1825 // 5 years

	// Generate Client Intermediary
	clientInterPriv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	clientInterSerialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	clientInterTemplate := x509.Certificate{
		SerialNumber: clientInterSerialNumber,
		Subject: pkix.Name{
			Organization: []string{"Autentico Client Intermediary CA"},
			CommonName:   "Autentico Client Intermediary CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(interAgeDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	clientInterDerBytes, err := x509.CreateCertificate(rand.Reader, &clientInterTemplate, &template, &clientInterPriv.PublicKey, priv)
	if err != nil {
		return err
	}

	clientInterCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientInterDerBytes})

	clientInterPrivBytes, err := x509.MarshalPKCS8PrivateKey(clientInterPriv)
	if err != nil {
		return err
	}
	clientInterPrivPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: clientInterPrivBytes})

	clientInterEncryptedKey, err := crypto.Encrypt(clientInterPrivPEM, interPassword)
	if err != nil {
		return err
	}

	clientInterExpire := clientInterTemplate.NotAfter
	clientInterCert := ca.Certificate{
		ID:            ca.GenerateID(),
		Type:          "client-int",
		CreatedAt:     time.Now(),
		CertPEM:       string(clientInterCertPEM),
		KeyCiphertext: clientInterEncryptedKey,
		ExpireDate:    &clientInterExpire,
	}

	if err := ca.InsertCertificate(db.GetWriteDB(), clientInterCert); err != nil {
		return err
	}

	fmt.Printf("Client Intermediary CA initialized successfully. ID: %s\n", clientInterCert.ID)

	// Generate Server Intermediary
	serverInterPriv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	serverInterSerialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	serverInterTemplate := x509.Certificate{
		SerialNumber: serverInterSerialNumber,
		Subject: pkix.Name{
			Organization: []string{"Autentico Server Intermediary CA"},
			CommonName:   "Autentico Server Intermediary CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(interAgeDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	serverInterDerBytes, err := x509.CreateCertificate(rand.Reader, &serverInterTemplate, &template, &serverInterPriv.PublicKey, priv)
	if err != nil {
		return err
	}

	serverInterCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverInterDerBytes})

	serverInterPrivBytes, err := x509.MarshalPKCS8PrivateKey(serverInterPriv)
	if err != nil {
		return err
	}
	serverInterPrivPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverInterPrivBytes})

	serverInterEncryptedKey, err := crypto.Encrypt(serverInterPrivPEM, serverInterPassword)
	if err != nil {
		return err
	}

	serverInterExpire := serverInterTemplate.NotAfter
	serverInterCert := ca.Certificate{
		ID:            ca.GenerateID(),
		Type:          "server-int",
		CreatedAt:     time.Now(),
		CertPEM:       string(serverInterCertPEM),
		KeyCiphertext: serverInterEncryptedKey,
		ExpireDate:    &serverInterExpire,
	}

	if err := ca.InsertCertificate(db.GetWriteDB(), serverInterCert); err != nil {
		return err
	}

	fmt.Printf("Server Intermediary CA initialized successfully. ID: %s\n", serverInterCert.ID)

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
		ageDays = 1825 // 5 years
	}

	caCertRec, err := ca.GetActiveRootCA(db.GetReadDB())
	if err != nil {
		return fmt.Errorf("failed to get active root CA: %w", err)
	}
	if caCertRec == nil {
		return fmt.Errorf("no active Root CA found: run 'autentico ca init' first")
	}

	clientInter, err := ca.GetActiveIntermediaryCA(db.GetReadDB(), "client-int")
	if err != nil {
		return err
	}
	serverInter, err := ca.GetActiveIntermediaryCA(db.GetReadDB(), "server-int")
	if err != nil {
		return err
	}

	refreshClient := clientInter == nil || (clientInter.ExpireDate != nil && time.Until(*clientInter.ExpireDate) < 365*24*time.Hour)
	refreshServer := serverInter == nil || (serverInter.ExpireDate != nil && time.Until(*serverInter.ExpireDate) < 365*24*time.Hour)

	if !refreshClient && !refreshServer {
		fmt.Println("No intermediary CA needs to be refreshed (both have > 1 year remaining).")
		return nil
	}

	rootPassword := c.String("ca-key-pass")
	if rootPassword == "" {
		pw, err := promptPassword("Enter master password for Root CA: ")
		if err != nil {
			return err
		}
		rootPassword = pw
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

	if refreshClient {
	interPassword := c.String("client-key-pass")
	if interPassword == "" {
		pw, err := promptPassword("Enter new password for new Intermediary CA: ")
		if err != nil {
			return err
		}
		interPassword = pw
	}

		if clientInter != nil {
			if err := ca.RevokeCertificate(db.GetWriteDB(), clientInter.ID); err != nil {
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
				Organization: []string{"Autentico Client Intermediary CA"},
				CommonName:   "Autentico Client Intermediary CA",
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(time.Duration(ageDays) * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
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

		expireDate := template.NotAfter

		cert := ca.Certificate{
			ID:            ca.GenerateID(),
			Type:          "client-int",
			CreatedAt:     time.Now(),
			CertPEM:       string(certPEM),
			KeyCiphertext: encryptedKey,
			ExpireDate:    &expireDate,
		}

		if err := ca.InsertCertificate(db.GetWriteDB(), cert); err != nil {
			return err
		}

		fmt.Printf("New Client Intermediary CA generated and initialized successfully. ID: %s\n", cert.ID)
	}

	if refreshServer {
		serverInterPassword := config.GetBootstrap().DbAesKey
		if serverInterPassword == "" {
			return fmt.Errorf("DB AES key not configured")
		}

		if serverInter != nil {
			if err := ca.RevokeCertificate(db.GetWriteDB(), serverInter.ID); err != nil {
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
				Organization: []string{"Autentico Server Intermediary CA"},
				CommonName:   "Autentico Server Intermediary CA",
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(time.Duration(ageDays) * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
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

		encryptedKey, err := crypto.Encrypt(privPEM, serverInterPassword)
		if err != nil {
			return err
		}

		expireDate := template.NotAfter

		cert := ca.Certificate{
			ID:            ca.GenerateID(),
			Type:          "server-int",
			CreatedAt:     time.Now(),
			CertPEM:       string(certPEM),
			KeyCiphertext: encryptedKey,
			ExpireDate:    &expireDate,
		}

		if err := ca.InsertCertificate(db.GetWriteDB(), cert); err != nil {
			return err
		}

		fmt.Printf("New Server Intermediary CA generated and initialized successfully. ID: %s\n", cert.ID)
	}

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

	bundlePassword := c.String("password")
	if bundlePassword == "" {
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

		interCertRec, err := ca.GetActiveIntermediaryCA(readDb, "client-int")
		if err != nil {
			return fmt.Errorf("failed to get active intermediary CA: %w", err)
		}
		if interCertRec == nil {
			return fmt.Errorf("no active intermediary CA found")
		}

		interPassword := c.String("ca-key-pass")
		if interPassword == "" {
			pw, err := promptPassword("Enter password for Intermediary CA: ")
			if err != nil {
				return fmt.Errorf("failed to read intermediary password: %w", err)
			}
			interPassword = pw
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

	pfxData, err := pkcs12.Modern2023.Encode(priv, parsedCert, []*x509.Certificate{parsedInter}, bundlePassword)
	if err != nil {
		return fmt.Errorf("failed to create pkcs12 bundle: %w", err)
	}

	if err := os.WriteFile(filename, pfxData, 0600); err != nil {
		return fmt.Errorf("failed to write bundle file: %w", err)
	}

	fmt.Printf("Successfully wrote PKCS#12 bundle to %s\n", filename)
	return nil
}
