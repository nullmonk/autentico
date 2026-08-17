package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/eugenioenko/autentico/pkg/ca/crypto"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
	"software.sslmate.com/src/go-pkcs12"
)

func RespondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}

func HandleListCertificates(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user")
	certs, err := ListCertificates(db.GetReadDB())
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "Failed to list certificates")
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "Failed to list certificates")
		return
	}

	filteredCerts := make([]Certificate, 0)
	for _, c := range certs {
		if c.Type == "user" {
			if userID != "" {
				if c.UserID != nil && *c.UserID == userID {
					filteredCerts = append(filteredCerts, c)
				}
			} else {
				filteredCerts = append(filteredCerts, c)
			}
		}
	}

	RespondJSON(w, http.StatusOK, map[string]interface{}{"items": filteredCerts})
}

func HandleListAuthorities(w http.ResponseWriter, r *http.Request) {
	certs, err := ListCertificates(db.GetReadDB())
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "Failed to list certificates")
		return
	}

	filteredCerts := make([]Certificate, 0)
	for _, c := range certs {
		if c.Type == "ca" || c.Type == "intermediary" {
			filteredCerts = append(filteredCerts, c)
		}
	}

	RespondJSON(w, http.StatusOK, map[string]interface{}{"items": filteredCerts})
}

func HandleRevokeCertificate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := RevokeCertificate(db.GetWriteDB(), id); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "Failed to revoke certificate")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type GenerateCertRequest struct {
	IntermediaryID       string `json:"cert_id"`
	IntermediaryPassword string `json:"cert_pw"`
	UserID               string `json:"user_id"`
	BundlePassword       string `json:"bundle_password"`
}

func HandleGenerateUserCert(w http.ResponseWriter, r *http.Request) {
	var req GenerateCertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	if req.IntermediaryPassword == "" || req.BundlePassword == "" || req.IntermediaryID == "" || req.UserID == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing required fields")
		return
	}

	u, err := user.UserByID(req.UserID)
	if err != nil || u == nil {
		utils.WriteErrorResponse(w, http.StatusNotFound, "not_found", "User not found")
		return
	}

	interCertRec, err := GetCertificateByID(db.GetReadDB(), req.IntermediaryID)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "Failed to get active intermediary CA")
		return
	}
	if interCertRec == nil || interCertRec.Type != "intermediary" || interCertRec.RevokedAt != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid or inactive Intermediary CA")
		return
	}

	interPrivPEM, err := crypto.Decrypt(interCertRec.KeyCiphertext, req.IntermediaryPassword)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusForbidden, "access_denied", "Failed to decrypt intermediary CA key (wrong password?)")
		return
	}

	interBlock, _ := pem.Decode(interPrivPEM)
	if interBlock == nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "Failed to parse intermediary CA private key PEM")
		return
	}
	interPrivAny, err := x509.ParsePKCS8PrivateKey(interBlock.Bytes)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "Failed to parse intermediary CA PKCS8 private key")
		return
	}
	interPriv, ok := interPrivAny.(*rsa.PrivateKey)
	if !ok {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "Intermediary CA key is not RSA")
		return
	}

	interCertBlock, _ := pem.Decode([]byte(interCertRec.CertPEM))
	if interCertBlock == nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "Failed to parse intermediary CA cert PEM")
		return
	}
	interCert, err := x509.ParseCertificate(interCertBlock.Bytes)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "Failed to parse intermediary CA certificate")
		return
	}

	// generate user key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "Failed to generate key")
		return
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "Failed to generate serial")
		return
	}

	expireDate := interCert.NotAfter
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

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, interCert, &priv.PublicKey, interPriv)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "Failed to sign user cert")
		return
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "Failed to marshal user key")
		return
	}

	aesKey := config.GetBootstrap().DbAesKey
	if aesKey == "" {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "DB AES key not configured")
		return
	}

	encryptedKey, err := crypto.EncryptWithKey(privBytes, aesKey)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "Failed to encrypt user key")
		return
	}

	cert := Certificate{
		ID:             GenerateID(),
		Type:           "user",
		CreatedAt:      time.Now(),
		CertPEM:        string(certPEM),
		KeyCiphertext:  encryptedKey,
		UserID:         &u.ID,
		IntermediaryID: &interCertRec.ID,
		ExpireDate:     &expireDate,
	}

	if err := InsertCertificate(db.GetWriteDB(), cert); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "Failed to save user cert")
		return
	}

	parsedCert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "Failed to parse generated cert")
		return
	}
	pfxData, err := pkcs12.Encode(rand.Reader, priv, parsedCert, []*x509.Certificate{interCert}, req.BundlePassword)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "Failed to create pkcs12 bundle")
		return
	}

	w.Header().Set("Content-Type", "application/x-pkcs12")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.p12\"", u.Username))
	w.Write(pfxData)
}

func HandleDownloadUserCert(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	bundlePassword := r.URL.Query().Get("password")
	if bundlePassword == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Bundle password required")
		return
	}

	certRec, err := GetCertificateByID(db.GetReadDB(), id)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "Failed to get user cert")
		return
	}
	if certRec == nil || certRec.Type != "user" || certRec.RevokedAt != nil {
		utils.WriteErrorResponse(w, http.StatusNotFound, "not_found", "Active user certificate not found")
		return
	}

	interCertRec, err := GetCertificateByID(db.GetReadDB(), *certRec.IntermediaryID)
	if err != nil || interCertRec == nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "Failed to get intermediary cert")
		return
	}

	aesKey := config.GetBootstrap().DbAesKey
	privBytes, err := crypto.DecryptWithKey(certRec.KeyCiphertext, aesKey)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "Failed to decrypt user key")
		return
	}

	privAny, err := x509.ParsePKCS8PrivateKey(privBytes)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "Failed to parse user key")
		return
	}
	priv, ok := privAny.(*rsa.PrivateKey)
	if !ok {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "User key is not RSA")
		return
	}

	certBlock, _ := pem.Decode([]byte(certRec.CertPEM))
	if certBlock == nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "Failed to decode cert pem")
		return
	}
	parsedCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "Failed to parse user cert")
		return
	}

	interBlock, _ := pem.Decode([]byte(interCertRec.CertPEM))
	if interBlock == nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "Failed to decode inter pem")
		return
	}
	parsedInter, err := x509.ParseCertificate(interBlock.Bytes)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "Failed to parse inter cert")
		return
	}

	pfxData, err := pkcs12.Encode(rand.Reader, priv, parsedCert, []*x509.Certificate{parsedInter}, bundlePassword)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "Failed to create pkcs12 bundle")
		return
	}

	username := "user"
	if certRec.Username != nil {
		username = *certRec.Username
	}

	w.Header().Set("Content-Type", "application/x-pkcs12")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.p12\"", username))
	w.Write(pfxData)
}
