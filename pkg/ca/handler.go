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
		_ = json.NewEncoder(w).Encode(data)
	}
}

// @Summary List Certificates
// @Description List all certificates
// @Tags ca
// @Produce json
// @Param user query string false "User ID"
// @Param type query string false "Certificate Type"
// @Success 200 {object} map[string]interface{}
// @Failure 500 {object} model.ApiError
// @Router /admin/api/certificates [get]
func HandleListCertificates(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user")
	certType := r.URL.Query().Get("type")
	if certType == "" {
		certType = "user"
	}
	certs, err := ListCertificates(db.GetReadDB())
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "Failed to list certificates")
		return
	}

	filteredCerts := make([]Certificate, 0)
	for _, c := range certs {
		if c.Type == certType {
			if certType == "user" {
				if userID != "" {
					if c.UserID != nil && *c.UserID == userID {
						filteredCerts = append(filteredCerts, c)
					}
				} else {
					filteredCerts = append(filteredCerts, c)
				}
			} else {
				filteredCerts = append(filteredCerts, c)
			}
		}
	}

	RespondJSON(w, http.StatusOK, map[string]interface{}{"items": filteredCerts})
}

func HandleGetCAChain(w http.ResponseWriter, r *http.Request) {
	root, err := GetActiveRootCA(db.GetReadDB())
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "Failed to get root CA")
		return
	}
	if root == nil {
		utils.WriteErrorResponse(w, http.StatusNotFound, "not_found", "Root CA not found")
		return
	}

	clientInter, err := GetActiveIntermediaryCA(db.GetReadDB(), "client-int")
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "Failed to get client intermediary CA")
		return
	}

	serverInter, err := GetActiveIntermediaryCA(db.GetReadDB(), "server-int")
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "Failed to get server intermediary CA")
		return
	}

	chain := ""
	if clientInter != nil {
		chain += clientInter.CertPEM + "\n"
	}
	if serverInter != nil {
		chain += serverInter.CertPEM + "\n"
	}
	chain += root.CertPEM

	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", "attachment; filename=\"ca-chain.crt\"")
	_, _ = w.Write([]byte(chain))
}

// @Summary List Certificate Authorities
// @Description List all certificate authorities
// @Tags ca
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 500 {object} model.ApiError
// @Router /admin/api/certificates/authorities [get]
func HandleListAuthorities(w http.ResponseWriter, r *http.Request) {
	certs, err := ListCertificates(db.GetReadDB())
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "Failed to list certificates")
		return
	}

	filteredCerts := make([]Certificate, 0)
	for _, c := range certs {
		if c.Type == "ca" || c.Type == "client-int" || c.Type == "server-int" || c.Type == "intermediary" {
			filteredCerts = append(filteredCerts, c)
		}
	}

	RespondJSON(w, http.StatusOK, map[string]interface{}{"items": filteredCerts})
}

// @Summary Revoke Certificate
// @Description Revoke a certificate by ID
// @Tags ca
// @Produce json
// @Param id path string true "Certificate ID"
// @Success 204
// @Failure 500 {object} model.ApiError
// @Router /admin/api/certificates/{id} [delete]
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
	Username             string `json:"username"`
}

// @Summary Generate User Certificate
// @Description Generate a new certificate for a user
// @Tags ca
// @Accept json
// @Produce json
// @Param request body GenerateCertRequest true "Generate Certificate Request"
// @Success 201 {object} Certificate
// @Failure 400 {object} model.ApiError
// @Failure 500 {object} model.ApiError
// @Router /admin/api/certificates [post]
func HandleGenerateUserCert(w http.ResponseWriter, r *http.Request) {
	var req GenerateCertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	if req.IntermediaryPassword == "" || req.IntermediaryID == "" || req.Username == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing required fields")
		return
	}

	u, err := user.UserByUsername(req.Username)
	if err != nil || u == nil {
		utils.WriteErrorResponse(w, http.StatusNotFound, "not_found", "User not found")
		return
	}

	interCertRec, err := GetCertificateByID(db.GetReadDB(), req.IntermediaryID)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "Failed to get active intermediary CA")
		return
	}
	if interCertRec == nil || (interCertRec.Type != "intermediary" && interCertRec.Type != "client-int") || interCertRec.RevokedAt != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid or inactive Intermediary CA")
		return
	}
	if interCertRec.ExpireDate != nil && time.Until(*interCertRec.ExpireDate) < 365*24*time.Hour {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Client Intermediary CA has less than 1 year remaining. Please run 'autentico ca refresh' in the CLI to generate a new intermediary.")
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

	expireDate := time.Now().Add(365 * 24 * time.Hour)
	if expireDate.After(interCert.NotAfter) {
		expireDate = interCert.NotAfter
	}
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

	aesKeyUser := config.GetBootstrap().DbAesKey
	if aesKeyUser == "" {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "DB AES key not configured")
		return
	}

	encryptedKey, err := crypto.EncryptWithKey(privBytes, aesKeyUser)
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
		CN:             &u.Username,
	}

	if err := InsertCertificate(db.GetWriteDB(), cert); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "Failed to save user cert")
		return
	}

	RespondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"id":      cert.ID,
	})
}

type GenerateServerCertRequest struct {
	IntermediaryID       string   `json:"cert_id"`
	IntermediaryPassword string   `json:"cert_pw"`
	Hosts                []string `json:"hosts"`
}

// @Summary Generate Server Certificate
// @Description Generate a new certificate for a server
// @Tags ca
// @Accept json
// @Produce json
// @Param request body GenerateServerCertRequest true "Generate Server Certificate Request"
// @Success 201 {object} Certificate
// @Failure 400 {object} model.ApiError
// @Failure 500 {object} model.ApiError
// @Router /admin/api/certificates/server [post]
func HandleGenerateServerCert(w http.ResponseWriter, r *http.Request) {
	var req GenerateServerCertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	if req.IntermediaryID == "" || len(req.Hosts) == 0 {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing required fields")
		return
	}

	interCertRec, err := GetCertificateByID(db.GetReadDB(), req.IntermediaryID)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "Failed to get active intermediary CA")
		return
	}
	if interCertRec == nil || (interCertRec.Type != "intermediary" && interCertRec.Type != "server-int") || interCertRec.RevokedAt != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid or inactive Server Intermediary CA")
		return
	}
	if interCertRec.ExpireDate != nil && time.Until(*interCertRec.ExpireDate) < 365*24*time.Hour {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Server Intermediary CA has less than 1 year remaining. Please run 'autentico ca refresh' in the CLI to generate a new intermediary.")
		return
	}

	aesKey := config.GetBootstrap().DbAesKey
	if aesKey == "" {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "DB AES key not configured")
		return
	}

	interPrivPEM, err := crypto.Decrypt(interCertRec.KeyCiphertext, aesKey)
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

	expireDate := time.Now().Add(365 * 24 * time.Hour)
	if expireDate.After(interCert.NotAfter) {
		expireDate = interCert.NotAfter
	}

	hostsJson, _ := json.Marshal(req.Hosts)
	hostsStr := string(hostsJson)
	cn := req.Hosts[0]

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Autentico Server"},
			CommonName:   cn,
		},
		DNSNames:              req.Hosts,
		NotBefore:             time.Now(),
		NotAfter:              expireDate,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, interCert, &priv.PublicKey, interPriv)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "Failed to sign server cert")
		return
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "Failed to marshal server key")
		return
	}

	encryptedKey, err := crypto.EncryptWithKey(privBytes, aesKey)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "Failed to encrypt server key")
		return
	}

	cert := Certificate{
		ID:             GenerateID(),
		Type:           "server",
		CreatedAt:      time.Now(),
		CertPEM:        string(certPEM),
		KeyCiphertext:  encryptedKey,
		IntermediaryID: &interCertRec.ID,
		ExpireDate:     &expireDate,
		CN:             &cn,
		Hosts:          &hostsStr,
	}

	if err := InsertCertificate(db.GetWriteDB(), cert); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "Failed to save server cert")
		return
	}

	RespondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"id":      cert.ID,
	})
}

// @Summary Download User Certificate Bundle
// @Description Download a PKCS12 bundle for a user certificate
// @Tags ca
// @Produce application/x-pkcs12
// @Param id path string true "Certificate ID"
// @Param password query string true "Password for the bundle"
// @Success 200 {file} file
// @Failure 400 {object} model.ApiError
// @Failure 404 {object} model.ApiError
// @Failure 500 {object} model.ApiError
// @Router /admin/api/certificates/{id}/bundle [get]
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

	pfxData, err := pkcs12.Modern2023.Encode(priv, parsedCert, []*x509.Certificate{parsedInter}, bundlePassword)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "Failed to create pkcs12 bundle")
		return
	}

	filename := "user"
	if certRec.Username != nil {
		filename = *certRec.Username
	} else if certRec.CN != nil {
		filename = *certRec.CN
	}

	w.Header().Set("Content-Type", "application/x-pkcs12")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.p12\"", filename))
	_, _ = w.Write(pfxData)
}

type GenerateServerCertFromCSRRequest struct {
	CSR string `json:"csr"`
}

type GenerateServerCertFromCSRResponse struct {
	Certificate string `json:"certificate"`
	ID          string `json:"id"`
}

// @Summary Generate Server Certificate from CSR
// @Description Generate a new certificate for a server using a CSR
// @Tags ca
// @Accept json
// @Produce json
// @Param request body GenerateServerCertFromCSRRequest true "Generate Server Certificate from CSR Request"
// @Success 201 {object} Certificate
// @Failure 400 {object} model.ApiError
// @Failure 500 {object} model.ApiError
// @Router /admin/api/ca/server [post]
func HandleGenerateServerCertFromCSR(w http.ResponseWriter, r *http.Request) {
	var req GenerateServerCertFromCSRRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	if req.CSR == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing CSR")
		return
	}

	csrBlock, _ := pem.Decode([]byte(req.CSR))
	if csrBlock == nil || csrBlock.Type != "CERTIFICATE REQUEST" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid CSR PEM format")
		return
	}

	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Failed to parse CSR")
		return
	}

	if err := csr.CheckSignature(); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid CSR signature")
		return
	}

	interCertRec, err := GetActiveIntermediaryCA(db.GetReadDB(), "server-int")
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "Failed to get active intermediary CA")
		return
	}
	if interCertRec == nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Active Server Intermediary CA not found")
		return
	}
	if interCertRec.ExpireDate != nil && time.Until(*interCertRec.ExpireDate) < 365*24*time.Hour {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Server Intermediary CA has less than 1 year remaining. Please run 'autentico ca refresh' in the CLI to generate a new intermediary.")
		return
	}

	aesKey := config.GetBootstrap().DbAesKey
	if aesKey == "" {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "DB AES key not configured")
		return
	}

	interPrivPEM, err := crypto.Decrypt(interCertRec.KeyCiphertext, aesKey)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "Failed to decrypt intermediary CA key")
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

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "Failed to generate serial")
		return
	}

	expireDate := time.Now().Add(365 * 24 * time.Hour)
	if expireDate.After(interCert.NotAfter) {
		expireDate = interCert.NotAfter
	}

	cn := csr.Subject.CommonName
	var hosts []string
	if cn != "" {
		hosts = append(hosts, cn)
	}
	for _, dnsName := range csr.DNSNames {
		found := false
		for _, h := range hosts {
			if h == dnsName {
				found = true
				break
			}
		}
		if !found {
			hosts = append(hosts, dnsName)
		}
	}
	for _, ip := range csr.IPAddresses {
		hosts = append(hosts, ip.String())
	}

	if len(hosts) == 0 {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "CSR must contain a Common Name or Subject Alternative Names")
		return
	}

	hostsJson, _ := json.Marshal(hosts)
	hostsStr := string(hostsJson)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      csr.Subject,
		DNSNames:     csr.DNSNames,
		IPAddresses:  csr.IPAddresses,
		NotBefore:    time.Now(),
		NotAfter:     expireDate,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, interCert, csr.PublicKey, interPriv)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "Failed to sign server cert")
		return
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	cert := Certificate{
		ID:             GenerateID(),
		Type:           "server",
		CreatedAt:      time.Now(),
		CertPEM:        string(certPEM),
		KeyCiphertext:  nil,
		IntermediaryID: &interCertRec.ID,
		ExpireDate:     &expireDate,
		CN:             &cn,
		Hosts:          &hostsStr,
	}

	if err := InsertCertificate(db.GetWriteDB(), cert); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "internal_error", "Failed to save server cert")
		return
	}

	RespondJSON(w, http.StatusOK, GenerateServerCertFromCSRResponse{
		Certificate: string(certPEM),
		ID:          cert.ID,
	})
}
