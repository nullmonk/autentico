package apitoken

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/eugenioenko/autentico/pkg/api"
	"github.com/eugenioenko/autentico/pkg/audit"
	"github.com/eugenioenko/autentico/pkg/ca/crypto"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/jwtutil"
	"github.com/eugenioenko/autentico/pkg/key"
	"github.com/eugenioenko/autentico/pkg/middleware"
	"github.com/eugenioenko/autentico/pkg/model"
	"github.com/eugenioenko/autentico/pkg/utils"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/xid"
)

func HandleCreateApiToken(w http.ResponseWriter, r *http.Request) {
	admin := middleware.AuthInfoFromContext(r.Context()).User

	var req CreateApiTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	if req.Name == "" || req.ExpiresAt.Before(time.Now()) {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid name or expiration date")
		return
	}

	tokenID := "atk_" + xid.New().String()
	now := time.Now()

	claims := jwtutil.AccessTokenClaims{
		ID:                tokenID,
		UserID:            admin.ID, // Although it's an API token, it's created by an admin
		PreferredUsername: req.Name,
		Role:              "api",
		Routes:            req.Routes,
		IssuedAt:          now.Unix(),
		ExpiresAt:         req.ExpiresAt.Unix(),
		Issuer:            config.GetBootstrap().AppAuthIssuer,
		Audience:          []string{config.AdminClientID},
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodRS256, &claims)
	jwtToken.Header["kid"] = config.GetBootstrap().AuthJwkCertKeyID

	signedToken, err := jwtToken.SignedString(key.GetPrivateKey())
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to sign token")
		return
	}

	aesKey := config.GetBootstrap().DbAesKey
	if aesKey == "" {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "DB AES key not configured")
		return
	}

	encryptedToken, err := crypto.EncryptWithKey([]byte(signedToken), aesKey)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to encrypt token")
		return
	}

	dbToken := &ApiToken{
		ID:              tokenID,
		Name:            req.Name,
		TokenCiphertext: string(encryptedToken),
		CreatedBy:       admin.ID,
		CreatedAt:       now,
		ExpiresAt:       req.ExpiresAt,
	}

	if err := Create(dbToken); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to store token")
		return
	}

	audit.Log(audit.EventApiTokenCreated, admin, audit.TargetApiToken, tokenID, audit.Detail("name", req.Name), utils.GetClientIP(r))

	res := CreateApiTokenResponse{
		ID:        tokenID,
		Name:      req.Name,
		Token:     signedToken,
		CreatedAt: now,
		ExpiresAt: req.ExpiresAt,
	}

	utils.SuccessResponse(w, res, http.StatusOK)
}

func HandleListApiTokens(w http.ResponseWriter, r *http.Request) {
	params := api.ParseListParams(r)

	tokens, total, err := List(params.Limit, params.Offset)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to fetch tokens")
		return
	}

	if tokens == nil {
		tokens = []ApiToken{}
	}

	utils.SuccessResponse(w, ApiTokenListResponse{
		ListResponse: model.ListResponse[ApiToken]{
			Items: tokens,
			Total: total,
		},
	}, http.StatusOK)
}

func HandleRevokeApiToken(w http.ResponseWriter, r *http.Request) {
	admin := middleware.AuthInfoFromContext(r.Context()).User
	id := r.PathValue("id")

	if err := Revoke(id); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to revoke token")
		return
	}

	audit.Log(audit.EventApiTokenRevoked, admin, audit.TargetApiToken, id, nil, utils.GetClientIP(r))
	utils.SuccessResponse(w, map[string]interface{}{}, http.StatusNoContent)
}
