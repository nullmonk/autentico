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

// @Summary Create API Token
// @Description Create a new API token with specific routes access
// @Tags apitokens
// @Accept json
// @Produce json
// @Param request body CreateApiTokenRequest true "Create API Token Request"
// @Success 201 {object} CreateApiTokenResponse
// @Failure 400 {object} model.ApiError
// @Failure 500 {object} model.ApiError
// @Router /admin/api/api-tokens [post]
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

	utils.SuccessResponse(w, res, http.StatusCreated)
}

// AvailableAdminRoutes is a hardcoded list of all known API routes
// until Go 1.22's mux allows introspection.
var AvailableAdminRoutes = []AvailableRoute{
	{Method: "GET", Path: "/admin/api/users"},
	{Method: "POST", Path: "/admin/api/users"},
	{Method: "GET", Path: "/admin/api/users/{id}"},
	{Method: "PUT", Path: "/admin/api/users/{id}"},
	{Method: "DELETE", Path: "/admin/api/users/{id}"},
	{Method: "POST", Path: "/admin/api/users/{id}/deactivate"},
	{Method: "POST", Path: "/admin/api/users/{id}/reactivate"},
	{Method: "POST", Path: "/admin/api/users/{id}/unlock"},
	{Method: "POST", Path: "/admin/api/users/{id}/revoke-sessions"},
	{Method: "POST", Path: "/admin/api/users/lookup"},
	{Method: "GET", Path: "/admin/api/clients"},
	{Method: "POST", Path: "/admin/api/clients"},
	{Method: "GET", Path: "/admin/api/clients/{client_id}"},
	{Method: "PUT", Path: "/admin/api/clients/{client_id}"},
	{Method: "DELETE", Path: "/admin/api/clients/{client_id}"},
	{Method: "GET", Path: "/admin/api/sessions"},
	{Method: "DELETE", Path: "/admin/api/sessions/{id}"},
	{Method: "GET", Path: "/admin/api/idp-sessions"},
	{Method: "GET", Path: "/admin/api/users/{id}/idp-sessions"},
	{Method: "GET", Path: "/admin/api/idp-sessions/{id}/sessions"},
	{Method: "DELETE", Path: "/admin/api/idp-sessions/{id}"},
	{Method: "GET", Path: "/admin/api/federation"},
	{Method: "POST", Path: "/admin/api/federation"},
	{Method: "GET", Path: "/admin/api/federation/{id}"},
	{Method: "PUT", Path: "/admin/api/federation/{id}"},
	{Method: "DELETE", Path: "/admin/api/federation/{id}"},
	{Method: "GET", Path: "/admin/api/groups"},
	{Method: "POST", Path: "/admin/api/groups"},
	{Method: "GET", Path: "/admin/api/groups/{id}"},
	{Method: "PUT", Path: "/admin/api/groups/{id}"},
	{Method: "DELETE", Path: "/admin/api/groups/{id}"},
	{Method: "GET", Path: "/admin/api/groups/{id}/members"},
	{Method: "POST", Path: "/admin/api/groups/{id}/members"},
	{Method: "DELETE", Path: "/admin/api/groups/{id}/members/{user_id}"},
	{Method: "GET", Path: "/admin/api/users/{id}/groups"},
	{Method: "GET", Path: "/admin/api/tokens"},
	{Method: "DELETE", Path: "/admin/api/tokens/{id}"},
	{Method: "POST", Path: "/admin/api/api-tokens"},
	{Method: "GET", Path: "/admin/api/api-tokens"},
	{Method: "DELETE", Path: "/admin/api/api-tokens/{id}"},
	{Method: "GET", Path: "/admin/api/api-tokens/routes"},
	{Method: "GET", Path: "/admin/api/stats"},
	{Method: "GET", Path: "/admin/api/settings"},
	{Method: "PUT", Path: "/admin/api/settings"},
	{Method: "POST", Path: "/admin/api/settings/test-smtp"},
	{Method: "GET", Path: "/admin/api/settings/export"},
	{Method: "POST", Path: "/admin/api/settings/import/preview"},
	{Method: "POST", Path: "/admin/api/settings/import/apply"},
	{Method: "GET", Path: "/admin/api/audit-logs"},
	{Method: "GET", Path: "/admin/api/deletion-requests"},
	{Method: "POST", Path: "/admin/api/deletion-requests/{id}/approve"},
	{Method: "DELETE", Path: "/admin/api/deletion-requests/{id}"},
	{Method: "GET", Path: "/admin/api/certificates"},
	{Method: "POST", Path: "/admin/api/certificates"},
	{Method: "GET", Path: "/admin/api/certificates/authorities"},
	{Method: "GET", Path: "/admin/api/certificates/{id}/bundle"},
	{Method: "DELETE", Path: "/admin/api/certificates/{id}"},
}

// @Summary List available routes
// @Description List all available admin API routes that can be assigned to an API token
// @Tags apitokens
// @Produce json
// @Success 200 {array} AvailableRoute
// @Router /admin/api/api-tokens/routes [get]
func HandleListAvailableRoutes(w http.ResponseWriter, r *http.Request) {
	utils.SuccessResponse(w, AvailableAdminRoutes, http.StatusOK)
}

// @Summary List API Tokens
// @Description List all created API tokens
// @Tags apitokens
// @Produce json
// @Param limit query int false "Limit"
// @Param offset query int false "Offset"
// @Success 200 {object} ApiTokenListResponse
// @Failure 500 {object} model.ApiError
// @Router /admin/api/api-tokens [get]
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

// @Summary Revoke API Token
// @Description Revoke an API token by ID
// @Tags apitokens
// @Produce json
// @Param id path string true "API Token ID"
// @Success 204
// @Failure 500 {object} model.ApiError
// @Router /admin/api/api-tokens/{id} [delete]
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
