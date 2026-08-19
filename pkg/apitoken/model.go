package apitoken

import (
	"time"

	"github.com/eugenioenko/autentico/pkg/model"
)

type ApiToken struct {
	ID              string    `db:"id" json:"id"`
	Name            string    `db:"name" json:"name"`
	TokenCiphertext string    `db:"token_ciphertext" json:"-"`
	CreatedBy       string    `db:"created_by" json:"created_by"`
	CreatedAt       time.Time `db:"created_at" json:"created_at"`
	ExpiresAt       time.Time `db:"expires_at" json:"expires_at"`
}

type CreateApiTokenRequest struct {
	Name      string    `json:"name"`
	ExpiresAt time.Time `json:"expires_at"`
	Routes    []string  `json:"routes"`
}

type CreateApiTokenResponse struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Token     string    `json:"token"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type ApiTokenListResponse struct {
	model.ListResponse[ApiToken]
}

type AvailableRoute struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}
