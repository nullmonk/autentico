package ca

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

type Certificate struct {
	ID            string     `json:"id"`
	Type          string     `json:"type"` // "ca", "intermediary", "user"
	CreatedAt     time.Time  `json:"created_at"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	UserID        *string    `json:"user_id,omitempty"`
	Username      *string    `json:"username,omitempty"`
	IntermediaryID *string   `json:"intermediary_id,omitempty"`
	ExpireDate    *time.Time `json:"expire_date,omitempty"`
	CertPEM       string     `json:"cert_pem,omitempty"`
	KeyCiphertext []byte     `json:"-"`
	CN            *string    `json:"cn,omitempty"`
	Hosts         *string    `json:"hosts,omitempty"`
}

func GenerateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
