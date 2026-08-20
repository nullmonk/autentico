package apitoken

import (
	"database/sql"
	"fmt"

	"github.com/eugenioenko/autentico/pkg/db"
)

func Create(token *ApiToken) error {
	query := `
		INSERT INTO api_tokens (id, name, token_ciphertext, created_by, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`
	_, err := db.GetDB().Exec(query, token.ID, token.Name, token.TokenCiphertext, token.CreatedBy, token.CreatedAt, token.ExpiresAt)
	if err != nil {
		return fmt.Errorf("failed to insert api token: %w", err)
	}
	return nil
}

func List(limit, offset int) ([]ApiToken, int, error) {
	query := `
		SELECT a.id, a.name, COALESCE(u.username, a.created_by), a.created_at, a.expires_at
		FROM api_tokens a
		LEFT JOIN users u ON a.created_by = u.id
		ORDER BY a.created_at DESC
		LIMIT ? OFFSET ?
	`
	rows, err := db.GetDB().Query(query, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var tokens []ApiToken
	for rows.Next() {
		var t ApiToken
		if err := rows.Scan(&t.ID, &t.Name, &t.CreatedBy, &t.CreatedAt, &t.ExpiresAt); err != nil {
			return nil, 0, err
		}
		tokens = append(tokens, t)
	}

	var total int
	err = db.GetDB().QueryRow(`SELECT COUNT(*) FROM api_tokens`).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	return tokens, total, nil
}

func Revoke(id string) error {
	res, err := db.GetDB().Exec(`DELETE FROM api_tokens WHERE id = ?`, id)
	if err != nil {
		return err
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func GetByID(id string) (*ApiToken, error) {
	var t ApiToken
	err := db.GetDB().QueryRow(`
		SELECT a.id, a.name, a.token_ciphertext, COALESCE(u.username, a.created_by), a.created_at, a.expires_at
		FROM api_tokens a
		LEFT JOIN users u ON a.created_by = u.id
		WHERE a.id = ?
	`, id).Scan(&t.ID, &t.Name, &t.TokenCiphertext, &t.CreatedBy, &t.CreatedAt, &t.ExpiresAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &t, nil
}
