package ca

import (
	"database/sql"
	"errors"
	"time"
)

func InsertCertificate(db *sql.DB, cert Certificate) error {
	_, err := db.Exec(
		"INSERT INTO certificates (id, type, created_at, revoked_at, user_id, cert_pem, key_ciphertext, intermediary_id, expire_date, cn, hosts) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		cert.ID, cert.Type, cert.CreatedAt, cert.RevokedAt, cert.UserID, cert.CertPEM, cert.KeyCiphertext, cert.IntermediaryID, cert.ExpireDate, cert.CN, cert.Hosts,
	)
	return err
}

func GetActiveRootCA(db *sql.DB) (*Certificate, error) {
	row := db.QueryRow("SELECT id, type, created_at, revoked_at, cert_pem, key_ciphertext, expire_date FROM certificates WHERE type = 'ca' AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1")
	var cert Certificate
	var revokedAt, expireDate sql.NullTime
	err := row.Scan(&cert.ID, &cert.Type, &cert.CreatedAt, &revokedAt, &cert.CertPEM, &cert.KeyCiphertext, &expireDate)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if revokedAt.Valid {
		cert.RevokedAt = &revokedAt.Time
	}
	if expireDate.Valid {
		cert.ExpireDate = &expireDate.Time
	}
	return &cert, nil
}

func GetActiveIntermediaryCA(db *sql.DB, interType string) (*Certificate, error) {
	row := db.QueryRow("SELECT id, type, created_at, revoked_at, cert_pem, key_ciphertext, expire_date FROM certificates WHERE type = ? AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1", interType)
	var cert Certificate
	var revokedAt, expireDate sql.NullTime
	err := row.Scan(&cert.ID, &cert.Type, &cert.CreatedAt, &revokedAt, &cert.CertPEM, &cert.KeyCiphertext, &expireDate)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if revokedAt.Valid {
		cert.RevokedAt = &revokedAt.Time
	}
	if expireDate.Valid {
		cert.ExpireDate = &expireDate.Time
	}
	return &cert, nil
}

func GetCertificateByID(db *sql.DB, id string) (*Certificate, error) {
	row := db.QueryRow(`
		SELECT c.id, c.type, c.created_at, c.revoked_at, c.user_id, c.cert_pem, c.key_ciphertext, c.intermediary_id, c.expire_date, u.username, c.cn, c.hosts
		FROM certificates c
		LEFT JOIN users u ON c.user_id = u.id
		WHERE c.id = ?
	`, id)
	var cert Certificate
	var username, userID, interID, cn, hosts sql.NullString
	var revokedAt, expireDate sql.NullTime

	err := row.Scan(&cert.ID, &cert.Type, &cert.CreatedAt, &revokedAt, &userID, &cert.CertPEM, &cert.KeyCiphertext, &interID, &expireDate, &username, &cn, &hosts)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if username.Valid {
		cert.Username = &username.String
	}
	if revokedAt.Valid {
		cert.RevokedAt = &revokedAt.Time
	}
	if userID.Valid {
		cert.UserID = &userID.String
	}
	if interID.Valid {
		cert.IntermediaryID = &interID.String
	}
	if expireDate.Valid {
		cert.ExpireDate = &expireDate.Time
	}
	if cn.Valid {
		cert.CN = &cn.String
	}
	if hosts.Valid {
		cert.Hosts = &hosts.String
	}
	return &cert, nil
}

func GetUserCertificate(db *sql.DB, userID string) (*Certificate, error) {
	row := db.QueryRow(`
		SELECT id, type, created_at, revoked_at, user_id, cert_pem, key_ciphertext, intermediary_id, expire_date, cn, hosts
		FROM certificates
		WHERE user_id = ? AND revoked_at IS NULL
		ORDER BY created_at DESC LIMIT 1
	`, userID)
	var cert Certificate
	var uID, interID, cn, hosts sql.NullString
	var revokedAt, expireDate sql.NullTime

	err := row.Scan(&cert.ID, &cert.Type, &cert.CreatedAt, &revokedAt, &uID, &cert.CertPEM, &cert.KeyCiphertext, &interID, &expireDate, &cn, &hosts)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if revokedAt.Valid {
		cert.RevokedAt = &revokedAt.Time
	}
	if uID.Valid {
		cert.UserID = &uID.String
	}
	if interID.Valid {
		cert.IntermediaryID = &interID.String
	}
	if expireDate.Valid {
		cert.ExpireDate = &expireDate.Time
	}
	if cn.Valid {
		cert.CN = &cn.String
	}
	if hosts.Valid {
		cert.Hosts = &hosts.String
	}

	return &cert, nil
}

func ListCertificates(db *sql.DB) ([]Certificate, error) {
	rows, err := db.Query(`
		SELECT c.id, c.type, c.created_at, c.revoked_at, c.user_id, c.cert_pem, c.intermediary_id, c.expire_date, u.username, c.cn, c.hosts
		FROM certificates c
		LEFT JOIN users u ON c.user_id = u.id
		ORDER BY c.created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var certs []Certificate
	for rows.Next() {
		var cert Certificate
		var username, userID, interID, cn, hosts sql.NullString
		var revokedAt, expireDate sql.NullTime

		if err := rows.Scan(&cert.ID, &cert.Type, &cert.CreatedAt, &revokedAt, &userID, &cert.CertPEM, &interID, &expireDate, &username, &cn, &hosts); err != nil {
			return nil, err
		}
		if username.Valid {
			cert.Username = &username.String
		}
		if revokedAt.Valid {
			cert.RevokedAt = &revokedAt.Time
		}
		if userID.Valid {
			cert.UserID = &userID.String
		}
		if interID.Valid {
			cert.IntermediaryID = &interID.String
		}
		if expireDate.Valid {
			cert.ExpireDate = &expireDate.Time
		}
		if cn.Valid {
			cert.CN = &cn.String
		}
		if hosts.Valid {
			cert.Hosts = &hosts.String
		}
		certs = append(certs, cert)
	}
	return certs, rows.Err()
}

func RevokeCertificate(db *sql.DB, id string) error {
	now := time.Now()
	_, err := db.Exec("UPDATE certificates SET revoked_at = ?, key_ciphertext = NULL WHERE id = ?", now, id)
	return err
}

func DeleteAllCertificates(db *sql.DB) error {
	_, err := db.Exec("DELETE FROM certificates")
	return err
}
