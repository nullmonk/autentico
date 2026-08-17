package migrations

const migration011 = `
CREATE TABLE IF NOT EXISTS certificates (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    revoked_at DATETIME,
    user_id TEXT,
    cert_pem TEXT NOT NULL,
    key_ciphertext BLOB,
	intermediary_id TEXT,
	expire_date DATETIME,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
`
