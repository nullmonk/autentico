package migrations

const migration014 = `
	ALTER TABLE users ADD COLUMN require_password_change BOOLEAN DEFAULT FALSE;
`
