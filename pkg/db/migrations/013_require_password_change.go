package migrations

const migration013 = `
	ALTER TABLE users ADD COLUMN require_password_change BOOLEAN DEFAULT FALSE;
`
