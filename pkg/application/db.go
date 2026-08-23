package application

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/rs/xid"
)

func Create(req ApplicationCreateRequest) (*Application, error) {
	appID := xid.New().String()

	app := &Application{
		ID:        appID,
		Name:      req.Name,
		Icon:      req.Icon,
		URL:       req.URL,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
		Groups:    req.Groups,
	}
	if app.Groups == nil {
		app.Groups = []string{}
	}

	tx, err := db.GetDB().Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	_, err = tx.Exec(`
		INSERT INTO applications (id, name, icon, url, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, app.ID, app.Name, app.Icon, app.URL, app.CreatedAt, app.UpdatedAt)
	if err != nil {
		return nil, err
	}

	for _, groupID := range app.Groups {
		_, err = tx.Exec(`
			INSERT INTO application_groups (application_id, group_id)
			VALUES (?, ?)
		`, app.ID, groupID)
		if err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return app, nil
}

func Update(id string, req ApplicationUpdateRequest) (*Application, error) {
	app, err := GetByID(id)
	if err != nil {
		return nil, err
	}

	if req.Name != "" {
		app.Name = req.Name
	}
	app.Icon = req.Icon
	app.URL = req.URL
	app.UpdatedAt = time.Now().UTC()
	if req.Groups != nil {
		app.Groups = req.Groups
	}

	tx, err := db.GetDB().Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	_, err = tx.Exec(`
		UPDATE applications
		SET name = ?, icon = ?, url = ?, updated_at = ?
		WHERE id = ?
	`, app.Name, app.Icon, app.URL, app.UpdatedAt, app.ID)
	if err != nil {
		return nil, err
	}

	if req.Groups != nil {
		_, err = tx.Exec(`DELETE FROM application_groups WHERE application_id = ?`, app.ID)
		if err != nil {
			return nil, err
		}

		for _, groupID := range req.Groups {
			_, err = tx.Exec(`
				INSERT INTO application_groups (application_id, group_id)
				VALUES (?, ?)
			`, app.ID, groupID)
			if err != nil {
				return nil, err
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return app, nil
}

func Delete(id string) error {
	_, err := db.GetDB().Exec(`DELETE FROM applications WHERE id = ?`, id)
	return err
}

func GetByID(id string) (*Application, error) {
	row := db.GetDB().QueryRow(`
		SELECT id, name, icon, url, created_at, updated_at
		FROM applications
		WHERE id = ?
	`, id)

	var app Application
	err := row.Scan(&app.ID, &app.Name, &app.Icon, &app.URL, &app.CreatedAt, &app.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("application not found")
	} else if err != nil {
		return nil, err
	}

	app.Groups, err = getApplicationGroups(app.ID)
	if err != nil {
		return nil, err
	}

	return &app, nil
}

func List() ([]Application, error) {
	rows, err := db.GetDB().Query(`
		SELECT id, name, icon, url, created_at, updated_at
		FROM applications
		ORDER BY name ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var apps []Application
	for rows.Next() {
		var app Application
		err := rows.Scan(&app.ID, &app.Name, &app.Icon, &app.URL, &app.CreatedAt, &app.UpdatedAt)
		if err != nil {
			return nil, err
		}
		app.Groups, err = getApplicationGroups(app.ID)
		if err != nil {
			return nil, err
		}
		apps = append(apps, app)
	}
	return apps, nil
}

func ListForUser(userID string) ([]Application, error) {
	// An application with no groups assigned is public - visible to every
	// user - so the group join is a LEFT JOIN and rows with no group at all
	// (ag.group_id IS NULL) pass through unconditionally.
	rows, err := db.GetDB().Query(`
		SELECT DISTINCT a.id, a.name, a.icon, a.url, a.created_at, a.updated_at
		FROM applications a
		LEFT JOIN application_groups ag ON a.id = ag.application_id
		LEFT JOIN user_groups ug ON ug.group_id = ag.group_id AND ug.user_id = ?
		WHERE ag.group_id IS NULL OR ug.user_id IS NOT NULL
		ORDER BY a.name ASC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var apps []Application
	for rows.Next() {
		var app Application
		err := rows.Scan(&app.ID, &app.Name, &app.Icon, &app.URL, &app.CreatedAt, &app.UpdatedAt)
		if err != nil {
			return nil, err
		}
		// The groups array is not strictly needed for the user view, but let's populate it anyway
		app.Groups, err = getApplicationGroups(app.ID)
		if err != nil {
			return nil, err
		}
		apps = append(apps, app)
	}
	if apps == nil {
		apps = []Application{}
	}
	return apps, nil
}

func getApplicationGroups(appID string) ([]string, error) {
	rows, err := db.GetDB().Query(`
		SELECT group_id FROM application_groups WHERE application_id = ?
	`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []string
	for rows.Next() {
		var groupID string
		if err := rows.Scan(&groupID); err != nil {
			return nil, err
		}
		groups = append(groups, groupID)
	}
	if groups == nil {
		groups = []string{}
	}
	return groups, nil
}
