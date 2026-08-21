package application

import (
	"fmt"
	"time"

	validation "github.com/go-ozzo/ozzo-validation"
)

type Application struct {
	ID        string
	Name      string
	Icon      string
	URL       string
	CreatedAt time.Time
	UpdatedAt time.Time
	Groups    []string
}

type ApplicationResponse struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Icon      string    `json:"icon"`
	URL       string    `json:"url"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Groups    []string  `json:"groups"` // Array of group IDs
}

func (a *Application) ToResponse() ApplicationResponse {
	return ApplicationResponse{
		ID:        a.ID,
		Name:      a.Name,
		Icon:      a.Icon,
		URL:       a.URL,
		CreatedAt: a.CreatedAt,
		UpdatedAt: a.UpdatedAt,
		Groups:    a.Groups,
	}
}

type ApplicationCreateRequest struct {
	Name   string   `json:"name"`
	Icon   string   `json:"icon"`
	URL    string   `json:"url"`
	Groups []string `json:"groups"` // Array of group IDs
}

type ApplicationUpdateRequest struct {
	Name   string   `json:"name,omitempty"`
	Icon   string   `json:"icon"`
	URL    string   `json:"url"`
	Groups []string `json:"groups"` // Array of group IDs
}

func ValidateApplicationCreateRequest(input ApplicationCreateRequest) error {
	if err := validation.Validate(input.Name, validation.Required, validation.Length(1, 100)); err != nil {
		return fmt.Errorf("name is invalid: %w", err)
	}
	return nil
}

func ValidateApplicationUpdateRequest(input ApplicationUpdateRequest) error {
	if input.Name != "" {
		if err := validation.Validate(input.Name, validation.Length(1, 100)); err != nil {
			return fmt.Errorf("name is invalid: %w", err)
		}
	}
	return nil
}
