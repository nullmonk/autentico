package application

type ApplicationNode struct {
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Icon        string            `json:"icon,omitempty"`
	URL         string            `json:"url,omitempty"`
	Groups      []string          `json:"groups,omitempty"` // ADO groups required for visibility
	Items       []ApplicationNode `json:"items,omitempty"`  // Child items (for categories)
}
