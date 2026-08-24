package application

import (
	"encoding/json"
	"net/http"

	"github.com/eugenioenko/autentico/pkg/appsettings"
	"github.com/eugenioenko/autentico/pkg/audit"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/middleware"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// HandleGetSettingsApplications returns all applications (admin endpoint)
// @Summary Get applications config
// @Description Returns the applications setting JSON
// @Tags admin-applications
// @Security AdminAuth
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /admin/api/applications [get]
func HandleGetSettingsApplications(w http.ResponseWriter, r *http.Request) {
	val, err := appsettings.GetSetting("applications")
	if err != nil || val == "" {
		val = "[]"
	}

	var nodes []ApplicationNode
	if err := json.Unmarshal([]byte(val), &nodes); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to parse applications")
		return
	}
	if nodes == nil {
		nodes = []ApplicationNode{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": nodes})
}

// HandleUpdateSettingsApplications updates the applications JSON
// @Summary Update applications
// @Description Updates the applications setting JSON
// @Tags admin-applications
// @Security AdminAuth
// @Accept json
// @Produce json
// @Param request body []ApplicationNode true "Applications tree"
// @Success 204
// @Router /admin/api/applications [put]
func HandleUpdateSettingsApplications(w http.ResponseWriter, r *http.Request) {
	var req []ApplicationNode
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	if req == nil {
		req = []ApplicationNode{}
	}

	b, err := json.Marshal(req)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to serialize applications")
		return
	}

	if err := appsettings.SetSetting("applications", string(b)); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to save applications")
		return
	}

	audit.Log(
		audit.EventSettingsUpdated,
		audit.ActorFromRequest(r),
		audit.TargetSettings,
		"",
		audit.Detail("key", "applications"),
		utils.GetClientIP(r),
	)

	w.WriteHeader(http.StatusNoContent)
}

// HandleListUserApplications returns all applications for the current user based on their groups
// @Summary List user applications
// @Description Returns applications that the authenticated user has access to based on group memberships
// @Tags account-applications
// @Security UserAuth
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /account/api/applications [get]
func HandleListUserApplications(w http.ResponseWriter, r *http.Request) {
	authInfo := middleware.AuthInfoFromContext(r.Context())
	if authInfo == nil || authInfo.User == nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", "User not found in context")
		return
	}

	// Fetch user's groups
	rows, err := db.GetDB().Query(`SELECT group_id FROM user_groups WHERE user_id = ?`, authInfo.User.ID)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to get user groups")
		return
	}
	defer func() {
		_ = rows.Close()
	}()
	userGroups := make(map[string]bool)
	for rows.Next() {
		var g string
		if err := rows.Scan(&g); err == nil {
			userGroups[g] = true
		}
	}

	val, err := appsettings.GetSetting("applications")
	if err != nil || val == "" {
		val = "[]"
	}

	var nodes []ApplicationNode
	if err := json.Unmarshal([]byte(val), &nodes); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to parse applications")
		return
	}

	filtered := filterApplications(nodes, userGroups)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": filtered})
}

func filterApplications(nodes []ApplicationNode, userGroups map[string]bool) []ApplicationNode {
	var result []ApplicationNode
	for _, node := range nodes {
		// If it has items, it's a category
		if node.Items != nil { // Could check length, but keeping structure is good
			filteredItems := filterApplications(node.Items, userGroups)
			// Only include the category if it has items after filtering, or if it was empty to begin with?
			// The requirements say: "empty categories are hidden", "filtered down based on the users roles"
			// Wait, the requirements actually said: "if a category becomes empty after filtering, we won't render that category."
			// BUT a category with no name is a spacer. Let's see if we should preserve empty spacers.
			// Let's assume spacers without items are empty.
			if len(filteredItems) > 0 {
				node.Items = filteredItems
				result = append(result, node)
			}
		} else {
			// It's an app
			hasAccess := len(node.Groups) == 0
			for _, g := range node.Groups {
				if userGroups[g] {
					hasAccess = true
					break
				}
			}
			if hasAccess {
				result = append(result, node)
			}
		}
	}
	if result == nil {
		result = []ApplicationNode{}
	}
	return result
}
