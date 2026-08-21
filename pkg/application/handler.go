package application

import (
	"encoding/json"
	"net/http"

	"github.com/eugenioenko/autentico/pkg/audit"
	"github.com/eugenioenko/autentico/pkg/middleware"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// HandleListApplications returns all applications (admin endpoint)
// @Summary List applications
// @Description Returns all applications
// @Tags admin-applications
// @Security AdminAuth
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /admin/api/applications [get]
func HandleListApplications(w http.ResponseWriter, r *http.Request) {
	apps, err := List()
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to list applications")
		return
	}

	res := make([]ApplicationResponse, len(apps))
	for i, app := range apps {
		res[i] = app.ToResponse()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"data": res})
}

// HandleCreateApplication creates a new application (admin endpoint)
// @Summary Create application
// @Description Creates a new application
// @Tags admin-applications
// @Security AdminAuth
// @Accept json
// @Produce json
// @Param request body ApplicationCreateRequest true "Application details"
// @Success 201 {object} map[string]interface{}
// @Router /admin/api/applications [post]
func HandleCreateApplication(w http.ResponseWriter, r *http.Request) {
	var req ApplicationCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	if err := ValidateApplicationCreateRequest(req); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	app, err := Create(req)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to create application")
		return
	}

	audit.Log(
		audit.EventApplicationCreated,
		audit.ActorFromRequest(r),
		"application",
		app.ID,
		audit.Detail("name", app.Name),
		utils.GetClientIP(r),
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{"data": app.ToResponse()})
}

// HandleGetApplication gets an application by ID (admin endpoint)
// @Summary Get application
// @Description Gets an application by ID
// @Tags admin-applications
// @Security AdminAuth
// @Produce json
// @Param id path string true "Application ID"
// @Success 200 {object} map[string]interface{}
// @Router /admin/api/applications/{id} [get]
func HandleGetApplication(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	app, err := GetByID(id)
	if err != nil {
		if err.Error() == "application not found" {
			utils.WriteErrorResponse(w, http.StatusNotFound, "not_found", "Application not found")
			return
		}
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to get application")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"data": app.ToResponse()})
}

// HandleUpdateApplication updates an application (admin endpoint)
// @Summary Update application
// @Description Updates an application
// @Tags admin-applications
// @Security AdminAuth
// @Accept json
// @Produce json
// @Param id path string true "Application ID"
// @Param request body ApplicationUpdateRequest true "Application updates"
// @Success 200 {object} map[string]interface{}
// @Router /admin/api/applications/{id} [put]
func HandleUpdateApplication(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req ApplicationUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	if err := ValidateApplicationUpdateRequest(req); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	app, err := Update(id, req)
	if err != nil {
		if err.Error() == "application not found" {
			utils.WriteErrorResponse(w, http.StatusNotFound, "not_found", "Application not found")
			return
		}
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to update application")
		return
	}

	audit.Log(
		audit.EventApplicationUpdated,
		audit.ActorFromRequest(r),
		"application",
		app.ID,
		audit.Detail("name", app.Name),
		utils.GetClientIP(r),
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"data": app.ToResponse()})
}

// HandleDeleteApplication deletes an application (admin endpoint)
// @Summary Delete application
// @Description Deletes an application
// @Tags admin-applications
// @Security AdminAuth
// @Produce json
// @Param id path string true "Application ID"
// @Success 200 {object} map[string]interface{}
// @Router /admin/api/applications/{id} [delete]
func HandleDeleteApplication(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := Delete(id); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to delete application")
		return
	}

	audit.Log(
		audit.EventApplicationDeleted,
		audit.ActorFromRequest(r),
		"application",
		id,
		nil,
		utils.GetClientIP(r),
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"message": "Application deleted successfully"})
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

	apps, err := ListForUser(authInfo.User.ID)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to list applications")
		return
	}

	res := make([]ApplicationResponse, len(apps))
	for i, app := range apps {
		res[i] = app.ToResponse()
	}
	if res == nil {
		res = []ApplicationResponse{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"data": res})
}
