package forcepasswordchange

import (
	"log/slog"
	"net/http"

	"fmt"
	"github.com/eugenioenko/autentico/pkg/audit"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	"github.com/eugenioenko/autentico/pkg/reqid"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
	"github.com/eugenioenko/autentico/view"
	"github.com/gorilla/csrf"
)

type OauthParams struct {
	RedirectURI         string
	State               string
	ClientID            string
	Scope               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
}

func paramsFromRequest(r *http.Request, getter func(string) string) OauthParams {
	return OauthParams{
		RedirectURI:         getter("redirect_uri"),
		State:               getter("state"),
		ClientID:            getter("client_id"),
		Scope:               getter("scope"),
		Nonce:               getter("nonce"),
		CodeChallenge:       getter("code_challenge"),
		CodeChallengeMethod: getter("code_challenge_method"),
	}
}

func RenderForcePasswordChange(w http.ResponseWriter, r *http.Request, userID string, params OauthParams, errMsg string) {
	cfg := config.Get()
	tmpl, err := view.ParseTemplate("force_password_change")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	data := map[string]any{
		"UserID":              userID,
		"RedirectURI":         params.RedirectURI,
		"State":               params.State,
		"ClientID":            params.ClientID,
		"Scope":               params.Scope,
		"Nonce":               params.Nonce,
		"CodeChallenge":       params.CodeChallenge,
		"CodeChallengeMethod": params.CodeChallengeMethod,
		"Error":               errMsg,
		"ThemeTitle":          cfg.Theme.Title,
		"ThemeLogoUrl":        cfg.Theme.LogoUrl,
		csrf.TemplateTag:      csrf.TemplateField(r),
	}
	view.InjectNonce(r, data)
	if err = tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, "Template Execution Error", http.StatusInternalServerError)
	}
}

func HandleForcePasswordChange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	params := paramsFromRequest(r, r.FormValue)
	userID := r.FormValue("user_id")
	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirm_password")

	reqID := reqid.Get(r.Context())

	// Validate user ID exists
	if userID == "" {
		http.Error(w, "Missing user ID", http.StatusBadRequest)
		return
	}

	usr, err := user.UserByID(userID)
	if err != nil || usr == nil {
		slog.Error("force-password-change: failed to look up user", "request_id", reqID, "error", err)
		http.Error(w, "Invalid user", http.StatusBadRequest)
		return
	}

	// Double check they actually require a password change
	if !usr.RequirePasswordChange {
		http.Error(w, "Password change not required", http.StatusBadRequest)
		return
	}

	// Validate passwords match
	if password != confirmPassword {
		RenderForcePasswordChange(w, r, userID, params, "Passwords do not match.")
		return
	}

	// Validate password length
	cfg := config.Get()
	if len(password) < cfg.ValidationMinPasswordLength {
		RenderForcePasswordChange(w, r, userID, params,
			fmt.Sprintf("Password must be at least %d characters.", cfg.ValidationMinPasswordLength))
		return
	}
	if len(password) > cfg.ValidationMaxPasswordLength {
		RenderForcePasswordChange(w, r, userID, params, "Password is too long.")
		return
	}

	// Update the user's password
	f := false
	if err := user.UpdateUser(userID, user.UserUpdateRequest{Password: password, RequirePasswordChange: &f}); err != nil {
		slog.Error("force-password-change: failed to update password", "request_id", reqID, "error", err)
		RenderForcePasswordChange(w, r, userID, params, "Failed to update password. Please try again.")
		return
	}

	// Invalidate all sessions for this user (security: password was changed)
	_ = user.RevokeOtherUserAccess(userID, "")
	_ = idpsession.DeactivateAllForUser(userID)

	audit.Log(audit.EventPasswordChanged, usr, audit.TargetUser, userID, audit.Detail("source", "forced"), utils.GetClientIP(r))

	// Rather than finalizing login here, redirect back to login page so they log in with the new password.
	// We want to force a clean re-login.
	redirectURL := config.GetBootstrap().AppOAuthPath + "/authorize?client_id=" + params.ClientID + "&redirect_uri=" + params.RedirectURI + "&state=" + params.State + "&scope=" + params.Scope + "&response_type=code"
	if params.Nonce != "" {
		redirectURL += "&nonce=" + params.Nonce
	}
	if params.CodeChallenge != "" {
		redirectURL += "&code_challenge=" + params.CodeChallenge + "&code_challenge_method=" + params.CodeChallengeMethod
	}

	http.Redirect(w, r, redirectURL, http.StatusFound)
}
