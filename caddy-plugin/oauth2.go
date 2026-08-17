package caddy_plugin

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	cookieNameSessionPrefix = "autentico_session_"
	cookieNameState         = "autentico_state"
	callbackPath            = "/.autentico/callback"
)

func getAppConfig(ctx caddy.Context) (*AutenticoApp, error) {
	appIface, err := ctx.App("autentico")
	if err != nil {
		return nil, fmt.Errorf("autentico app not configured")
	}
	app, ok := appIface.(*AutenticoApp)
	if !ok {
		return nil, fmt.Errorf("autentico app type mismatch")
	}
	return app, nil
}

func handleOAuth2(h *AutenticoHandler, w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	app, err := getAppConfig(h.ctx)
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	// 1. Check if this is the callback endpoint
	if strings.HasPrefix(r.URL.Path, callbackPath) {
		return handleCallback(app, w, r)
	}

	// 2. Load all available valid sessions
	sessions := make(map[string]*Session)
	for _, cookie := range r.Cookies() {
		if strings.HasPrefix(cookie.Name, cookieNameSessionPrefix) {
			serverName := strings.TrimPrefix(cookie.Name, cookieNameSessionPrefix)
			serverConfig, ok := app.Servers[serverName]
			if ok {
				// Added validation check for the ServerName parameter here
				sess, err := decodeAndVerifySession(cookie.Value, serverConfig.ClientSecret, serverName)
				if err == nil {
					sessions[serverName] = sess
				}
			}
		}
	}

	// 3. Evaluate Access Control Rules and find missing authentications
	allow, missingServers := evaluateRules(h.Rules, sessions)

	if !allow {
		if len(missingServers) > 0 {
			// Redirect to the first missing server login
			return redirectToLogin(app, missingServers[0], w, r)
		}
		// If there are no missing servers to log in to, but it evaluated to false,
		// it means the user logged in but lacks the appropriate roles.
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("access denied by Autentico rules"))
	}

	// 4. Inject Headers if configured
	if h.InjectHeaders {
		// Strip any existing incoming X-Autentico-* headers to prevent spoofing
		for k := range r.Header {
			if strings.HasPrefix(strings.ToLower(k), "x-autentico-") {
				r.Header.Del(k)
			}
		}

		// If rules exist, inject from a session that satisfied the rules.
		// If no rules exist, we can inject from ANY valid session found.
		// Wait, if there are NO rules, `missingServers` would be empty, but we still need *at least one* valid session to inject from.
		// If there are no rules and no valid sessions, we should probably force login to the default server if we are acting as a proxy that injects headers.
		if len(h.Rules) == 0 && len(sessions) == 0 {
			return redirectToLogin(app, "default", w, r)
		}

		// Inject from the first valid session
		for _, sess := range sessions {
			injectHeaders(r, sess.Claims)
			break // only inject from one session
		}
	}

	// 5. Proxy the request downstream
	return next.ServeHTTP(w, r)
}

func evaluateRules(rules []Rule, sessions map[string]*Session) (bool, []string) {
	if len(rules) == 0 {
		return true, nil // No rules means allow
	}

	// Implicit OR at the top level
	var allMissing []string
	for _, rule := range rules {
		satisfied, missing := rule.Evaluate(sessions)
		if satisfied {
			return true, nil
		}
		allMissing = append(allMissing, missing...)
	}

	return false, deduplicate(allMissing)
}

func redirectToLogin(app *AutenticoApp, serverName string, w http.ResponseWriter, r *http.Request) error {
	serverConfig, ok := app.Servers[serverName]
	if !ok {
		return caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("server '%s' not configured", serverName))
	}

	provider, err := app.GetProvider(serverName)
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("failed to get provider for %s: %v", serverName, err))
	}

	redirectURL := buildRedirectURL(r)

	oauth2Config := oauth2.Config{
		ClientID:     serverConfig.ClientID,
		ClientSecret: serverConfig.ClientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "groups"},
	}

	state := generateRandomString(32)
	nonce := generateRandomString(32)

	stateData := map[string]string{
		"state":       state,
		"nonce":       nonce,
		"server_name": serverName,
		"return_to":   r.URL.String(),
	}
	stateJSON, _ := json.Marshal(stateData)
	encodedState := base64.RawURLEncoding.EncodeToString(stateJSON)

	http.SetCookie(w, &http.Cookie{
		Name:     cookieNameState,
		Value:    encodedState,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   300, // 5 minutes
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
	})

	url := oauth2Config.AuthCodeURL(state, oidc.Nonce(nonce))
	http.Redirect(w, r, url, http.StatusFound)
	return nil
}

func handleCallback(app *AutenticoApp, w http.ResponseWriter, r *http.Request) error {
	ctx := context.Background()

	stateCookie, err := r.Cookie(cookieNameState)
	if err != nil {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("state cookie missing"))
	}

	stateJSON, err := base64.RawURLEncoding.DecodeString(stateCookie.Value)
	if err != nil {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("invalid state cookie"))
	}

	var stateData map[string]string
	if err := json.Unmarshal(stateJSON, &stateData); err != nil {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("invalid state data"))
	}

	if r.URL.Query().Get("state") != stateData["state"] {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("state mismatch"))
	}

	serverName := stateData["server_name"]
	serverConfig, ok := app.Servers[serverName]
	if !ok {
		return caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("server '%s' not found", serverName))
	}

	provider, err := app.GetProvider(serverName)
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("failed to get provider: %v", err))
	}

	redirectURL := buildRedirectURL(r)

	oauth2Config := oauth2.Config{
		ClientID:     serverConfig.ClientID,
		ClientSecret: serverConfig.ClientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
	}

	oauth2Token, err := oauth2Config.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("failed to exchange token: %v", err))
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("no id_token field in oauth2 token"))
	}

	oidcConfig := &oidc.Config{
		ClientID: serverConfig.ClientID,
	}
	verifier := provider.Verifier(oidcConfig)

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("failed to verify ID Token: %v", err))
	}

	if idToken.Nonce != stateData["nonce"] {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("nonce mismatch"))
	}

	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("failed to parse claims: %v", err))
	}

	// Create and store session
	sess := Session{
		AccessToken: oauth2Token.AccessToken,
		Claims:      claims,
		ServerName:  serverName,
		ExpiresAt:   oauth2Token.Expiry.Unix(),
	}

	encodedSess, err := encodeAndSignSession(&sess, serverConfig.ClientSecret)
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("failed to encode session: %v", err))
	}

	http.SetCookie(w, &http.Cookie{
		Name:     cookieNameSessionPrefix + serverName,
		Value:    encodedSess,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		MaxAge:   int(time.Until(oauth2Token.Expiry).Seconds()),
	})

	// Clear state cookie
	http.SetCookie(w, &http.Cookie{
		Name:   cookieNameState,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	returnTo := stateData["return_to"]
	if returnTo == "" {
		returnTo = "/"
	}

	http.Redirect(w, r, returnTo, http.StatusFound)
	return nil
}

func injectHeaders(r *http.Request, claims map[string]interface{}) {
	caser := cases.Title(language.English)
	for k, v := range claims {
		headerName := "X-Autentico-" + caser.String(strings.ReplaceAll(k, "_", "-"))
		switch val := v.(type) {
		case string:
			r.Header.Set(headerName, val)
		case []interface{}:
			var strs []string
			for _, item := range val {
				if str, ok := item.(string); ok {
					strs = append(strs, str)
				}
			}
			r.Header.Set(headerName, strings.Join(strs, ","))
		case float64:
			r.Header.Set(headerName, fmt.Sprintf("%v", val))
		case bool:
			r.Header.Set(headerName, fmt.Sprintf("%t", val))
		}
	}
}

func buildRedirectURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s%s", scheme, r.Host, callbackPath)
}

func generateRandomString(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
