package adminapi

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	webauthnpkg "github.com/yourorg/aegisnas-pi4/internal/webauthn"
)

const adminWebAuthnSessionDescription = "admin-webauthn-session"

type adminTokenStartRequest struct {
	Token string `json:"token"`
}

type adminWebAuthnStateRequest struct {
	State string `json:"state"`
}

type adminWebAuthnLoginFinishRequest struct {
	State      string                          `json:"state"`
	Credential webauthnpkg.AssertionCredential `json:"credential"`
}

type adminWebAuthnRegisterOptionsRequest struct {
	Subject        string `json:"subject"`
	Username       string `json:"username"`
	DisplayName    string `json:"display_name"`
	CredentialName string `json:"credential_name"`
}

type adminWebAuthnRegisterFinishRequest struct {
	State      string                             `json:"state"`
	Credential webauthnpkg.RegistrationCredential `json:"credential"`
}

func HandleAdminTokenStart(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	var req adminTokenStartRequest
	if err := decodeBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	validation, err := validateAdminBearerToken(req.Token)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid or expired token"})
		return
	}
	required, monitorAllowed := adminWebAuthnRequiredForIdentity(cfg, validation.Identity, validation.Description, "token")
	if !required {
		writeJSON(w, http.StatusOK, map[string]any{"complete": true, "token": req.Token, "auth_mode": "token"})
		return
	}
	runtime, err := adminWebAuthnRuntimeFromRequest(cfg, r)
	if err != nil {
		if monitorAllowed {
			recordAdminWebAuthnMonitorAllowed(cfg, validation.Identity, "token", runtime, err.Error())
			writeJSON(w, http.StatusOK, map[string]any{"complete": true, "token": req.Token, "auth_mode": "token", "monitor_allowed": true})
			return
		}
		writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
		return
	}
	challenge, err := webauthnpkg.BeginAuthentication(cfg, runtime, adminWebAuthnPrincipalFromIdentity(validation.Identity, "token", "", nil))
	if err != nil {
		if monitorAllowed {
			recordAdminWebAuthnMonitorAllowed(cfg, validation.Identity, "token", runtime, err.Error())
			writeJSON(w, http.StatusOK, map[string]any{"complete": true, "token": req.Token, "auth_mode": "token", "monitor_allowed": true})
			return
		}
		writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"complete":         false,
		"step_up_required": true,
		"auth_mode":        "webauthn",
		"state":            challenge.State,
		"expires_at":       challenge.ExpiresAt,
		"publicKey":        challenge.PublicKey,
	})
}

func HandleAdminWebAuthnLoginOptions(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	var req adminWebAuthnStateRequest
	if err := decodeBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	challenge, err := webauthnpkg.AuthenticationChallengeForState(cfg, req.State)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"complete":         false,
		"step_up_required": true,
		"auth_mode":        "webauthn",
		"state":            challenge.State,
		"expires_at":       challenge.ExpiresAt,
		"publicKey":        challenge.PublicKey,
	})
}

func HandleAdminWebAuthnLoginFinish(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	var req adminWebAuthnLoginFinishRequest
	if err := decodeBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	origin := adminWebAuthnOriginFromRequest(r)
	result, err := webauthnpkg.FinishAuthentication(cfg, req.State, req.Credential, origin)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if !result.Allowed {
		writeJSON(w, http.StatusForbidden, result)
		return
	}
	identity := AdminIdentity{
		Subject:     result.Subject,
		DisplayName: result.DisplayName,
		Role:        firstNonEmpty(result.Role, adminRoleReadOnly),
		Source:      "webauthn",
		Tenants:     result.Tenants,
		Permissions: permissionsForAdminRole(firstNonEmpty(result.Role, adminRoleReadOnly)),
		BreakGlass:  false,
	}
	token, expiresAt, err := mintAdminWebAuthnSession(identity, result.FirstFactor, result.Provider, result.Groups, result.SessionExpiresAt)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	audit(r, "admin_webauthn.login", "subject="+identity.Subject, "success")
	writeJSON(w, http.StatusOK, map[string]any{
		"complete":   true,
		"token":      token,
		"auth_mode":  "webauthn",
		"expires_at": expiresAt.UTC().Format(time.RFC3339),
		"identity":   identity,
	})
}

func HandleGetAdminWebAuthn(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	report := webauthnpkg.BuildReport(cfg)
	decision := strings.TrimSpace(r.URL.Query().Get("decision"))
	ceremony := strings.TrimSpace(r.URL.Query().Get("ceremony"))
	subject := strings.TrimSpace(r.URL.Query().Get("subject"))
	limit := parseUpstreamAAAHistoryLimit(r.URL.Query().Get("limit"), 100)
	credentials, err := db.ListAdminWebAuthnCredentials(subject, true, limit)
	if err != nil && db.DB != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	events := []db.AdminWebAuthnEvent{}
	if decision != "" || ceremony != "" || limit != 100 {
		events, err = db.ListAdminWebAuthnEvents(decision, ceremony, limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"report":       report,
		"credentials":  credentials,
		"events":       events,
	})
}

func HandleBeginAdminWebAuthnRegistration(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	var req adminWebAuthnRegisterOptionsRequest
	if err := decodeBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	identity := adminIdentityFromRequest(r)
	subject := firstNonEmpty(req.Subject, req.Username, identity.Subject)
	displayName := firstNonEmpty(req.DisplayName, identity.DisplayName, subject)
	runtime, err := adminWebAuthnRuntimeFromRequest(cfg, r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	challenge, err := webauthnpkg.BeginRegistration(cfg, runtime, webauthnpkg.PrincipalContext{
		Subject:        subject,
		Username:       firstNonEmpty(req.Username, subject),
		DisplayName:    displayName,
		Role:           identity.Role,
		Source:         "admin-api",
		Provider:       "local",
		Tenants:        identity.Tenants,
		FirstFactor:    "admin-api",
		CredentialName: firstNonEmpty(req.CredentialName, "Admin passkey"),
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	audit(r, "admin_webauthn.register.options", "subject="+subject, "success")
	writeJSON(w, http.StatusCreated, challenge)
}

func HandleFinishAdminWebAuthnRegistration(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	var req adminWebAuthnRegisterFinishRequest
	if err := decodeBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	result, err := webauthnpkg.FinishRegistration(cfg, req.State, req.Credential, adminWebAuthnOriginFromRequest(r))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	audit(r, "admin_webauthn.register.finish", "subject="+result.Credential.Subject, "success")
	writeJSON(w, http.StatusCreated, result)
}

func HandleRevokeAdminWebAuthnCredential(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(chi.URLParam(r, "id"))
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "credential id is required"})
		return
	}
	if err := db.RevokeAdminWebAuthnCredential(id, userFromRequest(r), time.Now().UTC()); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	audit(r, "admin_webauthn.credential.revoke", id, "success")
	w.WriteHeader(http.StatusNoContent)
}

func maybeBeginAdminWebAuthnSSOStepUp(w http.ResponseWriter, r *http.Request, cfg *config.Config, username string, identity AdminIdentity, provider string, groups []string, upstreamExpiry time.Time) (bool, error) {
	required, monitorAllowed := adminWebAuthnRequiredForIdentity(cfg, identity, adminSSOSessionDescription+":"+provider, "sso")
	if !required {
		return false, nil
	}
	runtime, err := adminWebAuthnRuntimeFromRequest(cfg, r)
	if err != nil {
		if monitorAllowed {
			recordAdminWebAuthnMonitorAllowed(cfg, identity, "sso", runtime, err.Error())
			return false, nil
		}
		return false, err
	}
	challenge, err := webauthnpkg.BeginAuthentication(cfg, runtime, webauthnpkg.PrincipalContext{
		Subject:     identity.Subject,
		Username:    firstNonEmpty(username, identity.Subject),
		DisplayName: identity.DisplayName,
		Role:        identity.Role,
		Source:      "sso",
		Provider:    provider,
		Tenants:     identity.Tenants,
		Groups:      groups,
		FirstFactor: "sso",
		BreakGlass:  identity.BreakGlass,
	})
	if err != nil {
		if monitorAllowed {
			recordAdminWebAuthnMonitorAllowed(cfg, identity, "sso", runtime, err.Error())
			return false, nil
		}
		return false, err
	}
	_ = upstreamExpiry
	http.Redirect(w, r, loginWebAuthnURL(challenge.State, "sso"), http.StatusFound)
	return true, nil
}

func adminWebAuthnRequiredForIdentity(cfg *config.Config, identity AdminIdentity, description, firstFactor string) (bool, bool) {
	if cfg == nil || strings.HasPrefix(description, adminWebAuthnSessionDescription) {
		return false, false
	}
	policy := webauthnpkg.PolicyFromConfig(cfg)
	required := webauthnpkg.RequiredFor(policy, webauthnpkg.PrincipalContext{
		Subject:     identity.Subject,
		Username:    identity.Subject,
		DisplayName: identity.DisplayName,
		Role:        identity.Role,
		Source:      identity.Source,
		Tenants:     identity.Tenants,
		FirstFactor: firstFactor,
		BreakGlass:  identity.BreakGlass,
	})
	if !required {
		return false, false
	}
	return true, policy.Mode == "monitor" || !policy.FailClosed
}

func adminWebAuthnPrincipalFromIdentity(identity AdminIdentity, firstFactor, provider string, groups []string) webauthnpkg.PrincipalContext {
	return webauthnpkg.PrincipalContext{
		Subject:     identity.Subject,
		Username:    identity.Subject,
		DisplayName: identity.DisplayName,
		Role:        identity.Role,
		Source:      identity.Source,
		Provider:    provider,
		Tenants:     identity.Tenants,
		Groups:      groups,
		FirstFactor: firstFactor,
		BreakGlass:  identity.BreakGlass,
	}
}

func recordAdminWebAuthnMonitorAllowed(cfg *config.Config, identity AdminIdentity, firstFactor string, runtime webauthnpkg.RuntimeContext, reason string) {
	webauthnpkg.RecordMonitorAllowed(cfg, adminWebAuthnPrincipalFromIdentity(identity, firstFactor, "", nil), runtime, reason)
}

func adminWebAuthnRuntimeFromRequest(cfg *config.Config, r *http.Request) (webauthnpkg.RuntimeContext, error) {
	return webauthnpkg.ResolveRuntimeContext(cfg, adminWebAuthnOriginFromRequest(r), adminWebAuthnHostFromRequest(r))
}

func adminWebAuthnOriginFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
		return origin
	}
	if referer := strings.TrimSpace(r.Header.Get("Referer")); referer != "" {
		if parsed, err := url.Parse(referer); err == nil && parsed.Scheme != "" && parsed.Host != "" {
			return parsed.Scheme + "://" + parsed.Host
		}
	}
	scheme := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))
	if scheme == "" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	return scheme + "://" + adminWebAuthnHostFromRequest(r)
}

func adminWebAuthnHostFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	if host := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); host != "" {
		return host
	}
	return strings.TrimSpace(r.Host)
}

func loginWebAuthnURL(state, mode string) string {
	values := url.Values{}
	values.Set("webauthn_state", state)
	if mode != "" {
		values.Set("auth_mode", mode)
	}
	return "/login#" + values.Encode()
}

func mintAdminWebAuthnSession(identity AdminIdentity, firstFactor, provider string, groups []string, expiresAt time.Time) (string, time.Time, error) {
	if db.DB == nil {
		return "", time.Time{}, sql.ErrConnDone
	}
	token, err := randomToken(32)
	if err != nil {
		return "", time.Time{}, err
	}
	if expiresAt.IsZero() {
		expiresAt = time.Now().UTC().Add(8 * time.Hour)
	}
	description := adminWebAuthnSessionDescription
	if strings.TrimSpace(firstFactor) != "" {
		description += ":" + strings.TrimSpace(firstFactor)
	}
	if strings.TrimSpace(provider) != "" {
		description += ":" + strings.TrimSpace(provider)
	}
	_, err = db.DB.Exec(`INSERT INTO api_tokens (token, description, created_by, created_at, expires_at, enabled)
		VALUES (?, ?, ?, datetime('now'), ?, 1)`, hashToken(token), description, identity.Subject, expiresAt.UTC())
	if err != nil {
		return "", time.Time{}, err
	}
	sessionIdentity := identity
	sessionIdentity.Source = "webauthn"
	if err := storeAdminSession(hashToken(token), sessionIdentity, firstNonEmpty(provider, firstFactor, "webauthn"), groups, expiresAt); err != nil {
		_, _ = db.DB.Exec(`DELETE FROM api_tokens WHERE token = ?`, hashToken(token))
		return "", time.Time{}, err
	}
	return token, expiresAt, nil
}

func adminWebAuthnSessionActive(description string) bool {
	return strings.HasPrefix(strings.TrimSpace(description), adminWebAuthnSessionDescription)
}

func adminWebAuthnSummaryForAuthOptions(cfg *config.Config) map[string]any {
	report := webauthnpkg.BuildReport(cfg)
	return map[string]any{
		"enabled":                 report.Policy.Enabled,
		"mode":                    report.Policy.Mode,
		"status":                  report.Status,
		"require_for_sso":         report.Policy.RequireForSSO,
		"require_for_token_login": report.Policy.RequireForTokenLogin,
		"require_for_roles":       report.Policy.RequireForRoles,
		"user_verification":       report.Policy.UserVerification,
	}
}

func webAuthnSessionDescriptionFromRequest(r *http.Request) bool {
	return adminWebAuthnSessionActive(tokenDescriptionFromRequest(r))
}

func adminWebAuthnErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("Admin passkey MFA failed: %s", err.Error())
}
