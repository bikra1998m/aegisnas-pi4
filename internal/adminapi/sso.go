package adminapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"golang.org/x/oauth2"
)

const (
	adminSSOComponent          = "admin_sso"
	adminSSOStateCookie        = "aegis_admin_sso_state"
	adminSSONonceCookie        = "aegis_admin_sso_nonce"
	adminSSOVerifierCookie     = "aegis_admin_sso_verifier"
	adminSSOSessionDescription = "admin-sso-session"
	adminSSOMaxSessionLifetime = 8 * time.Hour
	adminSSOCookieLifetime     = 10 * time.Minute
	adminSSOHTTPTimeout        = 10 * time.Second
)

type oidcMetadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

func HandleAdminAuthOptions(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}

	provider := strings.TrimSpace(strings.ToLower(cfg.Integrations.AdminSSO.Provider))
	supported := cfg.Integrations.AdminSSO.Enabled && adminSSOProviderSupported(provider)
	response := map[string]any{
		"token_login": true,
		"sso": map[string]any{
			"enabled":      cfg.Integrations.AdminSSO.Enabled,
			"provider":     provider,
			"supported":    supported,
			"redirect_url": cfg.Integrations.AdminSSO.RedirectURL,
			"issuer_url":   cfg.Integrations.AdminSSO.IssuerURL,
		},
	}
	if provider == "saml" {
		response["sso"].(map[string]any)["metadata_url"] = adminSSOMetadataURL(cfg)
	}
	writeJSON(w, http.StatusOK, response)
}

func HandleAdminSSOStart(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	if !cfg.Integrations.AdminSSO.Enabled {
		redirectLoginError(w, r, "Admin SSO is disabled.")
		return
	}
	provider := strings.ToLower(strings.TrimSpace(cfg.Integrations.AdminSSO.Provider))
	switch provider {
	case "oidc":
		handleAdminSSOStartOIDC(w, r, cfg)
	case "saml":
		handleAdminSSOStartSAML(w, r, cfg)
	default:
		_ = db.UpsertRuntimeStatus(adminSSOComponent, "degraded", "Admin SSO is enabled with an unsupported runtime provider.", map[string]any{
			"provider": cfg.Integrations.AdminSSO.Provider,
		})
		redirectLoginError(w, r, "This admin SSO provider is not supported.")
	}
}

func HandleAdminSSOCallback(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	if !cfg.Integrations.AdminSSO.Enabled {
		redirectLoginError(w, r, "Admin SSO is not available.")
		return
	}
	provider := strings.ToLower(strings.TrimSpace(cfg.Integrations.AdminSSO.Provider))
	switch provider {
	case "oidc":
		handleAdminSSOCallbackOIDC(w, r, cfg)
	case "saml":
		handleAdminSSOCallbackSAML(w, r, cfg)
	default:
		redirectLoginError(w, r, "This admin SSO provider is not supported.")
	}
}

func handleAdminSSOStartOIDC(w http.ResponseWriter, r *http.Request, cfg *config.Config) {
	ctx := oidc.ClientContext(r.Context(), &http.Client{Timeout: adminSSOHTTPTimeout})
	metadata, oauthCfg, err := adminSSOConfig(ctx, cfg)
	if err != nil {
		_ = db.UpsertRuntimeStatus(adminSSOComponent, "degraded", err.Error(), map[string]any{
			"provider": cfg.Integrations.AdminSSO.Provider,
			"issuer":   cfg.Integrations.AdminSSO.IssuerURL,
		})
		redirectLoginError(w, r, "Admin SSO configuration could not be prepared.")
		return
	}

	state, err := randomToken(32)
	if err != nil {
		redirectLoginError(w, r, "Could not create SSO state.")
		return
	}
	nonce, err := randomToken(32)
	if err != nil {
		redirectLoginError(w, r, "Could not create SSO nonce.")
		return
	}
	verifier, err := randomPKCEVerifier()
	if err != nil {
		redirectLoginError(w, r, "Could not create PKCE verifier.")
		return
	}

	setAdminSSOCookie(w, cfg, adminSSOStateCookie, state, adminSSOCookieLifetime)
	setAdminSSOCookie(w, cfg, adminSSONonceCookie, nonce, adminSSOCookieLifetime)
	setAdminSSOCookie(w, cfg, adminSSOVerifierCookie, verifier, adminSSOCookieLifetime)

	authURL := oauthCfg.AuthCodeURL(
		state,
		oauth2.AccessTypeOnline,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("code_challenge", pkceChallenge(verifier)),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
	_ = db.UpsertRuntimeStatus(adminSSOComponent, "ok", "Admin SSO redirect prepared.", map[string]any{
		"provider": cfg.Integrations.AdminSSO.Provider,
		"issuer":   metadata.Issuer,
	})
	http.Redirect(w, r, authURL, http.StatusFound)
}

func handleAdminSSOCallbackOIDC(w http.ResponseWriter, r *http.Request, cfg *config.Config) {
	if callbackErr := strings.TrimSpace(r.URL.Query().Get("error")); callbackErr != "" {
		description := strings.TrimSpace(r.URL.Query().Get("error_description"))
		message := callbackErr
		if description != "" {
			message += ": " + description
		}
		_ = db.UpsertRuntimeStatus(adminSSOComponent, "degraded", "Admin SSO provider returned an error.", map[string]any{
			"provider": cfg.Integrations.AdminSSO.Provider,
			"error":    message,
		})
		auditSSOEvent("admin-sso", "admin_sso_login", message, "failed", r.RemoteAddr)
		clearAdminSSOCookies(w, cfg)
		redirectLoginError(w, r, "Single sign-on failed at the identity provider.")
		return
	}

	expectedState, err := readAdminSSOCookie(r, adminSSOStateCookie)
	if err != nil || expectedState == "" || r.URL.Query().Get("state") != expectedState {
		_ = db.UpsertRuntimeStatus(adminSSOComponent, "degraded", "Admin SSO state validation failed.", map[string]any{
			"provider": cfg.Integrations.AdminSSO.Provider,
		})
		clearAdminSSOCookies(w, cfg)
		redirectLoginError(w, r, "Single sign-on state check failed.")
		return
	}

	expectedNonce, err := readAdminSSOCookie(r, adminSSONonceCookie)
	if err != nil || expectedNonce == "" {
		clearAdminSSOCookies(w, cfg)
		redirectLoginError(w, r, "Single sign-on nonce was not available.")
		return
	}
	verifier, err := readAdminSSOCookie(r, adminSSOVerifierCookie)
	if err != nil || verifier == "" {
		clearAdminSSOCookies(w, cfg)
		redirectLoginError(w, r, "Single sign-on PKCE verifier was not available.")
		return
	}

	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if code == "" {
		clearAdminSSOCookies(w, cfg)
		redirectLoginError(w, r, "Single sign-on did not return an authorization code.")
		return
	}

	ctx := oidc.ClientContext(r.Context(), &http.Client{Timeout: adminSSOHTTPTimeout})
	metadata, oauthCfg, err := adminSSOConfig(ctx, cfg)
	if err != nil {
		clearAdminSSOCookies(w, cfg)
		redirectLoginError(w, r, "Admin SSO configuration could not be loaded.")
		return
	}
	token, err := oauthCfg.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", verifier))
	if err != nil {
		_ = db.UpsertRuntimeStatus(adminSSOComponent, "degraded", err.Error(), map[string]any{
			"provider": cfg.Integrations.AdminSSO.Provider,
			"issuer":   metadata.Issuer,
		})
		auditSSOEvent("admin-sso", "admin_sso_login", err.Error(), "failed", r.RemoteAddr)
		clearAdminSSOCookies(w, cfg)
		redirectLoginError(w, r, "Single sign-on token exchange failed.")
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || strings.TrimSpace(rawIDToken) == "" {
		clearAdminSSOCookies(w, cfg)
		redirectLoginError(w, r, "Identity provider did not return an ID token.")
		return
	}

	idToken, claims, err := verifyIDToken(ctx, oauthCfg.ClientID, metadata, rawIDToken)
	if err != nil {
		_ = db.UpsertRuntimeStatus(adminSSOComponent, "degraded", err.Error(), map[string]any{
			"provider": cfg.Integrations.AdminSSO.Provider,
			"issuer":   metadata.Issuer,
		})
		auditSSOEvent("admin-sso", "admin_sso_login", err.Error(), "failed", r.RemoteAddr)
		clearAdminSSOCookies(w, cfg)
		redirectLoginError(w, r, "Single sign-on token validation failed.")
		return
	}
	if tokenNonce, _ := claimString(claims, "nonce"); tokenNonce != expectedNonce {
		clearAdminSSOCookies(w, cfg)
		redirectLoginError(w, r, "Single sign-on nonce check failed.")
		return
	}

	username := adminSSOUsername(claims)
	if username == "" {
		username = "oidc-admin"
	}
	groups := extractGroups(claims, cfg.Integrations.AdminSSO.GroupsClaim)
	groupCount := len(groups)
	identity, err := syncAdminPrincipalFromClaims(cfg, cfg.Integrations.AdminSSO.Provider, adminSSOSubject(cfg.Integrations.AdminSSO.Provider, username), claims, groups)
	if err != nil {
		_ = db.UpsertRuntimeStatus(adminSSOComponent, "degraded", err.Error(), map[string]any{
			"provider": cfg.Integrations.AdminSSO.Provider,
			"issuer":   metadata.Issuer,
			"username": username,
		})
		auditSSOEvent(username, "admin_sso_login", err.Error(), "failed", r.RemoteAddr)
		clearAdminSSOCookies(w, cfg)
		redirectLoginError(w, r, "Single sign-on is not authorized for this admin account.")
		return
	}

	sessionToken, expiresAt, err := mintAdminSSOSession(username, *identity, cfg.Integrations.AdminSSO.Provider, groups, idToken.Expiry)
	if err != nil {
		clearAdminSSOCookies(w, cfg)
		redirectLoginError(w, r, "Could not create an admin session.")
		return
	}

	_ = db.UpsertRuntimeStatus(adminSSOComponent, "ok", fmt.Sprintf("Admin SSO session created for %s.", username), map[string]any{
		"provider":    cfg.Integrations.AdminSSO.Provider,
		"issuer":      metadata.Issuer,
		"username":    username,
		"role":        identity.Role,
		"tenants":     identity.Tenants,
		"groups":      groupCount,
		"expires_at":  expiresAt.UTC().Format(time.RFC3339),
		"redirect_to": cfg.Integrations.AdminSSO.RedirectURL,
	})
	auditSSOEvent(username, "admin_sso_login", fmt.Sprintf("provider=%s role=%s groups=%d", cfg.Integrations.AdminSSO.Provider, identity.Role, groupCount), "success", r.RemoteAddr)
	clearAdminSSOCookies(w, cfg)
	http.Redirect(w, r, loginSuccessURL(sessionToken), http.StatusFound)
}

func adminSSOProviderSupported(provider string) bool {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "oidc", "saml":
		return true
	default:
		return false
	}
}

func HandleLogout(w http.ResponseWriter, r *http.Request) {
	if tokenHash := tokenHashFromRequest(r); tokenHash != "" && strings.HasPrefix(tokenDescriptionFromRequest(r), adminSSOSessionDescription) {
		removeAdminSession(tokenHash)
		_, _ = db.DB.Exec(`DELETE FROM api_tokens WHERE token = ?`, tokenHash)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged out"})
}

func AdminSSOCallbackPath(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	raw := strings.TrimSpace(cfg.Integrations.AdminSSO.RedirectURL)
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	cleaned := path.Clean("/" + strings.TrimPrefix(parsed.Path, "/"))
	if cleaned == "." || cleaned == "/" {
		return "/auth/callback"
	}
	return cleaned
}

func adminSSOConfig(ctx context.Context, cfg *config.Config) (*oidcMetadata, *oauth2.Config, error) {
	metadata, err := fetchOIDCMetadata(ctx, strings.TrimSpace(cfg.Integrations.AdminSSO.IssuerURL))
	if err != nil {
		return nil, nil, err
	}
	oauthCfg := &oauth2.Config{
		ClientID:     strings.TrimSpace(cfg.Integrations.AdminSSO.ClientID),
		ClientSecret: os.Getenv(strings.TrimSpace(cfg.Integrations.AdminSSO.ClientSecretEnv)),
		RedirectURL:  strings.TrimSpace(cfg.Integrations.AdminSSO.RedirectURL),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  metadata.AuthorizationEndpoint,
			TokenURL: metadata.TokenEndpoint,
		},
	}
	return metadata, oauthCfg, nil
}

func fetchOIDCMetadata(ctx context.Context, issuerURL string) (*oidcMetadata, error) {
	target := strings.TrimSpace(issuerURL)
	if target == "" {
		return nil, fmt.Errorf("issuer URL is empty")
	}
	if !strings.HasSuffix(target, "/.well-known/openid-configuration") {
		target = strings.TrimRight(target, "/") + "/.well-known/openid-configuration"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Timeout: adminSSOHTTPTimeout}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("OIDC discovery returned %s", resp.Status)
	}
	var metadata oidcMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, err
	}
	if strings.TrimSpace(metadata.Issuer) == "" || strings.TrimSpace(metadata.AuthorizationEndpoint) == "" ||
		strings.TrimSpace(metadata.TokenEndpoint) == "" || strings.TrimSpace(metadata.JWKSURI) == "" {
		return nil, fmt.Errorf("OIDC discovery document is incomplete")
	}
	return &metadata, nil
}

func verifyIDToken(ctx context.Context, clientID string, metadata *oidcMetadata, rawIDToken string) (*oidc.IDToken, map[string]any, error) {
	verifier := oidc.NewVerifier(metadata.Issuer, oidc.NewRemoteKeySet(ctx, metadata.JWKSURI), &oidc.Config{ClientID: clientID})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, nil, err
	}
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return nil, nil, err
	}
	return idToken, claims, nil
}

func randomToken(length int) (string, error) {
	if length <= 0 {
		length = 32
	}
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func randomPKCEVerifier() (string, error) {
	return randomToken(48)
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func setAdminSSOCookie(w http.ResponseWriter, cfg *config.Config, name, value string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   adminSSOCookieSecure(cfg),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl.Seconds()),
		Expires:  time.Now().Add(ttl),
	})
}

func clearAdminSSOCookies(w http.ResponseWriter, cfg *config.Config) {
	for _, name := range []string{adminSSOStateCookie, adminSSONonceCookie, adminSSOVerifierCookie} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Secure:   adminSSOCookieSecure(cfg),
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
			Expires:  time.Unix(0, 0),
		})
	}
}

func adminSSOCookieSecure(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	parsed, err := url.Parse(strings.TrimSpace(cfg.Integrations.AdminSSO.RedirectURL))
	return err == nil && strings.EqualFold(parsed.Scheme, "https")
}

func readAdminSSOCookie(r *http.Request, name string) (string, error) {
	cookie, err := r.Cookie(name)
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}

func loginSuccessURL(token string) string {
	return "/login#sso_token=" + url.QueryEscape(token) + "&auth_mode=sso"
}

func redirectLoginError(w http.ResponseWriter, r *http.Request, message string) {
	target := "/login"
	if strings.TrimSpace(message) != "" {
		target += "?sso_error=" + url.QueryEscape(message)
	}
	http.Redirect(w, r, target, http.StatusFound)
}

func mintAdminSSOSession(user string, identity AdminIdentity, provider string, groups []string, upstreamSessionExpiry time.Time) (string, time.Time, error) {
	token, err := randomToken(32)
	if err != nil {
		return "", time.Time{}, err
	}
	expiresAt := time.Now().Add(adminSSOMaxSessionLifetime)
	if !upstreamSessionExpiry.IsZero() && upstreamSessionExpiry.Before(expiresAt) {
		expiresAt = upstreamSessionExpiry
	}
	description := adminSSOSessionDescription
	if provider != "" {
		description += ":" + provider
	}
	_, err = db.DB.Exec(`INSERT INTO api_tokens (token, description, created_by, created_at, expires_at, enabled)
		VALUES (?, ?, ?, datetime('now'), ?, 1)`, hashToken(token), description, user, expiresAt.UTC())
	if err != nil {
		return "", time.Time{}, err
	}
	if err := storeAdminSession(hashToken(token), identity, provider, groups, expiresAt); err != nil {
		_, _ = db.DB.Exec(`DELETE FROM api_tokens WHERE token = ?`, hashToken(token))
		return "", time.Time{}, err
	}
	return token, expiresAt, nil
}

func adminSSOSubject(provider, username string) string {
	provider = strings.TrimSpace(strings.ToLower(provider))
	username = strings.TrimSpace(username)
	if provider == "" {
		return username
	}
	return provider + ":" + username
}

func adminSSOUsername(claims map[string]any) string {
	for _, key := range []string{"preferred_username", "email", "name", "sub"} {
		if value, ok := claimString(claims, key); ok {
			return value
		}
	}
	return ""
}

func claimString(claims map[string]any, key string) (string, bool) {
	value, ok := claims[key]
	if !ok {
		return "", false
	}
	text := strings.TrimSpace(fmt.Sprint(value))
	if text == "" || text == "<nil>" {
		return "", false
	}
	return text, true
}

func extractGroups(claims map[string]any, claimName string) []string {
	name := strings.TrimSpace(claimName)
	if name == "" {
		name = "groups"
	}
	raw, ok := claims[name]
	if !ok {
		return nil
	}
	switch value := raw.(type) {
	case []any:
		groups := make([]string, 0, len(value))
		for _, item := range value {
			text := strings.TrimSpace(fmt.Sprint(item))
			if text != "" && text != "<nil>" {
				groups = append(groups, text)
			}
		}
		return groups
	case []string:
		return value
	default:
		if text := strings.TrimSpace(fmt.Sprint(value)); text != "" && text != "<nil>" {
			return []string{text}
		}
	}
	return nil
}

func auditSSOEvent(user, action, details, result, remoteAddr string) {
	if db.DB == nil {
		return
	}
	_, _ = db.DB.Exec(`INSERT INTO audit_logs (user, action, details, result, ip_address)
		VALUES (?, ?, ?, ?, ?)`, user, action, details, result, remoteAddr)
}
