package adminapi

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

const adminSSOMetadataPath = "/api/v1/auth/sso/metadata"

func HandleAdminSSOMetadata(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	if !cfg.Integrations.AdminSSO.Enabled || !strings.EqualFold(strings.TrimSpace(cfg.Integrations.AdminSSO.Provider), "saml") {
		http.Error(w, "SAML admin SSO is not enabled", http.StatusNotFound)
		return
	}
	middleware, err := adminSAMLMiddleware(cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	middleware.ServeMetadata(w, r)
}

func adminSSOMetadataURL(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	redirectURL := strings.TrimSpace(cfg.Integrations.AdminSSO.RedirectURL)
	if redirectURL == "" {
		return ""
	}
	parsed, err := url.Parse(redirectURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	parsed.Path = adminSSOMetadataPath
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func handleAdminSSOStartSAML(w http.ResponseWriter, r *http.Request, cfg *config.Config) {
	middleware, err := adminSAMLMiddleware(cfg)
	if err != nil {
		_ = db.UpsertRuntimeStatus(adminSSOComponent, "degraded", err.Error(), map[string]any{
			"provider": cfg.Integrations.AdminSSO.Provider,
			"issuer":   cfg.Integrations.AdminSSO.IssuerURL,
		})
		redirectLoginError(w, r, "Admin SSO configuration could not be prepared.")
		return
	}

	_ = db.UpsertRuntimeStatus(adminSSOComponent, "ok", "Admin SSO redirect prepared.", map[string]any{
		"provider":     cfg.Integrations.AdminSSO.Provider,
		"issuer":       cfg.Integrations.AdminSSO.IssuerURL,
		"metadata_url": adminSSOMetadataURL(cfg),
	})
	middleware.HandleStartAuthFlow(w, r)
}

func handleAdminSSOCallbackSAML(w http.ResponseWriter, r *http.Request, cfg *config.Config) {
	middleware, err := adminSAMLMiddleware(cfg)
	if err != nil {
		_ = db.UpsertRuntimeStatus(adminSSOComponent, "degraded", err.Error(), map[string]any{
			"provider": cfg.Integrations.AdminSSO.Provider,
			"issuer":   cfg.Integrations.AdminSSO.IssuerURL,
		})
		redirectLoginError(w, r, "Admin SSO configuration could not be prepared.")
		return
	}
	if err := r.ParseForm(); err != nil {
		redirectLoginError(w, r, "Single sign-on response could not be parsed.")
		return
	}

	possibleRequestIDs := []string{}
	for _, trackedRequest := range middleware.RequestTracker.GetTrackedRequests(r) {
		possibleRequestIDs = append(possibleRequestIDs, trackedRequest.SAMLRequestID)
	}
	assertion, err := middleware.ServiceProvider.ParseResponse(r, possibleRequestIDs)
	if err != nil {
		_ = db.UpsertRuntimeStatus(adminSSOComponent, "degraded", err.Error(), map[string]any{
			"provider": cfg.Integrations.AdminSSO.Provider,
			"issuer":   cfg.Integrations.AdminSSO.IssuerURL,
		})
		auditSSOEvent("saml-admin", "admin_sso_login", err.Error(), "failed", r.RemoteAddr)
		redirectLoginError(w, r, "Single sign-on response validation failed.")
		return
	}

	if relayState := strings.TrimSpace(r.Form.Get("RelayState")); relayState != "" {
		_ = middleware.RequestTracker.StopTrackingRequest(w, r, relayState)
	}

	claims, groups, username := claimsFromSAMLAssertion(assertion, cfg.Integrations.AdminSSO.GroupsClaim)
	if username == "" {
		username = "saml-admin"
	}
	subject := adminSSOSubject(cfg.Integrations.AdminSSO.Provider, username)
	identity, err := syncAdminPrincipalFromClaims(cfg, cfg.Integrations.AdminSSO.Provider, subject, claims, groups)
	if err != nil {
		_ = db.UpsertRuntimeStatus(adminSSOComponent, "degraded", err.Error(), map[string]any{
			"provider": cfg.Integrations.AdminSSO.Provider,
			"issuer":   cfg.Integrations.AdminSSO.IssuerURL,
			"username": username,
		})
		auditSSOEvent(username, "admin_sso_login", err.Error(), "failed", r.RemoteAddr)
		redirectLoginError(w, r, "Single sign-on is not authorized for this admin account.")
		return
	}

	sessionToken, expiresAt, err := mintAdminSSOSession(username, *identity, cfg.Integrations.AdminSSO.Provider, groups, samlAssertionExpiry(assertion))
	if err != nil {
		redirectLoginError(w, r, "Could not create an admin session.")
		return
	}

	_ = db.UpsertRuntimeStatus(adminSSOComponent, "ok", fmt.Sprintf("Admin SSO session created for %s.", username), map[string]any{
		"provider":     cfg.Integrations.AdminSSO.Provider,
		"issuer":       cfg.Integrations.AdminSSO.IssuerURL,
		"metadata_url": adminSSOMetadataURL(cfg),
		"username":     username,
		"role":         identity.Role,
		"tenants":      identity.Tenants,
		"groups":       len(groups),
		"expires_at":   expiresAt.UTC().Format(time.RFC3339),
		"redirect_to":  cfg.Integrations.AdminSSO.RedirectURL,
	})
	auditSSOEvent(username, "admin_sso_login", fmt.Sprintf("provider=%s role=%s groups=%d", cfg.Integrations.AdminSSO.Provider, identity.Role, len(groups)), "success", r.RemoteAddr)
	http.Redirect(w, r, loginSuccessURL(sessionToken), http.StatusFound)
}

func adminSAMLMiddleware(cfg *config.Config) (*samlsp.Middleware, error) {
	redirectURL, err := url.Parse(strings.TrimSpace(cfg.Integrations.AdminSSO.RedirectURL))
	if err != nil || redirectURL.Scheme == "" || redirectURL.Host == "" {
		return nil, errors.New("admin SSO redirect URL is invalid")
	}
	baseURL := &url.URL{Scheme: redirectURL.Scheme, Host: redirectURL.Host}
	metadataURL, err := url.Parse(strings.TrimSpace(cfg.Integrations.AdminSSO.IssuerURL))
	if err != nil || metadataURL.Scheme == "" || metadataURL.Host == "" {
		return nil, errors.New("admin SSO issuer or metadata URL is invalid")
	}

	idpMetadata, err := samlsp.FetchMetadata(context.Background(), &http.Client{Timeout: adminSSOHTTPTimeout}, *metadataURL)
	if err != nil {
		return nil, err
	}
	privateKey, certificate, err := ensureAdminSAMLKeyPair(cfg)
	if err != nil {
		return nil, err
	}

	middleware, err := samlsp.New(samlsp.Options{
		EntityID:    strings.TrimSpace(cfg.Integrations.AdminSSO.ClientID),
		URL:         *baseURL,
		Key:         privateKey,
		Certificate: certificate,
		IDPMetadata: idpMetadata,
		SignRequest: true,
	})
	if err != nil {
		return nil, err
	}
	if metadataEndpoint, err := url.Parse(adminSSOMetadataURL(cfg)); err == nil {
		middleware.ServiceProvider.MetadataURL = *metadataEndpoint
	}
	middleware.ServiceProvider.AcsURL = *redirectURL
	middleware.ServiceProvider.DefaultRedirectURI = "/login"
	return middleware, nil
}

func ensureAdminSAMLKeyPair(cfg *config.Config) (*rsa.PrivateKey, *x509.Certificate, error) {
	certPath, keyPath, err := adminSAMLMaterialPaths(cfg)
	if err != nil {
		return nil, nil, err
	}
	if fileExists(certPath) && fileExists(keyPath) {
		return loadAdminSAMLKeyPair(certPath, keyPath)
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0700); err != nil {
		return nil, nil, err
	}

	privateKey, certificatePEM, keyPEM, err := generateAdminSAMLKeyPair(cfg)
	if err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(certPath, certificatePEM, 0600); err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return nil, nil, err
	}
	_, certificate, err := parseAdminSAMLKeyPair(certificatePEM, keyPEM)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, certificate, nil
}

func adminSAMLMaterialPaths(cfg *config.Config) (string, string, error) {
	if cfg == nil {
		return "", "", errors.New("configuration is required")
	}
	baseDir := filepath.Join(filepath.Dir(cfg.Database.Path), "admin-sso")
	return filepath.Join(baseDir, "saml-sp.crt"), filepath.Join(baseDir, "saml-sp.key"), nil
}

func loadAdminSAMLKeyPair(certPath, keyPath string) (*rsa.PrivateKey, *x509.Certificate, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}
	return parseAdminSAMLKeyPair(certPEM, keyPEM)
}

func parseAdminSAMLKeyPair(certPEM, keyPEM []byte) (*rsa.PrivateKey, *x509.Certificate, error) {
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, errors.New("invalid admin SAML private key pem")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, errors.New("invalid admin SAML certificate pem")
	}
	certificate, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, certificate, nil
}

func generateAdminSAMLKeyPair(cfg *config.Config) (*rsa.PrivateKey, []byte, []byte, error) {
	redirectURL, err := url.Parse(strings.TrimSpace(cfg.Integrations.AdminSSO.RedirectURL))
	if err != nil || redirectURL.Hostname() == "" {
		return nil, nil, nil, errors.New("admin SSO redirect URL is invalid")
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   redirectURL.Hostname(),
			Organization: []string{"AegisNAS Admin SSO"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{redirectURL.Hostname()},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, nil, err
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	return privateKey, certificatePEM, keyPEM, nil
}

func claimsFromSAMLAssertion(assertion *saml.Assertion, groupsClaim string) (map[string]any, []string, string) {
	claims := map[string]any{}
	if assertion == nil {
		return claims, nil, ""
	}
	subject := ""
	if assertion.Subject != nil && assertion.Subject.NameID != nil {
		subject = strings.TrimSpace(assertion.Subject.NameID.Value)
		if subject != "" {
			claims["sub"] = subject
			claims["name_id"] = subject
		}
	}
	for _, statement := range assertion.AttributeStatements {
		for _, attribute := range statement.Attributes {
			values := attributeValues(attribute)
			if len(values) == 0 {
				continue
			}
			storeSAMLClaim(claims, attribute.Name, values)
			storeSAMLClaim(claims, attribute.FriendlyName, values)
		}
	}

	if email := firstClaimValue(claims, "email", "mail", "EmailAddress"); email != "" {
		claims["email"] = email
	}
	if name := firstClaimValue(claims, "displayName", "commonName", "name", "cn"); name != "" {
		claims["name"] = name
	}
	if preferred := firstClaimValue(claims, "preferred_username", "uid", "userPrincipalName", "mail", "email"); preferred != "" {
		claims["preferred_username"] = preferred
	}
	username := firstClaimValue(claims, "preferred_username", "email", "mail", "uid")
	if username == "" {
		username = subject
	}
	groups := extractGroups(claims, groupsClaim)
	if len(groups) == 0 {
		groups = extractGroups(claims, "groups")
	}
	if len(groups) == 0 {
		groups = extractGroups(claims, "memberOf")
	}
	return claims, groups, username
}

func attributeValues(attribute saml.Attribute) []string {
	values := make([]string, 0, len(attribute.Values))
	for _, item := range attribute.Values {
		value := strings.TrimSpace(item.Value)
		if value == "" && item.NameID != nil {
			value = strings.TrimSpace(item.NameID.Value)
		}
		if value != "" {
			values = append(values, value)
		}
	}
	return values
}

func storeSAMLClaim(claims map[string]any, key string, values []string) {
	key = strings.TrimSpace(key)
	if key == "" || len(values) == 0 {
		return
	}
	if len(values) == 1 {
		claims[key] = values[0]
		return
	}
	claims[key] = values
}

func firstClaimValue(claims map[string]any, keys ...string) string {
	for _, key := range keys {
		value, ok := claims[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case string:
			if strings.TrimSpace(typed) != "" {
				return strings.TrimSpace(typed)
			}
		case []string:
			for _, item := range typed {
				if strings.TrimSpace(item) != "" {
					return strings.TrimSpace(item)
				}
			}
		case []any:
			for _, item := range typed {
				if text := strings.TrimSpace(fmt.Sprint(item)); text != "" && text != "<nil>" {
					return text
				}
			}
		default:
			if text := strings.TrimSpace(fmt.Sprint(typed)); text != "" && text != "<nil>" {
				return text
			}
		}
	}
	return ""
}

func samlAssertionExpiry(assertion *saml.Assertion) time.Time {
	if assertion == nil {
		return time.Time{}
	}
	var expiresAt time.Time
	if assertion.Conditions != nil && !assertion.Conditions.NotOnOrAfter.IsZero() {
		expiresAt = assertion.Conditions.NotOnOrAfter
	}
	for _, statement := range assertion.AuthnStatements {
		if statement.SessionNotOnOrAfter != nil && !statement.SessionNotOnOrAfter.IsZero() {
			if expiresAt.IsZero() || statement.SessionNotOnOrAfter.Before(expiresAt) {
				expiresAt = *statement.SessionNotOnOrAfter
			}
		}
	}
	return expiresAt
}

func fileExists(target string) bool {
	info, err := os.Stat(target)
	return err == nil && !info.IsDir()
}
