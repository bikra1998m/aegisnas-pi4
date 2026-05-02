package adminapi

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestHandleAdminSSOStartAndCallbackOIDC(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	var authNonce string
	issuer := newFakeOIDCProvider(t, privateKey, func() string { return authNonce }, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	defer issuer.Close()

	loadAdminSSOTestConfig(t, issuer.URL)

	startReq := httptest.NewRequest(http.MethodGet, "/api/v1/auth/sso/start", nil)
	startRes := httptest.NewRecorder()
	HandleAdminSSOStart(startRes, startReq)

	require.Equal(t, http.StatusFound, startRes.Code)
	location := startRes.Header().Get("Location")
	require.Contains(t, location, issuer.URL+"/authorize")
	authURL, err := url.Parse(location)
	require.NoError(t, err)
	assert.NotEmpty(t, authURL.Query().Get("state"))
	authNonce = authURL.Query().Get("nonce")
	assert.NotEmpty(t, authNonce)
	assert.NotEmpty(t, authURL.Query().Get("code_challenge"))
	assert.Equal(t, "S256", authURL.Query().Get("code_challenge_method"))

	stateCookie := findCookie(t, startRes.Result().Cookies(), adminSSOStateCookie)
	nonceCookie := findCookie(t, startRes.Result().Cookies(), adminSSONonceCookie)
	verifierCookie := findCookie(t, startRes.Result().Cookies(), adminSSOVerifierCookie)
	require.NotEmpty(t, stateCookie.Value)
	require.NotEmpty(t, nonceCookie.Value)
	require.NotEmpty(t, verifierCookie.Value)

	callbackReq := httptest.NewRequest(http.MethodGet, "/auth/callback?code=test-code&state="+url.QueryEscape(stateCookie.Value), nil)
	callbackReq.AddCookie(stateCookie)
	callbackReq.AddCookie(nonceCookie)
	callbackReq.AddCookie(verifierCookie)
	callbackRes := httptest.NewRecorder()
	HandleAdminSSOCallback(callbackRes, callbackReq)

	require.Equal(t, http.StatusFound, callbackRes.Code)
	redirect := callbackRes.Header().Get("Location")
	require.Contains(t, redirect, "/login#sso_token=")

	token := parseTokenFromRedirect(t, redirect)
	require.NotEmpty(t, token)

	var count int
	err = db.DB.QueryRow(`SELECT COUNT(*) FROM api_tokens WHERE token = ?`, hashToken(token)).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	status, err := db.GetRuntimeStatus(adminSSOComponent)
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.Equal(t, "ok", status.Status)
	assert.Contains(t, status.Message, "Admin SSO session created")
}

func TestHandleLogoutRevokesAdminSSOSession(t *testing.T) {
	loadAdminSSOTestConfig(t, "https://issuer.example.test")

	token, _, err := mintAdminSSOSession("alice@example.com", AdminIdentity{
		Subject:     "oidc:alice@example.com",
		DisplayName: "alice@example.com",
		Role:        adminRoleSuperAdmin,
		Source:      "oidc",
		Permissions: permissionsForAdminRole(adminRoleSuperAdmin),
	}, "oidc", []string{"aegisnas-admin"}, time.Now().Add(time.Hour))
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	req = req.WithContext(context.WithValue(req.Context(), tokenHashContextKey, hashToken(token)))
	req = req.WithContext(context.WithValue(req.Context(), tokenDescriptionContextKey, adminSSOSessionDescription+":oidc"))
	res := httptest.NewRecorder()
	HandleLogout(res, req)

	require.Equal(t, http.StatusOK, res.Code)
	var count int
	err = db.DB.QueryRow(`SELECT COUNT(*) FROM api_tokens WHERE token = ?`, hashToken(token)).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
	err = db.DB.QueryRow(`SELECT COUNT(*) FROM admin_sessions WHERE token_hash = ?`, hashToken(token)).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestHandleAdminSSOStartAndMetadataSAML(t *testing.T) {
	metadataServer := newFakeSAMLMetadataProvider(t)
	defer metadataServer.Close()

	cfg := loadAdminSSOTestConfigWithProvider(t, "saml", metadataServer.URL+"/metadata", "https://aegisnas.example.test/admin-sso", "http://127.0.0.1/auth/callback")

	optionsReq := httptest.NewRequest(http.MethodGet, "/api/v1/auth/options", nil)
	optionsRes := httptest.NewRecorder()
	HandleAdminAuthOptions(optionsRes, optionsReq)
	require.Equal(t, http.StatusOK, optionsRes.Code)

	var options map[string]any
	require.NoError(t, json.Unmarshal(optionsRes.Body.Bytes(), &options))
	sso, ok := options["sso"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "saml", sso["provider"])
	assert.Equal(t, true, sso["supported"])
	assert.Equal(t, adminSSOMetadataURL(cfg), sso["metadata_url"])

	startReq := httptest.NewRequest(http.MethodGet, "/api/v1/auth/sso/start", nil)
	startRes := httptest.NewRecorder()
	HandleAdminSSOStart(startRes, startReq)

	require.Equal(t, http.StatusFound, startRes.Code)
	location := startRes.Header().Get("Location")
	require.Contains(t, location, metadataServer.URL+"/idp/sso")
	redirectURL, err := url.Parse(location)
	require.NoError(t, err)
	assert.NotEmpty(t, redirectURL.Query().Get("SAMLRequest"))
	assert.NotEmpty(t, redirectURL.Query().Get("RelayState"))

	metadataReq := httptest.NewRequest(http.MethodGet, "/api/v1/auth/sso/metadata", nil)
	metadataRes := httptest.NewRecorder()
	HandleAdminSSOMetadata(metadataRes, metadataReq)

	require.Equal(t, http.StatusOK, metadataRes.Code)
	assert.Equal(t, "application/samlmetadata+xml", metadataRes.Header().Get("Content-type"))
	assert.Contains(t, metadataRes.Body.String(), cfg.Integrations.AdminSSO.ClientID)
	assert.Contains(t, metadataRes.Body.String(), cfg.Integrations.AdminSSO.RedirectURL)

	certPath, keyPath, err := adminSAMLMaterialPaths(cfg)
	require.NoError(t, err)
	_, err = os.Stat(certPath)
	require.NoError(t, err)
	_, err = os.Stat(keyPath)
	require.NoError(t, err)

	status, err := db.GetRuntimeStatus(adminSSOComponent)
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.Equal(t, "ok", status.Status)
	assert.Contains(t, status.Message, "redirect prepared")
}

func newFakeOIDCProvider(t *testing.T, key *rsa.PrivateKey, nonce func() string, fallback http.HandlerFunc) *httptest.Server {
	t.Helper()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeJSON(w, http.StatusOK, map[string]any{
				"issuer":                 serverURLFromRequest(r),
				"authorization_endpoint": serverURLFromRequest(r) + "/authorize",
				"token_endpoint":         serverURLFromRequest(r) + "/token",
				"jwks_uri":               serverURLFromRequest(r) + "/keys",
			})
		case "/keys":
			pub := key.PublicKey
			writeJSON(w, http.StatusOK, map[string]any{
				"keys": []map[string]any{
					{
						"kty": "RSA",
						"use": "sig",
						"alg": "RS256",
						"kid": "test-key",
						"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
						"e":   base64.RawURLEncoding.EncodeToString(bigEndianInt(pub.E)),
					},
				},
			})
		case "/token":
			require.NoError(t, r.ParseForm())
			assert.NotEmpty(t, r.Form.Get("code_verifier"))
			idToken := signIDToken(t, key, map[string]any{
				"iss":                serverURLFromRequest(r),
				"sub":                "user-123",
				"aud":                "aegisnas-admin",
				"exp":                time.Now().Add(time.Hour).Unix(),
				"iat":                time.Now().Add(-time.Minute).Unix(),
				"nonce":              nonce(),
				"preferred_username": "alice@example.com",
				"email":              "alice@example.com",
				"groups":             []string{"netops", "admins"},
			})
			writeJSON(w, http.StatusOK, map[string]any{
				"access_token": "access-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
				"id_token":     idToken,
			})
		default:
			fallback(w, r)
		}
	})

	server := httptest.NewServer(handler)
	return server
}

func newFakeSAMLMetadataProvider(t *testing.T) *httptest.Server {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(20260502),
		Subject: pkix.Name{
			CommonName:   "fake-idp.example.test",
			Organization: []string{"AegisNAS Tests"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)
	certB64 := base64.StdEncoding.EncodeToString(certDER)

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/metadata":
			w.Header().Set("Content-Type", "application/samlmetadata+xml")
			_, _ = fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%[1]s/metadata">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" WantAuthnRequestsSigned="true">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>%[2]s</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="%[1]s/idp/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`, server.URL, certB64)
		default:
			http.NotFound(w, r)
		}
	}))
	return server
}

func loadAdminSSOTestConfig(t *testing.T, issuerURL string) *config.Config {
	return loadAdminSSOTestConfigWithProvider(t, "oidc", issuerURL, "aegisnas-admin", "http://127.0.0.1/auth/callback")
}

func loadAdminSSOTestConfigWithProvider(t *testing.T, provider, issuerURL, clientID, redirectURL string) *config.Config {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "admin-sso.db")
	require.NoError(t, db.Init(dbPath))
	require.NoError(t, db.Migrate())
	t.Cleanup(func() {
		_ = db.Close()
		db.DB = nil
	})

	tmpfile, err := os.CreateTemp("", "aegis-admin-sso-*.yaml")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = os.Remove(tmpfile.Name())
	})

	content := fmt.Sprintf(`
mode: two-nic
deployment:
  profile: branch
wan:
  name: eth0
  dhcp: true
lan:
  name: eth1
  address: 192.168.50.1/24
database:
  path: %q
logging:
  level: info
  output: stdout
health:
  port: 8080
telemetry:
  enabled: true
  prometheus_port: 9090
radius:
  auth_port: 1812
  acct_port: 1813
  request_timeout_seconds: 5
integrations:
  admin_sso:
    enabled: true
    provider: %q
    issuer_url: %q
    client_id: %q
    redirect_url: %q
    groups_claim: groups
`, filepath.ToSlash(dbPath), provider, issuerURL, clientID, redirectURL)
	_, err = tmpfile.WriteString(content)
	require.NoError(t, err)
	require.NoError(t, tmpfile.Close())

	cfg, err := config.Load(tmpfile.Name())
	require.NoError(t, err)
	require.NoError(t, cfg.Validate())
	return cfg
}

func signIDToken(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()

	header := map[string]any{
		"alg": "RS256",
		"kid": "test-key",
		"typ": "JWT",
	}
	headerJSON, err := json.Marshal(header)
	require.NoError(t, err)
	claimsJSON, err := json.Marshal(claims)
	require.NoError(t, err)

	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	require.NoError(t, err)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func parseTokenFromRedirect(t *testing.T, redirect string) string {
	t.Helper()

	parts := strings.SplitN(redirect, "#", 2)
	require.Len(t, parts, 2)
	values, err := url.ParseQuery(parts[1])
	require.NoError(t, err)
	return values.Get("sso_token")
}

func findCookie(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("cookie %s not found", name)
	return nil
}

func serverURLFromRequest(r *http.Request) string {
	return "http://" + r.Host
}

func bigEndianInt(value int) []byte {
	if value == 0 {
		return []byte{0}
	}
	var out []byte
	for value > 0 {
		out = append([]byte{byte(value & 0xff)}, out...)
		value >>= 8
	}
	return out
}
