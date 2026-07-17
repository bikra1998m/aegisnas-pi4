package adminapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestAdminTokenStartRequiresWebAuthnStepUp(t *testing.T) {
	cfg := prepareAdminWebAuthnAPIConfig(t)
	insertAdminWebAuthnCredentialForSubject(t, "system")
	insertAdminAPIToken(t, "secret-token", "Bootstrap admin token", "system")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/token/start", bytes.NewBufferString(`{"token":"secret-token"}`))
	req.Host = "admin.example.com"
	req.Header.Set("Origin", "https://admin.example.com")
	rec := httptest.NewRecorder()
	HandleAdminTokenStart(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var payload map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, false, payload["complete"])
	assert.Equal(t, true, payload["step_up_required"])
	assert.NotEmpty(t, payload["state"])
	assert.NotNil(t, payload["publicKey"])
	assert.Equal(t, cfg.AdminWebAuthn.Enabled, true)
}

func TestAuthMiddlewareRejectsStaticTokenWhenWebAuthnRequired(t *testing.T) {
	prepareAdminWebAuthnAPIConfig(t)
	insertAdminWebAuthnCredentialForSubject(t, "system")
	insertAdminAPIToken(t, "secret-token", "Bootstrap admin token", "system")

	nextCalled := false
	handler := AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/status", nil)
	req.Host = "admin.example.com"
	req.Header.Set("Origin", "https://admin.example.com")
	req.Header.Set("Authorization", "Bearer secret-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.False(t, nextCalled)
}

func TestProductionReadinessIncludesAdminWebAuthnCheck(t *testing.T) {
	cfg := prepareAdminWebAuthnAPIConfig(t)
	insertAdminWebAuthnCredentialForSubject(t, "system")
	report := buildProductionReadinessReport(cfg)
	var found bool
	for _, check := range report.Checks {
		if check.Key == "admin_webauthn_passkeys" {
			found = true
			assert.Equal(t, "passed", check.Status)
			assert.Contains(t, check.Dependencies, "/api/v1/system/webauthn")
		}
	}
	assert.True(t, found)
}

func TestOpenAPIAndSupportBundleIncludeAdminWebAuthn(t *testing.T) {
	spec := buildOpenAPISpec(httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil), nil)
	paths := spec["paths"].(map[string]any)
	assert.Contains(t, paths, "/api/v1/auth/token/start")
	assert.Contains(t, paths, "/api/v1/auth/webauthn/login/finish")
	assert.Contains(t, paths, "/api/v1/system/webauthn")
	assert.Contains(t, paths, "/api/v1/system/webauthn/register/options")

	var found bool
	for _, capture := range supportBundleAPICaptures() {
		if capture.archivePath == "api/webauthn.json" {
			found = true
			assert.Equal(t, "/api/v1/system/webauthn", capture.requestPath)
		}
	}
	assert.True(t, found)
}

func TestAuthorizeAdminWebAuthn(t *testing.T) {
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/webauthn"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/webauthn/register/options"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleSuperAdmin}, "POST", "/api/v1/system/webauthn/register/options"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleSuperAdmin}, "DELETE", "/api/v1/system/webauthn/credentials/wac_1"))
}

func prepareAdminWebAuthnAPIConfig(t *testing.T) *config.Config {
	t.Helper()
	tmpdb, err := os.CreateTemp("", "admin-webauthn-api-*.db")
	require.NoError(t, err)
	dbPath := tmpdb.Name()
	require.NoError(t, tmpdb.Close())
	require.NoError(t, db.Init(dbPath))
	require.NoError(t, db.Migrate())

	tmpcfg, err := os.CreateTemp("", "admin-webauthn-api-*.yaml")
	require.NoError(t, err)
	cfgPath := tmpcfg.Name()
	require.NoError(t, tmpcfg.Close())
	content := fmt.Sprintf(`
mode: two-nic
wan:
  name: eth0
lan:
  name: eth1
  address: 192.168.1.1/24
database:
  path: %s
admin_webauthn:
  enabled: true
  mode: enforce
  fail_closed: true
  rp_id: admin.example.com
  rp_name: AegisNAS Admin
  origins:
    - https://admin.example.com
  challenge_ttl_seconds: 300
  session_ttl_seconds: 28800
  max_pending: 10000
  user_verification: preferred
  attestation: none
  resident_key: preferred
  require_for_roles: [super_admin]
  require_for_sso: true
  require_for_token_login: true
  break_glass_allowed: false
  audit_enabled: true
  retention_limit: 6000
radius:
  secret: secret
`, strconv.Quote(dbPath))
	require.NoError(t, os.WriteFile(cfgPath, []byte(content), 0644))
	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = db.Close()
		_ = os.Remove(dbPath)
		_ = os.Remove(cfgPath)
	})
	return cfg
}

func insertAdminWebAuthnCredentialForSubject(t *testing.T, subject string) {
	t.Helper()
	require.NoError(t, db.UpsertAdminWebAuthnCredential(db.AdminWebAuthnCredential{
		ID:               "wac_test_" + subject,
		CredentialIDHash: db.HashAdminWebAuthnCredentialID([]byte("credential-" + subject)),
		CredentialIDB64:  "Y3JlZGVudGlhbC0" + subject,
		UsernameHash:     db.HashIdentityUsername(subject),
		Subject:          subject,
		DisplayName:      subject,
		CredentialName:   "Test passkey",
		PublicKeyCOSEB64: "pQECAyYgASFYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIlggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		PublicKeyAlg:     -7,
		SignCount:        1,
		Transports:       []string{"internal"},
		Enabled:          true,
	}, time.Now().UTC()))
}

func insertAdminAPIToken(t *testing.T, token, description, createdBy string) {
	t.Helper()
	_, err := db.DB.Exec(`INSERT INTO api_tokens (token, description, created_by, created_at, enabled)
		VALUES (?, ?, ?, datetime('now'), 1)`, hashToken(token), description, createdBy)
	require.NoError(t, err)
}
