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
	mfapkg "github.com/yourorg/aegisnas-pi4/internal/mfa"
)

func TestHandleMFAEnrollmentAndVerify(t *testing.T) {
	cfg := prepareMFAAPIConfig(t)

	enrollReq := httptest.NewRequest(http.MethodPost, "/api/v1/system/mfa/enroll", bytes.NewBufferString(`{"username":"alice@example.com"}`))
	enrollRec := httptest.NewRecorder()
	HandleEnrollMFA(enrollRec, enrollReq)
	require.Equal(t, http.StatusCreated, enrollRec.Code)

	var enrollment mfapkg.Enrollment
	require.NoError(t, json.Unmarshal(enrollRec.Body.Bytes(), &enrollment))
	require.NotEmpty(t, enrollment.Secret)
	require.Len(t, enrollment.RecoveryCodes, 1)

	code := mfapkg.GenerateTOTP(enrollment.Secret, mfapkg.TOTPOptions{
		Algorithm:     "SHA1",
		Digits:        6,
		PeriodSeconds: 30,
		Now:           time.Now().UTC(),
	})
	verifyReq := httptest.NewRequest(http.MethodPost, "/api/v1/system/mfa/verify", bytes.NewBufferString(fmt.Sprintf(`{"username":"alice@example.com","code":%q}`, code)))
	verifyRec := httptest.NewRecorder()
	HandleVerifyMFA(verifyRec, verifyReq)
	require.Equal(t, http.StatusOK, verifyRec.Code)
	var verified map[string]any
	require.NoError(t, json.Unmarshal(verifyRec.Body.Bytes(), &verified))
	assert.Equal(t, true, verified["allowed"])

	statusReq := httptest.NewRequest(http.MethodGet, "/api/v1/system/mfa?decision=accepted&limit=10", nil)
	statusRec := httptest.NewRecorder()
	HandleGetMFA(statusRec, statusReq)
	require.Equal(t, http.StatusOK, statusRec.Code)
	var payload map[string]any
	require.NoError(t, json.Unmarshal(statusRec.Body.Bytes(), &payload))
	report := payload["report"].(map[string]any)
	assert.Equal(t, "ready", report["status"])
	assert.Equal(t, cfg.MFA.Enabled, report["enabled"])
}

func TestProductionReadinessIncludesMFACheck(t *testing.T) {
	cfg := prepareMFAAPIConfig(t)
	_, err := mfapkg.EnrollTOTP(httptest.NewRequest(http.MethodPost, "/", nil).Context(), cfg, "admin@example.com")
	require.NoError(t, err)
	report := buildProductionReadinessReport(cfg)
	var found bool
	for _, check := range report.Checks {
		if check.Key == "mfa_challenge_otp" {
			found = true
			assert.Equal(t, "passed", check.Status)
			assert.Contains(t, check.Dependencies, "/api/v1/system/mfa")
		}
	}
	assert.True(t, found)
}

func TestOpenAPIAndSupportBundleIncludeMFA(t *testing.T) {
	spec := buildOpenAPISpec(httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil), nil)
	paths := spec["paths"].(map[string]any)
	assert.Contains(t, paths, "/api/v1/system/mfa")
	assert.Contains(t, paths, "/api/v1/system/mfa/enroll")

	var found bool
	for _, capture := range supportBundleAPICaptures() {
		if capture.archivePath == "api/mfa.json" {
			found = true
			assert.Equal(t, "/api/v1/system/mfa", capture.requestPath)
		}
	}
	assert.True(t, found)
}

func prepareMFAAPIConfig(t *testing.T) *config.Config {
	t.Helper()
	t.Setenv("AEGIS_MFA_SEALING_KEY", "0123456789abcdef0123456789abcdef")
	tmpdb, err := os.CreateTemp("", "mfa-api-*.db")
	require.NoError(t, err)
	dbPath := tmpdb.Name()
	require.NoError(t, tmpdb.Close())
	require.NoError(t, db.Init(dbPath))
	require.NoError(t, db.Migrate())
	restoreHasher := db.SetMFARecoveryCodeHasherForTesting(testMFAAPIRecoveryHash, testMFAAPIRecoveryCompare)

	tmpcfg, err := os.CreateTemp("", "mfa-api-*.yaml")
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
portal:
  enabled: true
  radius_auth: false
  local_fallback: true
identity:
  failover:
    enabled: true
    mode: enforce
    fail_closed: true
    source_order: [local]
    max_failures: 3
    circuit_open_seconds: 300
    stale_cache_seconds: 3600
    split_result_policy: deny
    health_check_interval_seconds: 60
    audit_enabled: true
    retention_limit: 6000
mfa:
  enabled: true
  mode: enforce
  fail_closed: true
  otp:
    enabled: true
    issuer: AegisNAS
    algorithm: SHA1
    digits: 6
    period_seconds: 30
    window_steps: 1
    max_attempts: 3
    sealing_key_ref: env:AEGIS_MFA_SEALING_KEY
    step_up_roles: [admin]
    required_for_admins: true
  radius_challenge:
    enabled: true
    ttl_seconds: 300
    max_pending: 100
    prompt: Enter OTP
    state_bytes: 32
  recovery:
    enabled: true
    code_count: 1
    code_bytes: 8
  audit_enabled: true
  retention_limit: 6000
radius:
  secret: secret
`, strconv.Quote(dbPath))
	require.NoError(t, os.WriteFile(cfgPath, []byte(content), 0644))
	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	t.Cleanup(func() {
		restoreHasher()
		_ = db.Close()
		_ = os.Remove(dbPath)
		_ = os.Remove(cfgPath)
	})
	return cfg
}

func testMFAAPIRecoveryHash(code string) (string, error) {
	return "test$" + code, nil
}

func testMFAAPIRecoveryCompare(hash, code string) bool {
	return hash == "test$"+code
}
