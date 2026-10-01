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
	report := productionReadinessReport{}
	addProductionMFACheck(&report, cfg)
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
	prepareMFATestSchema(t)
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

func prepareMFATestSchema(t *testing.T) {
	t.Helper()
	statements := []string{
		`CREATE TABLE IF NOT EXISTS mfa_totp_secrets (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username_hash TEXT NOT NULL UNIQUE,
			secret_ciphertext TEXT NOT NULL,
			secret_nonce TEXT NOT NULL,
			algorithm TEXT NOT NULL DEFAULT 'SHA1',
			digits INTEGER NOT NULL DEFAULT 6,
			period_seconds INTEGER NOT NULL DEFAULT 30,
			issuer TEXT NOT NULL DEFAULT 'AegisNAS',
			enabled BOOLEAN NOT NULL DEFAULT 1,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_verified_at DATETIME
		)`,
		`CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username_hash TEXT NOT NULL,
			code_hash TEXT NOT NULL,
			used_at DATETIME,
			expires_at DATETIME,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS mfa_challenges (
			id TEXT PRIMARY KEY,
			state_hash TEXT NOT NULL UNIQUE,
			username_hash TEXT NOT NULL,
			source TEXT NOT NULL,
			role TEXT,
			identity_source TEXT,
			auth_method TEXT,
			challenge_type TEXT NOT NULL DEFAULT 'totp',
			status TEXT NOT NULL DEFAULT 'pending',
			attempt_count INTEGER NOT NULL DEFAULT 0,
			max_attempts INTEGER NOT NULL DEFAULT 5,
			prompt TEXT,
			expires_at DATETIME NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			verified_at DATETIME,
			failure_reason TEXT,
			details_json TEXT NOT NULL DEFAULT '{}',
			CHECK (status IN ('pending', 'verified', 'expired', 'failed'))
		)`,
		`CREATE TABLE IF NOT EXISTS mfa_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			observed_at DATETIME NOT NULL,
			username_hash TEXT NOT NULL,
			source TEXT NOT NULL,
			method TEXT NOT NULL,
			decision TEXT NOT NULL,
			reason TEXT NOT NULL,
			challenge_id TEXT,
			role TEXT,
			identity_source TEXT,
			auth_method TEXT,
			details_json TEXT NOT NULL DEFAULT '{}',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_mfa_totp_secrets_username ON mfa_totp_secrets(username_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_mfa_recovery_codes_username ON mfa_recovery_codes(username_hash, used_at, expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_mfa_challenges_state ON mfa_challenges(state_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_mfa_challenges_status_expires ON mfa_challenges(status, expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_mfa_challenges_username ON mfa_challenges(username_hash, created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_mfa_events_observed_at ON mfa_events(observed_at)`,
		`CREATE INDEX IF NOT EXISTS idx_mfa_events_decision ON mfa_events(decision, observed_at)`,
		`CREATE INDEX IF NOT EXISTS idx_mfa_events_username_hash ON mfa_events(username_hash, observed_at)`,
		`CREATE INDEX IF NOT EXISTS idx_mfa_events_method ON mfa_events(method, observed_at)`,
	}
	for _, statement := range statements {
		_, err := db.DB.Exec(statement)
		require.NoError(t, err)
	}
}

func testMFAAPIRecoveryHash(code string) (string, error) {
	return "test$" + code, nil
}

func testMFAAPIRecoveryCompare(hash, code string) bool {
	return hash == "test$"+code
}
