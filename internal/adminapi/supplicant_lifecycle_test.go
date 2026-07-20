package adminapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestHandleRenderAndGetSupplicantLifecycle(t *testing.T) {
	prepareSupplicantLifecycleAPIConfig(t)
	body := bytes.Buffer{}
	require.NoError(t, json.NewEncoder(&body).Encode(map[string]any{
		"platform":             "windows",
		"username":             "alice@example.com",
		"device_id":            "AA:BB:CC:DD:EE:FF",
		"eap_method":           "tls",
		"delivery":             "api",
		"tls_protected":        true,
		"delivery_token_valid": true,
		"audit":                true,
	}))

	renderRec := httptest.NewRecorder()
	HandleRenderSupplicantProfile(renderRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/supplicant-lifecycle/profile", &body))
	require.Equal(t, http.StatusOK, renderRec.Code)
	assert.Contains(t, renderRec.Body.String(), `"signature_algorithm":"HMAC-SHA256"`)
	assert.Contains(t, renderRec.Body.String(), `"decision":"accepted"`)
	assert.NotContains(t, renderRec.Body.String(), "alice@example.com")

	rec := httptest.NewRecorder()
	HandleGetSupplicantLifecycle(rec, httptest.NewRequest(http.MethodGet, "/api/v1/system/supplicant-lifecycle?limit=10", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	var payload supplicantLifecycleResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, "ready", payload.Status)
	assert.Equal(t, "enforce", payload.Policy.Mode)
	assert.Equal(t, "AegisNAS-Enterprise", payload.Policy.SSID)
	assert.Equal(t, 1, payload.Runtime.TotalEvents)
	assert.Equal(t, 1, payload.Runtime.Accepted)
	require.NotEmpty(t, payload.Profiles)
	assert.Equal(t, "active", payload.Profiles[0].Status)
}

func TestProductionReadinessIncludesSupplicantLifecycle(t *testing.T) {
	prepareSupplicantLifecycleAPIConfig(t)
	report := buildProductionReadinessReport(config.Get())
	assert.Equal(t, "passed", productionReadinessCheckStatus(report.Checks, "supplicant_lifecycle"))
}

func TestAuthorizeSupplicantLifecycle(t *testing.T) {
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/supplicant-lifecycle"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/supplicant-lifecycle/evaluate"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/supplicant-lifecycle/profile"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/supplicant-lifecycle/evaluate"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/supplicant-lifecycle/profile"))
}

func prepareSupplicantLifecycleAPIConfig(t *testing.T) *config.Config {
	t.Helper()
	t.Setenv("AEGIS_SUPPLICANT_PROFILE_SIGNING_KEY", "test-profile-signing-secret")
	tmpdb, err := os.CreateTemp("", "supplicant-lifecycle-api-*.db")
	require.NoError(t, err)
	dbPath := tmpdb.Name()
	require.NoError(t, tmpdb.Close())
	require.NoError(t, db.Init(dbPath))
	require.NoError(t, db.Migrate())
	t.Cleanup(func() {
		db.Close()
		_ = os.Remove(dbPath)
	})

	tmpcfg, err := os.CreateTemp("", "supplicant-lifecycle-api-*.yaml")
	require.NoError(t, err)
	cfgPath := tmpcfg.Name()
	require.NoError(t, tmpcfg.Close())
	t.Cleanup(func() { _ = os.Remove(cfgPath) })

	content := fmt.Sprintf(`
mode: two-nic
deployment:
  profile: enterprise
  form: physical
  hardware:
    memory_mb: 8192
    cpu_cores: 4
wan:
  name: eth0
lan:
  name: eth1
  address: 192.168.1.1/24
database:
  path: %s
telemetry:
  enabled: true
  prometheus_port: 9090
portal:
  enabled: true
  local_fallback: true
  branding: AegisNAS Onboarding
radius:
  secret: secret
  auth_port: 1812
  acct_port: 1813
  request_timeout_seconds: 5
  eap:
    default_type: tls
    tls_min_version: "1.2"
    tls_max_version: "1.3"
    check_crl: true
    ca_path_reload_interval: 3600
    framework:
      enabled: true
      mode: enforce
      fail_closed: true
      allowed_methods: [tls, peap, ttls]
      allowed_inner_methods: [mschapv2, pap, gtc, tls]
      require_message_authenticator: true
      require_identity_binding: true
      telemetry_enabled: true
      identity_sources:
        - name: certificate-subject
          source: certificate
          enabled: true
          methods: [tls]
          allow_certificate_subject: true
          priority: 10
        - name: identity-failover
          source: identity_failover
          enabled: true
          methods: [peap, ttls]
          allow_password_verifier: true
          priority: 20
      method_policies:
        - method: tls
          enabled: true
          identity_source: certificate-subject
          require_certificate: true
          require_revocation: true
        - method: peap
          enabled: true
          inner_methods: [mschapv2]
          identity_source: identity-failover
          allow_password_verifier: true
onboarding:
  device_inventory_enabled: true
  portal_enabled: true
  certificate_enrollment_enabled: true
  eap_tls_enabled: true
  ca_mode: internal
  ca_cert_path: /etc/aegisnas/pki/ca.crt
  ca_key_path: /etc/aegisnas/pki/ca.key
  certificate_lifecycle:
    enabled: true
    mode: enforce
    fail_closed: true
    default_template: device-eap-tls
    templates: [device-eap-tls]
    active_issuer: aegisnas-local
    issuer_rotation_mode: disabled
    issuer_overlap_seconds: 2592000
    certificate_validity_days: 365
    max_certificate_validity_days: 825
    renewal_window_days: 30
    require_csr: true
    require_proof_of_possession: true
    require_device_binding: true
    require_subject_alt_name: true
    allowed_key_types: [rsa, ecdsa]
    min_rsa_bits: 2048
    allowed_ecdsa_curves: [P-256, P-384]
    escrow_policy: forbid
    crl_enabled: true
    est_enabled: true
    scep_enabled: true
    byod_portal_enabled: true
    audit_enabled: true
    event_retention_limit: 100
    inventory_retention_limit: 100
  supplicant_lifecycle:
    enabled: true
    mode: enforce
    fail_closed: true
    ssid: AegisNAS-Enterprise
    security: wpa2-enterprise
    default_platform: windows
    allowed_platforms: [windows, macos, ios, android, linux]
    default_eap_method: tls
    allowed_eap_methods: [tls, peap, ttls]
    default_inner_method: mschapv2
    allowed_inner_methods: [mschapv2, pap, gtc, tls]
    anonymous_identity: anonymous@aegisnas.local
    require_anonymous_identity: true
    server_names: [radius.example.com]
    trust_anchor_pins: [0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef]
    require_trust_anchor_pinning: true
    allow_password_change: true
    password_change_providers: [active-directory, identity-failover]
    require_verifier_compatibility: true
    compatible_verifiers: [active-directory, identity-failover, local]
    max_password_age_days: 90
    expiry_warning_days: 14
    grace_period_days: 7
    min_password_length: 12
    require_mfa_for_change: true
    require_tls_for_delivery: true
    require_signed_profiles: true
    profile_signing_key_ref: env:AEGIS_SUPPLICANT_PROFILE_SIGNING_KEY
    profile_validity_days: 365
    delivery_token_ttl_seconds: 900
    audit_enabled: true
    event_retention_limit: 100
    profile_retention_limit: 100
`, strconvQuote(dbPath))
	require.NoError(t, os.WriteFile(cfgPath, []byte(content), 0644))
	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.NoError(t, cfg.Validate())
	return cfg
}
