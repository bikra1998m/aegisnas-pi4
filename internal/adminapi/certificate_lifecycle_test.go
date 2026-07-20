package adminapi

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestHandleGetAndEvaluateCertificateLifecycle(t *testing.T) {
	prepareCertificateLifecycleAPIConfig(t)
	csrPEM := certificateLifecycleTestCSR(t, "device-1", []string{"device-1"})
	body := bytes.Buffer{}
	require.NoError(t, json.NewEncoder(&body).Encode(map[string]any{
		"protocol":                "est",
		"device_id":               "device-1",
		"csr_pem":                 csrPEM,
		"requested_validity_days": 90,
		"device_bound":            true,
		"revocation_checked":      true,
		"crl_reachable":           true,
		"certificate_serial":      "serial-1",
		"certificate_not_after":   time.Now().Add(90 * 24 * time.Hour).UTC().Format(time.RFC3339),
		"audit":                   true,
	}))

	evalRec := httptest.NewRecorder()
	HandleEvaluateCertificateLifecycle(evalRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/certificate-lifecycle/evaluate", &body))
	require.Equal(t, http.StatusOK, evalRec.Code)
	assert.Contains(t, evalRec.Body.String(), `"decision":"accepted"`)
	assert.Contains(t, evalRec.Body.String(), `"audited":true`)

	rec := httptest.NewRecorder()
	HandleGetCertificateLifecycle(rec, httptest.NewRequest(http.MethodGet, "/api/v1/system/certificate-lifecycle?limit=10", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	var payload certificateLifecycleResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, "ready", payload.Status)
	assert.Equal(t, "enforce", payload.Policy.Mode)
	assert.Equal(t, "aegisnas-local", payload.Policy.ActiveIssuer)
	assert.Equal(t, 1, payload.Runtime.TotalEvents)
	assert.Equal(t, 1, payload.Runtime.Accepted)
	require.Len(t, payload.Events, 1)
	assert.NotContains(t, payload.Events[0].SubjectHash, "device-1")
	require.Len(t, payload.Inventory, 1)
	assert.Equal(t, "active", payload.Inventory[0].Status)
}

func TestProductionReadinessIncludesCertificateLifecycle(t *testing.T) {
	prepareCertificateLifecycleAPIConfig(t)
	report := buildProductionReadinessReport(config.Get())
	assert.Equal(t, "passed", productionReadinessCheckStatus(report.Checks, "certificate_lifecycle"))
}

func TestAuthorizeCertificateLifecycle(t *testing.T) {
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/certificate-lifecycle"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/certificate-lifecycle/evaluate"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/certificate-lifecycle/evaluate"))
}

func prepareCertificateLifecycleAPIConfig(t *testing.T) *config.Config {
	t.Helper()
	tmpdb, err := os.CreateTemp("", "cert-lifecycle-api-*.db")
	require.NoError(t, err)
	dbPath := tmpdb.Name()
	require.NoError(t, tmpdb.Close())
	require.NoError(t, db.Init(dbPath))
	require.NoError(t, db.Migrate())
	t.Cleanup(func() {
		db.Close()
		_ = os.Remove(dbPath)
	})

	tmpcfg, err := os.CreateTemp("", "cert-lifecycle-api-*.yaml")
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
portal:
  enabled: true
  local_fallback: true
  branding: AegisNAS Onboarding
radius:
  secret: secret
  auth_port: 1812
  acct_port: 1813
  request_timeout_seconds: 5
  clients:
    - ip: 192.0.2.10
      shortname: lab-ap
      secret: secret
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
      allowed_methods: [peap, ttls, tls]
      allowed_inner_methods: [mschapv2, pap, chap, gtc, tls]
      require_message_authenticator: true
      require_identity_binding: true
      telemetry_enabled: true
      identity_sources:
        - name: identity-failover
          source: identity_failover
          enabled: true
          methods: [peap, ttls]
          allow_password_verifier: true
          priority: 10
        - name: certificate-subject
          source: certificate
          enabled: true
          methods: [tls]
          allow_certificate_subject: true
          priority: 20
      method_policies:
        - method: tls
          enabled: true
          identity_source: certificate-subject
          require_certificate: true
          require_revocation: true
          allow_password_verifier: false
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
    templates: [device-eap-tls, byod-eap-tls]
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
    allowed_key_types: [rsa, ecdsa, ed25519]
    min_rsa_bits: 2048
    allowed_ecdsa_curves: [P-256, P-384, P-521]
    escrow_policy: forbid
    crl_enabled: true
    est_enabled: true
    scep_enabled: true
    byod_portal_enabled: true
    audit_enabled: true
    event_retention_limit: 6000
    inventory_retention_limit: 100000
`, strconvQuote(dbPath))
	require.NoError(t, os.WriteFile(cfgPath, []byte(content), 0644))
	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.NoError(t, cfg.Validate())
	return cfg
}

func certificateLifecycleTestCSR(t *testing.T, commonName string, dnsNames []string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: commonName},
		DNSNames: dnsNames,
	}, key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func strconvQuote(value string) string {
	data, _ := json.Marshal(value)
	return string(data)
}
