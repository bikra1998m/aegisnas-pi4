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

func TestHandleGetAndEvaluateEAPFramework(t *testing.T) {
	prepareEAPFrameworkAPIConfig(t)

	body := bytes.NewBufferString(`{
		"method":"peap",
		"inner_method":"mschapv2",
		"nas_type":"cisco",
		"nas_identifier":"ap-1",
		"user_name":"alice@example.com",
		"calling_station_id":"aa:bb:cc:dd:ee:ff",
		"eap_message_present":true,
		"message_authenticator_present":true,
		"identity_source":"identity-failover",
		"audit":true
	}`)
	evalRec := httptest.NewRecorder()
	HandleEvaluateEAPFramework(evalRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/eap-framework/evaluate", body))
	require.Equal(t, http.StatusOK, evalRec.Code)
	assert.Contains(t, evalRec.Body.String(), `"decision":"accepted"`)
	assert.Contains(t, evalRec.Body.String(), `"audited":true`)

	rec := httptest.NewRecorder()
	HandleGetEAPFramework(rec, httptest.NewRequest(http.MethodGet, "/api/v1/system/eap-framework?limit=10", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	var payload struct {
		Status string `json:"status"`
		Policy struct {
			Mode           string   `json:"mode"`
			AllowedMethods []string `json:"allowed_methods"`
		} `json:"policy"`
		Runtime struct {
			TotalEvents int `json:"total_events"`
			Accepted    int `json:"accepted"`
		} `json:"runtime"`
		Events []db.EAPMethodEvent `json:"events"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, "ready", payload.Status)
	assert.Equal(t, "enforce", payload.Policy.Mode)
	assert.Contains(t, payload.Policy.AllowedMethods, "peap")
	assert.Equal(t, 1, payload.Runtime.TotalEvents)
	assert.Equal(t, 1, payload.Runtime.Accepted)
	require.Len(t, payload.Events, 1)
	assert.NotContains(t, payload.Events[0].UserNameHash, "alice")
}

func TestProductionReadinessIncludesEAPFrameworkCheck(t *testing.T) {
	cfg := prepareEAPFrameworkAPIConfig(t)
	report := buildProductionReadinessReport(cfg)
	var found bool
	for _, check := range report.Checks {
		if check.Key == "eap_method_framework" {
			found = true
			assert.Equal(t, "passed", check.Status)
			assert.Contains(t, check.Dependencies, "/api/v1/system/eap-framework")
		}
	}
	assert.True(t, found)
}

func TestOpenAPIAndSupportBundleIncludeEAPFramework(t *testing.T) {
	spec := buildOpenAPISpec(httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil), nil)
	paths := spec["paths"].(map[string]any)
	assert.Contains(t, paths, "/api/v1/system/eap-framework")
	assert.Contains(t, paths, "/api/v1/system/eap-framework/evaluate")

	var found bool
	for _, capture := range supportBundleAPICaptures() {
		if capture.archivePath == "api/eap-framework.json" {
			found = true
			assert.Equal(t, "/api/v1/system/eap-framework", capture.requestPath)
		}
	}
	assert.True(t, found)
}

func TestAuthorizeEAPFramework(t *testing.T) {
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/eap-framework"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/eap-framework/evaluate"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/eap-framework/evaluate"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleSuperAdmin}, "POST", "/api/v1/system/eap-framework/evaluate"))
}

func prepareEAPFrameworkAPIConfig(t *testing.T) *config.Config {
	t.Helper()
	tmpdb, err := os.CreateTemp("", "eap-framework-api-*.db")
	require.NoError(t, err)
	dbPath := tmpdb.Name()
	require.NoError(t, tmpdb.Close())
	require.NoError(t, db.Init(dbPath))
	require.NoError(t, db.Migrate())
	t.Cleanup(func() {
		db.Close()
		_ = os.Remove(dbPath)
	})

	tmpcfg, err := os.CreateTemp("", "eap-framework-api-*.yaml")
	require.NoError(t, err)
	cfgPath := tmpcfg.Name()
	require.NoError(t, tmpcfg.Close())
	t.Cleanup(func() { _ = os.Remove(cfgPath) })
	content := fmt.Sprintf(`
mode: two-nic
wan:
  name: eth0
lan:
  name: eth1
  address: 192.168.1.1/24
database:
  path: %s
radius:
  secret: secret
  auth_port: 1812
  acct_port: 1813
  max_sessions: 1024
  request_timeout_seconds: 5
  clients:
    - ip: 192.0.2.10
      shortname: lab-ap
      secret: secret
  eap:
    default_type: peap
    peap_inner: mschapv2
    ttls_inner: pap
    tls_min_version: "1.2"
    tls_max_version: "1.3"
    framework:
      enabled: true
      mode: enforce
      fail_closed: true
      allowed_methods: [peap, ttls, tls]
      allowed_inner_methods: [mschapv2, pap, chap, gtc, tls]
      default_outer_identity_source: configured-default
      default_inner_identity_source: identity-failover
      unsupported_method_action: reject
      require_message_authenticator: true
      require_identity_binding: true
      telemetry_enabled: true
      event_retention_limit: 6000
      method_timeout_seconds: 60
      fragment_size: 1024
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
        - method: peap
          enabled: true
          inner_methods: [mschapv2, gtc]
          identity_source: identity-failover
          allow_password_verifier: true
          min_tls_version: "1.2"
          max_tls_version: "1.3"
        - method: ttls
          enabled: true
          inner_methods: [mschapv2, pap]
          identity_source: identity-failover
          allow_password_verifier: true
          min_tls_version: "1.2"
          max_tls_version: "1.3"
        - method: tls
          enabled: true
          identity_source: certificate-subject
          require_certificate: true
          allow_password_verifier: false
          min_tls_version: "1.2"
          max_tls_version: "1.3"
`, dbPath)
	require.NoError(t, os.WriteFile(cfgPath, []byte(content), 0644))
	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	return cfg
}
