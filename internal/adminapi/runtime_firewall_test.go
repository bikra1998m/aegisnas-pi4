package adminapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestRuntimeFirewallAPIPreviewStatusHistoryReadinessAndSupportBundle(t *testing.T) {
	prepareRuntimeFirewallAPITestRuntime(t)
	_, err := db.DB.Exec(`INSERT INTO acl_policies (name, rules_json, enabled) VALUES (?, ?, 1)`,
		"guest-web", `[{"id":"allow-https","action":"permit","direction":"in","protocol":"tcp","source":"any","destination":"any","destination_port":"443"}]`)
	require.NoError(t, err)
	_, err = db.DB.Exec(`INSERT INTO sessions (id, username, ip, ipv6_address, acl_policy_name, start_time)
		VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`, "s-web", "guest", "192.0.2.40", "2001:db8::40", "guest-web")
	require.NoError(t, err)

	previewRec := httptest.NewRecorder()
	HandlePreviewRuntimeFirewall(previewRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/runtime-firewall/preview", bytes.NewBufferString(`{}`)))
	require.Equal(t, http.StatusOK, previewRec.Code, previewRec.Body.String())
	var previewPayload struct {
		EventID string `json:"event_id"`
		Plan    struct {
			Status  string `json:"status"`
			Summary struct {
				ManagedSessions  int `json:"managed_sessions"`
				IPv6Sessions     int `json:"ipv6_sessions"`
				AppliedRuleCount int `json:"applied_rule_count"`
			} `json:"summary"`
		} `json:"plan"`
	}
	require.NoError(t, json.Unmarshal(previewRec.Body.Bytes(), &previewPayload))
	assert.NotEmpty(t, previewPayload.EventID)
	assert.Equal(t, "ready", previewPayload.Plan.Status)
	assert.Equal(t, 1, previewPayload.Plan.Summary.ManagedSessions)
	assert.Equal(t, 1, previewPayload.Plan.Summary.IPv6Sessions)
	assert.Equal(t, 6, previewPayload.Plan.Summary.AppliedRuleCount)

	statusRec := httptest.NewRecorder()
	HandleGetRuntimeFirewall(statusRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/runtime-firewall", nil))
	require.Equal(t, http.StatusOK, statusRec.Code, statusRec.Body.String())
	assert.Contains(t, statusRec.Body.String(), `"stateful":true`)
	assert.Contains(t, statusRec.Body.String(), `"recent_events"`)

	historyRec := httptest.NewRecorder()
	HandleListRuntimeFirewallHistory(historyRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/runtime-firewall/history?limit=5", nil))
	require.Equal(t, http.StatusOK, historyRec.Code, historyRec.Body.String())
	assert.Contains(t, historyRec.Body.String(), `"preview_events":1`)

	readiness := buildProductionReadinessReport(config.Get())
	assert.Equal(t, "passed", productionReadinessCheckStatus(readiness.Checks, "stateful_local_firewall"))

	spec := buildOpenAPISpec(httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil), config.Get())
	paths := spec["paths"].(map[string]any)
	for _, path := range []string{
		"/api/v1/system/runtime-firewall",
		"/api/v1/system/runtime-firewall/preview",
		"/api/v1/system/runtime-firewall/apply",
		"/api/v1/system/runtime-firewall/rollback",
		"/api/v1/system/runtime-firewall/history",
	} {
		_, ok := paths[path]
		assert.True(t, ok, "OpenAPI path %s should exist", path)
	}

	foundStatusCapture := false
	foundHistoryCapture := false
	for _, capture := range supportBundleAPICaptures() {
		if capture.archivePath == "api/runtime-firewall.json" {
			foundStatusCapture = true
		}
		if capture.archivePath == "api/runtime-firewall-history.json" {
			foundHistoryCapture = true
		}
	}
	assert.True(t, foundStatusCapture)
	assert.True(t, foundHistoryCapture)
}

func TestRuntimeFirewallRBAC(t *testing.T) {
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/runtime-firewall"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/runtime-firewall/preview"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/runtime-firewall/history"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/runtime-firewall/apply"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/runtime-firewall/rollback"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/runtime-firewall/apply"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/runtime-firewall/rollback"))
}

func prepareRuntimeFirewallAPITestRuntime(t *testing.T) {
	t.Helper()
	previousDB := db.DB
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	content := `
mode: two-nic
deployment:
  profile: enterprise
  form: virtual
  hardware:
    memory_mb: 8192
    cpu_cores: 4
    storage_gb: 64
wan:
  name: ens33
  dhcp: true
lan:
  name: ens37
  address: 192.168.50.1/24
database:
  path: ":memory:"
radius:
  secret: radius-shared-secret
  dynamic_auth:
    enabled: true
    port: 3799
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(content), 0o600))
	_, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.NoError(t, db.Init(":memory:"))
	db.DB.SetMaxOpenConns(1)
	require.NoError(t, db.Migrate())
	t.Cleanup(func() {
		_ = db.Close()
		db.DB = previousDB
	})
}
