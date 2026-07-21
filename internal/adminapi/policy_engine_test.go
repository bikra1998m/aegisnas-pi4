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

func TestPolicyEngineAPIValidateEvaluateAndReport(t *testing.T) {
	preparePolicyEngineAPITestConfig(t)
	_, err := db.DB.Exec(`DELETE FROM policy_rules`)
	require.NoError(t, err)
	_, err = db.DB.Exec(`INSERT INTO policy_rules (name, description, priority, enabled, match_conditions, action, vlan)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"employee-access", "typed employee rule", 100, true,
		`{"all":[{"field":"authenticated","op":"eq","value":true},{"field":"groups","op":"contains","value":"employees"}]}`,
		"allow", 30)
	require.NoError(t, err)

	validateReq := httptest.NewRequest(http.MethodPost, "/api/v1/system/policy-engine/validate", bytes.NewBufferString(`{
		"expression": {"field":"source_ip","op":"cidr","value":"10.0.0.0/8"}
	}`))
	validateRec := httptest.NewRecorder()
	HandleValidatePolicyExpression(validateRec, validateReq)
	require.Equal(t, http.StatusOK, validateRec.Code)
	assert.Contains(t, validateRec.Body.String(), `"valid":true`)

	evaluateReq := httptest.NewRequest(http.MethodPost, "/api/v1/system/policy-engine/evaluate", bytes.NewBufferString(`{
		"username": "alice@example.com",
		"authenticated": true,
		"groups": ["employees"],
		"calling_station_id": "aa:bb:cc:dd:ee:ff",
		"tenant": "corp"
	}`))
	evaluateRec := httptest.NewRecorder()
	HandleEvaluatePolicyEngine(evaluateRec, evaluateReq)
	require.Equal(t, http.StatusOK, evaluateRec.Code)
	var result struct {
		Decision struct {
			Allow bool `json:"allow"`
			VLAN  *int `json:"vlan"`
		} `json:"decision"`
		MatchedRules []struct {
			Name string `json:"name"`
		} `json:"matched_rules"`
	}
	require.NoError(t, json.Unmarshal(evaluateRec.Body.Bytes(), &result))
	assert.True(t, result.Decision.Allow)
	require.NotNil(t, result.Decision.VLAN)
	assert.Equal(t, 30, *result.Decision.VLAN)
	require.Len(t, result.MatchedRules, 1)
	assert.Equal(t, "employee-access", result.MatchedRules[0].Name)

	reportReq := httptest.NewRequest(http.MethodGet, "/api/v1/system/policy-engine", nil)
	reportRec := httptest.NewRecorder()
	HandleGetPolicyEngine(reportRec, reportReq)
	require.Equal(t, http.StatusOK, reportRec.Code)
	var report policyEngineReport
	require.NoError(t, json.Unmarshal(reportRec.Body.Bytes(), &report))
	assert.Equal(t, "passed", report.Status)
	assert.Equal(t, 1, report.Summary.TotalRecords)
	assert.Len(t, report.Rules, 1)
	assert.True(t, report.Rules[0].Typed)

	replay, err := db.ListPolicyEngineReplaySamples(10)
	require.NoError(t, err)
	require.Len(t, replay, 1)
	assert.Contains(t, replay[0].RequestReplayJSON, "employees")
	assert.NotContains(t, replay[0].RequestReplayJSON, "alice@example.com")
	assert.NotContains(t, replay[0].RequestReplayJSON, "aa:bb:cc:dd:ee:ff")
}

func TestPolicyEngineAuthorization(t *testing.T) {
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/policy-engine"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/policy-engine/evaluate"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/policy-engine/evaluate"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/policy-engine/validate"))
}

func preparePolicyEngineAPITestConfig(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "policy-engine.db")
	cfgPath := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`
mode: two-nic
wan:
  name: eth0
lan:
  name: eth1
database:
  path: `+strconvQuote(dbPath)+`
health:
  port: 8080
telemetry:
  enabled: true
  prometheus_port: 9090
radius:
  auth_port: 1812
  acct_port: 1813
  request_timeout_seconds: 5
policy:
  default_role: guest-basic
  typed_engine_enabled: true
  mode: enforce
  fail_closed: true
  audit_enabled: true
  allow_legacy_conditions: false
  require_typed_rules: true
  max_expression_depth: 8
  max_expression_nodes: 128
  max_list_values: 128
  evaluation_retention_limit: 10000
`), 0644))
	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.NoError(t, cfg.Validate())
	require.NoError(t, db.Init(dbPath))
	t.Cleanup(func() { _ = db.Close() })
	require.NoError(t, db.Migrate())
	return cfg
}
