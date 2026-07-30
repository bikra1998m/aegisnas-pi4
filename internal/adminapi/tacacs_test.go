package adminapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

func TestTACACSAPICommandSetEvaluateAndReadiness(t *testing.T) {
	cfg := preparePolicyEngineAPITestConfig(t)
	cfg.TACACS.Enabled = true
	cfg.TACACS.Mode = "enforce"
	cfg.TACACS.FailClosed = true
	cfg.TACACS.SecretRef = "env:AEGIS_SECRET_TACACS_SHARED"
	cfg.TACACS.RequireKnownClient = true
	cfg.TACACS.AllowUnencrypted = false
	cfg.Policy.TypedEngineEnabled = false
	cfg.TACACS.Clients = []config.TACACSClientConfig{{
		Name:      "sw1",
		Address:   "192.0.2.10",
		SecretRef: "env:AEGIS_SECRET_TACACS_SW1",
		Vendor:    "cisco",
		Enabled:   true,
	}}

	createBody := []byte(`{
		"name":"ops-show",
		"description":"permit safe show commands",
		"default_action":"deny",
		"permit":["show *"],
		"deny":["show running-config"],
		"roles":["ops"],
		"privilege_levels":[5,15],
		"vendors":["cisco"]
	}`)
	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/system/tacacs/command-sets", bytes.NewReader(createBody))
	createRec := httptest.NewRecorder()
	HandleCreateTACACSCommandSet(createRec, createReq)
	require.Equal(t, http.StatusOK, createRec.Code)

	evalReq := httptest.NewRequest(http.MethodPost, "/api/v1/system/tacacs/evaluate", bytes.NewReader([]byte(`{
		"username":"alice",
		"role":"ops",
		"client_name":"sw1",
		"client_ip":"192.0.2.10",
		"vendor":"cisco",
		"command":"show interfaces status",
		"privilege_level":5,
		"authenticated":true
	}`)))
	evalRec := httptest.NewRecorder()
	HandleEvaluateTACACSCommand(evalRec, evalReq)
	require.Equal(t, http.StatusOK, evalRec.Code)
	var decision struct {
		Permit            bool   `json:"permit"`
		Status            string `json:"status"`
		MatchedCommandSet string `json:"matched_command_set"`
	}
	require.NoError(t, json.Unmarshal(evalRec.Body.Bytes(), &decision))
	assert.True(t, decision.Permit)
	assert.Equal(t, "permit", decision.Status)
	assert.Equal(t, "ops-show", decision.MatchedCommandSet)

	reportReq := httptest.NewRequest(http.MethodGet, "/api/v1/system/tacacs?limit=5", nil)
	reportRec := httptest.NewRecorder()
	HandleGetTACACS(reportRec, reportReq)
	require.Equal(t, http.StatusOK, reportRec.Code)
	assert.Contains(t, reportRec.Body.String(), `"effective_sets":1`)

	readiness := buildProductionReadinessReport(cfg)
	found := false
	for _, check := range readiness.Checks {
		if check.Key == "tacacs_command_authorization" {
			found = true
			assert.Equal(t, "passed", check.Status)
		}
	}
	assert.True(t, found)
}

func TestTACACSAuthorizationRules(t *testing.T) {
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/tacacs"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/tacacs/evaluate"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/tacacs/evaluate"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/tacacs/command-sets"))
}

func TestOpenAPIIncludesTACACS(t *testing.T) {
	spec := buildOpenAPISpec(httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil), nil)
	paths, ok := spec["paths"].(map[string]any)
	require.True(t, ok)

	tacacsPath, ok := paths["/api/v1/system/tacacs"].(map[string]any)
	require.True(t, ok)
	readOp, ok := tacacsPath["get"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "Read TACACS+ command authorization state", readOp["summary"])

	evaluatePath, ok := paths["/api/v1/system/tacacs/evaluate"].(map[string]any)
	require.True(t, ok)
	evaluateOp, ok := evaluatePath["post"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "Evaluate TACACS+ command authorization", evaluateOp["summary"])

	commandSetsPath, ok := paths["/api/v1/system/tacacs/command-sets"].(map[string]any)
	require.True(t, ok)
	createOp, ok := commandSetsPath["post"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "Create TACACS+ command set", createOp["summary"])
}
