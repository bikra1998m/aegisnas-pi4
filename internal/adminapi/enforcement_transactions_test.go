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

func TestEnforcementTransactionsAPIHistoryOpenAPIReadinessSupportBundleAndRBAC(t *testing.T) {
	prepareEnforcementTransactionsAPITestRuntime(t)

	statusRec := httptest.NewRecorder()
	HandleGetEnforcementTransactions(statusRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/enforcement-transactions", nil))
	require.Equal(t, http.StatusOK, statusRec.Code, statusRec.Body.String())
	assert.Contains(t, statusRec.Body.String(), `"schema_version":1`)
	assert.Contains(t, statusRec.Body.String(), `"controller_sync"`)

	previewRec := httptest.NewRecorder()
	HandlePreviewEnforcementTransaction(previewRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/enforcement-transactions/preview", bytes.NewBufferString(`{"targets":["controller_sync"]}`)))
	require.Equal(t, http.StatusOK, previewRec.Code, previewRec.Body.String())
	var previewPayload struct {
		Result struct {
			Operation string `json:"operation"`
			Status    string `json:"status"`
			Plan      struct {
				Status string `json:"status"`
			} `json:"plan"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal(previewRec.Body.Bytes(), &previewPayload))
	assert.Equal(t, "preview", previewPayload.Result.Operation)
	assert.Equal(t, "previewed", previewPayload.Result.Status)
	assert.Equal(t, "skipped", previewPayload.Result.Plan.Status)

	driftRec := httptest.NewRecorder()
	HandleDetectEnforcementTransactionDrift(driftRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/enforcement-transactions/drift", bytes.NewBufferString(`{"targets":["controller_sync"]}`)))
	require.Equal(t, http.StatusOK, driftRec.Code, driftRec.Body.String())
	assert.Contains(t, driftRec.Body.String(), `"operation":"drift"`)

	applyRec := httptest.NewRecorder()
	HandleApplyEnforcementTransaction(applyRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/enforcement-transactions/apply", bytes.NewBufferString(`{"targets":["controller_sync"]}`)))
	require.Equal(t, http.StatusOK, applyRec.Code, applyRec.Body.String())
	assert.Contains(t, applyRec.Body.String(), `"status":"skipped"`)

	historyRec := httptest.NewRecorder()
	HandleListEnforcementTransactionHistory(historyRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/enforcement-transactions/history?limit=5", nil))
	require.Equal(t, http.StatusOK, historyRec.Code, historyRec.Body.String())
	assert.Contains(t, historyRec.Body.String(), `"total_transactions":3`)
	assert.Contains(t, historyRec.Body.String(), `"transactions"`)

	readiness := buildProductionReadinessReport(config.Get())
	assert.NotEmpty(t, productionReadinessCheckStatus(readiness.Checks, "atomic_enforcement_transactions"))

	spec := buildOpenAPISpec(httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil), config.Get())
	paths := spec["paths"].(map[string]any)
	for _, path := range []string{
		"/api/v1/system/enforcement-transactions",
		"/api/v1/system/enforcement-transactions/preview",
		"/api/v1/system/enforcement-transactions/apply",
		"/api/v1/system/enforcement-transactions/drift",
		"/api/v1/system/enforcement-transactions/rollback",
		"/api/v1/system/enforcement-transactions/history",
	} {
		_, ok := paths[path]
		assert.True(t, ok, "OpenAPI path %s should exist", path)
	}

	foundStatusCapture := false
	foundHistoryCapture := false
	for _, capture := range supportBundleAPICaptures() {
		if capture.archivePath == "api/enforcement-transactions.json" {
			foundStatusCapture = true
		}
		if capture.archivePath == "api/enforcement-transactions-history.json" {
			foundHistoryCapture = true
		}
	}
	assert.True(t, foundStatusCapture)
	assert.True(t, foundHistoryCapture)

	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/enforcement-transactions"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/enforcement-transactions/preview"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/enforcement-transactions/drift"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/enforcement-transactions/apply"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/enforcement-transactions/rollback"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/enforcement-transactions/apply"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/enforcement-transactions/rollback"))
}

func prepareEnforcementTransactionsAPITestRuntime(t *testing.T) {
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
policy:
  runtime_shaping_enabled: true
  enforcement_transactions:
    enabled: true
    fail_closed: true
    targets: ["controller_sync"]
    require_preview_before_apply: true
    auto_rollback_on_failure: true
    drift_check_after_apply: true
    apply_timeout_seconds: 5
    rollback_timeout_seconds: 5
    history_retention_limit: 5000
    compensation_retention_limit: 1000
database:
  path: ":memory:"
radius:
  secret: radius-shared-secret
  dynamic_auth:
    enabled: true
    port: 3799
integrations:
  controller:
    enabled: false
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
