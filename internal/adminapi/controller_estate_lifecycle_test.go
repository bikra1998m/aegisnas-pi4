package adminapi

import (
	"encoding/json"
	"fmt"
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

func TestControllerEstateLifecycleAPIPreviewApplyStatusHistoryReadinessAndSupportBundle(t *testing.T) {
	prepareControllerEstateLifecycleAPITestRuntime(t)

	previewRec := httptest.NewRecorder()
	HandlePreviewControllerEstateLifecycle(previewRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/controller-estate-lifecycle/preview", nil))
	require.Equal(t, http.StatusOK, previewRec.Code, previewRec.Body.String())
	var previewPayload struct {
		EventID string `json:"event_id"`
		Report  struct {
			FeatureID        string `json:"feature_id"`
			Status           string `json:"status"`
			DesiredStateHash string `json:"desired_state_hash"`
			Summary          struct {
				ConfiguredAdapter    string `json:"configured_adapter"`
				InventoryObjectCount int    `json:"inventory_object_count"`
				WLANTemplateCount    int    `json:"wlan_template_count"`
				DeleteGuardCount     int    `json:"delete_guard_count"`
				ComplianceCheckCount int    `json:"compliance_check_count"`
				PassedCheckCount     int    `json:"passed_check_count"`
				WarningCount         int    `json:"warning_count"`
				BlockerCount         int    `json:"blocker_count"`
			} `json:"summary"`
			Configured struct {
				TokenEnv     string `json:"token_env"`
				TokenPresent bool   `json:"token_present"`
			} `json:"configured"`
		} `json:"report"`
	}
	require.NoError(t, json.Unmarshal(previewRec.Body.Bytes(), &previewPayload))
	assert.NotEmpty(t, previewPayload.EventID)
	assert.Equal(t, "NAS-0078", previewPayload.Report.FeatureID)
	assert.Equal(t, "ready", previewPayload.Report.Status)
	assert.Equal(t, "generic-rest", previewPayload.Report.Summary.ConfiguredAdapter)
	assert.GreaterOrEqual(t, previewPayload.Report.Summary.InventoryObjectCount, 4)
	assert.Equal(t, 2, previewPayload.Report.Summary.WLANTemplateCount)
	assert.Greater(t, previewPayload.Report.Summary.DeleteGuardCount, 0)
	assert.Equal(t, previewPayload.Report.Summary.ComplianceCheckCount, previewPayload.Report.Summary.PassedCheckCount)
	assert.Zero(t, previewPayload.Report.Summary.WarningCount)
	assert.Zero(t, previewPayload.Report.Summary.BlockerCount)
	assert.NotEmpty(t, previewPayload.Report.DesiredStateHash)
	assert.Equal(t, "AEGIS_TEST_CONTROLLER_TOKEN", previewPayload.Report.Configured.TokenEnv)
	assert.True(t, previewPayload.Report.Configured.TokenPresent)
	assert.NotContains(t, previewRec.Body.String(), "controller-secret-token")

	applyRec := httptest.NewRecorder()
	HandleApplyControllerEstateLifecycle(applyRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/controller-estate-lifecycle/apply", nil))
	require.Equal(t, http.StatusOK, applyRec.Code, applyRec.Body.String())
	assert.Contains(t, applyRec.Body.String(), `"status":"applied"`)

	statusRec := httptest.NewRecorder()
	HandleGetControllerEstateLifecycle(statusRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/controller-estate-lifecycle", nil))
	require.Equal(t, http.StatusOK, statusRec.Code, statusRec.Body.String())
	assert.Contains(t, statusRec.Body.String(), `"ready_for_external_validation":true`)
	assert.Contains(t, statusRec.Body.String(), `"recent_events"`)

	historyRec := httptest.NewRecorder()
	HandleListControllerEstateLifecycleHistory(historyRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/controller-estate-lifecycle/history?limit=5", nil))
	require.Equal(t, http.StatusOK, historyRec.Code, historyRec.Body.String())
	assert.Contains(t, historyRec.Body.String(), `"feature_id":"NAS-0078"`)
	assert.Contains(t, historyRec.Body.String(), `"preview_events":1`)
	assert.Contains(t, historyRec.Body.String(), `"applied_count":1`)

	readiness := buildProductionReadinessReport(config.Get())
	assert.Equal(t, "passed", productionReadinessCheckStatus(readiness.Checks, "controller_estate_lifecycle"))

	systemRec := httptest.NewRecorder()
	HandleGetSystemStatus(systemRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/status", nil))
	require.Equal(t, http.StatusOK, systemRec.Code, systemRec.Body.String())
	assert.Contains(t, systemRec.Body.String(), `"controller_estate_lifecycle"`)

	spec := buildOpenAPISpec(httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil), config.Get())
	paths := spec["paths"].(map[string]any)
	for _, path := range []string{
		"/api/v1/system/controller-estate-lifecycle",
		"/api/v1/system/controller-estate-lifecycle/preview",
		"/api/v1/system/controller-estate-lifecycle/apply",
		"/api/v1/system/controller-estate-lifecycle/history",
	} {
		_, ok := paths[path]
		assert.True(t, ok, "OpenAPI path %s should exist", path)
	}

	foundStatusCapture := false
	foundHistoryCapture := false
	for _, capture := range supportBundleAPICaptures() {
		if capture.archivePath == "api/controller-estate-lifecycle.json" {
			foundStatusCapture = true
		}
		if capture.archivePath == "api/controller-estate-lifecycle-history.json" {
			foundHistoryCapture = true
		}
	}
	assert.True(t, foundStatusCapture)
	assert.True(t, foundHistoryCapture)
}

func TestControllerEstateLifecycleRBAC(t *testing.T) {
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/controller-estate-lifecycle"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/controller-estate-lifecycle/preview"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/controller-estate-lifecycle/history"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/controller-estate-lifecycle/apply"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/controller-estate-lifecycle/apply"))
}

func prepareControllerEstateLifecycleAPITestRuntime(t *testing.T) {
	t.Helper()
	t.Setenv("AEGIS_TEST_CONTROLLER_TOKEN", "controller-secret-token")
	previousDB := db.DB
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	content := fmt.Sprintf(`
mode: two-nic
deployment:
  profile: enterprise
  form: virtual
wan:
  name: ens33
  dhcp: true
lan:
  name: ens37
  address: 192.168.50.1/24
database:
  path: ":memory:"
radius:
  secret: radius-secret
integrations:
  controller:
    enabled: true
    platform: generic
    endpoint: https://controller.example.test/aegisnas
    api_token_env: AEGIS_TEST_CONTROLLER_TOKEN
    sync_mode: monitor
wireless:
  enabled: false
  ssids:
    - name: Corp
      auth_mode: wpa2-enterprise
      vlan: 20
      dynamic_vlan: true
      identity_source: local
      bandwidth_profile: corp-standard
    - name: Guest
      auth_mode: captive-portal
      vlan: 40
      portal_profile: guest
`)
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
