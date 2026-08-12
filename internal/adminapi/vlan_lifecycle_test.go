package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestVLANLifecycleAPIPreviewStatusHistoryReadinessAndSupportBundle(t *testing.T) {
	prepareRuntimeQoSAPITestRuntime(t)
	_, err := db.DB.Exec(`INSERT INTO roles (name, description, vlan, priority)
		VALUES (?, ?, ?, ?)`, "corp", "Corp users", 30, 50)
	require.NoError(t, err)
	_, err = db.DB.Exec(`INSERT INTO policy_rules (name, description, priority, enabled, match_conditions, action, vlan)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, "guest-vlan", "Guest VLAN", 10, true, `{"authenticated":false}`, "allow", 20)
	require.NoError(t, err)

	previewRec := httptest.NewRecorder()
	HandlePreviewVLANLifecycle(previewRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/vlan-lifecycle/preview", nil))
	require.Equal(t, http.StatusOK, previewRec.Code, previewRec.Body.String())
	var previewPayload struct {
		EventID string `json:"event_id"`
		Plan    struct {
			Status          string `json:"status"`
			ParentInterface string `json:"parent_interface"`
			Summary         struct {
				VLANCount         int `json:"vlan_count"`
				SubinterfaceCount int `json:"subinterface_count"`
				CommandCount      int `json:"command_count"`
			} `json:"summary"`
			CommandPreview []string `json:"command_preview"`
		} `json:"plan"`
	}
	require.NoError(t, json.Unmarshal(previewRec.Body.Bytes(), &previewPayload))
	assert.NotEmpty(t, previewPayload.EventID)
	assert.Equal(t, "ready", previewPayload.Plan.Status)
	assert.Equal(t, "ens37", previewPayload.Plan.ParentInterface)
	assert.Equal(t, 2, previewPayload.Plan.Summary.VLANCount)
	assert.Equal(t, 2, previewPayload.Plan.Summary.SubinterfaceCount)
	assert.NotZero(t, previewPayload.Plan.Summary.CommandCount)
	assert.Contains(t, previewPayload.Plan.CommandPreview, "ip link add link ens37 name ens37.30 type vlan id 30")

	statusRec := httptest.NewRecorder()
	HandleGetVLANLifecycle(statusRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/vlan-lifecycle", nil))
	require.Equal(t, http.StatusOK, statusRec.Code, statusRec.Body.String())
	assert.Contains(t, statusRec.Body.String(), `"intents"`)
	assert.Contains(t, statusRec.Body.String(), `"recent_events"`)

	historyRec := httptest.NewRecorder()
	HandleListVLANLifecycleHistory(historyRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/vlan-lifecycle/history?limit=5", nil))
	require.Equal(t, http.StatusOK, historyRec.Code, historyRec.Body.String())
	assert.Contains(t, historyRec.Body.String(), `"preview_events":1`)

	readiness := buildProductionReadinessReport(config.Get())
	assert.Equal(t, "passed", productionReadinessCheckStatus(readiness.Checks, "dynamic_vlan_lifecycle"))

	spec := buildOpenAPISpec(httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil), config.Get())
	paths := spec["paths"].(map[string]any)
	for _, path := range []string{
		"/api/v1/system/vlan-lifecycle",
		"/api/v1/system/vlan-lifecycle/preview",
		"/api/v1/system/vlan-lifecycle/apply",
		"/api/v1/system/vlan-lifecycle/rollback",
		"/api/v1/system/vlan-lifecycle/history",
	} {
		_, ok := paths[path]
		assert.True(t, ok, "OpenAPI path %s should exist", path)
	}

	foundStatusCapture := false
	foundHistoryCapture := false
	for _, capture := range supportBundleAPICaptures() {
		if capture.archivePath == "api/vlan-lifecycle.json" {
			foundStatusCapture = true
		}
		if capture.archivePath == "api/vlan-lifecycle-history.json" {
			foundHistoryCapture = true
		}
	}
	assert.True(t, foundStatusCapture)
	assert.True(t, foundHistoryCapture)
}

func TestVLANLifecycleRBAC(t *testing.T) {
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/vlan-lifecycle"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/vlan-lifecycle/preview"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/vlan-lifecycle/history"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/vlan-lifecycle/apply"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/vlan-lifecycle/rollback"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/vlan-lifecycle/apply"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/vlan-lifecycle/rollback"))
}
