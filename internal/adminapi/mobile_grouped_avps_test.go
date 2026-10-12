package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

func TestMobileGroupedAVPAPIPreviewApplyStatusHistory(t *testing.T) {
	prepareMobileGroupedAVPAPITestRuntime(t)

	previewRec := httptest.NewRecorder()
	HandlePreviewMobileGroupedAVPs(previewRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/mobile-grouped-avps/preview", nil))
	require.Equal(t, http.StatusOK, previewRec.Code, previewRec.Body.String())
	var previewPayload struct {
		EventID string `json:"event_id"`
		Report  struct {
			FeatureID       string `json:"feature_id"`
			Status          string `json:"status"`
			PlanFingerprint string `json:"plan_fingerprint"`
			Summary         struct {
				VendorScopeCount         int `json:"vendor_scope_count"`
				EvidencePolicyCount      int `json:"evidence_policy_count"`
				CompiledAttributeCount   int `json:"compiled_attribute_count"`
				GroupedAttributeCount    int `json:"grouped_attribute_count"`
				ComplianceCheckCount     int `json:"compliance_check_count"`
				PassedCheckCount         int `json:"passed_check_count"`
				ExternalRequirementCount int `json:"external_requirement_count"`
			} `json:"summary"`
		} `json:"report"`
	}
	require.NoError(t, json.Unmarshal(previewRec.Body.Bytes(), &previewPayload))
	assert.NotEmpty(t, previewPayload.EventID)
	assert.Equal(t, "NAS-0092", previewPayload.Report.FeatureID)
	assert.Equal(t, "ready", previewPayload.Report.Status)
	assert.GreaterOrEqual(t, previewPayload.Report.Summary.VendorScopeCount, 5)
	assert.Greater(t, previewPayload.Report.Summary.EvidencePolicyCount, 0)
	assert.Greater(t, previewPayload.Report.Summary.CompiledAttributeCount, 0)
	assert.Greater(t, previewPayload.Report.Summary.GroupedAttributeCount, 0)
	assert.Equal(t, previewPayload.Report.Summary.ComplianceCheckCount, previewPayload.Report.Summary.PassedCheckCount)
	assert.Greater(t, previewPayload.Report.Summary.ExternalRequirementCount, 0)
	assert.NotEmpty(t, previewPayload.Report.PlanFingerprint)

	applyRec := httptest.NewRecorder()
	HandleApplyMobileGroupedAVPs(applyRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/mobile-grouped-avps/apply", nil))
	require.Equal(t, http.StatusOK, applyRec.Code, applyRec.Body.String())
	assert.Contains(t, applyRec.Body.String(), `"status":"ready"`)

	statusRec := httptest.NewRecorder()
	HandleGetMobileGroupedAVPs(statusRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/mobile-grouped-avps", nil))
	require.Equal(t, http.StatusOK, statusRec.Code, statusRec.Body.String())
	assert.Contains(t, statusRec.Body.String(), `"ready_for_external_validation":true`)
	assert.Contains(t, statusRec.Body.String(), `"scopes"`)

	historyRec := httptest.NewRecorder()
	HandleListMobileGroupedAVPHistory(historyRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/mobile-grouped-avps/history?limit=5", nil))
	require.Equal(t, http.StatusOK, historyRec.Code, historyRec.Body.String())
	assert.Contains(t, historyRec.Body.String(), `"feature_id":"NAS-0092"`)
	assert.Contains(t, historyRec.Body.String(), `"preview_events":1`)
	assert.Contains(t, historyRec.Body.String(), `"applied_count":1`)
}

func TestMobileGroupedAVPRBACOpenAPIAndSupportBundle(t *testing.T) {
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/mobile-grouped-avps"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/mobile-grouped-avps/preview"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/mobile-grouped-avps/history"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/mobile-grouped-avps/apply"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/mobile-grouped-avps/apply"))

	var foundStatusCapture, foundHistoryCapture bool
	for _, capture := range supportBundleAPICaptures() {
		if capture.archivePath == "api/mobile-grouped-avps.json" {
			foundStatusCapture = true
		}
		if capture.archivePath == "api/mobile-grouped-avps-history.json" {
			foundHistoryCapture = true
		}
	}
	assert.True(t, foundStatusCapture)
	assert.True(t, foundHistoryCapture)

	spec := buildOpenAPISpec(httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil), config.Get())
	paths := spec["paths"].(map[string]any)
	for _, path := range []string{
		"/api/v1/system/mobile-grouped-avps",
		"/api/v1/system/mobile-grouped-avps/preview",
		"/api/v1/system/mobile-grouped-avps/apply",
		"/api/v1/system/mobile-grouped-avps/history",
	} {
		_, ok := paths[path]
		assert.True(t, ok, "OpenAPI path %s should exist", path)
	}
}

func prepareMobileGroupedAVPAPITestRuntime(t *testing.T) {
	t.Helper()
	prepareBroadbandGovernanceSelfServiceAPITestRuntime(t)
	cfg := config.Get()
	cfg.Mobile.GroupedAVPs = config.MobileGroupedAVPConfig{
		Enabled:         true,
		Mode:            "enforce",
		FailClosed:      true,
		SafeRawEvidence: true,
		HashRawValues:   true,
	}
}
