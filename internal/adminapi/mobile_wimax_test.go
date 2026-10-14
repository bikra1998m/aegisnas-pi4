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

func TestWiMAXServiceFlowsAPIPreviewApplyStatusHistory(t *testing.T) {
	prepareWiMAXServiceFlowAPITestRuntime(t)

	previewRec := httptest.NewRecorder()
	HandlePreviewWiMAXServiceFlows(previewRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/wimax-service-flows/preview", nil))
	require.Equal(t, http.StatusOK, previewRec.Code, previewRec.Body.String())
	var previewPayload struct {
		EventID string `json:"event_id"`
		Report  struct {
			FeatureID       string `json:"feature_id"`
			Status          string `json:"status"`
			PlanFingerprint string `json:"plan_fingerprint"`
			Summary         struct {
				SubscriberProfileCount   int `json:"subscriber_profile_count"`
				ServiceFlowCount         int `json:"service_flow_count"`
				ASNProfileCount          int `json:"asn_profile_count"`
				MobilityPolicyCount      int `json:"mobility_policy_count"`
				RadiusAttributeCount     int `json:"radius_attribute_count"`
				ComplianceCheckCount     int `json:"compliance_check_count"`
				PassedCheckCount         int `json:"passed_check_count"`
				ExternalRequirementCount int `json:"external_requirement_count"`
			} `json:"summary"`
		} `json:"report"`
	}
	require.NoError(t, json.Unmarshal(previewRec.Body.Bytes(), &previewPayload))
	assert.NotEmpty(t, previewPayload.EventID)
	assert.Equal(t, "NAS-0096", previewPayload.Report.FeatureID)
	assert.Equal(t, "ready", previewPayload.Report.Status)
	assert.GreaterOrEqual(t, previewPayload.Report.Summary.SubscriberProfileCount, 2)
	assert.GreaterOrEqual(t, previewPayload.Report.Summary.ServiceFlowCount, 3)
	assert.GreaterOrEqual(t, previewPayload.Report.Summary.ASNProfileCount, 2)
	assert.GreaterOrEqual(t, previewPayload.Report.Summary.MobilityPolicyCount, 2)
	assert.Greater(t, previewPayload.Report.Summary.RadiusAttributeCount, 0)
	assert.Equal(t, previewPayload.Report.Summary.ComplianceCheckCount, previewPayload.Report.Summary.PassedCheckCount)
	assert.Greater(t, previewPayload.Report.Summary.ExternalRequirementCount, 0)
	assert.NotEmpty(t, previewPayload.Report.PlanFingerprint)

	applyRec := httptest.NewRecorder()
	HandleApplyWiMAXServiceFlows(applyRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/wimax-service-flows/apply", nil))
	require.Equal(t, http.StatusOK, applyRec.Code, applyRec.Body.String())
	assert.Contains(t, applyRec.Body.String(), `"status":"ready"`)

	statusRec := httptest.NewRecorder()
	HandleGetWiMAXServiceFlows(statusRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/wimax-service-flows", nil))
	require.Equal(t, http.StatusOK, statusRec.Code, statusRec.Body.String())
	assert.Contains(t, statusRec.Body.String(), `"ready_for_external_validation":true`)
	assert.Contains(t, statusRec.Body.String(), `"subscriber_profiles"`)
	assert.Contains(t, statusRec.Body.String(), `"service_flows"`)
	assert.Contains(t, statusRec.Body.String(), `"asn_profiles"`)

	historyRec := httptest.NewRecorder()
	HandleListWiMAXServiceFlowHistory(historyRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/wimax-service-flows/history?limit=5", nil))
	require.Equal(t, http.StatusOK, historyRec.Code, historyRec.Body.String())
	assert.Contains(t, historyRec.Body.String(), `"feature_id":"NAS-0096"`)
	assert.Contains(t, historyRec.Body.String(), `"preview_events":1`)
	assert.Contains(t, historyRec.Body.String(), `"applied_count":1`)
	assert.Contains(t, historyRec.Body.String(), `"ready_profile_count":9`)
}

func TestWiMAXServiceFlowsRBACOpenAPIReadinessSupportBundleAndStatus(t *testing.T) {
	prepareWiMAXServiceFlowAPITestRuntime(t)

	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/wimax-service-flows"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/wimax-service-flows/preview"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/wimax-service-flows/history"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/wimax-service-flows/apply"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/wimax-service-flows/apply"))

	var foundStatusCapture, foundHistoryCapture bool
	for _, capture := range supportBundleAPICaptures() {
		if capture.archivePath == "api/wimax-service-flows.json" {
			foundStatusCapture = true
		}
		if capture.archivePath == "api/wimax-service-flows-history.json" {
			foundHistoryCapture = true
		}
	}
	assert.True(t, foundStatusCapture)
	assert.True(t, foundHistoryCapture)

	spec := buildOpenAPISpec(httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil), config.Get())
	paths := spec["paths"].(map[string]any)
	for _, path := range []string{
		"/api/v1/system/wimax-service-flows",
		"/api/v1/system/wimax-service-flows/preview",
		"/api/v1/system/wimax-service-flows/apply",
		"/api/v1/system/wimax-service-flows/history",
	} {
		_, ok := paths[path]
		assert.True(t, ok, "OpenAPI path %s should exist", path)
	}

	readiness := buildProductionReadinessReport(config.Get())
	var foundReadiness bool
	for _, check := range readiness.Checks {
		if check.Key == "wimax_service_flows" {
			foundReadiness = true
			assert.NotEqual(t, "blocked", check.Status)
			assert.Contains(t, check.Summary, "NAS-0096")
		}
	}
	assert.True(t, foundReadiness)

	statusRec := httptest.NewRecorder()
	HandleGetSystemStatus(statusRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/status", nil))
	require.Equal(t, http.StatusOK, statusRec.Code, statusRec.Body.String())
	assert.Contains(t, statusRec.Body.String(), `"wimax_service_flows"`)
	assert.Contains(t, statusRec.Body.String(), `"feature_id":"NAS-0096"`)
}

func prepareWiMAXServiceFlowAPITestRuntime(t *testing.T) {
	t.Helper()
	prepareMobilePolicyControlAPITestRuntime(t)
	cfg := config.Get()
	cfg.Mobile.WiMAX = config.MobileWiMAXConfig{
		Enabled:             true,
		Mode:                "enforce",
		FailClosed:          true,
		RedactSubscriberIDs: true,
		HashSubscriberIDs:   true,
	}
}
