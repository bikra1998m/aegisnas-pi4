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

func TestMobilePolicyControlAPIPreviewApplyStatusHistory(t *testing.T) {
	prepareMobilePolicyControlAPITestRuntime(t)

	previewRec := httptest.NewRecorder()
	HandlePreviewMobilePolicyControl(previewRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/mobile-policy-control/preview", nil))
	require.Equal(t, http.StatusOK, previewRec.Code, previewRec.Body.String())
	var previewPayload struct {
		EventID string `json:"event_id"`
		Report  struct {
			FeatureID       string `json:"feature_id"`
			Status          string `json:"status"`
			PlanFingerprint string `json:"plan_fingerprint"`
			Summary         struct {
				PolicyProfileCount       int `json:"policy_profile_count"`
				QoSClassCount            int `json:"qos_class_count"`
				RoamingPolicyCount       int `json:"roaming_policy_count"`
				FeedbackRuleCount        int `json:"feedback_rule_count"`
				PolicyAttributeCount     int `json:"policy_attribute_count"`
				ComplianceCheckCount     int `json:"compliance_check_count"`
				PassedCheckCount         int `json:"passed_check_count"`
				ExternalRequirementCount int `json:"external_requirement_count"`
			} `json:"summary"`
		} `json:"report"`
	}
	require.NoError(t, json.Unmarshal(previewRec.Body.Bytes(), &previewPayload))
	assert.NotEmpty(t, previewPayload.EventID)
	assert.Equal(t, "NAS-0095", previewPayload.Report.FeatureID)
	assert.Equal(t, "ready", previewPayload.Report.Status)
	assert.GreaterOrEqual(t, previewPayload.Report.Summary.PolicyProfileCount, 3)
	assert.GreaterOrEqual(t, previewPayload.Report.Summary.QoSClassCount, 3)
	assert.GreaterOrEqual(t, previewPayload.Report.Summary.RoamingPolicyCount, 2)
	assert.GreaterOrEqual(t, previewPayload.Report.Summary.FeedbackRuleCount, 2)
	assert.Greater(t, previewPayload.Report.Summary.PolicyAttributeCount, 0)
	assert.Equal(t, previewPayload.Report.Summary.ComplianceCheckCount, previewPayload.Report.Summary.PassedCheckCount)
	assert.Greater(t, previewPayload.Report.Summary.ExternalRequirementCount, 0)
	assert.NotEmpty(t, previewPayload.Report.PlanFingerprint)

	applyRec := httptest.NewRecorder()
	HandleApplyMobilePolicyControl(applyRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/mobile-policy-control/apply", nil))
	require.Equal(t, http.StatusOK, applyRec.Code, applyRec.Body.String())
	assert.Contains(t, applyRec.Body.String(), `"status":"ready"`)

	statusRec := httptest.NewRecorder()
	HandleGetMobilePolicyControl(statusRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/mobile-policy-control", nil))
	require.Equal(t, http.StatusOK, statusRec.Code, statusRec.Body.String())
	assert.Contains(t, statusRec.Body.String(), `"ready_for_external_validation":true`)
	assert.Contains(t, statusRec.Body.String(), `"policy_profiles"`)
	assert.Contains(t, statusRec.Body.String(), `"qos_classes"`)
	assert.Contains(t, statusRec.Body.String(), `"roaming_policies"`)

	historyRec := httptest.NewRecorder()
	HandleListMobilePolicyControlHistory(historyRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/mobile-policy-control/history?limit=5", nil))
	require.Equal(t, http.StatusOK, historyRec.Code, historyRec.Body.String())
	assert.Contains(t, historyRec.Body.String(), `"feature_id":"NAS-0095"`)
	assert.Contains(t, historyRec.Body.String(), `"preview_events":1`)
	assert.Contains(t, historyRec.Body.String(), `"applied_count":1`)
	assert.Contains(t, historyRec.Body.String(), `"ready_profile_count":10`)
}

func TestMobilePolicyControlRBACOpenAPIReadinessSupportBundleAndStatus(t *testing.T) {
	prepareMobilePolicyControlAPITestRuntime(t)

	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/mobile-policy-control"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/mobile-policy-control/preview"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/mobile-policy-control/history"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/mobile-policy-control/apply"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/mobile-policy-control/apply"))

	var foundStatusCapture, foundHistoryCapture bool
	for _, capture := range supportBundleAPICaptures() {
		if capture.archivePath == "api/mobile-policy-control.json" {
			foundStatusCapture = true
		}
		if capture.archivePath == "api/mobile-policy-control-history.json" {
			foundHistoryCapture = true
		}
	}
	assert.True(t, foundStatusCapture)
	assert.True(t, foundHistoryCapture)

	spec := buildOpenAPISpec(httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil), config.Get())
	paths := spec["paths"].(map[string]any)
	for _, path := range []string{
		"/api/v1/system/mobile-policy-control",
		"/api/v1/system/mobile-policy-control/preview",
		"/api/v1/system/mobile-policy-control/apply",
		"/api/v1/system/mobile-policy-control/history",
	} {
		_, ok := paths[path]
		assert.True(t, ok, "OpenAPI path %s should exist", path)
	}

	readiness := buildProductionReadinessReport(config.Get())
	var foundReadiness bool
	for _, check := range readiness.Checks {
		if check.Key == "mobile_policy_control" {
			foundReadiness = true
			assert.NotEqual(t, "blocked", check.Status)
			assert.Contains(t, check.Summary, "NAS-0095")
		}
	}
	assert.True(t, foundReadiness)

	statusRec := httptest.NewRecorder()
	HandleGetSystemStatus(statusRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/status", nil))
	require.Equal(t, http.StatusOK, statusRec.Code, statusRec.Body.String())
	assert.Contains(t, statusRec.Body.String(), `"mobile_policy_control"`)
	assert.Contains(t, statusRec.Body.String(), `"feature_id":"NAS-0095"`)
}

func prepareMobilePolicyControlAPITestRuntime(t *testing.T) {
	t.Helper()
	prepareMobileChargingAPITestRuntime(t)
	cfg := config.Get()
	cfg.Policy.TypedEngineEnabled = true
	cfg.Policy.RuntimeShapingEnabled = true
	cfg.Radius.DynamicAuth = config.DynamicAuthConfig{
		Enabled:         true,
		OutboundEnabled: true,
	}
	cfg.Broadband.QoSServiceFlows = config.BroadbandQoSServiceFlowConfig{Enabled: true}
	cfg.Mobile.PolicyControl = config.MobilePolicyControlConfig{
		Enabled:             true,
		Mode:                "enforce",
		FailClosed:          true,
		RedactSubscriberIDs: true,
		HashSubscriberIDs:   true,
	}
}
