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

func TestMobileSessionAPIPreviewApplyStatusHistory(t *testing.T) {
	prepareMobileSessionAPITestRuntime(t)

	previewRec := httptest.NewRecorder()
	HandlePreviewMobileSessions(previewRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/mobile-sessions/preview", nil))
	require.Equal(t, http.StatusOK, previewRec.Code, previewRec.Body.String())
	var previewPayload struct {
		EventID string `json:"event_id"`
		Report  struct {
			FeatureID       string `json:"feature_id"`
			Status          string `json:"status"`
			PlanFingerprint string `json:"plan_fingerprint"`
			Summary         struct {
				APNProfileCount            int `json:"apn_profile_count"`
				BearerTemplateCount        int `json:"bearer_template_count"`
				RoamingPartnerCount        int `json:"roaming_partner_count"`
				RadiusAttributeCount       int `json:"radius_attribute_count"`
				StateStepCount             int `json:"state_step_count"`
				ComplianceCheckCount       int `json:"compliance_check_count"`
				PassedCheckCount           int `json:"passed_check_count"`
				ExternalRequirementCount   int `json:"external_requirement_count"`
				EnabledAPNProfileCount     int `json:"enabled_apn_profile_count"`
				EnabledBearerTemplateCount int `json:"enabled_bearer_template_count"`
				EnabledRoamingPartnerCount int `json:"enabled_roaming_partner_count"`
			} `json:"summary"`
		} `json:"report"`
	}
	require.NoError(t, json.Unmarshal(previewRec.Body.Bytes(), &previewPayload))
	assert.NotEmpty(t, previewPayload.EventID)
	assert.Equal(t, "NAS-0093", previewPayload.Report.FeatureID)
	assert.Equal(t, "ready", previewPayload.Report.Status)
	assert.GreaterOrEqual(t, previewPayload.Report.Summary.APNProfileCount, 2)
	assert.GreaterOrEqual(t, previewPayload.Report.Summary.BearerTemplateCount, 2)
	assert.GreaterOrEqual(t, previewPayload.Report.Summary.RoamingPartnerCount, 2)
	assert.Greater(t, previewPayload.Report.Summary.RadiusAttributeCount, 0)
	assert.GreaterOrEqual(t, previewPayload.Report.Summary.StateStepCount, 6)
	assert.Equal(t, previewPayload.Report.Summary.ComplianceCheckCount, previewPayload.Report.Summary.PassedCheckCount)
	assert.Greater(t, previewPayload.Report.Summary.ExternalRequirementCount, 0)
	assert.NotEmpty(t, previewPayload.Report.PlanFingerprint)

	applyRec := httptest.NewRecorder()
	HandleApplyMobileSessions(applyRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/mobile-sessions/apply", nil))
	require.Equal(t, http.StatusOK, applyRec.Code, applyRec.Body.String())
	assert.Contains(t, applyRec.Body.String(), `"status":"ready"`)

	statusRec := httptest.NewRecorder()
	HandleGetMobileSessions(statusRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/mobile-sessions", nil))
	require.Equal(t, http.StatusOK, statusRec.Code, statusRec.Body.String())
	assert.Contains(t, statusRec.Body.String(), `"ready_for_external_validation":true`)
	assert.Contains(t, statusRec.Body.String(), `"apn_profiles"`)
	assert.Contains(t, statusRec.Body.String(), `"bearer_templates"`)

	historyRec := httptest.NewRecorder()
	HandleListMobileSessionHistory(historyRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/mobile-sessions/history?limit=5", nil))
	require.Equal(t, http.StatusOK, historyRec.Code, historyRec.Body.String())
	assert.Contains(t, historyRec.Body.String(), `"feature_id":"NAS-0093"`)
	assert.Contains(t, historyRec.Body.String(), `"preview_events":1`)
	assert.Contains(t, historyRec.Body.String(), `"applied_count":1`)
	assert.Contains(t, historyRec.Body.String(), `"ready_profile_count":6`)
}

func TestMobileSessionRBACOpenAPIAndSupportBundle(t *testing.T) {
	prepareMobileSessionAPITestRuntime(t)

	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/mobile-sessions"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/mobile-sessions/preview"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/mobile-sessions/history"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/mobile-sessions/apply"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/mobile-sessions/apply"))

	var foundStatusCapture, foundHistoryCapture bool
	for _, capture := range supportBundleAPICaptures() {
		if capture.archivePath == "api/mobile-sessions.json" {
			foundStatusCapture = true
		}
		if capture.archivePath == "api/mobile-sessions-history.json" {
			foundHistoryCapture = true
		}
	}
	assert.True(t, foundStatusCapture)
	assert.True(t, foundHistoryCapture)

	spec := buildOpenAPISpec(httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil), config.Get())
	paths := spec["paths"].(map[string]any)
	for _, path := range []string{
		"/api/v1/system/mobile-sessions",
		"/api/v1/system/mobile-sessions/preview",
		"/api/v1/system/mobile-sessions/apply",
		"/api/v1/system/mobile-sessions/history",
	} {
		_, ok := paths[path]
		assert.True(t, ok, "OpenAPI path %s should exist", path)
	}

	readiness := buildProductionReadinessReport(config.Get())
	var foundReadiness bool
	for _, check := range readiness.Checks {
		if check.Key == "mobile_session_state" {
			foundReadiness = true
			assert.NotEqual(t, "blocking", check.Status)
			assert.Contains(t, check.Summary, "NAS-0093")
		}
	}
	assert.True(t, foundReadiness)
}

func prepareMobileSessionAPITestRuntime(t *testing.T) {
	t.Helper()
	prepareMobileGroupedAVPAPITestRuntime(t)
	cfg := config.Get()
	cfg.Mobile.Sessions = config.MobileSessionConfig{
		Enabled:             true,
		Mode:                "enforce",
		FailClosed:          true,
		StateReconciliation: true,
		HandoverTracking:    true,
		RoamingTracking:     true,
		RedactSubscriberIDs: true,
		HashSubscriberIDs:   true,
	}
}
