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

func TestMobileChargingAPIPreviewApplyStatusHistory(t *testing.T) {
	prepareMobileChargingAPITestRuntime(t)

	previewRec := httptest.NewRecorder()
	HandlePreviewMobileCharging(previewRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/mobile-charging/preview", nil))
	require.Equal(t, http.StatusOK, previewRec.Code, previewRec.Body.String())
	var previewPayload struct {
		EventID string `json:"event_id"`
		Report  struct {
			FeatureID       string `json:"feature_id"`
			Status          string `json:"status"`
			PlanFingerprint string `json:"plan_fingerprint"`
			Summary         struct {
				StreamCount               int `json:"stream_count"`
				RatingGroupCount          int `json:"rating_group_count"`
				QuotaPolicyCount          int `json:"quota_policy_count"`
				CorrelationAttributeCount int `json:"correlation_attribute_count"`
				MediationReferenceCount   int `json:"mediation_reference_count"`
				ComplianceCheckCount      int `json:"compliance_check_count"`
				PassedCheckCount          int `json:"passed_check_count"`
				ExternalRequirementCount  int `json:"external_requirement_count"`
			} `json:"summary"`
		} `json:"report"`
	}
	require.NoError(t, json.Unmarshal(previewRec.Body.Bytes(), &previewPayload))
	assert.NotEmpty(t, previewPayload.EventID)
	assert.Equal(t, "NAS-0094", previewPayload.Report.FeatureID)
	assert.Equal(t, "ready", previewPayload.Report.Status)
	assert.GreaterOrEqual(t, previewPayload.Report.Summary.StreamCount, 3)
	assert.GreaterOrEqual(t, previewPayload.Report.Summary.RatingGroupCount, 2)
	assert.GreaterOrEqual(t, previewPayload.Report.Summary.QuotaPolicyCount, 2)
	assert.Greater(t, previewPayload.Report.Summary.CorrelationAttributeCount, 0)
	assert.GreaterOrEqual(t, previewPayload.Report.Summary.MediationReferenceCount, 4)
	assert.Equal(t, previewPayload.Report.Summary.ComplianceCheckCount, previewPayload.Report.Summary.PassedCheckCount)
	assert.Greater(t, previewPayload.Report.Summary.ExternalRequirementCount, 0)
	assert.NotEmpty(t, previewPayload.Report.PlanFingerprint)

	applyRec := httptest.NewRecorder()
	HandleApplyMobileCharging(applyRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/mobile-charging/apply", nil))
	require.Equal(t, http.StatusOK, applyRec.Code, applyRec.Body.String())
	assert.Contains(t, applyRec.Body.String(), `"status":"ready"`)

	statusRec := httptest.NewRecorder()
	HandleGetMobileCharging(statusRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/mobile-charging", nil))
	require.Equal(t, http.StatusOK, statusRec.Code, statusRec.Body.String())
	assert.Contains(t, statusRec.Body.String(), `"ready_for_external_validation":true`)
	assert.Contains(t, statusRec.Body.String(), `"rating_groups"`)
	assert.Contains(t, statusRec.Body.String(), `"quota_policies"`)

	historyRec := httptest.NewRecorder()
	HandleListMobileChargingHistory(historyRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/mobile-charging/history?limit=5", nil))
	require.Equal(t, http.StatusOK, historyRec.Code, historyRec.Body.String())
	assert.Contains(t, historyRec.Body.String(), `"feature_id":"NAS-0094"`)
	assert.Contains(t, historyRec.Body.String(), `"preview_events":1`)
	assert.Contains(t, historyRec.Body.String(), `"applied_count":1`)
	assert.Contains(t, historyRec.Body.String(), `"ready_profile_count":7`)
}

func TestMobileChargingRBACOpenAPIReadinessSupportBundleAndStatus(t *testing.T) {
	prepareMobileChargingAPITestRuntime(t)

	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/mobile-charging"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/mobile-charging/preview"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/mobile-charging/history"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/mobile-charging/apply"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/mobile-charging/apply"))

	var foundStatusCapture, foundHistoryCapture bool
	for _, capture := range supportBundleAPICaptures() {
		if capture.archivePath == "api/mobile-charging.json" {
			foundStatusCapture = true
		}
		if capture.archivePath == "api/mobile-charging-history.json" {
			foundHistoryCapture = true
		}
	}
	assert.True(t, foundStatusCapture)
	assert.True(t, foundHistoryCapture)

	spec := buildOpenAPISpec(httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil), config.Get())
	paths := spec["paths"].(map[string]any)
	for _, path := range []string{
		"/api/v1/system/mobile-charging",
		"/api/v1/system/mobile-charging/preview",
		"/api/v1/system/mobile-charging/apply",
		"/api/v1/system/mobile-charging/history",
	} {
		_, ok := paths[path]
		assert.True(t, ok, "OpenAPI path %s should exist", path)
	}

	readiness := buildProductionReadinessReport(config.Get())
	var foundReadiness bool
	for _, check := range readiness.Checks {
		if check.Key == "mobile_charging_correlation" {
			foundReadiness = true
			assert.NotEqual(t, "blocked", check.Status)
			assert.Contains(t, check.Summary, "NAS-0094")
		}
	}
	assert.True(t, foundReadiness)

	statusRec := httptest.NewRecorder()
	HandleGetSystemStatus(statusRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/status", nil))
	require.Equal(t, http.StatusOK, statusRec.Code, statusRec.Body.String())
	assert.Contains(t, statusRec.Body.String(), `"mobile_charging_correlation"`)
	assert.Contains(t, statusRec.Body.String(), `"feature_id":"NAS-0094"`)
}

func prepareMobileChargingAPITestRuntime(t *testing.T) {
	t.Helper()
	prepareMobileSessionAPITestRuntime(t)
	cfg := config.Get()
	cfg.Radius.AccountingCharging = config.RadiusAccountingChargingConfig{
		Enabled:       true,
		RatingEnabled: true,
		ExportEnabled: true,
	}
	cfg.Mobile.Charging = config.MobileChargingConfig{
		Enabled:                   true,
		Mode:                      "enforce",
		FailClosed:                true,
		RequireDatabase:           true,
		RequireMobileSessions:     true,
		RequireAccountingCharging: true,
		RequireOnlineCharging:     true,
		RequireOfflineCharging:    true,
		RequireMediation:          true,
		QuotaCorrelation:          true,
		RedactSubscriberIDs:       true,
		HashSubscriberIDs:         true,
	}
}
