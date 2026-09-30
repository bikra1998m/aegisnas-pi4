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

func TestBroadbandSubscriberStateAPIPreviewApplyStatusHistoryReadinessAndSupportBundle(t *testing.T) {
	prepareBroadbandSubscriberStateAPITestRuntime(t)

	previewRec := httptest.NewRecorder()
	HandlePreviewBroadbandSubscriberState(previewRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/broadband-subscriber-state/preview", nil))
	require.Equal(t, http.StatusOK, previewRec.Code, previewRec.Body.String())
	var previewPayload struct {
		EventID string `json:"event_id"`
		Report  struct {
			FeatureID       string `json:"feature_id"`
			Status          string `json:"status"`
			PlanFingerprint string `json:"plan_fingerprint"`
			Summary         struct {
				EnabledProductCount       int `json:"enabled_product_count"`
				EnabledServicePolicyCount int `json:"enabled_service_policy_count"`
				StateCount                int `json:"state_count"`
				TransitionCount           int `json:"transition_count"`
				RequiredTransitionCount   int `json:"required_transition_count"`
				AccountingTransitionCount int `json:"accounting_transition_count"`
				RecoveryTransitionCount   int `json:"recovery_transition_count"`
				ComplianceCheckCount      int `json:"compliance_check_count"`
				PassedCheckCount          int `json:"passed_check_count"`
				BlockerCount              int `json:"blocker_count"`
				ExternalRequirementCount  int `json:"external_requirement_count"`
			} `json:"summary"`
		} `json:"report"`
	}
	require.NoError(t, json.Unmarshal(previewRec.Body.Bytes(), &previewPayload))
	assert.NotEmpty(t, previewPayload.EventID)
	assert.Equal(t, "NAS-0083", previewPayload.Report.FeatureID)
	assert.Equal(t, "ready", previewPayload.Report.Status)
	assert.Equal(t, 1, previewPayload.Report.Summary.EnabledProductCount)
	assert.Equal(t, 2, previewPayload.Report.Summary.EnabledServicePolicyCount)
	assert.GreaterOrEqual(t, previewPayload.Report.Summary.StateCount, 15)
	assert.GreaterOrEqual(t, previewPayload.Report.Summary.TransitionCount, 20)
	assert.Greater(t, previewPayload.Report.Summary.RequiredTransitionCount, 0)
	assert.Greater(t, previewPayload.Report.Summary.AccountingTransitionCount, 0)
	assert.Greater(t, previewPayload.Report.Summary.RecoveryTransitionCount, 0)
	assert.Equal(t, previewPayload.Report.Summary.ComplianceCheckCount, previewPayload.Report.Summary.PassedCheckCount)
	assert.Zero(t, previewPayload.Report.Summary.BlockerCount)
	assert.Greater(t, previewPayload.Report.Summary.ExternalRequirementCount, 0)
	assert.NotEmpty(t, previewPayload.Report.PlanFingerprint)

	applyRec := httptest.NewRecorder()
	HandleApplyBroadbandSubscriberState(applyRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/broadband-subscriber-state/apply", nil))
	require.Equal(t, http.StatusOK, applyRec.Code, applyRec.Body.String())
	assert.Contains(t, applyRec.Body.String(), `"status":"applied"`)

	statusRec := httptest.NewRecorder()
	HandleGetBroadbandSubscriberState(statusRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/broadband-subscriber-state", nil))
	require.Equal(t, http.StatusOK, statusRec.Code, statusRec.Body.String())
	assert.Contains(t, statusRec.Body.String(), `"ready_for_external_validation":true`)
	assert.Contains(t, statusRec.Body.String(), `"recent_events"`)

	historyRec := httptest.NewRecorder()
	HandleListBroadbandSubscriberStateHistory(historyRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/broadband-subscriber-state/history?limit=5", nil))
	require.Equal(t, http.StatusOK, historyRec.Code, historyRec.Body.String())
	assert.Contains(t, historyRec.Body.String(), `"feature_id":"NAS-0083"`)
	assert.Contains(t, historyRec.Body.String(), `"preview_events":1`)
	assert.Contains(t, historyRec.Body.String(), `"applied_count":1`)

	readiness := buildProductionReadinessReport(config.Get())
	assert.Equal(t, "passed", productionReadinessCheckStatus(readiness.Checks, "broadband_subscriber_state"))

	systemRec := httptest.NewRecorder()
	HandleGetSystemStatus(systemRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/status", nil))
	require.Equal(t, http.StatusOK, systemRec.Code, systemRec.Body.String())
	assert.Contains(t, systemRec.Body.String(), `"broadband_subscriber_state"`)

	spec := buildOpenAPISpec(httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil), config.Get())
	paths := spec["paths"].(map[string]any)
	for _, path := range []string{
		"/api/v1/system/broadband-subscriber-state",
		"/api/v1/system/broadband-subscriber-state/preview",
		"/api/v1/system/broadband-subscriber-state/apply",
		"/api/v1/system/broadband-subscriber-state/history",
	} {
		_, ok := paths[path]
		assert.True(t, ok, "OpenAPI path %s should exist", path)
	}

	foundStatusCapture := false
	foundHistoryCapture := false
	for _, capture := range supportBundleAPICaptures() {
		if capture.archivePath == "api/broadband-subscriber-state.json" {
			foundStatusCapture = true
		}
		if capture.archivePath == "api/broadband-subscriber-state-history.json" {
			foundHistoryCapture = true
		}
	}
	assert.True(t, foundStatusCapture)
	assert.True(t, foundHistoryCapture)
}

func TestBroadbandSubscriberStateRBAC(t *testing.T) {
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/broadband-subscriber-state"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/broadband-subscriber-state/preview"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/broadband-subscriber-state/history"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/broadband-subscriber-state/apply"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/broadband-subscriber-state/apply"))
}

func prepareBroadbandSubscriberStateAPITestRuntime(t *testing.T) {
	t.Helper()
	preparePPPoEAccessLifecycleAPITestRuntime(t)
	cfg := config.Get()
	cfg.Radius.SQLAccounting.Enabled = true
	cfg.Broadband.Subscriber = config.BroadbandSubscriberStateConfig{
		Enabled:                  true,
		Mode:                     "enforce",
		FailClosed:               true,
		DefaultAccessMethod:      "pppoe",
		MaxSessions:              4096,
		MaxSessionsPerSubscriber: 4,
		MaxReconnects:            3,
		ReconnectWindowSeconds:   300,
		AccountingGraceSeconds:   90,
		RecoveryScanSeconds:      60,
		RequireAccountingStart:   true,
		RequireAccountingStop:    true,
		RequireSessionOwnership:  true,
		ServiceLegsEnabled:       true,
		PolicyTransitionsEnabled: true,
		ReconnectRecoveryEnabled: true,
		QuotaHooksEnabled:        true,
		ChargingHooksEnabled:     true,
		DualStackRequired:        true,
		RoutePolicyRequired:      true,
		QoSRequired:              true,
		NATRequired:              true,
		CoARequired:              true,
		EventRetentionLimit:      10000,
		Products: []config.BroadbandSubscriberProductConfig{
			{
				Name:                  "residential-fiber",
				Enabled:               true,
				Role:                  "residential",
				ServiceChain:          "retail-internet",
				AddressPool:           "pppoe-v4",
				IPv6Pool:              "pppoe-v6",
				DelegatedIPv6Pool:     "pppoe-pd",
				RoutePolicy:           "residential",
				QoSProfile:            "silver",
				TranslationPool:       "cgnat-pool",
				QuotaProfile:          "unlimited",
				MaxSessions:           4,
				SessionTimeoutSeconds: 86400,
				IdleTimeoutSeconds:    3600,
				VendorPacks:           []string{"standard", "aegisnas", "mikrotik", "huawei"},
			},
		},
		ServicePolicies: []config.BroadbandSubscriberServicePolicyConfig{
			{
				Name:            "base-internet-start",
				Enabled:         true,
				Product:         "residential-fiber",
				Leg:             "internet",
				Trigger:         "accounting-start",
				RequiredState:   "service_active",
				NextState:       "accounting_started",
				AccountingClass: "internet",
				RoutePolicy:     "residential",
				QoSProfile:      "silver",
				TranslationPool: "cgnat-pool",
				VendorPacks:     []string{"standard", "aegisnas", "mikrotik"},
			},
			{
				Name:          "quota-policy-update",
				Enabled:       true,
				Product:       "residential-fiber",
				Leg:           "quota",
				Trigger:       "quota-threshold",
				RequiredState: "interim_seen",
				NextState:     "policy_update_pending",
				CoAAction:     "rate-limit",
				QoSProfile:    "silver",
				VendorPacks:   []string{"standard", "aegisnas"},
			},
		},
		FailurePolicies: []config.BroadbandSubscriberFailurePolicyConfig{
			{
				Name:                 "accounting-gap-recovery",
				Enabled:              true,
				Failure:              "accounting-gap",
				Action:               "recover",
				TargetState:          "recovered",
				RecoveryAfterSeconds: 120,
			},
		},
	}
}
