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

func TestBroadbandCommercialCatalogAPIPreviewApplyStatusHistoryReadinessAndSupportBundle(t *testing.T) {
	prepareBroadbandCommercialCatalogAPITestRuntime(t)

	previewRec := httptest.NewRecorder()
	HandlePreviewBroadbandCommercialCatalog(previewRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/broadband-commercial-catalog/preview", nil))
	require.Equal(t, http.StatusOK, previewRec.Code, previewRec.Body.String())
	var previewPayload struct {
		EventID string `json:"event_id"`
		Report  struct {
			FeatureID       string `json:"feature_id"`
			Status          string `json:"status"`
			PlanFingerprint string `json:"plan_fingerprint"`
			Summary         struct {
				AccountCount                  int `json:"account_count"`
				EnabledPlanCount              int `json:"enabled_plan_count"`
				EnabledBundleCount            int `json:"enabled_bundle_count"`
				ActiveSubscriptionCount       int `json:"active_subscription_count"`
				EnabledConcurrencyPolicyCount int `json:"enabled_concurrency_policy_count"`
				AuthorizationBindingCount     int `json:"authorization_binding_count"`
				AccountingBindingCount        int `json:"accounting_binding_count"`
				ComplianceCheckCount          int `json:"compliance_check_count"`
				PassedCheckCount              int `json:"passed_check_count"`
				BlockerCount                  int `json:"blocker_count"`
				ExternalRequirementCount      int `json:"external_requirement_count"`
			} `json:"summary"`
		} `json:"report"`
	}
	require.NoError(t, json.Unmarshal(previewRec.Body.Bytes(), &previewPayload))
	assert.NotEmpty(t, previewPayload.EventID)
	assert.Equal(t, "NAS-0084", previewPayload.Report.FeatureID)
	assert.Equal(t, "ready", previewPayload.Report.Status)
	assert.Equal(t, 1, previewPayload.Report.Summary.AccountCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.EnabledPlanCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.EnabledBundleCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.ActiveSubscriptionCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.EnabledConcurrencyPolicyCount)
	assert.GreaterOrEqual(t, previewPayload.Report.Summary.AuthorizationBindingCount, 4)
	assert.GreaterOrEqual(t, previewPayload.Report.Summary.AccountingBindingCount, 4)
	assert.Equal(t, previewPayload.Report.Summary.ComplianceCheckCount, previewPayload.Report.Summary.PassedCheckCount)
	assert.Zero(t, previewPayload.Report.Summary.BlockerCount)
	assert.Greater(t, previewPayload.Report.Summary.ExternalRequirementCount, 0)
	assert.NotEmpty(t, previewPayload.Report.PlanFingerprint)

	applyRec := httptest.NewRecorder()
	HandleApplyBroadbandCommercialCatalog(applyRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/broadband-commercial-catalog/apply", nil))
	require.Equal(t, http.StatusOK, applyRec.Code, applyRec.Body.String())
	assert.Contains(t, applyRec.Body.String(), `"status":"applied"`)

	statusRec := httptest.NewRecorder()
	HandleGetBroadbandCommercialCatalog(statusRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/broadband-commercial-catalog", nil))
	require.Equal(t, http.StatusOK, statusRec.Code, statusRec.Body.String())
	assert.Contains(t, statusRec.Body.String(), `"ready_for_external_validation":true`)
	assert.Contains(t, statusRec.Body.String(), `"subscriptions"`)

	historyRec := httptest.NewRecorder()
	HandleListBroadbandCommercialCatalogHistory(historyRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/broadband-commercial-catalog/history?limit=5", nil))
	require.Equal(t, http.StatusOK, historyRec.Code, historyRec.Body.String())
	assert.Contains(t, historyRec.Body.String(), `"feature_id":"NAS-0084"`)
	assert.Contains(t, historyRec.Body.String(), `"preview_events":1`)
	assert.Contains(t, historyRec.Body.String(), `"applied_count":1`)

	readiness := buildProductionReadinessReport(config.Get())
	assert.Equal(t, "passed", productionReadinessCheckStatus(readiness.Checks, "broadband_commercial_catalog"))

	systemRec := httptest.NewRecorder()
	HandleGetSystemStatus(systemRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/status", nil))
	require.Equal(t, http.StatusOK, systemRec.Code, systemRec.Body.String())
	assert.Contains(t, systemRec.Body.String(), `"broadband_commercial_catalog"`)

	spec := buildOpenAPISpec(httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil), config.Get())
	paths := spec["paths"].(map[string]any)
	for _, path := range []string{
		"/api/v1/system/broadband-commercial-catalog",
		"/api/v1/system/broadband-commercial-catalog/preview",
		"/api/v1/system/broadband-commercial-catalog/apply",
		"/api/v1/system/broadband-commercial-catalog/history",
	} {
		_, ok := paths[path]
		assert.True(t, ok, "OpenAPI path %s should exist", path)
	}

	foundStatusCapture := false
	foundHistoryCapture := false
	for _, capture := range supportBundleAPICaptures() {
		if capture.archivePath == "api/broadband-commercial-catalog.json" {
			foundStatusCapture = true
		}
		if capture.archivePath == "api/broadband-commercial-catalog-history.json" {
			foundHistoryCapture = true
		}
	}
	assert.True(t, foundStatusCapture)
	assert.True(t, foundHistoryCapture)
}

func TestBroadbandCommercialCatalogRBAC(t *testing.T) {
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/broadband-commercial-catalog"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/broadband-commercial-catalog/preview"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/broadband-commercial-catalog/history"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/broadband-commercial-catalog/apply"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/broadband-commercial-catalog/apply"))
}

func prepareBroadbandCommercialCatalogAPITestRuntime(t *testing.T) {
	t.Helper()
	prepareBroadbandSubscriberStateAPITestRuntime(t)
	cfg := config.Get()
	cfg.Radius.SQLAccounting.Enabled = true
	cfg.Broadband.CommercialCatalog = config.BroadbandCommercialCatalog{
		Enabled:                       true,
		Mode:                          "enforce",
		FailClosed:                    true,
		DefaultBillingPeriod:          "monthly",
		DefaultCurrency:               "USD",
		AllowFamilyAccounts:           true,
		RequireActiveSubscription:     true,
		RequireBundleEligibility:      true,
		EnforceConcurrency:            true,
		AccountingCorrelationRequired: true,
		CoAOnLimit:                    true,
		MaxAccounts:                   100000,
		MaxSubscriptions:              250000,
		MaxSessionsPerAccount:         8,
		MaxSessionsPerSubscription:    4,
		EventRetentionLimit:           10000,
		Accounts: []config.BroadbandCommercialAccountConfig{
			{AccountID: "acct-lab-1", Tenant: "retail", Status: "active", BillingMode: "postpaid", OwnerName: "Lab Account", Contact: "noc@example.net", MaxSubscriptions: 4, MaxSessions: 8, Tags: []string{"lab", "retail"}},
		},
		Plans: []config.BroadbandCommercialPlanConfig{
			{Name: "fiber-100m", Enabled: true, Product: "residential-fiber", DisplayName: "Fiber 100M", BillingPeriod: "monthly", PriceMicros: 49990000, Currency: "USD", MaxSessions: 4, MaxDevices: 32, DownstreamKbps: 100000, UpstreamKbps: 25000, VendorPacks: []string{"standard", "aegisnas", "mikrotik", "huawei"}},
		},
		Bundles: []config.BroadbandCommercialBundleConfig{
			{Name: "home-internet", Enabled: true, DisplayName: "Home Internet", Plans: []string{"fiber-100m"}, RequiredPlans: []string{"fiber-100m"}, MaxConcurrentSubscriptions: 4, SharedConcurrency: true, Priority: 100, EligibilityTags: []string{"retail"}},
		},
		Subscriptions: []config.BroadbandCommercialSubscriptionConfig{
			{SubscriptionID: "sub-commercial-1", AccountID: "acct-lab-1", SubscriberID: "sub-lab-cpe-01", Username: "lab-cpe-01@example.net", Plan: "fiber-100m", Bundle: "home-internet", Status: "active", AutoRenew: true, MaxSessions: 4, DeviceLimit: 32, EligibilityTags: []string{"retail"}},
		},
		ConcurrencyPolicies: []config.BroadbandCommercialConcurrencyPolicyConfig{
			{Name: "fiber-plan-limit", Enabled: true, Scope: "plan", Plan: "fiber-100m", MaxSessions: 4, MaxSessionsPerSubscriber: 4, BurstSessions: 1, GraceSeconds: 60, Action: "reject", CoAAction: "disconnect-excess"},
		},
	}
}
