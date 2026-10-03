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

func TestBroadbandQuotaBalanceAPIPreviewApplyStatusHistoryReadinessAndSupportBundle(t *testing.T) {
	prepareBroadbandQuotaBalanceAPITestRuntime(t)

	previewRec := httptest.NewRecorder()
	HandlePreviewBroadbandQuotaBalance(previewRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/broadband-quota-balance/preview", nil))
	require.Equal(t, http.StatusOK, previewRec.Code, previewRec.Body.String())
	var previewPayload struct {
		EventID string `json:"event_id"`
		Report  struct {
			FeatureID       string `json:"feature_id"`
			Status          string `json:"status"`
			PlanFingerprint string `json:"plan_fingerprint"`
			Summary         struct {
				WalletCount               int `json:"wallet_count"`
				EnabledQuotaProfileCount  int `json:"enabled_quota_profile_count"`
				TopUpCount                int `json:"top_up_count"`
				EnabledRatingRuleCount    int `json:"enabled_rating_rule_count"`
				EnabledResetPolicyCount   int `json:"enabled_reset_policy_count"`
				AuthorizationBindingCount int `json:"authorization_binding_count"`
				AccountingBindingCount    int `json:"accounting_binding_count"`
				ComplianceCheckCount      int `json:"compliance_check_count"`
				PassedCheckCount          int `json:"passed_check_count"`
				BlockerCount              int `json:"blocker_count"`
				ExternalRequirementCount  int `json:"external_requirement_count"`
			} `json:"summary"`
		} `json:"report"`
	}
	require.NoError(t, json.Unmarshal(previewRec.Body.Bytes(), &previewPayload))
	assert.NotEmpty(t, previewPayload.EventID)
	assert.Equal(t, "NAS-0085", previewPayload.Report.FeatureID)
	assert.Equal(t, "ready", previewPayload.Report.Status)
	assert.Equal(t, 1, previewPayload.Report.Summary.WalletCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.EnabledQuotaProfileCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.TopUpCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.EnabledRatingRuleCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.EnabledResetPolicyCount)
	assert.GreaterOrEqual(t, previewPayload.Report.Summary.AuthorizationBindingCount, 4)
	assert.GreaterOrEqual(t, previewPayload.Report.Summary.AccountingBindingCount, 4)
	assert.Equal(t, previewPayload.Report.Summary.ComplianceCheckCount, previewPayload.Report.Summary.PassedCheckCount)
	assert.Zero(t, previewPayload.Report.Summary.BlockerCount)
	assert.Greater(t, previewPayload.Report.Summary.ExternalRequirementCount, 0)
	assert.NotEmpty(t, previewPayload.Report.PlanFingerprint)

	applyRec := httptest.NewRecorder()
	HandleApplyBroadbandQuotaBalance(applyRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/broadband-quota-balance/apply", nil))
	require.Equal(t, http.StatusOK, applyRec.Code, applyRec.Body.String())
	assert.Contains(t, applyRec.Body.String(), `"status":"applied"`)

	statusRec := httptest.NewRecorder()
	HandleGetBroadbandQuotaBalance(statusRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/broadband-quota-balance", nil))
	require.Equal(t, http.StatusOK, statusRec.Code, statusRec.Body.String())
	assert.Contains(t, statusRec.Body.String(), `"ready_for_external_validation":true`)
	assert.Contains(t, statusRec.Body.String(), `"wallets"`)

	historyRec := httptest.NewRecorder()
	HandleListBroadbandQuotaBalanceHistory(historyRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/broadband-quota-balance/history?limit=5", nil))
	require.Equal(t, http.StatusOK, historyRec.Code, historyRec.Body.String())
	assert.Contains(t, historyRec.Body.String(), `"feature_id":"NAS-0085"`)
	assert.Contains(t, historyRec.Body.String(), `"preview_events":1`)
	assert.Contains(t, historyRec.Body.String(), `"applied_count":1`)

	readiness := buildProductionReadinessReport(config.Get())
	assert.Equal(t, "passed", productionReadinessCheckStatus(readiness.Checks, "broadband_quota_balance"))

	systemRec := httptest.NewRecorder()
	HandleGetSystemStatus(systemRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/status", nil))
	require.Equal(t, http.StatusOK, systemRec.Code, systemRec.Body.String())
	assert.Contains(t, systemRec.Body.String(), `"broadband_quota_balance"`)

	spec := buildOpenAPISpec(httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil), config.Get())
	paths := spec["paths"].(map[string]any)
	for _, path := range []string{
		"/api/v1/system/broadband-quota-balance",
		"/api/v1/system/broadband-quota-balance/preview",
		"/api/v1/system/broadband-quota-balance/apply",
		"/api/v1/system/broadband-quota-balance/history",
	} {
		_, ok := paths[path]
		assert.True(t, ok, "OpenAPI path %s should exist", path)
	}

	foundStatusCapture := false
	foundHistoryCapture := false
	for _, capture := range supportBundleAPICaptures() {
		if capture.archivePath == "api/broadband-quota-balance.json" {
			foundStatusCapture = true
		}
		if capture.archivePath == "api/broadband-quota-balance-history.json" {
			foundHistoryCapture = true
		}
	}
	assert.True(t, foundStatusCapture)
	assert.True(t, foundHistoryCapture)
}

func TestBroadbandQuotaBalanceRBAC(t *testing.T) {
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/broadband-quota-balance"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/broadband-quota-balance/preview"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/broadband-quota-balance/history"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/broadband-quota-balance/apply"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/broadband-quota-balance/apply"))
}

func prepareBroadbandQuotaBalanceAPITestRuntime(t *testing.T) {
	t.Helper()
	prepareBroadbandCommercialCatalogAPITestRuntime(t)
	cfg := config.Get()
	cfg.Radius.AccountingCharging = config.RadiusAccountingChargingConfig{
		Enabled:             true,
		RatingEnabled:       true,
		ExportEnabled:       true,
		ExportFormat:        "jsonl",
		DefaultPlan:         "fiber-100m",
		Currency:            "USD",
		InputMicrosPerGiB:   25000000,
		OutputMicrosPerGiB:  25000000,
		MinimumChargeMicros: 1000000,
	}
	cfg.Broadband.QuotaBalance = config.BroadbandQuotaBalanceConfig{
		Enabled:                       true,
		Mode:                          "enforce",
		FailClosed:                    true,
		DefaultCurrency:               "USD",
		DefaultQuotaPeriod:            "monthly",
		RequireCommercialCatalog:      true,
		RequireActiveWallet:           true,
		RequireQuotaProfile:           true,
		RatingEnabled:                 true,
		TopUpEnabled:                  true,
		PrepaidEnabled:                true,
		PostpaidEnabled:               true,
		AccountingCorrelationRequired: true,
		AutoSuspendOnExhaustion:       true,
		CoAOnExhaustion:               true,
		EventRetentionLimit:           10000,
		Wallets: []config.BroadbandQuotaWalletConfig{
			{WalletID: "wallet-lab-1", AccountID: "acct-lab-1", SubscriptionID: "sub-commercial-1", SubscriberID: "sub-lab-cpe-01", Username: "lab-cpe-01@example.net", BillingMode: "prepaid", Status: "active", Currency: "USD", BalanceMicros: 25000000, QuotaProfile: "monthly-500g", AutoRecharge: true, Tags: []string{"lab"}},
		},
		QuotaProfiles: []config.BroadbandQuotaProfileConfig{
			{Name: "monthly-500g", Enabled: true, Period: "monthly", IncludedTotalOctets: 536870912000, OverageRateMicrosPerMB: 25000, WarningThresholdPercent: 80, HardLimit: true, ThrottleProfile: "shape-10m", ExhaustedRole: "quota-exhausted", ResetPolicy: "monthly-reset", VendorPacks: []string{"standard", "aegisnas", "mikrotik"}},
		},
		TopUps: []config.BroadbandTopUpGrantConfig{
			{TopUpID: "topup-lab-1", WalletID: "wallet-lab-1", AmountMicros: 10000000, BonusMicros: 1000000, Currency: "USD", QuotaOctets: 107374182400, Status: "applied", PaymentRef: "pay-lab-1", IdempotencyKey: "topup-lab-1", Source: "operator"},
		},
		RatingRules: []config.BroadbandQuotaRatingRuleConfig{
			{Name: "fiber-100m-overage", Enabled: true, Plan: "fiber-100m", QuotaProfile: "monthly-500g", Unit: "total-octets", PriceMicros: 25000, Rounding: "up", MinimumChargeMicros: 1000000},
		},
		ResetPolicies: []config.BroadbandQuotaResetPolicyConfig{
			{Name: "monthly-reset", Enabled: true, Period: "monthly", ResetDay: 1, ResetHour: 3, CarryOverOctets: 107374182400, CarryOverBalanceMicros: 5000000},
		},
	}
}
