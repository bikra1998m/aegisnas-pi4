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

func TestBroadbandQoSServiceFlowsAPIPreviewApplyStatusHistory(t *testing.T) {
	prepareBroadbandQoSServiceFlowsAPITestRuntime(t)

	previewRec := httptest.NewRecorder()
	HandlePreviewBroadbandQoSServiceFlows(previewRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/broadband-qos-service-flows/preview", nil))
	require.Equal(t, http.StatusOK, previewRec.Code, previewRec.Body.String())
	var previewPayload struct {
		EventID string `json:"event_id"`
		Report  struct {
			FeatureID       string `json:"feature_id"`
			Status          string `json:"status"`
			PlanFingerprint string `json:"plan_fingerprint"`
			Summary         struct {
				ProfileCount             int `json:"profile_count"`
				ServiceFlowCount         int `json:"service_flow_count"`
				AggregatePolicyCount     int `json:"aggregate_policy_count"`
				CompiledAttributeCount   int `json:"compiled_attribute_count"`
				ComplianceCheckCount     int `json:"compliance_check_count"`
				PassedCheckCount         int `json:"passed_check_count"`
				ExternalRequirementCount int `json:"external_requirement_count"`
			} `json:"summary"`
		} `json:"report"`
	}
	require.NoError(t, json.Unmarshal(previewRec.Body.Bytes(), &previewPayload))
	assert.NotEmpty(t, previewPayload.EventID)
	assert.Equal(t, "NAS-0087", previewPayload.Report.FeatureID)
	assert.Equal(t, "ready", previewPayload.Report.Status)
	assert.Equal(t, 1, previewPayload.Report.Summary.ProfileCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.ServiceFlowCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.AggregatePolicyCount)
	assert.GreaterOrEqual(t, previewPayload.Report.Summary.CompiledAttributeCount, 3)
	assert.Equal(t, previewPayload.Report.Summary.ComplianceCheckCount, previewPayload.Report.Summary.PassedCheckCount)
	assert.Greater(t, previewPayload.Report.Summary.ExternalRequirementCount, 0)
	assert.NotEmpty(t, previewPayload.Report.PlanFingerprint)

	applyRec := httptest.NewRecorder()
	HandleApplyBroadbandQoSServiceFlows(applyRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/broadband-qos-service-flows/apply", nil))
	require.Equal(t, http.StatusOK, applyRec.Code, applyRec.Body.String())
	assert.Contains(t, applyRec.Body.String(), `"status":"ready"`)

	statusRec := httptest.NewRecorder()
	HandleGetBroadbandQoSServiceFlows(statusRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/broadband-qos-service-flows", nil))
	require.Equal(t, http.StatusOK, statusRec.Code, statusRec.Body.String())
	assert.Contains(t, statusRec.Body.String(), `"ready_for_external_validation":true`)
	assert.Contains(t, statusRec.Body.String(), `"flows"`)

	historyRec := httptest.NewRecorder()
	HandleListBroadbandQoSServiceFlowHistory(historyRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/broadband-qos-service-flows/history?limit=5", nil))
	require.Equal(t, http.StatusOK, historyRec.Code, historyRec.Body.String())
	assert.Contains(t, historyRec.Body.String(), `"feature_id":"NAS-0087"`)
	assert.Contains(t, historyRec.Body.String(), `"preview_events":1`)
	assert.Contains(t, historyRec.Body.String(), `"applied_count":1`)
}

func TestBroadbandQoSServiceFlowsRBAC(t *testing.T) {
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/broadband-qos-service-flows"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/broadband-qos-service-flows/preview"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/broadband-qos-service-flows/history"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/broadband-qos-service-flows/apply"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/broadband-qos-service-flows/apply"))
}

func prepareBroadbandQoSServiceFlowsAPITestRuntime(t *testing.T) {
	t.Helper()
	prepareBroadbandCommercialCatalogAPITestRuntime(t)
	cfg := config.Get()
	cfg.Radius.SQLAccounting.Enabled = true
	cfg.Radius.AccountingServices.Enabled = true
	cfg.Radius.DynamicAuth.Enabled = true
	cfg.Broadband.QoSServiceFlows = config.BroadbandQoSServiceFlowConfig{
		Enabled:                       true,
		Mode:                          "enforce",
		FailClosed:                    true,
		RequireSubscriberState:        true,
		RequireCommercialCatalog:      true,
		RequireRuntimeQoS:             true,
		RequireRateCompiler:           true,
		AccountingCorrelationRequired: true,
		CoAOnChange:                   true,
		AggregateControlEnabled:       true,
		Scheduler:                     "htb",
		DefaultTrafficClass:           "data",
		EventRetentionLimit:           10000,
		Profiles: []config.BroadbandQoSProfileConfig{
			{Name: "silver", Enabled: true, TrafficClass: "data", Scheduler: "htb", Priority: 4, DSCPMark: 10, DownloadMinRateKbps: 50000, DownloadRateKbps: 100000, DownloadPeakRateKbps: 120000, UploadMinRateKbps: 10000, UploadRateKbps: 20000, UploadPeakRateKbps: 25000, DownloadBurstKbps: 120000, UploadBurstKbps: 25000, BurstTimeSeconds: 10, AggregateLimitKbps: 1000000, MaxSubscribers: 128, VendorPacks: []string{"mikrotik", "huawei", "zte"}},
		},
		ServiceFlows: []config.BroadbandQoSServiceFlowIntentConfig{
			{Name: "fiber-internet", Enabled: true, Product: "residential-fiber", ServiceLeg: "internet", SubscriberID: "sub-lab-cpe-01", Username: "lab-cpe-01@example.net", Role: "residential", Tenant: "retail", Direction: "bidirectional", Profile: "silver", Aggregate: "tenant-retail", AccountingKey: "acct-class-internet", Precedence: 100, CoAAction: "rate-limit", VendorPacks: []string{"mikrotik", "huawei", "zte"}},
		},
		AggregatePolicies: []config.BroadbandQoSAggregatePolicyConfig{
			{Name: "tenant-retail", Enabled: true, Scope: "tenant", Tenant: "retail", Profile: "silver", MaxSubscribers: 1000, DownloadLimitKbps: 1000000, UploadLimitKbps: 250000, OversubscriptionRatio: 20, Scheduler: "htb", DropPrecedence: "low", VendorPacks: []string{"mikrotik", "huawei"}},
		},
	}
}
