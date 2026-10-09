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

func TestBroadbandServiceActivationAPIPreviewApplyStatusHistory(t *testing.T) {
	prepareBroadbandServiceActivationAPITestRuntime(t)

	previewRec := httptest.NewRecorder()
	HandlePreviewBroadbandServiceActivation(previewRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/broadband-service-activation/preview", nil))
	require.Equal(t, http.StatusOK, previewRec.Code, previewRec.Body.String())
	var previewPayload struct {
		EventID string `json:"event_id"`
		Report  struct {
			FeatureID       string `json:"feature_id"`
			Status          string `json:"status"`
			PlanFingerprint string `json:"plan_fingerprint"`
			Summary         struct {
				ServiceCount             int `json:"service_count"`
				RoutePolicyCount         int `json:"route_policy_count"`
				MulticastProfileCount    int `json:"multicast_profile_count"`
				ActivationPolicyCount    int `json:"activation_policy_count"`
				RouteAttributeCount      int `json:"route_attribute_count"`
				MulticastAttributeCount  int `json:"multicast_attribute_count"`
				RadiusAttributeCount     int `json:"radius_attribute_count"`
				ComplianceCheckCount     int `json:"compliance_check_count"`
				PassedCheckCount         int `json:"passed_check_count"`
				ExternalRequirementCount int `json:"external_requirement_count"`
			} `json:"summary"`
		} `json:"report"`
	}
	require.NoError(t, json.Unmarshal(previewRec.Body.Bytes(), &previewPayload))
	assert.NotEmpty(t, previewPayload.EventID)
	assert.Equal(t, "NAS-0090", previewPayload.Report.FeatureID)
	assert.Equal(t, "ready", previewPayload.Report.Status)
	assert.Equal(t, 1, previewPayload.Report.Summary.ServiceCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.RoutePolicyCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.MulticastProfileCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.ActivationPolicyCount)
	assert.Greater(t, previewPayload.Report.Summary.RouteAttributeCount, 0)
	assert.Greater(t, previewPayload.Report.Summary.MulticastAttributeCount, 0)
	assert.Greater(t, previewPayload.Report.Summary.RadiusAttributeCount, 0)
	assert.Equal(t, previewPayload.Report.Summary.ComplianceCheckCount, previewPayload.Report.Summary.PassedCheckCount)
	assert.Greater(t, previewPayload.Report.Summary.ExternalRequirementCount, 0)
	assert.NotEmpty(t, previewPayload.Report.PlanFingerprint)

	applyRec := httptest.NewRecorder()
	HandleApplyBroadbandServiceActivation(applyRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/broadband-service-activation/apply", nil))
	require.Equal(t, http.StatusOK, applyRec.Code, applyRec.Body.String())
	assert.Contains(t, applyRec.Body.String(), `"status":"ready"`)

	statusRec := httptest.NewRecorder()
	HandleGetBroadbandServiceActivation(statusRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/broadband-service-activation", nil))
	require.Equal(t, http.StatusOK, statusRec.Code, statusRec.Body.String())
	assert.Contains(t, statusRec.Body.String(), `"ready_for_external_validation":true`)
	assert.Contains(t, statusRec.Body.String(), `"transactions"`)

	historyRec := httptest.NewRecorder()
	HandleListBroadbandServiceActivationHistory(historyRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/broadband-service-activation/history?limit=5", nil))
	require.Equal(t, http.StatusOK, historyRec.Code, historyRec.Body.String())
	assert.Contains(t, historyRec.Body.String(), `"feature_id":"NAS-0090"`)
	assert.Contains(t, historyRec.Body.String(), `"preview_events":1`)
	assert.Contains(t, historyRec.Body.String(), `"applied_count":1`)
}

func TestBroadbandServiceActivationRBAC(t *testing.T) {
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/broadband-service-activation"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/broadband-service-activation/preview"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/broadband-service-activation/history"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/broadband-service-activation/apply"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/broadband-service-activation/apply"))
}

func TestBroadbandServiceActivationSupportBundleCaptures(t *testing.T) {
	var foundStatusCapture, foundHistoryCapture bool
	for _, capture := range supportBundleAPICaptures() {
		if capture.archivePath == "api/broadband-service-activation.json" {
			foundStatusCapture = true
		}
		if capture.archivePath == "api/broadband-service-activation-history.json" {
			foundHistoryCapture = true
		}
	}
	assert.True(t, foundStatusCapture)
	assert.True(t, foundHistoryCapture)
}

func prepareBroadbandServiceActivationAPITestRuntime(t *testing.T) {
	t.Helper()
	prepareBroadbandDHCPSecurityAPITestRuntime(t)
	cfg := config.Get()
	cfg.Radius.SQLAccounting.Enabled = true
	cfg.Radius.AccountingServices.Enabled = true
	cfg.Radius.DynamicAuth.Enabled = true
	cfg.Radius.RoutePolicy.Enabled = true
	cfg.Radius.RoutePolicy.DynamicRouting.Enabled = true
	cfg.Broadband.AddressLeases.Enabled = true
	cfg.Broadband.QoSServiceFlows.Enabled = true
	cfg.Broadband.ServiceActivation = config.BroadbandServiceActivationConfig{
		Enabled:                  true,
		Mode:                     "enforce",
		FailClosed:               true,
		RequireSubscriberState:   true,
		RequireCommercialCatalog: true,
		RequireAddressLeases:     true,
		RequireQoSServiceFlows:   true,
		RequireDHCPSecurity:      true,
		RequireRouteExport:       true,
		RequireAccounting:        true,
		RequireDynamicAuth:       true,
		TransactionalApply:       true,
		RollbackOnFailure:        true,
		RoutePublishEnabled:      true,
		MulticastEnabled:         true,
		ActivationTimeoutSeconds: 60,
		EventRetentionLimit:      10000,
		Services: []config.BroadbandServiceActivationServiceConfig{
			{Name: "fiber-internet-activation", Enabled: true, Required: true, Product: "residential-fiber", SubscriberID: "sub-lab-cpe-01", Username: "lab-cpe-01@example.net", Tenant: "retail", ServiceChain: "retail-internet", RoutePolicy: "retail-bgp", MulticastProfile: "iptv-basic", AddressPool: "pppoe-v4", QoSProfile: "silver", AccountingClass: "internet", VendorPacks: []string{"standard", "erx", "huawei", "h3c", "nokia", "zte"}},
		},
		RoutePolicies: []config.BroadbandActivationRoutePolicyConfig{
			{Name: "retail-bgp", Enabled: true, VRF: "retail", Protocol: "bgp", IPv4Routes: []string{"100.64.0.0/24"}, IPv6Routes: []string{"2001:db8:100::/48"}, NextHop: "192.0.2.1", RouteTarget: "65000:100", Metric: 100, Preference: 100, WithdrawOnDeactivate: true, VendorPacks: []string{"standard", "erx", "huawei", "h3c", "nokia", "zte"}},
		},
		MulticastProfiles: []config.BroadbandMulticastProfileConfig{
			{Name: "iptv-basic", Enabled: true, Mode: "igmp-mld", Groups: []string{"239.1.1.1", "ff3e::1"}, SourceAddresses: []string{"198.51.100.10"}, MaxGroups: 64, QuerierInterface: "eth1.100", VLAN: 120, VRF: "retail", EntitlementRequired: true, VendorPacks: []string{"standard", "erx", "huawei", "h3c", "nokia", "zte"}},
		},
		ActivationPolicies: []config.BroadbandActivationPolicyConfig{
			{Name: "retail-transactional", Enabled: true, MatchProduct: "residential-fiber", MatchTenant: "retail", AllowRollback: true, RequireRoutes: true, RequireMulticast: true, RequireAccounting: true, ChangeWindow: "always", FailureAction: "rollback"},
		},
	}
}
