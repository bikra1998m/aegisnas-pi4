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

func TestBroadbandDHCPSecurityAPIPreviewApplyStatusHistory(t *testing.T) {
	prepareBroadbandDHCPSecurityAPITestRuntime(t)

	previewRec := httptest.NewRecorder()
	HandlePreviewBroadbandDHCPSecurity(previewRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/broadband-dhcp-security/preview", nil))
	require.Equal(t, http.StatusOK, previewRec.Code, previewRec.Body.String())
	var previewPayload struct {
		EventID string `json:"event_id"`
		Report  struct {
			FeatureID       string `json:"feature_id"`
			Status          string `json:"status"`
			PlanFingerprint string `json:"plan_fingerprint"`
			Summary         struct {
				RelayAgentCount          int `json:"relay_agent_count"`
				PortCount                int `json:"port_count"`
				TrustedPortCount         int `json:"trusted_port_count"`
				Option82RuleCount        int `json:"option82_rule_count"`
				SourceGuardPolicyCount   int `json:"source_guard_policy_count"`
				CompiledOptionCount      int `json:"compiled_option_count"`
				ComplianceCheckCount     int `json:"compliance_check_count"`
				PassedCheckCount         int `json:"passed_check_count"`
				ExternalRequirementCount int `json:"external_requirement_count"`
			} `json:"summary"`
		} `json:"report"`
	}
	require.NoError(t, json.Unmarshal(previewRec.Body.Bytes(), &previewPayload))
	assert.NotEmpty(t, previewPayload.EventID)
	assert.Equal(t, "NAS-0089", previewPayload.Report.FeatureID)
	assert.Equal(t, "ready", previewPayload.Report.Status)
	assert.Equal(t, 1, previewPayload.Report.Summary.RelayAgentCount)
	assert.Equal(t, 2, previewPayload.Report.Summary.PortCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.TrustedPortCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.Option82RuleCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.SourceGuardPolicyCount)
	assert.GreaterOrEqual(t, previewPayload.Report.Summary.CompiledOptionCount, 7)
	assert.Equal(t, previewPayload.Report.Summary.ComplianceCheckCount, previewPayload.Report.Summary.PassedCheckCount)
	assert.Greater(t, previewPayload.Report.Summary.ExternalRequirementCount, 0)
	assert.NotEmpty(t, previewPayload.Report.PlanFingerprint)

	applyRec := httptest.NewRecorder()
	HandleApplyBroadbandDHCPSecurity(applyRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/broadband-dhcp-security/apply", nil))
	require.Equal(t, http.StatusOK, applyRec.Code, applyRec.Body.String())
	assert.Contains(t, applyRec.Body.String(), `"status":"ready"`)

	statusRec := httptest.NewRecorder()
	HandleGetBroadbandDHCPSecurity(statusRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/broadband-dhcp-security", nil))
	require.Equal(t, http.StatusOK, statusRec.Code, statusRec.Body.String())
	assert.Contains(t, statusRec.Body.String(), `"ready_for_external_validation":true`)
	assert.Contains(t, statusRec.Body.String(), `"bindings"`)

	historyRec := httptest.NewRecorder()
	HandleListBroadbandDHCPSecurityHistory(historyRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/broadband-dhcp-security/history?limit=5", nil))
	require.Equal(t, http.StatusOK, historyRec.Code, historyRec.Body.String())
	assert.Contains(t, historyRec.Body.String(), `"feature_id":"NAS-0089"`)
	assert.Contains(t, historyRec.Body.String(), `"preview_events":1`)
	assert.Contains(t, historyRec.Body.String(), `"applied_count":1`)
}

func TestBroadbandDHCPSecurityRBAC(t *testing.T) {
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/broadband-dhcp-security"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/broadband-dhcp-security/preview"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/broadband-dhcp-security/history"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/broadband-dhcp-security/apply"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/broadband-dhcp-security/apply"))
}

func prepareBroadbandDHCPSecurityAPITestRuntime(t *testing.T) {
	t.Helper()
	prepareBroadbandCommercialCatalogAPITestRuntime(t)
	cfg := config.Get()
	cfg.DHCP.Enabled = true
	cfg.Radius.SQLAccounting.Enabled = true
	cfg.Radius.AccountingServices.Enabled = true
	cfg.Radius.DynamicAuth.Enabled = true
	cfg.Broadband.AddressLeases.Enabled = true
	cfg.Broadband.Subscriber.Enabled = true
	cfg.Broadband.Subscriber.DefaultAccessMethod = "dhcp"
	cfg.Broadband.Subscriber.Products = []config.BroadbandSubscriberProductConfig{
		{Name: "residential-fiber", Enabled: true, Role: "subscriber"},
	}
	cfg.Broadband.DHCPSecurity = config.BroadbandDHCPSecurityConfig{
		Enabled:                  true,
		Mode:                     "enforce",
		FailClosed:               true,
		RequireDHCP:              true,
		RequireSubscriberState:   true,
		RequireAddressLeases:     true,
		RequireAccounting:        true,
		RequireDynamicAuth:       true,
		RelayEnabled:             true,
		SnoopingEnabled:          true,
		SourceGuardEnabled:       true,
		Option82Required:         true,
		DropUnknownBindings:      true,
		TrustedUplinkRequired:    true,
		Option82Policy:           "append",
		BindingRetentionSeconds:  86400,
		EventRetentionLimit:      10000,
		ViolationHoldDownSeconds: 300,
		RelayAgents: []config.BroadbandDHCPRelayAgentConfig{
			{Name: "relay-vlan100", Enabled: true, Interface: "eth1.100", VLAN: 100, GatewayAddress: "192.0.2.1", ServerGroup: "dhcp-core", VRF: "retail", CircuitIDTemplate: "{{interface}}:{{vlan}}", RemoteIDTemplate: "{{tenant}}", AppendOption82: true, Trusted: true, MaxClients: 4096, VendorPacks: []string{"standard", "cisco", "huawei"}},
		},
		Ports: []config.BroadbandDHCPSecurityPortConfig{
			{Name: "subscriber-port-1", Enabled: true, Interface: "eth1.100", VLAN: 100, Role: "access", CircuitID: "olt1/1/1", RemoteID: "retail", SubscriberProduct: "residential-fiber", Tenant: "retail", MaxLeases: 4, SourceGuardPolicy: "strict-access", VendorPacks: []string{"standard", "cisco"}},
			{Name: "uplink", Enabled: true, Interface: "eth1", VLAN: 0, Role: "uplink", Trusted: true, MaxLeases: 100000, VendorPacks: []string{"standard"}},
		},
		Option82Rules: []config.BroadbandDHCPOption82RuleConfig{
			{Name: "access-option82", Enabled: true, MatchInterface: "eth1.100", MatchVLAN: 100, CircuitIDTemplate: "{{port}}", RemoteIDTemplate: "{{tenant}}", Action: "append", RequireRemoteID: true, VendorPacks: []string{"standard", "cisco"}},
		},
		SourceGuardPolicies: []config.BroadbandDHCPSourceGuardPolicyConfig{
			{Name: "strict-access", Enabled: true, Mode: "enforce", Interfaces: []string{"eth1.100"}, VLANs: []int{100}, AllowUnknown: false, MaxBindings: 4096, IPv6Enabled: true, ActionOnViolation: "drop", CoAAction: "disconnect"},
		},
		RADIUSCorrelation: []config.BroadbandDHCPRADIUSCorrelationConfig{
			{Name: "option82-accounting", Enabled: true, Source: "option82", Attributes: []string{"Class", "NAS-Port-Id", "Calling-Station-Id"}, AccountingStages: []string{"start", "interim", "stop"}},
		},
	}
}
