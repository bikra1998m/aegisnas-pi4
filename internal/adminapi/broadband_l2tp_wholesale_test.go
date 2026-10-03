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

func TestBroadbandL2TPWholesaleAPIPreviewApplyStatusHistory(t *testing.T) {
	prepareBroadbandL2TPWholesaleAPITestRuntime(t)

	previewRec := httptest.NewRecorder()
	HandlePreviewBroadbandL2TPWholesale(previewRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/broadband-l2tp-wholesale/preview", nil))
	require.Equal(t, http.StatusOK, previewRec.Code, previewRec.Body.String())
	var previewPayload struct {
		EventID string `json:"event_id"`
		Report  struct {
			FeatureID       string `json:"feature_id"`
			Status          string `json:"status"`
			PlanFingerprint string `json:"plan_fingerprint"`
			Summary         struct {
				RealmCount               int `json:"realm_count"`
				TunnelProfileCount       int `json:"tunnel_profile_count"`
				FailoverPolicyCount      int `json:"failover_policy_count"`
				CompiledAttributeCount   int `json:"compiled_attribute_count"`
				ComplianceCheckCount     int `json:"compliance_check_count"`
				PassedCheckCount         int `json:"passed_check_count"`
				ExternalRequirementCount int `json:"external_requirement_count"`
			} `json:"summary"`
		} `json:"report"`
	}
	require.NoError(t, json.Unmarshal(previewRec.Body.Bytes(), &previewPayload))
	assert.NotEmpty(t, previewPayload.EventID)
	assert.Equal(t, "NAS-0088", previewPayload.Report.FeatureID)
	assert.Equal(t, "ready", previewPayload.Report.Status)
	assert.Equal(t, 1, previewPayload.Report.Summary.RealmCount)
	assert.Equal(t, 2, previewPayload.Report.Summary.TunnelProfileCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.FailoverPolicyCount)
	assert.GreaterOrEqual(t, previewPayload.Report.Summary.CompiledAttributeCount, 8)
	assert.Equal(t, previewPayload.Report.Summary.ComplianceCheckCount, previewPayload.Report.Summary.PassedCheckCount)
	assert.Greater(t, previewPayload.Report.Summary.ExternalRequirementCount, 0)
	assert.NotEmpty(t, previewPayload.Report.PlanFingerprint)

	applyRec := httptest.NewRecorder()
	HandleApplyBroadbandL2TPWholesale(applyRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/broadband-l2tp-wholesale/apply", nil))
	require.Equal(t, http.StatusOK, applyRec.Code, applyRec.Body.String())
	assert.Contains(t, applyRec.Body.String(), `"status":"ready"`)

	statusRec := httptest.NewRecorder()
	HandleGetBroadbandL2TPWholesale(statusRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/broadband-l2tp-wholesale", nil))
	require.Equal(t, http.StatusOK, statusRec.Code, statusRec.Body.String())
	assert.Contains(t, statusRec.Body.String(), `"ready_for_external_validation":true`)
	assert.Contains(t, statusRec.Body.String(), `"realm_bindings"`)

	historyRec := httptest.NewRecorder()
	HandleListBroadbandL2TPWholesaleHistory(historyRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/broadband-l2tp-wholesale/history?limit=5", nil))
	require.Equal(t, http.StatusOK, historyRec.Code, historyRec.Body.String())
	assert.Contains(t, historyRec.Body.String(), `"feature_id":"NAS-0088"`)
	assert.Contains(t, historyRec.Body.String(), `"preview_events":1`)
	assert.Contains(t, historyRec.Body.String(), `"applied_count":1`)
}

func TestBroadbandL2TPWholesaleRBAC(t *testing.T) {
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/broadband-l2tp-wholesale"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/broadband-l2tp-wholesale/preview"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/broadband-l2tp-wholesale/history"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/broadband-l2tp-wholesale/apply"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/broadband-l2tp-wholesale/apply"))
}

func prepareBroadbandL2TPWholesaleAPITestRuntime(t *testing.T) {
	t.Helper()
	prepareBroadbandCommercialCatalogAPITestRuntime(t)
	cfg := config.Get()
	cfg.Radius.SQLAccounting.Enabled = true
	cfg.Radius.AccountingServices.Enabled = true
	cfg.Radius.DynamicAuth.Enabled = true
	cfg.Radius.Upstream.Enabled = true
	cfg.Radius.Upstream.Routes = []config.RadiusProxyRouteConfig{
		{Name: "wholesale-retail-auth", Enabled: true, Realm: "retail.example.net"},
		{Name: "wholesale-retail-acct", Enabled: true, Realm: "acct.retail.example.net"},
	}
	cfg.Broadband.Subscriber.WholesaleEnabled = true
	cfg.Broadband.L2TPWholesale = config.BroadbandL2TPWholesaleConfig{
		Enabled:                     true,
		Mode:                        "enforce",
		FailClosed:                  true,
		RequirePPPoE:                true,
		RequireSubscriberState:      true,
		RequireProxyRoutes:          true,
		RequireAccountingDelegation: true,
		RequireTunnelFailover:       true,
		RealmIsolationRequired:      true,
		StripCustomerRealm:          true,
		AccountingDelegationEnabled: true,
		CoAOnFailover:               true,
		SelectionPolicy:             "realm",
		DefaultTunnelProfile:        "lns-primary",
		Realms: []config.BroadbandWholesaleRealmConfig{
			{Name: "wholesale-retail", Enabled: true, Realm: "retail.example.net", Tenant: "retail", Partner: "partner-a", MatchRealms: []string{"retail.example.net"}, AccessMethod: "pppoe", TunnelProfile: "lns-primary", ProxyRoute: "wholesale-retail-auth", AccountingRoute: "wholesale-retail-acct", AddressPool: "wholesale-v4", QoSProfile: "silver", Product: "residential-fiber", StripRealm: true, RequireAccounting: true, VendorPacks: []string{"standard", "cisco", "juniper", "nokia"}},
		},
		TunnelProfiles: []config.BroadbandL2TPTunnelProfileConfig{
			{Name: "lns-primary", Enabled: true, Mode: "lns", LocalName: "aegisnas-lac", PeerName: "partner-lns-1", LocalAddress: "198.51.100.1", PeerAddress: "192.0.2.10", SecretRef: "env:L2TP_SECRET", TunnelGroup: "wholesale-retail", WindowSize: 4, HelloIntervalSeconds: 60, SessionLimit: 4096, RequireEncryption: true, AllowedAuth: []string{"pap", "chap"}, VendorPacks: []string{"cisco", "juniper", "nokia"}},
			{Name: "lns-backup", Enabled: true, Mode: "lns", LocalName: "aegisnas-lac", PeerName: "partner-lns-2", LocalAddress: "198.51.100.2", PeerAddress: "192.0.2.11", SecretRef: "env:L2TP_SECRET", TunnelGroup: "wholesale-retail-backup", WindowSize: 4, HelloIntervalSeconds: 60, SessionLimit: 4096, RequireEncryption: true, AllowedAuth: []string{"pap", "chap"}, VendorPacks: []string{"cisco"}},
		},
		FailoverPolicies: []config.BroadbandL2TPFailoverPolicyConfig{
			{Name: "retail-failover", Enabled: true, Realm: "retail.example.net", PrimaryTunnel: "lns-primary", BackupTunnels: []string{"lns-backup"}, Action: "standby", HoldDownSeconds: 30, MaxFailures: 3, AccountingReplay: true, CoAAction: "reauth"},
		},
	}
}
