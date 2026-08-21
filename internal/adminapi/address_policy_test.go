package adminapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/radius"
)

func TestAddressPolicyAPIReadinessOpenAPISupportBundleAndRBAC(t *testing.T) {
	prepareRuntimeQoSAPITestRuntime(t)
	cfg := config.Get()
	cfg.Radius.Vendor.CompatibilityPacks = []string{
		productconfigs.VendorPackStandard,
		productconfigs.VendorPackAegisNAS,
		productconfigs.VendorPackCisco,
		productconfigs.VendorPackJuniper,
		productconfigs.VendorPackHuawei,
		productconfigs.VendorPackMikroTik,
		productconfigs.VendorPackNokia,
	}
	cfg.Radius.AddressPolicy = config.RadiusAddressPolicyConfig{
		Enabled:        true,
		FailClosed:     true,
		MaxAssignments: 16,
		DefaultOwner:   "aegisnas",
		ConflictMode:   "block",
		StopWithdrawal: true,
		DHCPv6: config.RadiusDHCPv6PolicyConfig{
			Enabled:          true,
			ManagedAddress:   true,
			OtherConfig:      true,
			PrefixDelegation: true,
		},
		RA: config.RadiusRAPolicyConfig{
			Enabled:                 true,
			OtherConfigFlag:         true,
			DefaultRouterPreference: "medium",
		},
		Pools: []config.RadiusAddressPoolConfig{
			{Name: "branch-v4", Family: "ipv4", CIDR: "198.51.100.0/29", Start: "198.51.100.2", End: "198.51.100.6", Gateway: "198.51.100.1", Mode: "address"},
			{Name: "branch-v6", Family: "ipv6", CIDR: "2001:db8:10::/120", Mode: "address"},
			{Name: "branch-pd", Family: "ipv6", CIDR: "2001:db8:100::/48", DelegatedPrefixLength: 56, Mode: "delegated-prefix"},
			{Name: "branch-ra", Family: "ipv6", CIDR: "2001:db8:200::/56", PrefixLength: 64, Mode: "ra-prefix"},
		},
		RolePolicies: []config.RadiusAddressRolePolicy{
			{
				Role:              "branch-dualstack",
				Owner:             "address-team",
				IPv4Pool:          "branch-v4",
				IPv6Pool:          "branch-v6",
				DelegatedIPv6Pool: "branch-pd",
				RAPrefixPool:      "branch-ra",
				VendorPacks:       []string{productconfigs.VendorPackStandard, productconfigs.VendorPackAegisNAS, productconfigs.VendorPackCisco},
			},
		},
	}

	compileRec := httptest.NewRecorder()
	HandleCompileAddressPolicy(compileRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/address-policy/compile", bytes.NewBufferString(`{
		"role": "branch-dualstack",
		"session_id": "session-1",
		"acct_session_id": "acct-1",
		"calling_station_id": "aa:bb:cc:dd:ee:ff",
		"nas_identifier": "bng-01",
		"pack_keys": ["standard", "aegisnas", "cisco", "juniper", "huawei", "mikrotik", "nokia"]
	}`)))
	require.Equal(t, http.StatusOK, compileRec.Code, compileRec.Body.String())
	var compilePayload struct {
		EventID string `json:"event_id"`
		Result  struct {
			Status      string                           `json:"status"`
			Decision    radius.AddressPolicyDecision     `json:"decision"`
			Attributes  []radius.AddressPolicyAttribute  `json:"attributes"`
			Diagnostics []radius.AddressPolicyDiagnostic `json:"diagnostics"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal(compileRec.Body.Bytes(), &compilePayload))
	assert.NotEmpty(t, compilePayload.EventID)
	assert.Equal(t, "compiled", compilePayload.Result.Status)
	assert.Equal(t, "address-team", compilePayload.Result.Decision.Owner)
	assert.Equal(t, "branch-v4", compilePayload.Result.Decision.IPv4Pool)
	assert.NotEmpty(t, compilePayload.Result.Decision.IPv4Address)
	assert.NotEmpty(t, compilePayload.Result.Decision.DelegatedIPv6Prefix)
	assertAddressPolicyAPIAttribute(t, compilePayload.Result.Attributes, productconfigs.VendorPackStandard, "Framed-IP-Address")
	assertAddressPolicyAPIAttribute(t, compilePayload.Result.Attributes, productconfigs.VendorPackAegisNAS, "AegisNAS-RA-Prefix")
	assertAddressPolicyAPIAttribute(t, compilePayload.Result.Attributes, productconfigs.VendorPackCisco, "Cisco-AVPair")

	previewRec := httptest.NewRecorder()
	HandlePreviewAddressPolicy(previewRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/address-policy/preview", bytes.NewBufferString(`{
		"role": "branch-dualstack",
		"lifecycle_action": "accounting-stop",
		"pack_keys": ["aegisnas", "cisco"]
	}`)))
	require.Equal(t, http.StatusOK, previewRec.Code, previewRec.Body.String())
	assert.Contains(t, previewRec.Body.String(), `"status":"compiled"`)
	assert.Contains(t, previewRec.Body.String(), `"withdraw":true`)

	decompileRec := httptest.NewRecorder()
	HandleDecompileAddressPolicy(decompileRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/address-policy/decompile", bytes.NewBufferString(`{
		"pack_key": "aegisnas",
		"role": "branch-dualstack",
		"attributes": [
			{"pack_key":"aegisnas","name":"AegisNAS-Address-Owner","value":"address-team"},
			{"pack_key":"aegisnas","name":"AegisNAS-IPv4-Pool","value":"branch-v4"},
			{"pack_key":"aegisnas","name":"AegisNAS-Framed-IP-Address","value":"198.51.100.2"},
			{"pack_key":"aegisnas","name":"AegisNAS-Delegated-IPv6-Prefix","value":"2001:db8:100::/56"},
			{"pack_key":"aegisnas","name":"AegisNAS-RA-Prefix","value":"2001:db8:200::/64"}
		]
	}`)))
	require.Equal(t, http.StatusOK, decompileRec.Code, decompileRec.Body.String())
	assert.Contains(t, decompileRec.Body.String(), `"status":"decompiled"`)
	assert.Contains(t, decompileRec.Body.String(), `"owner":"address-team"`)

	getRec := httptest.NewRecorder()
	HandleGetAddressPolicy(getRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/address-policy", nil))
	require.Equal(t, http.StatusOK, getRec.Code, getRec.Body.String())
	assert.Contains(t, getRec.Body.String(), `"compiler_version":1`)
	assert.Contains(t, getRec.Body.String(), `"pool_count":4`)
	assert.Contains(t, getRec.Body.String(), `"total_events":3`)
	assert.Contains(t, getRec.Body.String(), `"active_assignments":4`)

	historyRec := httptest.NewRecorder()
	HandleListAddressPolicyHistory(historyRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/address-policy/history?limit=2", nil))
	require.Equal(t, http.StatusOK, historyRec.Code, historyRec.Body.String())
	assert.Contains(t, historyRec.Body.String(), `"compiled_count":1`)
	assert.Contains(t, historyRec.Body.String(), `"previewed_count":1`)
	assert.Contains(t, historyRec.Body.String(), `"decompiled_count":1`)
	assert.Contains(t, historyRec.Body.String(), `"ownership"`)

	readiness := buildProductionReadinessReport(cfg)
	assert.Equal(t, "passed", productionReadinessCheckStatus(readiness.Checks, "ipv4_ipv6_pool_dhcpv6_ra_pd"))

	spec := buildOpenAPISpec(httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil), cfg)
	paths := spec["paths"].(map[string]any)
	for _, path := range []string{
		"/api/v1/system/address-policy",
		"/api/v1/system/address-policy/preview",
		"/api/v1/system/address-policy/compile",
		"/api/v1/system/address-policy/decompile",
		"/api/v1/system/address-policy/history",
	} {
		_, ok := paths[path]
		assert.True(t, ok, "OpenAPI path %s should exist", path)
	}

	foundStatusCapture := false
	foundHistoryCapture := false
	for _, capture := range supportBundleAPICaptures() {
		if capture.archivePath == "api/address-policy.json" {
			foundStatusCapture = true
		}
		if capture.archivePath == "api/address-policy-history.json" {
			foundHistoryCapture = true
		}
	}
	assert.True(t, foundStatusCapture)
	assert.True(t, foundHistoryCapture)

	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/address-policy"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/address-policy/preview"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/address-policy/compile"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/address-policy/compile"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/address-policy/decompile"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/address-policy/history"))
}

func assertAddressPolicyAPIAttribute(t *testing.T, attrs []radius.AddressPolicyAttribute, packKey, name string) {
	t.Helper()
	for _, attr := range attrs {
		if attr.PackKey == packKey && attr.Name == name {
			return
		}
	}
	t.Fatalf("attribute %s/%s not found in %#v", packKey, name, attrs)
}
