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

func TestRoutePolicyAPIReadinessOpenAPISupportBundleAndRBAC(t *testing.T) {
	prepareRuntimeQoSAPITestRuntime(t)
	cfg := config.Get()
	cfg.Radius.Vendor.CompatibilityPacks = []string{
		productconfigs.VendorPackStandard,
		productconfigs.VendorPackAegisNAS,
		productconfigs.VendorPackCisco,
		productconfigs.VendorPackJuniper,
		productconfigs.VendorPackHuawei,
		productconfigs.VendorPackNokia,
	}
	cfg.Radius.RoutePolicy = config.RadiusRoutePolicyConfig{
		Enabled:        true,
		FailClosed:     true,
		MaxRoutes:      8,
		DefaultVRF:     "default",
		DefaultOwner:   "aegisnas",
		ConflictMode:   "block",
		StopWithdrawal: true,
		VRFs: []config.RadiusVRFConfig{
			{Name: "corp", RouteDistinguisher: "65000:10"},
		},
		RolePolicies: []config.RadiusRouteRolePolicy{
			{
				Role:  "branch-vpn",
				VRF:   "corp",
				Owner: "network-team",
				IPv4Routes: []config.RadiusRouteConfig{
					{Destination: "10.80.0.0/16", Gateway: "192.0.2.1", Metric: 10},
				},
				IPv6Routes: []config.RadiusRouteConfig{
					{Destination: "2001:db8:80::/48", Gateway: "2001:db8::1", Metric: 20},
				},
				VendorPacks: []string{productconfigs.VendorPackStandard, productconfigs.VendorPackAegisNAS, productconfigs.VendorPackCisco},
			},
		},
	}

	compileRec := httptest.NewRecorder()
	HandleCompileRoutePolicy(compileRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/route-policy/compile", bytes.NewBufferString(`{
		"role": "branch-vpn",
		"session_id": "session-1",
		"acct_session_id": "acct-1",
		"calling_station_id": "aa:bb:cc:dd:ee:ff",
		"nas_identifier": "bng-01",
		"pack_keys": ["standard", "aegisnas", "cisco", "juniper", "huawei", "nokia"]
	}`)))
	require.Equal(t, http.StatusOK, compileRec.Code, compileRec.Body.String())
	var compilePayload struct {
		EventID string `json:"event_id"`
		Result  struct {
			Status      string                         `json:"status"`
			Decision    radius.RoutePolicyDecision     `json:"decision"`
			Attributes  []radius.RoutePolicyAttribute  `json:"attributes"`
			Diagnostics []radius.RoutePolicyDiagnostic `json:"diagnostics"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal(compileRec.Body.Bytes(), &compilePayload))
	assert.NotEmpty(t, compilePayload.EventID)
	assert.Equal(t, "compiled", compilePayload.Result.Status)
	assert.Equal(t, "corp", compilePayload.Result.Decision.VRF)
	assert.Equal(t, "network-team", compilePayload.Result.Decision.Owner)
	assert.Len(t, compilePayload.Result.Decision.IPv4Routes, 1)
	assert.Len(t, compilePayload.Result.Decision.IPv6Routes, 1)
	assertRoutePolicyAPIAttribute(t, compilePayload.Result.Attributes, productconfigs.VendorPackStandard, "Framed-Route")
	assertRoutePolicyAPIAttribute(t, compilePayload.Result.Attributes, productconfigs.VendorPackAegisNAS, "AegisNAS-VRF")
	assertRoutePolicyAPIAttribute(t, compilePayload.Result.Attributes, productconfigs.VendorPackCisco, "Cisco-AVPair")

	previewRec := httptest.NewRecorder()
	HandlePreviewRoutePolicy(previewRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/route-policy/preview", bytes.NewBufferString(`{
		"role": "branch-vpn",
		"lifecycle_action": "accounting-stop",
		"pack_keys": ["aegisnas", "cisco"]
	}`)))
	require.Equal(t, http.StatusOK, previewRec.Code, previewRec.Body.String())
	assert.Contains(t, previewRec.Body.String(), `"status":"compiled"`)
	assert.Contains(t, previewRec.Body.String(), `"withdraw":true`)

	decompileRec := httptest.NewRecorder()
	HandleDecompileRoutePolicy(decompileRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/route-policy/decompile", bytes.NewBufferString(`{
		"pack_key": "aegisnas",
		"role": "branch-vpn",
		"attributes": [
			{"pack_key":"aegisnas","name":"AegisNAS-VRF","value":"corp"},
			{"pack_key":"aegisnas","name":"AegisNAS-Route-Owner","value":"network-team"},
			{"pack_key":"aegisnas","name":"AegisNAS-Framed-Route","value":"10.80.0.0/16 192.0.2.1 10"},
			{"pack_key":"aegisnas","name":"AegisNAS-Framed-IPv6-Route","value":"2001:db8:80::/48 2001:db8::1 20"}
		]
	}`)))
	require.Equal(t, http.StatusOK, decompileRec.Code, decompileRec.Body.String())
	assert.Contains(t, decompileRec.Body.String(), `"status":"decompiled"`)
	assert.Contains(t, decompileRec.Body.String(), `"vrf":"corp"`)

	getRec := httptest.NewRecorder()
	HandleGetRoutePolicy(getRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/route-policy", nil))
	require.Equal(t, http.StatusOK, getRec.Code, getRec.Body.String())
	assert.Contains(t, getRec.Body.String(), `"compiler_version":1`)
	assert.Contains(t, getRec.Body.String(), `"policy_count":1`)
	assert.Contains(t, getRec.Body.String(), `"total_events":3`)
	assert.Contains(t, getRec.Body.String(), `"active_routes":2`)

	historyRec := httptest.NewRecorder()
	HandleListRoutePolicyHistory(historyRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/route-policy/history?limit=2", nil))
	require.Equal(t, http.StatusOK, historyRec.Code, historyRec.Body.String())
	assert.Contains(t, historyRec.Body.String(), `"compiled_count":1`)
	assert.Contains(t, historyRec.Body.String(), `"previewed_count":1`)
	assert.Contains(t, historyRec.Body.String(), `"decompiled_count":1`)
	assert.Contains(t, historyRec.Body.String(), `"ownership"`)

	readiness := buildProductionReadinessReport(cfg)
	assert.Equal(t, "passed", productionReadinessCheckStatus(readiness.Checks, "per_session_route_vrf_policy"))

	spec := buildOpenAPISpec(httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil), cfg)
	paths := spec["paths"].(map[string]any)
	for _, path := range []string{
		"/api/v1/system/route-policy",
		"/api/v1/system/route-policy/preview",
		"/api/v1/system/route-policy/compile",
		"/api/v1/system/route-policy/decompile",
		"/api/v1/system/route-policy/history",
	} {
		_, ok := paths[path]
		assert.True(t, ok, "OpenAPI path %s should exist", path)
	}

	foundStatusCapture := false
	foundHistoryCapture := false
	for _, capture := range supportBundleAPICaptures() {
		if capture.archivePath == "api/route-policy.json" {
			foundStatusCapture = true
		}
		if capture.archivePath == "api/route-policy-history.json" {
			foundHistoryCapture = true
		}
	}
	assert.True(t, foundStatusCapture)
	assert.True(t, foundHistoryCapture)

	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/route-policy"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/route-policy/preview"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/route-policy/compile"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/route-policy/compile"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/route-policy/decompile"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/route-policy/history"))
}

func assertRoutePolicyAPIAttribute(t *testing.T, attrs []radius.RoutePolicyAttribute, packKey, name string) {
	t.Helper()
	for _, attr := range attrs {
		if attr.PackKey == packKey && attr.Name == name {
			return
		}
	}
	t.Fatalf("attribute %s/%s not found in %#v", packKey, name, attrs)
}
