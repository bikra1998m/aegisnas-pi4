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

func TestTranslationPolicyAPIReadinessOpenAPISupportBundleAndRBAC(t *testing.T) {
	prepareRuntimeQoSAPITestRuntime(t)
	cfg := config.Get()
	cfg.Radius.Vendor.CompatibilityPacks = []string{
		productconfigs.VendorPackAegisNAS,
		productconfigs.VendorPackCisco,
		productconfigs.VendorPackJuniper,
		productconfigs.VendorPackHuawei,
		productconfigs.VendorPackH3C,
		productconfigs.VendorPackNokia,
		productconfigs.VendorPackStarent,
		productconfigs.VendorPackERX,
	}
	cfg.Radius.TranslationPolicy = config.RadiusTranslationPolicyConfig{
		Enabled:               true,
		FailClosed:            true,
		MaxMappings:           16,
		DefaultOwner:          "aegisnas",
		ConflictMode:          "block",
		StopWithdrawal:        true,
		AllocationMode:        "deterministic",
		DefaultPortBlockSize:  512,
		MinPort:               10000,
		MaxPort:               12047,
		DefaultNAT64Prefix:    "64:ff9b::/96",
		LoggingRequired:       true,
		AccountingCorrelation: true,
		Pools: []config.RadiusTranslationPoolConfig{
			{Name: "cgnat-public", Family: "ipv4", CIDR: "198.51.100.0/29", Start: "198.51.100.2", End: "198.51.100.6", PortStart: 10000, PortEnd: 12047, PortBlockSize: 512, Mode: "cgnat"},
		},
		RolePolicies: []config.RadiusTranslationRolePolicy{
			{
				Role:                  "branch-dualstack",
				Owner:                 "nat-team",
				TranslationMode:       "dual-stack",
				PublicPool:            "cgnat-public",
				PrivateIPv4Prefix:     "100.64.1.0/24",
				SubscriberIPv6Prefix:  "2001:db8:57::/64",
				NAT64Prefix:           "64:ff9b::/96",
				PortBlockSize:         512,
				LoggingProfile:        "lawful-cgnat",
				AccountingCorrelation: true,
				VendorPacks:           []string{productconfigs.VendorPackAegisNAS, productconfigs.VendorPackCisco, productconfigs.VendorPackStarent},
			},
		},
	}

	compileRec := httptest.NewRecorder()
	HandleCompileTranslationPolicy(compileRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/translation-policy/compile", bytes.NewBufferString(`{
		"role": "branch-dualstack",
		"session_id": "session-1",
		"acct_session_id": "acct-1",
		"calling_station_id": "aa:bb:cc:dd:ee:ff",
		"nas_identifier": "bng-01",
		"pack_keys": ["aegisnas", "cisco", "juniper", "huawei", "h3c", "nokia", "starent", "erx"]
	}`)))
	require.Equal(t, http.StatusOK, compileRec.Code, compileRec.Body.String())
	var compilePayload struct {
		EventID string `json:"event_id"`
		Result  struct {
			Status      string                               `json:"status"`
			Decision    radius.TranslationPolicyDecision     `json:"decision"`
			Attributes  []radius.TranslationPolicyAttribute  `json:"attributes"`
			Diagnostics []radius.TranslationPolicyDiagnostic `json:"diagnostics"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal(compileRec.Body.Bytes(), &compilePayload))
	assert.NotEmpty(t, compilePayload.EventID)
	assert.Equal(t, "compiled", compilePayload.Result.Status)
	assert.Equal(t, "nat-team", compilePayload.Result.Decision.Owner)
	assert.Equal(t, "dual-stack", compilePayload.Result.Decision.TranslationMode)
	assert.Equal(t, "cgnat-public", compilePayload.Result.Decision.PublicPool)
	assert.NotEmpty(t, compilePayload.Result.Decision.PublicIPv4)
	assert.NotEmpty(t, compilePayload.Result.Decision.AccountingKey)
	assertTranslationPolicyAPIAttribute(t, compilePayload.Result.Attributes, productconfigs.VendorPackAegisNAS, "AegisNAS-Translation-NAT64-Prefix")
	assertTranslationPolicyAPIAttribute(t, compilePayload.Result.Attributes, productconfigs.VendorPackCisco, "Cisco-AVPair")
	assertTranslationPolicyAPIAttribute(t, compilePayload.Result.Attributes, productconfigs.VendorPackStarent, "SN-NAT-IP-Address")

	previewRec := httptest.NewRecorder()
	HandlePreviewTranslationPolicy(previewRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/translation-policy/preview", bytes.NewBufferString(`{
		"role": "branch-dualstack",
		"lifecycle_action": "accounting-stop",
		"pack_keys": ["aegisnas", "cisco"]
	}`)))
	require.Equal(t, http.StatusOK, previewRec.Code, previewRec.Body.String())
	assert.Contains(t, previewRec.Body.String(), `"status":"compiled"`)
	assert.Contains(t, previewRec.Body.String(), `"withdraw":true`)

	decompileRec := httptest.NewRecorder()
	HandleDecompileTranslationPolicy(decompileRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/translation-policy/decompile", bytes.NewBufferString(`{
		"pack_key": "aegisnas",
		"role": "branch-dualstack",
		"attributes": [
			{"pack_key":"aegisnas","name":"AegisNAS-Translation-Owner","value":"nat-team"},
			{"pack_key":"aegisnas","name":"AegisNAS-Translation-Mode","value":"dual-stack"},
			{"pack_key":"aegisnas","name":"AegisNAS-Translation-Public-IPv4-Pool","value":"cgnat-public"},
			{"pack_key":"aegisnas","name":"AegisNAS-Translation-Public-IPv4-Address","value":"198.51.100.2"},
			{"pack_key":"aegisnas","name":"AegisNAS-Translation-NAT64-Prefix","value":"64:ff9b::/96"},
			{"pack_key":"aegisnas","name":"AegisNAS-Translation-Port-Block-Start","value":"10000"},
			{"pack_key":"aegisnas","name":"AegisNAS-Translation-Port-Block-End","value":"10511"}
		]
	}`)))
	require.Equal(t, http.StatusOK, decompileRec.Code, decompileRec.Body.String())
	assert.Contains(t, decompileRec.Body.String(), `"status":"decompiled"`)
	assert.Contains(t, decompileRec.Body.String(), `"owner":"nat-team"`)

	getRec := httptest.NewRecorder()
	HandleGetTranslationPolicy(getRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/translation-policy", nil))
	require.Equal(t, http.StatusOK, getRec.Code, getRec.Body.String())
	assert.Contains(t, getRec.Body.String(), `"compiler_version":1`)
	assert.Contains(t, getRec.Body.String(), `"pool_count":1`)
	assert.Contains(t, getRec.Body.String(), `"total_events":3`)
	assert.Contains(t, getRec.Body.String(), `"active_mappings":1`)

	historyRec := httptest.NewRecorder()
	HandleListTranslationPolicyHistory(historyRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/translation-policy/history?limit=2", nil))
	require.Equal(t, http.StatusOK, historyRec.Code, historyRec.Body.String())
	assert.Contains(t, historyRec.Body.String(), `"compiled_count":1`)
	assert.Contains(t, historyRec.Body.String(), `"previewed_count":1`)
	assert.Contains(t, historyRec.Body.String(), `"decompiled_count":1`)
	assert.Contains(t, historyRec.Body.String(), `"ownership"`)

	readiness := buildProductionReadinessReport(cfg)
	assert.Equal(t, "passed", productionReadinessCheckStatus(readiness.Checks, "cgnat_nat64_deterministic_translation"))

	spec := buildOpenAPISpec(httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil), cfg)
	paths := spec["paths"].(map[string]any)
	for _, path := range []string{
		"/api/v1/system/translation-policy",
		"/api/v1/system/translation-policy/preview",
		"/api/v1/system/translation-policy/compile",
		"/api/v1/system/translation-policy/decompile",
		"/api/v1/system/translation-policy/history",
	} {
		_, ok := paths[path]
		assert.True(t, ok, "OpenAPI path %s should exist", path)
	}

	foundStatusCapture := false
	foundHistoryCapture := false
	for _, capture := range supportBundleAPICaptures() {
		if capture.archivePath == "api/translation-policy.json" {
			foundStatusCapture = true
		}
		if capture.archivePath == "api/translation-policy-history.json" {
			foundHistoryCapture = true
		}
	}
	assert.True(t, foundStatusCapture)
	assert.True(t, foundHistoryCapture)

	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/translation-policy"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/translation-policy/preview"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/translation-policy/compile"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/translation-policy/compile"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/translation-policy/decompile"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/translation-policy/history"))
}

func assertTranslationPolicyAPIAttribute(t *testing.T, attrs []radius.TranslationPolicyAttribute, packKey, name string) {
	t.Helper()
	for _, attr := range attrs {
		if attr.PackKey == packKey && attr.Name == name {
			return
		}
	}
	t.Fatalf("attribute %s/%s not found in %#v", packKey, name, attrs)
}
