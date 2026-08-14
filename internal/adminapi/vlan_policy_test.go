package adminapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/radius"
)

func TestVLANPolicyAPIReadinessOpenAPISupportBundleAndRBAC(t *testing.T) {
	prepareRuntimeQoSAPITestRuntime(t)
	cfg := config.Get()
	cfg.Radius.Vendor.CompatibilityPacks = []string{"standard", "aegisnas", "extreme", "hp"}
	cfg.Radius.VLANPolicy = config.RadiusVLANPolicyConfig{
		Enabled:             true,
		FailClosed:          true,
		MaxTaggedVLANs:      10,
		DefaultFallbackVLAN: 99,
		Pools: []config.RadiusVLANPoolConfig{
			{Name: "branch-data", VLANs: []int{21, 22}, Strategy: "hash-calling-station"},
		},
		RolePolicies: []config.RadiusVLANRolePolicy{
			{
				Role:         "voice-device",
				Pool:         "branch-data",
				VoiceVLAN:    30,
				TaggedVLANs:  []int{40},
				FallbackVLAN: 99,
				AuthFailVLAN: 98,
				QinQ: config.RadiusQinQConfig{
					Enabled:   true,
					OuterVLAN: 3000,
					InnerVLAN: 21,
					Mode:      "provider-bridge",
				},
				VendorPacks: []string{"standard", "aegisnas", "extreme", "hp"},
			},
		},
	}

	compileRec := httptest.NewRecorder()
	HandleCompileVLANPolicy(compileRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/vlan-policy/compile", bytes.NewBufferString(`{
		"role": "voice-device",
		"calling_station_id": "aa:bb:cc:dd:ee:ff",
		"nas_identifier": "branch-ap-01"
	}`)))
	require.Equal(t, http.StatusOK, compileRec.Code, compileRec.Body.String())
	var compilePayload struct {
		EventID string `json:"event_id"`
		Result  struct {
			Status      string                        `json:"status"`
			Decision    radius.VLANPolicyDecision     `json:"decision"`
			Attributes  []radius.VLANPolicyAttribute  `json:"attributes"`
			Diagnostics []radius.VLANPolicyDiagnostic `json:"diagnostics"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal(compileRec.Body.Bytes(), &compilePayload))
	assert.NotEmpty(t, compilePayload.EventID)
	assert.Equal(t, "compiled", compilePayload.Result.Status)
	assert.Equal(t, "pool", compilePayload.Result.Decision.AssignmentMode)
	assert.Equal(t, "branch-data", compilePayload.Result.Decision.PoolName)
	assert.Contains(t, []int{21, 22}, compilePayload.Result.Decision.EffectiveVLAN)
	assert.Equal(t, 30, compilePayload.Result.Decision.VoiceVLAN)
	assert.Equal(t, []int{40}, compilePayload.Result.Decision.TaggedVLANs)
	assert.True(t, compilePayload.Result.Decision.QinQEnabled)
	assert.Empty(t, compilePayload.Result.Diagnostics)
	assertVLANPolicyAPIAttribute(t, compilePayload.Result.Attributes, "standard", "Egress-VLANID")
	assertVLANPolicyAPIAttribute(t, compilePayload.Result.Attributes, "aegisnas", "AegisNAS-QinQ-Outer-VLAN")
	assertVLANPolicyAPIAttribute(t, compilePayload.Result.Attributes, "extreme", "Extreme-Netlogin-Extended-Vlan")

	previewRec := httptest.NewRecorder()
	HandlePreviewVLANPolicy(previewRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/vlan-policy/preview", bytes.NewBufferString(`{
		"role": "voice-device",
		"auth_failed": true
	}`)))
	require.Equal(t, http.StatusOK, previewRec.Code, previewRec.Body.String())
	assert.Contains(t, previewRec.Body.String(), `"status":"compiled"`)
	assert.Contains(t, previewRec.Body.String(), `"assignment_mode":"auth-fail"`)

	decompileRec := httptest.NewRecorder()
	HandleDecompileVLANPolicy(decompileRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/vlan-policy/decompile", bytes.NewBufferString(`{
		"pack_key": "aegisnas",
		"role": "voice-device",
		"attributes": [
			{"pack_key":"aegisnas","name":"AegisNAS-Data-VLAN","value":"21"},
			{"pack_key":"aegisnas","name":"AegisNAS-Voice-VLAN","value":"30"},
			{"pack_key":"aegisnas","name":"AegisNAS-Tagged-VLAN","value":"40"},
			{"pack_key":"aegisnas","name":"AegisNAS-QinQ-Outer-VLAN","value":"3000"},
			{"pack_key":"aegisnas","name":"AegisNAS-QinQ-Inner-VLAN","value":"21"}
		]
	}`)))
	require.Equal(t, http.StatusOK, decompileRec.Code, decompileRec.Body.String())
	assert.Contains(t, decompileRec.Body.String(), `"status":"decompiled"`)
	assert.Contains(t, decompileRec.Body.String(), `"voice_vlan":30`)

	getRec := httptest.NewRecorder()
	HandleGetVLANPolicy(getRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/vlan-policy", nil))
	require.Equal(t, http.StatusOK, getRec.Code, getRec.Body.String())
	assert.Contains(t, getRec.Body.String(), `"compiler_version":1`)
	assert.Contains(t, getRec.Body.String(), `"policy_count":1`)
	assert.Contains(t, getRec.Body.String(), `"total_events":3`)

	historyRec := httptest.NewRecorder()
	HandleListVLANPolicyHistory(historyRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/vlan-policy/history?limit=2", nil))
	require.Equal(t, http.StatusOK, historyRec.Code, historyRec.Body.String())
	assert.Contains(t, historyRec.Body.String(), `"compiled_count":1`)
	assert.Contains(t, historyRec.Body.String(), `"previewed_count":1`)
	assert.Contains(t, historyRec.Body.String(), `"decompiled_count":1`)

	readiness := buildProductionReadinessReport(cfg)
	assert.Equal(t, "passed", productionReadinessCheckStatus(readiness.Checks, "tagged_vlan_qinq_policy"))

	spec := buildOpenAPISpec(httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil), cfg)
	paths := spec["paths"].(map[string]any)
	for _, path := range []string{
		"/api/v1/system/vlan-policy",
		"/api/v1/system/vlan-policy/preview",
		"/api/v1/system/vlan-policy/compile",
		"/api/v1/system/vlan-policy/decompile",
		"/api/v1/system/vlan-policy/history",
	} {
		_, ok := paths[path]
		assert.True(t, ok, "OpenAPI path %s should exist", path)
	}

	foundStatusCapture := false
	foundHistoryCapture := false
	for _, capture := range supportBundleAPICaptures() {
		if capture.archivePath == "api/vlan-policy.json" {
			foundStatusCapture = true
		}
		if capture.archivePath == "api/vlan-policy-history.json" {
			foundHistoryCapture = true
		}
	}
	assert.True(t, foundStatusCapture)
	assert.True(t, foundHistoryCapture)

	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/vlan-policy"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/vlan-policy/preview"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/vlan-policy/compile"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/vlan-policy/decompile"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/vlan-policy/history"))
}

func assertVLANPolicyAPIAttribute(t *testing.T, attrs []radius.VLANPolicyAttribute, packKey, name string) {
	t.Helper()
	for _, attr := range attrs {
		if attr.PackKey == packKey && attr.Name == name {
			return
		}
	}
	t.Fatalf("attribute %s/%s not found in %#v", packKey, name, attrs)
}
