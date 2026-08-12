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
)

func TestRateCompilerAPIReadinessOpenAPISupportBundleAndRBAC(t *testing.T) {
	prepareRuntimeQoSAPITestRuntime(t)

	body := bytes.NewBufferString(`{
		"pack_keys": ["mikrotik", "wispr", "ubnt", "huawei", "h3c", "tplink", "zte"],
		"download_rate_kbps": 50000,
		"upload_rate_kbps": 20000,
		"download_burst_rate_kbps": 80000,
		"upload_burst_rate_kbps": 30000,
		"download_burst_threshold_kbps": 40000,
		"upload_burst_threshold_kbps": 10000,
		"download_burst_time_seconds": 10,
		"upload_burst_time_seconds": 10,
		"priority": 3,
		"download_min_rate_kbps": 10000,
		"upload_min_rate_kbps": 5000
	}`)
	compileRec := httptest.NewRecorder()
	HandleCompileRate(compileRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/rate-compiler/compile", body))
	require.Equal(t, http.StatusOK, compileRec.Code, compileRec.Body.String())
	var compilePayload struct {
		EventID string `json:"event_id"`
		Result  struct {
			Status         string `json:"status"`
			AttributeCount int    `json:"attribute_count"`
			Attributes     []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
				Unit  string `json:"unit"`
			} `json:"attributes"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal(compileRec.Body.Bytes(), &compilePayload))
	assert.NotEmpty(t, compilePayload.EventID)
	assert.Equal(t, "ready", compilePayload.Result.Status)
	assert.Equal(t, 13, compilePayload.Result.AttributeCount)
	assert.Contains(t, compileRec.Body.String(), `"Mikrotik-Rate-Limit"`)
	assert.Contains(t, compileRec.Body.String(), `"integer-bps"`)

	decompileRec := httptest.NewRecorder()
	HandleDecompileRate(decompileRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/rate-compiler/decompile", bytes.NewBufferString(`{
		"pack_key": "ubnt",
		"attributes": [
			{"name":"UBNT-Data-Rate-DL","value":"50000000"},
			{"name":"UBNT-Data-Rate-UL","value":"20000000"}
		]
	}`)))
	require.Equal(t, http.StatusOK, decompileRec.Code, decompileRec.Body.String())
	assert.Contains(t, decompileRec.Body.String(), `"download_rate_kbps":50000`)
	assert.Contains(t, decompileRec.Body.String(), `"upload_rate_kbps":20000`)

	getRec := httptest.NewRecorder()
	HandleGetRateCompiler(getRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/rate-compiler", nil))
	require.Equal(t, http.StatusOK, getRec.Code, getRec.Body.String())
	assert.Contains(t, getRec.Body.String(), `"compiler_version":1`)
	assert.Contains(t, getRec.Body.String(), `"compiled_count":1`)
	assert.Contains(t, getRec.Body.String(), `"decompiled_count":1`)

	readiness := buildProductionReadinessReport(config.Get())
	assert.Equal(t, "passed", productionReadinessCheckStatus(readiness.Checks, "vendor_rate_compiler"))

	spec := buildOpenAPISpec(httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil), config.Get())
	paths := spec["paths"].(map[string]any)
	_, hasGet := paths["/api/v1/system/rate-compiler"]
	_, hasCompile := paths["/api/v1/system/rate-compiler/compile"]
	_, hasDecompile := paths["/api/v1/system/rate-compiler/decompile"]
	assert.True(t, hasGet)
	assert.True(t, hasCompile)
	assert.True(t, hasDecompile)

	foundCapture := false
	for _, capture := range supportBundleAPICaptures() {
		if capture.archivePath == "api/rate-compiler.json" {
			foundCapture = true
		}
	}
	assert.True(t, foundCapture)

	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/rate-compiler"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/rate-compiler/compile"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/rate-compiler/decompile"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/rate-compiler/compile"))
}
