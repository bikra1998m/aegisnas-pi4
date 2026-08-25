package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

func TestJuniperExtremePackAPIHistoryOpenAPIReadinessSupportBundleAndRBAC(t *testing.T) {
	prepareRuntimeQoSAPITestRuntime(t)

	statusRec := httptest.NewRecorder()
	HandleGetJuniperExtremePack(statusRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/juniper-extreme-pack?history_limit=5", nil))
	require.Equal(t, http.StatusOK, statusRec.Code)
	var statusPayload struct {
		Report productconfigs.JuniperExtremePackReport `json:"report"`
	}
	require.NoError(t, json.Unmarshal(statusRec.Body.Bytes(), &statusPayload))
	assert.Equal(t, productconfigs.JuniperExtremePackFeatureID, statusPayload.Report.FeatureID)
	assert.Equal(t, productconfigs.JuniperExtremePackExpectedAttributeCount, statusPayload.Report.Summary.AttributeCount)
	assert.Equal(t, productconfigs.JuniperExtremePackExpectedAttributeCount, statusPayload.Report.Summary.SoftwareCertifiedMappings)
	assert.Equal(t, productconfigs.JuniperExtremePackExpectedAttributeCount, statusPayload.Report.Summary.ExternalRequiredMappings)
	assert.Equal(t, 4, statusPayload.Report.Summary.ProductScopeCount)
	require.Len(t, statusPayload.Report.Records, productconfigs.JuniperExtremePackExpectedAttributeCount)

	recordRec := httptest.NewRecorder()
	HandleRecordJuniperExtremePack(recordRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/juniper-extreme-pack/record", nil))
	require.Equal(t, http.StatusOK, recordRec.Code)
	var recordPayload struct {
		EventID string `json:"event_id"`
		Status  string `json:"status"`
	}
	require.NoError(t, json.Unmarshal(recordRec.Body.Bytes(), &recordPayload))
	assert.Contains(t, recordPayload.EventID, "nas-0063-")
	assert.Equal(t, "recorded", recordPayload.Status)

	historyRec := httptest.NewRecorder()
	HandleListJuniperExtremePackHistory(historyRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/juniper-extreme-pack/history?limit=5", nil))
	require.Equal(t, http.StatusOK, historyRec.Code)
	assert.Contains(t, historyRec.Body.String(), recordPayload.EventID)

	openAPI := buildOpenAPISpec(httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil), nil)
	paths := openAPI["paths"].(map[string]any)
	for _, path := range []string{
		"/api/v1/system/juniper-extreme-pack",
		"/api/v1/system/juniper-extreme-pack/record",
		"/api/v1/system/juniper-extreme-pack/history",
	} {
		assert.Contains(t, paths, path)
	}

	readiness := buildProductionReadinessReport(config.Get())
	assert.Equal(t, "passed", productionReadinessCheckStatus(readiness.Checks, "juniper_extreme_pack"))

	captures := supportBundleAPICaptures()
	hasPack := false
	hasHistory := false
	for _, capture := range captures {
		if capture.archivePath == "api/juniper-extreme-pack.json" {
			hasPack = true
		}
		if capture.archivePath == "api/juniper-extreme-pack-history.json" {
			hasHistory = true
		}
	}
	assert.True(t, hasPack)
	assert.True(t, hasHistory)

	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/juniper-extreme-pack"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/juniper-extreme-pack/history"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/juniper-extreme-pack/record"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/juniper-extreme-pack/record"))
}
