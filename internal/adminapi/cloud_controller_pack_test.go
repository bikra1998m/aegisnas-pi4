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

func TestCloudControllerPackAPIHistoryOpenAPIReadinessSupportBundleAndRBAC(t *testing.T) {
	prepareRuntimeQoSAPITestRuntime(t)

	statusRec := httptest.NewRecorder()
	HandleGetCloudControllerPack(statusRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/cloud-controller-pack?history_limit=5", nil))
	require.Equal(t, http.StatusOK, statusRec.Code, statusRec.Body.String())
	var statusPayload struct {
		Report struct {
			Summary       productconfigs.CloudControllerPackSummary       `json:"summary"`
			Records       []productconfigs.CloudControllerAttributeRecord `json:"records"`
			Grammar       []productconfigs.CloudControllerGrammarRecord   `json:"grammar"`
			ProductScopes []productconfigs.CloudControllerProductScope    `json:"product_scopes"`
		} `json:"report"`
		ReleaseCertificationChecklist string `json:"release_certification_checklist"`
	}
	require.NoError(t, json.Unmarshal(statusRec.Body.Bytes(), &statusPayload))
	assert.Equal(t, productconfigs.CloudControllerPackExpectedAttributeCount, statusPayload.Report.Summary.AttributeCount)
	assert.Equal(t, productconfigs.CloudControllerPackExpectedAttributeCount, statusPayload.Report.Summary.SoftwareCertifiedMappings)
	assert.Equal(t, productconfigs.CloudControllerPackExpectedAttributeCount, statusPayload.Report.Summary.ExternalRequiredMappings)
	assert.Equal(t, "docs/nas-0066-release-certification-checklist.md", statusPayload.ReleaseCertificationChecklist)
	require.Len(t, statusPayload.Report.Records, productconfigs.CloudControllerPackExpectedAttributeCount)
	require.NotEmpty(t, statusPayload.Report.Grammar)
	require.GreaterOrEqual(t, len(statusPayload.Report.ProductScopes), 8)

	recordRec := httptest.NewRecorder()
	HandleRecordCloudControllerPack(recordRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/cloud-controller-pack/record", nil))
	require.Equal(t, http.StatusOK, recordRec.Code, recordRec.Body.String())
	var recordPayload struct {
		EventID string `json:"event_id"`
		Status  string `json:"status"`
	}
	require.NoError(t, json.Unmarshal(recordRec.Body.Bytes(), &recordPayload))
	assert.Contains(t, recordPayload.EventID, "nas-0066-")
	assert.Equal(t, "recorded", recordPayload.Status)

	historyRec := httptest.NewRecorder()
	HandleListCloudControllerPackHistory(historyRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/cloud-controller-pack/history?limit=5", nil))
	require.Equal(t, http.StatusOK, historyRec.Code, historyRec.Body.String())
	assert.Contains(t, historyRec.Body.String(), `"total_events":1`)
	assert.Contains(t, historyRec.Body.String(), `"software_certified_mappings":7`)

	readiness := buildProductionReadinessReport(config.Get())
	assert.Equal(t, "passed", productionReadinessCheckStatus(readiness.Checks, "cloud_controller_pack"))

	spec := buildOpenAPISpec(httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil), nil)
	paths := spec["paths"].(map[string]any)
	for _, path := range []string{
		"/api/v1/system/cloud-controller-pack",
		"/api/v1/system/cloud-controller-pack/record",
		"/api/v1/system/cloud-controller-pack/history",
	} {
		_, ok := paths[path]
		assert.True(t, ok, "OpenAPI path %s should exist", path)
	}

	foundReportCapture := false
	foundHistoryCapture := false
	for _, capture := range supportBundleAPICaptures() {
		if capture.archivePath == "api/cloud-controller-pack.json" {
			foundReportCapture = true
		}
		if capture.archivePath == "api/cloud-controller-pack-history.json" {
			foundHistoryCapture = true
		}
	}
	assert.True(t, foundReportCapture)
	assert.True(t, foundHistoryCapture)

	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/cloud-controller-pack"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/cloud-controller-pack/history"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/cloud-controller-pack/record"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/cloud-controller-pack/record"))
}
