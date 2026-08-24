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

func TestVendorMappingCertificationAPIHistoryOpenAPIReadinessSupportBundleAndRBAC(t *testing.T) {
	prepareRuntimeQoSAPITestRuntime(t)

	statusRec := httptest.NewRecorder()
	HandleGetVendorMappingCertification(statusRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/vendor-mapping-certification?history_limit=5", nil))
	require.Equal(t, http.StatusOK, statusRec.Code, statusRec.Body.String())
	var statusPayload struct {
		Report struct {
			Summary productconfigs.VendorMappingCertificationSummary  `json:"summary"`
			Records []productconfigs.VendorMappingCertificationRecord `json:"records"`
		} `json:"report"`
		ReleaseCertificationChecklist string `json:"release_certification_checklist"`
	}
	require.NoError(t, json.Unmarshal(statusRec.Body.Bytes(), &statusPayload))
	assert.Equal(t, productconfigs.VendorMappingCertificationBaselineCount, statusPayload.Report.Summary.BaselinePartialMappings)
	assert.Equal(t, productconfigs.VendorMappingCertificationBaselineCount, statusPayload.Report.Summary.CertifiedMappings)
	assert.Equal(t, productconfigs.VendorMappingCertificationBaselineCount, statusPayload.Report.Summary.ExternalRequiredMappings)
	assert.Equal(t, "docs/nas-0060-release-certification-checklist.md", statusPayload.ReleaseCertificationChecklist)
	require.Len(t, statusPayload.Report.Records, productconfigs.VendorMappingCertificationBaselineCount)

	recordRec := httptest.NewRecorder()
	HandleRecordVendorMappingCertification(recordRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/vendor-mapping-certification/record", nil))
	require.Equal(t, http.StatusOK, recordRec.Code, recordRec.Body.String())
	var recordPayload struct {
		EventID string `json:"event_id"`
		Status  string `json:"status"`
	}
	require.NoError(t, json.Unmarshal(recordRec.Body.Bytes(), &recordPayload))
	assert.NotEmpty(t, recordPayload.EventID)
	assert.Equal(t, "recorded", recordPayload.Status)

	historyRec := httptest.NewRecorder()
	HandleListVendorMappingCertificationHistory(historyRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/vendor-mapping-certification/history?limit=5", nil))
	require.Equal(t, http.StatusOK, historyRec.Code, historyRec.Body.String())
	assert.Contains(t, historyRec.Body.String(), `"total_events":1`)
	assert.Contains(t, historyRec.Body.String(), `"certified_mappings":141`)

	readiness := buildProductionReadinessReport(config.Get())
	assert.Equal(t, "passed", productionReadinessCheckStatus(readiness.Checks, "vendor_mapping_certification"))

	spec := buildOpenAPISpec(httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil), nil)
	paths := spec["paths"].(map[string]any)
	for _, path := range []string{
		"/api/v1/system/vendor-mapping-certification",
		"/api/v1/system/vendor-mapping-certification/record",
		"/api/v1/system/vendor-mapping-certification/history",
	} {
		_, ok := paths[path]
		assert.True(t, ok, "OpenAPI path %s should exist", path)
	}

	foundReportCapture := false
	foundHistoryCapture := false
	for _, capture := range supportBundleAPICaptures() {
		if capture.archivePath == "api/vendor-mapping-certification.json" {
			foundReportCapture = true
		}
		if capture.archivePath == "api/vendor-mapping-certification-history.json" {
			foundHistoryCapture = true
		}
	}
	assert.True(t, foundReportCapture)
	assert.True(t, foundHistoryCapture)

	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/vendor-mapping-certification"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/vendor-mapping-certification/history"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/vendor-mapping-certification/record"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/vendor-mapping-certification/record"))
}
