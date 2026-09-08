package adminapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

func TestExternalVendorIntakeAPIHistoryOpenAPIReadinessSupportBundleAndRBAC(t *testing.T) {
	prepareRuntimeQoSAPITestRuntime(t)

	statusRec := httptest.NewRecorder()
	HandleGetExternalVendorIntake(statusRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/external-vendor-intake?history_limit=5", nil))
	require.Equal(t, http.StatusOK, statusRec.Code, statusRec.Body.String())
	var statusPayload struct {
		Governance struct {
			FeatureID                     string   `json:"feature_id"`
			Status                        string   `json:"status"`
			RequiredProvenanceFields      []string `json:"required_provenance_fields"`
			SupportedDictionaryDirectives []string `json:"supported_dictionary_directives"`
			SupportedWireTypes            []string `json:"supported_wire_types"`
		} `json:"governance"`
		ReleaseCertificationChecklist string `json:"release_certification_checklist"`
	}
	require.NoError(t, json.Unmarshal(statusRec.Body.Bytes(), &statusPayload))
	assert.Equal(t, productconfigs.ExternalVendorIntakeFeatureID, statusPayload.Governance.FeatureID)
	assert.Equal(t, productconfigs.ExternalVendorIntakeSoftwareReady, statusPayload.Governance.Status)
	assert.Contains(t, statusPayload.Governance.RequiredProvenanceFields, "source_sha256")
	assert.Contains(t, statusPayload.Governance.SupportedDictionaryDirectives, "ATTRIBUTE")
	assert.Contains(t, statusPayload.Governance.SupportedWireTypes, "integer")
	assert.Equal(t, "docs/nas-0073-release-certification-checklist.md", statusPayload.ReleaseCertificationChecklist)

	validBody := mustJSON(t, externalVendorIntakeAPIFixtureRequest())
	previewRec := httptest.NewRecorder()
	HandlePreviewExternalVendorIntake(previewRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/external-vendor-intake/preview", bytes.NewReader(validBody)))
	require.Equal(t, http.StatusOK, previewRec.Code, previewRec.Body.String())
	var previewPayload struct {
		Status string                                    `json:"status"`
		Report productconfigs.ExternalVendorIntakeReport `json:"report"`
	}
	require.NoError(t, json.Unmarshal(previewRec.Body.Bytes(), &previewPayload))
	assert.Equal(t, productconfigs.ExternalVendorIntakeSoftwareReady, previewPayload.Status)
	assert.Equal(t, "Ubiquiti", previewPayload.Report.Vendor.CanonicalName)
	assert.Equal(t, 4, previewPayload.Report.Summary.SoftwareReadyAttributes)
	assert.NotContains(t, previewRec.Body.String(), "dictionary_text")

	recordRec := httptest.NewRecorder()
	HandleRecordExternalVendorIntake(recordRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/external-vendor-intake/record", bytes.NewReader(validBody)))
	require.Equal(t, http.StatusOK, recordRec.Code, recordRec.Body.String())
	var recordPayload struct {
		EventID string `json:"event_id"`
		Status  string `json:"status"`
	}
	require.NoError(t, json.Unmarshal(recordRec.Body.Bytes(), &recordPayload))
	assert.Contains(t, recordPayload.EventID, "nas-0073-")
	assert.Equal(t, "recorded", recordPayload.Status)

	blocked := externalVendorIntakeAPIFixtureRequest()
	blocked.SourceSHA256 = strings.Repeat("0", 64)
	blockedRec := httptest.NewRecorder()
	HandleRecordExternalVendorIntake(blockedRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/external-vendor-intake/record", bytes.NewReader(mustJSON(t, blocked))))
	require.Equal(t, http.StatusConflict, blockedRec.Code, blockedRec.Body.String())
	assert.Contains(t, blockedRec.Body.String(), "source_sha256")

	historyRec := httptest.NewRecorder()
	HandleListExternalVendorIntakeHistory(historyRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/external-vendor-intake/history?limit=5", nil))
	require.Equal(t, http.StatusOK, historyRec.Code, historyRec.Body.String())
	assert.Contains(t, historyRec.Body.String(), `"total_events":2`)
	assert.Contains(t, historyRec.Body.String(), `"recorded_count":1`)
	assert.Contains(t, historyRec.Body.String(), `"blocked_count":1`)

	readiness := buildProductionReadinessReport(config.Get())
	assert.Equal(t, "passed", productionReadinessCheckStatus(readiness.Checks, "external_vendor_intake"))

	spec := buildOpenAPISpec(httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil), nil)
	paths := spec["paths"].(map[string]any)
	for _, path := range []string{
		"/api/v1/system/external-vendor-intake",
		"/api/v1/system/external-vendor-intake/preview",
		"/api/v1/system/external-vendor-intake/record",
		"/api/v1/system/external-vendor-intake/history",
	} {
		_, ok := paths[path]
		assert.True(t, ok, "OpenAPI path %s should exist", path)
	}

	foundReportCapture := false
	foundHistoryCapture := false
	for _, capture := range supportBundleAPICaptures() {
		if capture.archivePath == "api/external-vendor-intake.json" {
			foundReportCapture = true
		}
		if capture.archivePath == "api/external-vendor-intake-history.json" {
			foundHistoryCapture = true
		}
	}
	assert.True(t, foundReportCapture)
	assert.True(t, foundHistoryCapture)

	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/external-vendor-intake"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/external-vendor-intake/history"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/external-vendor-intake/preview"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/external-vendor-intake/record"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/external-vendor-intake/preview"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/external-vendor-intake/record"))
}

func externalVendorIntakeAPIFixtureRequest() productconfigs.ExternalVendorIntakeRequest {
	dictionary := `
VENDOR Ubiquiti 41112
BEGIN-VENDOR Ubiquiti
ATTRIBUTE UBNT-Data-Rate-DL 1 integer
ATTRIBUTE UBNT-Data-Rate-UL 3 integer
ATTRIBUTE UBNT-User-Role 10 string
ATTRIBUTE UBNT-PSK 11 octets
VALUE UBNT-User-Role guest 1
VALUE UBNT-User-Role employee 2
END-VENDOR Ubiquiti
`
	return productconfigs.ExternalVendorIntakeRequest{
		VendorName:       "UBNT",
		PEN:              41112,
		IntendedPackKey:  "ubnt",
		ProductFamilies:  []string{"UniFi Network"},
		DictionaryName:   "dictionary.ubnt",
		DictionaryText:   dictionary,
		SourceURL:        "https://ui.com/download/dictionary.ubnt",
		SourceSHA256:     externalVendorIntakeAPISHA(dictionary),
		LicenseID:        "Proprietary-Allowed-With-Grant",
		LicenseReference: "https://ui.com/legal",
		UpstreamVersion:  "unifi-network-9",
		RetrievedAt:      "2026-09-08T00:00:00Z",
		Submitter:        "ops",
	}
}

func externalVendorIntakeAPISHA(value string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return hex.EncodeToString(sum[:])
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	payload, err := json.Marshal(value)
	require.NoError(t, err)
	return payload
}
