package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
)

func TestHandleGetCompatibilityEvidenceFiltersAndPaginates(t *testing.T) {
	response := httptest.NewRecorder()
	HandleGetCompatibilityEvidence(response, httptest.NewRequest(http.MethodGet, "/api/v1/system/compatibility-evidence?claim=software_ready_external_required&limit=2", nil))
	require.Equal(t, http.StatusOK, response.Code)

	var first compatibilityEvidenceResponse
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &first))
	assert.Equal(t, productconfigs.CompatibilityEvidenceSchemaVersion, first.SchemaVersion)
	assert.Equal(t, productconfigs.DefaultDictionaryReleaseProfileID, first.ReleaseProfileID)
	assert.Greater(t, first.Summary.TotalRecords, 100)
	assert.Greater(t, first.Summary.ExternalRequiredCount, 0)
	assert.GreaterOrEqual(t, first.FilteredCount, len(first.Records))
	require.NotEmpty(t, first.Records)
	for _, record := range first.Records {
		assert.Equal(t, productconfigs.EvidenceClaimSoftwareReadyExternalNeeded, record.ClaimState)
		assert.Equal(t, productconfigs.EvidenceCertificationRequired, record.CertificationState)
	}

	if first.NextCursor != "" {
		response = httptest.NewRecorder()
		HandleGetCompatibilityEvidence(response, httptest.NewRequest(http.MethodGet, "/api/v1/system/compatibility-evidence?claim=software_ready_external_required&limit=2&cursor="+first.NextCursor, nil))
		require.Equal(t, http.StatusOK, response.Code)
		var second compatibilityEvidenceResponse
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &second))
		require.NotEmpty(t, second.Records)
		assert.NotEqual(t, first.Records[0].ID, second.Records[0].ID)
	}
}

func TestHandleGetCompatibilityEvidenceRejectsInvalidQueries(t *testing.T) {
	for _, target := range []string{
		"/api/v1/system/compatibility-evidence?limit=501",
		"/api/v1/system/compatibility-evidence?software_state=done",
		"/api/v1/system/compatibility-evidence?certification_state=trusted",
		"/api/v1/system/compatibility-evidence?claim=certified",
		"/api/v1/system/compatibility-evidence?cursor=not-base64",
	} {
		response := httptest.NewRecorder()
		HandleGetCompatibilityEvidence(response, httptest.NewRequest(http.MethodGet, target, nil))
		assert.Equal(t, http.StatusBadRequest, response.Code, target)
	}
}
