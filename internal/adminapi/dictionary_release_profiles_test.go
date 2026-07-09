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

func TestHandleGetDictionaryReleaseProfiles(t *testing.T) {
	response := httptest.NewRecorder()
	HandleGetDictionaryReleaseProfiles(response, httptest.NewRequest(http.MethodGet, "/api/v1/system/dictionary-release-profiles", nil))
	require.Equal(t, http.StatusOK, response.Code)

	var payload dictionaryReleaseProfilesResponse
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &payload))
	assert.Equal(t, productconfigs.DefaultDictionaryReleaseProfileID, payload.DefaultProfileID)
	assert.Equal(t, productconfigs.DefaultDictionaryReleaseProfileID, payload.ActiveProfileID)
	require.Len(t, payload.Profiles, 1)
	assert.Equal(t, "3.2.8", payload.Profiles[0].Release)
	assert.GreaterOrEqual(t, payload.Profiles[0].VendorAliasCount, 40)
	assert.NotEmpty(t, payload.Profiles[0].FirmwareProfiles)
}

func TestHandleGetDictionaryReleaseProfilesFiltersAndRejectsUnknown(t *testing.T) {
	response := httptest.NewRecorder()
	HandleGetDictionaryReleaseProfiles(response, httptest.NewRequest(http.MethodGet, "/api/v1/system/dictionary-release-profiles?id=freeradius-3.2.8", nil))
	require.Equal(t, http.StatusOK, response.Code)

	response = httptest.NewRecorder()
	HandleGetDictionaryReleaseProfiles(response, httptest.NewRequest(http.MethodGet, "/api/v1/system/dictionary-release-profiles?id=freeradius-4.0.0", nil))
	assert.Equal(t, http.StatusNotFound, response.Code)
}
