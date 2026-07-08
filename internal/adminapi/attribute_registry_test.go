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

func TestHandleGetAttributeRegistryFiltersAndPaginates(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/api/v1/system/attribute-registry?vendor=Aruba&status=partial&limit=2", nil)
	response := httptest.NewRecorder()
	HandleGetAttributeRegistry(response, request)
	require.Equal(t, http.StatusOK, response.Code)

	var first attributeRegistryResponse
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &first))
	assert.Equal(t, 7654, first.SourceAttributeCount)
	assert.Equal(t, 148, first.MappedCount)
	assert.Greater(t, first.FilteredCount, 2)
	require.Len(t, first.Entries, 2)
	assert.NotEmpty(t, first.NextCursor)
	for _, entry := range first.Entries {
		assert.Equal(t, "Aruba", entry.Vendor)
		assert.Equal(t, "partial", entry.DictionaryStatus)
	}

	request = httptest.NewRequest(http.MethodGet, "/api/v1/system/attribute-registry?vendor=Aruba&status=partial&limit=2&cursor="+first.NextCursor, nil)
	response = httptest.NewRecorder()
	HandleGetAttributeRegistry(response, request)
	require.Equal(t, http.StatusOK, response.Code)
	var second attributeRegistryResponse
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &second))
	require.NotEmpty(t, second.Entries)
	assert.NotEqual(t, first.Entries[0].Key, second.Entries[0].Key)
}

func TestHandleGetAttributeRegistryRejectsInvalidQueries(t *testing.T) {
	for _, target := range []string{
		"/api/v1/system/attribute-registry?limit=501",
		"/api/v1/system/attribute-registry?pen=-1",
		"/api/v1/system/attribute-registry?status=certified",
		"/api/v1/system/attribute-registry?cursor=not-base64",
	} {
		response := httptest.NewRecorder()
		HandleGetAttributeRegistry(response, httptest.NewRequest(http.MethodGet, target, nil))
		assert.Equal(t, http.StatusBadRequest, response.Code, target)
	}
}

func TestHandleGetAttributeRegistryMatchesMultiSemanticEntries(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/api/v1/system/attribute-registry?vendor=Meraki&semantic=device.group", nil)
	response := httptest.NewRecorder()
	HandleGetAttributeRegistry(response, request)
	require.Equal(t, http.StatusOK, response.Code)

	var payload attributeRegistryResponse
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &payload))
	require.NotEmpty(t, payload.Entries)
	var apName *productconfigs.AttributeRegistryEntry
	for idx := range payload.Entries {
		if payload.Entries[idx].Attribute == "Meraki-Ap-Name" {
			apName = &payload.Entries[idx]
			break
		}
	}
	require.NotNil(t, apName)
	assert.Contains(t, apName.Semantic, "accounting.identity")
	assert.Contains(t, apName.Semantic, "device.group")
	assert.Equal(t, "accounting.identity", apName.DecodeSemantic)
}
