package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleGetVendorCompatibility(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/vendor-compatibility", nil)
	rec := httptest.NewRecorder()

	HandleGetVendorCompatibility(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var payload map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))

	summary, ok := payload["summary"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "AegisNAS", summary["product_vendor_name"])
	assert.EqualValues(t, 55555, summary["product_vendor_id"])
	assert.EqualValues(t, 11, summary["product_attribute_count"])
	assert.Greater(t, int(summary["pack_count"].(float64)), 5)

	semantics, ok := payload["semantics"].([]any)
	require.True(t, ok)
	assert.NotEmpty(t, semantics)

	packs, ok := payload["packs"].([]any)
	require.True(t, ok)
	assert.NotEmpty(t, packs)

	activePacks, ok := payload["active_packs"].([]any)
	require.True(t, ok)
	assert.Contains(t, activePacks, "standard")
}
