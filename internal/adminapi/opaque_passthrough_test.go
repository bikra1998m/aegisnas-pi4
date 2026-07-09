package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/radius"
)

func TestHandleGetOpaquePassThrough(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/opaque-passthrough", nil)
	rec := httptest.NewRecorder()

	HandleGetOpaquePassThrough(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var payload radius.OpaquePassThroughReport
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, radius.OpaquePassThroughSchemaVersion, payload.SchemaVersion)
	assert.Equal(t, "ready", payload.Status)
	assert.Equal(t, "drop", payload.Policy.DefaultAction)
	assert.True(t, payload.Policy.Enabled)
	assert.Greater(t, payload.Summary.SourceAttributeCount, 7000)
	assert.NotEmpty(t, payload.SensitiveTypes)
	assert.Contains(t, payload.Notes[0], "certification")
}
