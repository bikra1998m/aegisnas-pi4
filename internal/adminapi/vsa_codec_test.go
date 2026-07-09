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

func TestHandleGetVSACodec(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/vsa-codec", nil)
	rec := httptest.NewRecorder()

	HandleGetVSACodec(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var payload radius.VSACodecReport
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, radius.VSACodecSchemaVersion, payload.SchemaVersion)
	assert.Equal(t, "ready", payload.Status)
	assert.Equal(t, 7654, payload.Summary.SourceAttributeCount)
	assert.Greater(t, payload.Summary.GroupedAttributeCount, 0)
	assert.Greater(t, payload.Summary.RepeatedAttributeCount, 0)
	assert.Len(t, payload.SupportedFormats, 9)
	assert.Equal(t, 4096, payload.Limits.MaxRADIUSPacketBytes)
	assert.Contains(t, payload.Notes[0], "certification")
}
