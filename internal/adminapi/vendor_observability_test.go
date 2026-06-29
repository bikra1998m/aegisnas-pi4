package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestHandleGetVendorObservability(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "admin-vendor-observability-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	require.NoError(t, tmpfile.Close())

	require.NoError(t, db.Init(tmpfile.Name()))
	defer db.Close()
	require.NoError(t, db.Migrate())
	require.NoError(t, db.RecordVendorObservability(db.VendorObservabilityDelta{
		VendorKey:                 "aruba",
		NASType:                   "controller",
		AuthSuccessDelta:          3,
		UnsupportedAttributeDelta: 1,
		Message:                   "auth response Access-Accept",
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/vendor-observability", nil)
	rec := httptest.NewRecorder()
	HandleGetVendorObservability(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var payload struct {
		Summary db.VendorObservabilitySummary  `json:"summary"`
		Vendors []db.VendorObservabilityRecord `json:"vendors"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, 1, payload.Summary.TotalVendors)
	assert.Equal(t, 3, payload.Summary.AuthSuccessCount)
	require.Len(t, payload.Vendors, 1)
	assert.Equal(t, "aruba", payload.Vendors[0].VendorKey)
}

func TestHandleExportVendorObservabilityCSV(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "admin-vendor-observability-export-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	require.NoError(t, tmpfile.Close())

	require.NoError(t, db.Init(tmpfile.Name()))
	defer db.Close()
	require.NoError(t, db.Migrate())
	require.NoError(t, db.RecordVendorObservability(db.VendorObservabilityDelta{
		VendorKey:        "cisco",
		NASType:          "switch",
		AuthFailureDelta: 1,
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/vendor-observability/export?format=csv", nil)
	rec := httptest.NewRecorder()
	HandleExportVendorObservability(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/csv")
	assert.Contains(t, rec.Body.String(), "vendor_key,nas_type,compatibility_score")
	assert.Contains(t, rec.Body.String(), "cisco,switch")
}
