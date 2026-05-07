package adminapi

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestHandleListHAHistory(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "ha-observability-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	require.NoError(t, tmpfile.Close())

	require.NoError(t, db.Init(tmpfile.Name()))
	defer db.Close()
	require.NoError(t, db.Migrate())
	require.NoError(t, db.RecordHAHistory("failover", "promoted", "Standby promoted.", "standby", "", map[string]any{"vip": "192.168.50.2"}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/ha/history", nil)
	rec := httptest.NewRecorder()
	HandleListHAHistory(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "\"history\"")
	assert.Contains(t, rec.Body.String(), "\"stats\"")
	assert.Contains(t, rec.Body.String(), "Standby promoted.")
}

func TestHandleExportHAHistoryCSV(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "ha-observability-export-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	require.NoError(t, tmpfile.Close())

	require.NoError(t, db.Init(tmpfile.Name()))
	defer db.Close()
	require.NoError(t, db.Migrate())
	require.NoError(t, db.RecordHAHistory("replication_publish", "success", "Published shared package.", "active", "", map[string]any{"source_node": "active-node"}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/ha/history/export?format=csv", nil)
	rec := httptest.NewRecorder()
	HandleExportHAHistory(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/csv; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Body.String(), "Published shared package.")
}
