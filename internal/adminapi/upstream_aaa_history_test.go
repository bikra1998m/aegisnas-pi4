package adminapi

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestHandleListUpstreamAAAHistory(t *testing.T) {
	_ = prepareSupportBundleTestConfig(t)

	require.NoError(t, db.RecordUpstreamAAAHistory("primary", "10.0.0.10", 1812, 1813, "ok", "reachable", "Access-Accept", 12, true, "2026-05-23T10:00:00Z"))
	require.NoError(t, db.RecordUpstreamAAAHistory("secondary", "10.0.0.11", 1812, 1813, "down", "i/o timeout", "", 0, true, "2026-05-23T10:05:00Z"))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/upstream-aaa-history?server=primary", nil)
	rec := httptest.NewRecorder()
	HandleListUpstreamAAAHistory(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var payload struct {
		Server  string                        `json:"server"`
		Count   int                           `json:"count"`
		History []db.UpstreamAAAHistoryRecord `json:"history"`
		Stats   db.UpstreamAAAHistoryStats    `json:"stats"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, "primary", payload.Server)
	assert.Len(t, payload.History, 1)
	assert.Equal(t, "primary", payload.History[0].ServerName)
	assert.Equal(t, 2, payload.Stats.TotalRecords)
	assert.Equal(t, 1, payload.Stats.OKCount)
	assert.Equal(t, 1, payload.Stats.DownCount)
}

func TestHandleExportUpstreamAAAHistoryCSV(t *testing.T) {
	_ = prepareSupportBundleTestConfig(t)

	require.NoError(t, db.RecordUpstreamAAAHistory("primary", "10.0.0.10", 1812, 1813, "degraded", "unexpected response", "Access-Reject", 18, true, "2026-05-23T10:00:00Z"))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/upstream-aaa-history/export?format=csv&status=degraded", nil)
	rec := httptest.NewRecorder()
	HandleExportUpstreamAAAHistory(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/csv; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Header().Get("Content-Disposition"), "aegisnas-upstream-aaa-history-degraded.csv")

	reader := csv.NewReader(strings.NewReader(rec.Body.String()))
	rows, err := reader.ReadAll()
	require.NoError(t, err)
	require.Len(t, rows, 2)
	assert.Equal(t, "server_name", rows[0][3])
	assert.Equal(t, "primary", rows[1][3])
	assert.Equal(t, "degraded", rows[1][7])
}

func TestHandleExportUpstreamAAAHistoryRejectsUnsupportedFormat(t *testing.T) {
	_ = prepareSupportBundleTestConfig(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/upstream-aaa-history/export?format=xml", nil)
	rec := httptest.NewRecorder()
	HandleExportUpstreamAAAHistory(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "unsupported export format")
}
