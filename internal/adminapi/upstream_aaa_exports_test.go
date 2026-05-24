package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestRunUpstreamAAAExportCycleAndListUpstreamAAAExports(t *testing.T) {
	prepareSupportBundleTestConfig(t)
	cfg := config.Get()
	require.NotNil(t, cfg)
	exportDir := filepath.Join(t.TempDir(), "upstream-aaa-exports")
	cfg.Telemetry.UpstreamAAAExports = config.DiagnosticsExportConfig{
		Enabled:         true,
		Directory:       exportDir,
		Format:          "both",
		IntervalMinutes: 60,
		RetentionCount:  2,
	}

	require.NoError(t, db.RecordUpstreamAAAHistory("primary", "10.0.0.10", 1812, 1813, "ok", "reachable", "Access-Accept", 12, true, "2026-05-25T10:00:00Z"))
	require.NoError(t, db.RecordUpstreamAAAHistory("secondary", "10.0.0.11", 1812, 1813, "down", "i/o timeout", "", 0, true, "2026-05-25T10:01:00Z"))

	now := time.Date(2026, 5, 25, 10, 30, 0, 0, time.UTC)
	origNow := upstreamAAAExportNow
	upstreamAAAExportNow = func() time.Time { return now }
	t.Cleanup(func() {
		upstreamAAAExportNow = origNow
	})

	runUpstreamAAAExportCycle(context.Background(), cfg)

	runtimeStatus, err := db.GetRuntimeStatus(upstreamAAAExportsComponent)
	require.NoError(t, err)
	require.NotNil(t, runtimeStatus)
	assert.Equal(t, "ok", runtimeStatus.Status)
	assert.Equal(t, now.Format(time.RFC3339), runtimeStatus.Details["last_export_at"])

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/upstream-aaa-exports", nil)
	rec := httptest.NewRecorder()
	HandleListUpstreamAAAExports(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var payload struct {
		Runtime *db.RuntimeStatus           `json:"runtime"`
		Exports []UpstreamAAAExportArtifact `json:"exports"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	require.NotNil(t, payload.Runtime)
	require.Len(t, payload.Exports, 2)
	assert.Equal(t, "ok", payload.Runtime.Status)
}

func TestHandleDownloadUpstreamAAAExport(t *testing.T) {
	prepareSupportBundleTestConfig(t)
	cfg := config.Get()
	require.NotNil(t, cfg)
	exportDir := filepath.Join(t.TempDir(), "upstream-aaa-export-downloads")
	cfg.Telemetry.UpstreamAAAExports = config.DiagnosticsExportConfig{
		Enabled:         true,
		Directory:       exportDir,
		Format:          "json",
		IntervalMinutes: 60,
		RetentionCount:  2,
	}

	require.NoError(t, db.RecordUpstreamAAAHistory("primary", "10.0.0.10", 1812, 1813, "degraded", "unexpected response", "Access-Reject", 18, true, "2026-05-25T10:05:00Z"))

	now := time.Date(2026, 5, 25, 10, 45, 0, 0, time.UTC)
	origNow := upstreamAAAExportNow
	upstreamAAAExportNow = func() time.Time { return now }
	t.Cleanup(func() {
		upstreamAAAExportNow = origNow
	})

	runUpstreamAAAExportCycle(context.Background(), cfg)

	artifacts, err := listUpstreamAAAExportArtifacts(cfg)
	require.NoError(t, err)
	require.Len(t, artifacts, 1)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/upstream-aaa-exports/download?name="+artifacts[0].Name, nil)
	rec := httptest.NewRecorder()
	HandleDownloadUpstreamAAAExport(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Header().Get("Content-Disposition"), artifacts[0].Name)
	assert.Contains(t, rec.Body.String(), `"server_name": "primary"`)
}
