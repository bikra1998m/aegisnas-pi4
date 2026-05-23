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

func TestRunHAExportCycleAndListHAExports(t *testing.T) {
	prepareSupportBundleTestConfig(t)
	cfg := config.Get()
	require.NotNil(t, cfg)
	exportDir := filepath.Join(t.TempDir(), "ha-exports")
	cfg.Telemetry.HAExports = config.DiagnosticsExportConfig{
		Enabled:         true,
		Directory:       exportDir,
		Format:          "both",
		IntervalMinutes: 60,
		RetentionCount:  2,
	}
	require.NoError(t, db.RecordHAHistory("failover", "promoted", "Standby promoted.", "standby", "", map[string]any{"vip": "192.168.50.2"}))
	require.NoError(t, db.RecordHAHistory("replication_publish", "success", "Published shared package.", "active", "", map[string]any{"source_node": "active-node"}))

	now := time.Date(2026, 5, 23, 11, 15, 0, 0, time.UTC)
	origNow := haExportNow
	haExportNow = func() time.Time { return now }
	t.Cleanup(func() {
		haExportNow = origNow
	})

	runHAExportCycle(context.Background(), cfg)

	runtimeStatus, err := db.GetRuntimeStatus(haExportsComponent)
	require.NoError(t, err)
	require.NotNil(t, runtimeStatus)
	assert.Equal(t, "ok", runtimeStatus.Status)
	assert.Equal(t, now.Format(time.RFC3339), runtimeStatus.Details["last_export_at"])

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/ha/exports", nil)
	rec := httptest.NewRecorder()
	HandleListHAExports(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var payload struct {
		Runtime *db.RuntimeStatus  `json:"runtime"`
		Exports []HAExportArtifact `json:"exports"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	require.NotNil(t, payload.Runtime)
	require.Len(t, payload.Exports, 2)
	assert.Equal(t, "ok", payload.Runtime.Status)
	assert.ElementsMatch(t, []string{"csv", "json"}, []string{payload.Exports[0].Format, payload.Exports[1].Format})
}

func TestHandleDownloadHAExport(t *testing.T) {
	prepareSupportBundleTestConfig(t)
	cfg := config.Get()
	require.NotNil(t, cfg)
	exportDir := filepath.Join(t.TempDir(), "ha-export-downloads")
	cfg.Telemetry.HAExports = config.DiagnosticsExportConfig{
		Enabled:         true,
		Directory:       exportDir,
		Format:          "json",
		IntervalMinutes: 60,
		RetentionCount:  2,
	}
	require.NoError(t, db.RecordHAHistory("replication_publish", "success", "Published shared package.", "active", "", map[string]any{"source_node": "active-node"}))

	now := time.Date(2026, 5, 23, 11, 30, 0, 0, time.UTC)
	origNow := haExportNow
	haExportNow = func() time.Time { return now }
	t.Cleanup(func() {
		haExportNow = origNow
	})

	runHAExportCycle(context.Background(), cfg)

	artifacts, err := listHAExportArtifacts(cfg)
	require.NoError(t, err)
	require.Len(t, artifacts, 1)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/ha/exports/download?name="+artifacts[0].Name, nil)
	rec := httptest.NewRecorder()
	HandleDownloadHAExport(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Header().Get("Content-Disposition"), artifacts[0].Name)
	assert.Contains(t, rec.Body.String(), `"replication_publish"`)
}
