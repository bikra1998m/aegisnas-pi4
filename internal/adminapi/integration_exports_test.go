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

func TestRunIntegrationExportCycleAndListIntegrationExports(t *testing.T) {
	prepareSupportBundleTestConfig(t)
	cfg := config.Get()
	require.NotNil(t, cfg)
	exportDir := filepath.Join(t.TempDir(), "integration-exports")
	cfg.Telemetry.IntegrationExports = config.DiagnosticsExportConfig{
		Enabled:         true,
		Directory:       exportDir,
		Format:          "both",
		IntervalMinutes: 60,
		RetentionCount:  2,
	}
	require.NoError(t, db.RecordIntegrationHistory("controller_automation", "ok", "Controller sync completed.", map[string]any{"adapter": "cisco"}))
	require.NoError(t, db.RecordIntegrationHistory("mdm_sync", "degraded", "MDM sync needs attention.", map[string]any{"provider": "intune"}))

	now := time.Date(2026, 5, 23, 10, 15, 0, 0, time.UTC)
	origNow := integrationExportNow
	integrationExportNow = func() time.Time { return now }
	t.Cleanup(func() {
		integrationExportNow = origNow
	})

	runIntegrationExportCycle(context.Background(), cfg)

	runtimeStatus, err := db.GetRuntimeStatus(integrationExportsComponent)
	require.NoError(t, err)
	require.NotNil(t, runtimeStatus)
	assert.Equal(t, "ok", runtimeStatus.Status)
	assert.Equal(t, now.Format(time.RFC3339), runtimeStatus.Details["last_export_at"])

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/integration-exports", nil)
	rec := httptest.NewRecorder()
	HandleListIntegrationExports(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var payload struct {
		Runtime *db.RuntimeStatus           `json:"runtime"`
		Exports []IntegrationExportArtifact `json:"exports"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	require.NotNil(t, payload.Runtime)
	require.Len(t, payload.Exports, 2)
	assert.Equal(t, "ok", payload.Runtime.Status)
	assert.ElementsMatch(t, []string{"csv", "json"}, []string{payload.Exports[0].Format, payload.Exports[1].Format})
}

func TestHandleDownloadIntegrationExport(t *testing.T) {
	prepareSupportBundleTestConfig(t)
	cfg := config.Get()
	require.NotNil(t, cfg)
	exportDir := filepath.Join(t.TempDir(), "integration-export-downloads")
	cfg.Telemetry.IntegrationExports = config.DiagnosticsExportConfig{
		Enabled:         true,
		Directory:       exportDir,
		Format:          "json",
		IntervalMinutes: 60,
		RetentionCount:  2,
	}
	require.NoError(t, db.RecordIntegrationHistory("posture_checks", "ok", "Compliance evaluation completed.", map[string]any{"provider": "workspace-one"}))

	now := time.Date(2026, 5, 23, 10, 30, 0, 0, time.UTC)
	origNow := integrationExportNow
	integrationExportNow = func() time.Time { return now }
	t.Cleanup(func() {
		integrationExportNow = origNow
	})

	runIntegrationExportCycle(context.Background(), cfg)

	artifacts, err := listIntegrationExportArtifacts(cfg)
	require.NoError(t, err)
	require.Len(t, artifacts, 1)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/integration-exports/download?name="+artifacts[0].Name, nil)
	rec := httptest.NewRecorder()
	HandleDownloadIntegrationExport(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Header().Get("Content-Disposition"), artifacts[0].Name)
	assert.Contains(t, rec.Body.String(), `"posture_checks"`)
}
