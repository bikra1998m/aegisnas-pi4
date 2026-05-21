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

func TestRunDiagnosticsExportCycleAndListDiagnosticsExports(t *testing.T) {
	prepareSupportBundleTestConfig(t)
	cfg := config.Get()
	require.NotNil(t, cfg)
	exportDir := filepath.Join(t.TempDir(), "diagnostics-exports")
	cfg.Telemetry.DiagnosticsExports = config.DiagnosticsExportConfig{
		Enabled:         true,
		Directory:       exportDir,
		Format:          "both",
		IntervalMinutes: 60,
		RetentionCount:  2,
	}

	now := time.Date(2026, 5, 21, 7, 45, 0, 0, time.UTC)
	origNow := diagnosticsExportNow
	origBuild := diagnosticsExportBuildReportFn
	origCSV := diagnosticsExportCSVFn
	diagnosticsExportNow = func() time.Time { return now }
	diagnosticsExportBuildReportFn = func(ctx context.Context) (DiagnosticsReport, error) {
		return DiagnosticsReport{
			GeneratedAt:       now.Format(time.RFC3339),
			ConfigPath:        config.Path(),
			DatabasePath:      cfg.Database.Path,
			SchemaVersion:     db.LatestSchemaVersion(),
			DeploymentProfile: cfg.Deployment.Profile,
			DeploymentForm:    cfg.Deployment.Form,
			HARole:            cfg.HighAvailability.Role,
			Summary: DiagnosticsSummary{
				Users:               2,
				ActiveSessions:      3,
				QuarantinedSessions: 1,
			},
		}, nil
	}
	diagnosticsExportCSVFn = func(report DiagnosticsReport) ([]byte, error) {
		return []byte("key,value\nactive_sessions,3\n"), nil
	}
	t.Cleanup(func() {
		diagnosticsExportNow = origNow
		diagnosticsExportBuildReportFn = origBuild
		diagnosticsExportCSVFn = origCSV
	})

	runDiagnosticsExportCycle(context.Background(), cfg)

	runtimeStatus, err := db.GetRuntimeStatus(diagnosticsExportsComponent)
	require.NoError(t, err)
	require.NotNil(t, runtimeStatus)
	assert.Equal(t, "ok", runtimeStatus.Status)
	assert.Equal(t, now.Format(time.RFC3339), runtimeStatus.Details["last_export_at"])

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/diagnostics-exports", nil)
	rec := httptest.NewRecorder()
	HandleListDiagnosticsExports(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var payload struct {
		Runtime *db.RuntimeStatus           `json:"runtime"`
		Exports []DiagnosticsExportArtifact `json:"exports"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	require.NotNil(t, payload.Runtime)
	require.Len(t, payload.Exports, 2)
	assert.Equal(t, "ok", payload.Runtime.Status)
	assert.ElementsMatch(t, []string{"csv", "json"}, []string{payload.Exports[0].Format, payload.Exports[1].Format})
}

func TestHandleDownloadDiagnosticsExport(t *testing.T) {
	prepareSupportBundleTestConfig(t)
	cfg := config.Get()
	require.NotNil(t, cfg)
	exportDir := filepath.Join(t.TempDir(), "diagnostics-downloads")
	cfg.Telemetry.DiagnosticsExports = config.DiagnosticsExportConfig{
		Enabled:         true,
		Directory:       exportDir,
		Format:          "json",
		IntervalMinutes: 60,
		RetentionCount:  2,
	}

	now := time.Date(2026, 5, 21, 8, 0, 0, 0, time.UTC)
	origNow := diagnosticsExportNow
	origBuild := diagnosticsExportBuildReportFn
	diagnosticsExportNow = func() time.Time { return now }
	diagnosticsExportBuildReportFn = func(ctx context.Context) (DiagnosticsReport, error) {
		return DiagnosticsReport{
			GeneratedAt:       now.Format(time.RFC3339),
			ConfigPath:        config.Path(),
			DatabasePath:      cfg.Database.Path,
			SchemaVersion:     db.LatestSchemaVersion(),
			DeploymentProfile: cfg.Deployment.Profile,
		}, nil
	}
	t.Cleanup(func() {
		diagnosticsExportNow = origNow
		diagnosticsExportBuildReportFn = origBuild
	})

	runDiagnosticsExportCycle(context.Background(), cfg)

	artifacts, err := listDiagnosticsExportArtifacts(cfg)
	require.NoError(t, err)
	require.Len(t, artifacts, 1)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/diagnostics-exports/download?name="+artifacts[0].Name, nil)
	rec := httptest.NewRecorder()
	HandleDownloadDiagnosticsExport(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Header().Get("Content-Disposition"), artifacts[0].Name)
	assert.Contains(t, rec.Body.String(), `"schema_version"`)
}
