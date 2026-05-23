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

func TestRunAuditExportCycleAndListAuditExports(t *testing.T) {
	prepareSupportBundleTestConfig(t)
	cfg := config.Get()
	require.NotNil(t, cfg)
	exportDir := filepath.Join(t.TempDir(), "audit-exports")
	cfg.Telemetry.AuditExports = config.DiagnosticsExportConfig{
		Enabled:         true,
		Directory:       exportDir,
		Format:          "both",
		IntervalMinutes: 60,
		RetentionCount:  2,
	}
	now := time.Date(2026, 5, 21, 9, 15, 0, 0, time.UTC)
	_, err := db.DB.Exec(`INSERT INTO audit_logs (timestamp, user, action, details, result, ip_address) VALUES (?, ?, ?, ?, ?, ?)`,
		now.Add(-2*time.Minute), "alice", "download_support_bundle", "bundle.zip", "downloaded", "10.0.0.10")
	require.NoError(t, err)
	_, err = db.DB.Exec(`INSERT INTO audit_logs (timestamp, user, action, details, result, ip_address) VALUES (?, ?, ?, ?, ?, ?)`,
		now.Add(-time.Minute), "bob", "apply_edge_network", "test", "ok", "10.0.0.11")
	require.NoError(t, err)

	origNow := auditExportNow
	auditExportNow = func() time.Time { return now }
	t.Cleanup(func() {
		auditExportNow = origNow
	})

	runAuditExportCycle(context.Background(), cfg)

	runtimeStatus, err := db.GetRuntimeStatus(auditExportsComponent)
	require.NoError(t, err)
	require.NotNil(t, runtimeStatus)
	assert.Equal(t, "ok", runtimeStatus.Status)
	assert.Equal(t, now.Format(time.RFC3339), runtimeStatus.Details["last_export_at"])

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/audit-exports", nil)
	rec := httptest.NewRecorder()
	HandleListAuditExports(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var payload struct {
		Runtime *db.RuntimeStatus     `json:"runtime"`
		Exports []AuditExportArtifact `json:"exports"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	require.NotNil(t, payload.Runtime)
	require.Len(t, payload.Exports, 2)
	assert.Equal(t, "ok", payload.Runtime.Status)
	assert.ElementsMatch(t, []string{"csv", "json"}, []string{payload.Exports[0].Format, payload.Exports[1].Format})
}

func TestHandleDownloadAuditExport(t *testing.T) {
	prepareSupportBundleTestConfig(t)
	cfg := config.Get()
	require.NotNil(t, cfg)
	exportDir := filepath.Join(t.TempDir(), "audit-export-downloads")
	cfg.Telemetry.AuditExports = config.DiagnosticsExportConfig{
		Enabled:         true,
		Directory:       exportDir,
		Format:          "json",
		IntervalMinutes: 60,
		RetentionCount:  2,
	}
	now := time.Date(2026, 5, 21, 9, 30, 0, 0, time.UTC)
	_, err := db.DB.Exec(`INSERT INTO audit_logs (timestamp, user, action, details, result, ip_address) VALUES (?, ?, ?, ?, ?, ?)`,
		now.Add(-time.Minute), "alice", "download_support_bundle", "bundle.zip", "downloaded", "10.0.0.10")
	require.NoError(t, err)

	origNow := auditExportNow
	auditExportNow = func() time.Time { return now }
	t.Cleanup(func() {
		auditExportNow = origNow
	})

	runAuditExportCycle(context.Background(), cfg)

	artifacts, err := listAuditExportArtifacts(cfg)
	require.NoError(t, err)
	require.Len(t, artifacts, 1)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/audit-exports/download?name="+artifacts[0].Name, nil)
	rec := httptest.NewRecorder()
	HandleDownloadAuditExport(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Header().Get("Content-Disposition"), artifacts[0].Name)
	assert.Contains(t, rec.Body.String(), `"download_support_bundle"`)
}
