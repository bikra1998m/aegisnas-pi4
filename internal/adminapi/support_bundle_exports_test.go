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

func TestRunSupportBundleExportCycleAndListSupportBundleExports(t *testing.T) {
	prepareSupportBundleTestConfig(t)
	cfg := config.Get()
	require.NotNil(t, cfg)
	exportDir := filepath.Join(t.TempDir(), "support-bundle-exports")
	cfg.Telemetry.SupportBundleExports = config.SupportBundleExportConfig{
		Enabled:         true,
		Directory:       exportDir,
		IntervalMinutes: 360,
		RetentionCount:  2,
	}

	now := time.Date(2026, 5, 25, 10, 30, 0, 0, time.UTC)
	origNow := supportBundleExportNow
	origBuild := supportBundleExportBuildFn
	supportBundleExportNow = func() time.Time { return now }
	supportBundleExportBuildFn = func(cfg *config.Config) ([]byte, string, error) {
		return []byte("support bundle bytes"), "aegisnas-support-bundle-20260525-103000Z.zip", nil
	}
	t.Cleanup(func() {
		supportBundleExportNow = origNow
		supportBundleExportBuildFn = origBuild
	})

	runSupportBundleExportCycle(context.Background(), cfg)

	runtimeStatus, err := db.GetRuntimeStatus(supportBundleExportsComponent)
	require.NoError(t, err)
	require.NotNil(t, runtimeStatus)
	assert.Equal(t, "ok", runtimeStatus.Status)
	assert.Equal(t, now.Format(time.RFC3339), runtimeStatus.Details["last_export_at"])

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/support-bundle-exports", nil)
	rec := httptest.NewRecorder()
	HandleListSupportBundleExports(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var payload struct {
		Runtime *db.RuntimeStatus             `json:"runtime"`
		Exports []SupportBundleExportArtifact `json:"exports"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	require.NotNil(t, payload.Runtime)
	require.Len(t, payload.Exports, 1)
	assert.Equal(t, "ok", payload.Runtime.Status)
	assert.Equal(t, "aegisnas-support-bundle-20260525-103000Z.zip", payload.Exports[0].Name)
}

func TestHandleDownloadSupportBundleExport(t *testing.T) {
	prepareSupportBundleTestConfig(t)
	cfg := config.Get()
	require.NotNil(t, cfg)
	exportDir := filepath.Join(t.TempDir(), "support-bundle-downloads")
	cfg.Telemetry.SupportBundleExports = config.SupportBundleExportConfig{
		Enabled:         true,
		Directory:       exportDir,
		IntervalMinutes: 360,
		RetentionCount:  2,
	}

	now := time.Date(2026, 5, 25, 10, 45, 0, 0, time.UTC)
	origNow := supportBundleExportNow
	origBuild := supportBundleExportBuildFn
	supportBundleExportNow = func() time.Time { return now }
	supportBundleExportBuildFn = func(cfg *config.Config) ([]byte, string, error) {
		return []byte("zip-bytes"), "aegisnas-support-bundle-20260525-104500Z.zip", nil
	}
	t.Cleanup(func() {
		supportBundleExportNow = origNow
		supportBundleExportBuildFn = origBuild
	})

	runSupportBundleExportCycle(context.Background(), cfg)

	artifacts, err := listSupportBundleExportArtifacts(cfg)
	require.NoError(t, err)
	require.Len(t, artifacts, 1)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/support-bundle-exports/download?name="+artifacts[0].Name, nil)
	rec := httptest.NewRecorder()
	HandleDownloadSupportBundleExport(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/zip", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Header().Get("Content-Disposition"), artifacts[0].Name)
	assert.Equal(t, "zip-bytes", rec.Body.String())
}
