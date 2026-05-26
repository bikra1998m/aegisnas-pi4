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

func TestRunGuestLifecycleExportCycleAndListGuestLifecycleExports(t *testing.T) {
	prepareSupportBundleTestConfig(t)
	cfg := config.Get()
	require.NotNil(t, cfg)
	exportDir := filepath.Join(t.TempDir(), "guest-lifecycle-exports")
	cfg.Telemetry.GuestLifecycleExports = config.DiagnosticsExportConfig{
		Enabled:         true,
		Directory:       exportDir,
		Format:          "both",
		IntervalMinutes: 60,
		RetentionCount:  2,
	}

	seedGuestLifecycleTestRows(t)

	now := time.Date(2026, 5, 25, 12, 15, 0, 0, time.UTC)
	origNow := guestLifecycleExportNow
	guestLifecycleExportNow = func() time.Time { return now }
	t.Cleanup(func() {
		guestLifecycleExportNow = origNow
	})

	runGuestLifecycleExportCycle(context.Background(), cfg)

	runtimeStatus, err := db.GetRuntimeStatus(guestLifecycleExportsComponent)
	require.NoError(t, err)
	require.NotNil(t, runtimeStatus)
	assert.Equal(t, "ok", runtimeStatus.Status)
	assert.Equal(t, now.Format(time.RFC3339), runtimeStatus.Details["last_export_at"])
	assert.EqualValues(t, defaultGuestLifecycleWindowHours, runtimeStatus.Details["window_hours"])
	assert.EqualValues(t, defaultGuestLifecycleBucketCount, runtimeStatus.Details["bucket_count"])
	assert.EqualValues(t, defaultGuestLifecycleLimit, runtimeStatus.Details["limit"])

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/guest-lifecycle-exports", nil)
	rec := httptest.NewRecorder()
	HandleListGuestLifecycleExports(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var payload struct {
		Runtime *db.RuntimeStatus              `json:"runtime"`
		Exports []GuestLifecycleExportArtifact `json:"exports"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	require.NotNil(t, payload.Runtime)
	require.Len(t, payload.Exports, 2)
	assert.Equal(t, "ok", payload.Runtime.Status)

	formats := make([]string, 0, len(payload.Exports))
	for _, artifact := range payload.Exports {
		formats = append(formats, artifact.Format)
	}
	assert.ElementsMatch(t, []string{"json", "csv"}, formats)
}

func TestHandleDownloadGuestLifecycleExport(t *testing.T) {
	prepareSupportBundleTestConfig(t)
	cfg := config.Get()
	require.NotNil(t, cfg)
	exportDir := filepath.Join(t.TempDir(), "guest-lifecycle-export-downloads")
	cfg.Telemetry.GuestLifecycleExports = config.DiagnosticsExportConfig{
		Enabled:         true,
		Directory:       exportDir,
		Format:          "json",
		IntervalMinutes: 60,
		RetentionCount:  2,
	}

	seedGuestLifecycleTestRows(t)

	now := time.Date(2026, 5, 25, 12, 20, 0, 0, time.UTC)
	origNow := guestLifecycleExportNow
	guestLifecycleExportNow = func() time.Time { return now }
	t.Cleanup(func() {
		guestLifecycleExportNow = origNow
	})

	runGuestLifecycleExportCycle(context.Background(), cfg)

	artifacts, err := listGuestLifecycleExportArtifacts(cfg)
	require.NoError(t, err)
	require.Len(t, artifacts, 1)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/guest-lifecycle-exports/download?name="+artifacts[0].Name, nil)
	rec := httptest.NewRecorder()
	HandleDownloadGuestLifecycleExport(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Header().Get("Content-Disposition"), artifacts[0].Name)
	assert.Contains(t, rec.Body.String(), `"summary"`)
	assert.Contains(t, rec.Body.String(), `"Alice Guest"`)
}
