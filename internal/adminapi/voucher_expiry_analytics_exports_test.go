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

func TestRunVoucherExpiryAnalyticsExportCycleAndListVoucherExpiryAnalyticsExports(t *testing.T) {
	prepareSupportBundleTestConfig(t)
	cfg := config.Get()
	require.NotNil(t, cfg)
	exportDir := filepath.Join(t.TempDir(), "voucher-expiry-analytics-exports")
	cfg.Telemetry.VoucherExpiryAnalyticsExports = config.DiagnosticsExportConfig{
		Enabled:         true,
		Directory:       exportDir,
		Format:          "both",
		IntervalMinutes: 60,
		RetentionCount:  2,
	}

	seedVoucherAnalyticsExportTestData(t)

	now := time.Date(2026, 6, 6, 12, 15, 0, 0, time.UTC)
	origNow := voucherExpiryAnalyticsExportNow
	voucherExpiryAnalyticsExportNow = func() time.Time { return now }
	t.Cleanup(func() {
		voucherExpiryAnalyticsExportNow = origNow
	})

	runVoucherExpiryAnalyticsExportCycle(context.Background(), cfg)

	runtimeStatus, err := db.GetRuntimeStatus(voucherExpiryAnalyticsExportsComponent)
	require.NoError(t, err)
	require.NotNil(t, runtimeStatus)
	assert.Equal(t, "ok", runtimeStatus.Status)
	assert.Equal(t, now.Format(time.RFC3339), runtimeStatus.Details["last_export_at"])
	assert.EqualValues(t, defaultVoucherAnalyticsWindowHours, runtimeStatus.Details["window_hours"])
	assert.EqualValues(t, defaultVoucherAnalyticsBucketCount, runtimeStatus.Details["bucket_count"])

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/voucher-expiry-analytics-exports", nil)
	rec := httptest.NewRecorder()
	HandleListVoucherExpiryAnalyticsExports(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var payload struct {
		Runtime *db.RuntimeStatus                      `json:"runtime"`
		Exports []VoucherExpiryAnalyticsExportArtifact `json:"exports"`
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

func TestHandleDownloadVoucherExpiryAnalyticsExport(t *testing.T) {
	prepareSupportBundleTestConfig(t)
	cfg := config.Get()
	require.NotNil(t, cfg)
	exportDir := filepath.Join(t.TempDir(), "voucher-expiry-analytics-export-downloads")
	cfg.Telemetry.VoucherExpiryAnalyticsExports = config.DiagnosticsExportConfig{
		Enabled:         true,
		Directory:       exportDir,
		Format:          "json",
		IntervalMinutes: 60,
		RetentionCount:  2,
	}

	seedVoucherAnalyticsExportTestData(t)

	now := time.Date(2026, 6, 6, 12, 30, 0, 0, time.UTC)
	origNow := voucherExpiryAnalyticsExportNow
	voucherExpiryAnalyticsExportNow = func() time.Time { return now }
	t.Cleanup(func() {
		voucherExpiryAnalyticsExportNow = origNow
	})

	runVoucherExpiryAnalyticsExportCycle(context.Background(), cfg)

	artifacts, err := listVoucherExpiryAnalyticsExportArtifacts(cfg)
	require.NoError(t, err)
	require.Len(t, artifacts, 1)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/voucher-expiry-analytics-exports/download?name="+artifacts[0].Name, nil)
	rec := httptest.NewRecorder()
	HandleDownloadVoucherExpiryAnalyticsExport(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Header().Get("Content-Disposition"), artifacts[0].Name)
	assert.Contains(t, rec.Body.String(), `"summary"`)
	assert.Contains(t, rec.Body.String(), `"expiring_in_window_count"`)
}
