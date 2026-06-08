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

func seedVoucherAnalyticsExportTestData(t *testing.T) {
	t.Helper()

	base := time.Now().UTC()
	_, err := db.DB.Exec(`INSERT INTO vouchers (
		code, role, duration_minutes, usage_limit, used_count, expires_at, created_at
	) VALUES
		(?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?)`,
		"VX-001", "guest-basic", 1440, 1, 0, base.Add(48*time.Hour).Format(time.RFC3339), base.Add(-6*time.Hour).Format(time.RFC3339),
		"VX-002", "guest-basic", 720, 5, 2, base.Add(36*time.Hour).Format(time.RFC3339), base.Add(-18*time.Hour).Format(time.RFC3339),
		"VX-003", "guest-vip", 60, 2, 2, base.Add(-4*time.Hour).Format(time.RFC3339), base.Add(-26*time.Hour).Format(time.RFC3339),
		"VX-004", "guest-standard", 30, 3, 1, base.Add(12*time.Hour).Format(time.RFC3339), base.Add(-2*time.Hour).Format(time.RFC3339),
	)
	require.NoError(t, err)
}

func TestRunVoucherAnalyticsExportCycleAndListVoucherAnalyticsExports(t *testing.T) {
	prepareSupportBundleTestConfig(t)
	cfg := config.Get()
	require.NotNil(t, cfg)
	exportDir := filepath.Join(t.TempDir(), "voucher-analytics-exports")
	cfg.Telemetry.VoucherAnalyticsExports = config.DiagnosticsExportConfig{
		Enabled:         true,
		Directory:       exportDir,
		Format:          "both",
		IntervalMinutes: 60,
		RetentionCount:  2,
	}

	seedVoucherAnalyticsExportTestData(t)

	now := time.Date(2026, 6, 6, 11, 45, 0, 0, time.UTC)
	origNow := voucherAnalyticsExportNow
	voucherAnalyticsExportNow = func() time.Time { return now }
	t.Cleanup(func() {
		voucherAnalyticsExportNow = origNow
	})

	runVoucherAnalyticsExportCycle(context.Background(), cfg)

	runtimeStatus, err := db.GetRuntimeStatus(voucherAnalyticsExportsComponent)
	require.NoError(t, err)
	require.NotNil(t, runtimeStatus)
	assert.Equal(t, "ok", runtimeStatus.Status)
	assert.Equal(t, now.Format(time.RFC3339), runtimeStatus.Details["last_export_at"])
	assert.EqualValues(t, defaultVoucherAnalyticsWindowHours, runtimeStatus.Details["window_hours"])
	assert.EqualValues(t, defaultVoucherAnalyticsBucketCount, runtimeStatus.Details["bucket_count"])

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/voucher-analytics-exports", nil)
	rec := httptest.NewRecorder()
	HandleListVoucherAnalyticsExports(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var payload struct {
		Runtime *db.RuntimeStatus                `json:"runtime"`
		Exports []VoucherAnalyticsExportArtifact `json:"exports"`
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

func TestHandleDownloadVoucherAnalyticsExport(t *testing.T) {
	prepareSupportBundleTestConfig(t)
	cfg := config.Get()
	require.NotNil(t, cfg)
	exportDir := filepath.Join(t.TempDir(), "voucher-analytics-export-downloads")
	cfg.Telemetry.VoucherAnalyticsExports = config.DiagnosticsExportConfig{
		Enabled:         true,
		Directory:       exportDir,
		Format:          "json",
		IntervalMinutes: 60,
		RetentionCount:  2,
	}

	seedVoucherAnalyticsExportTestData(t)

	now := time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC)
	origNow := voucherAnalyticsExportNow
	voucherAnalyticsExportNow = func() time.Time { return now }
	t.Cleanup(func() {
		voucherAnalyticsExportNow = origNow
	})

	runVoucherAnalyticsExportCycle(context.Background(), cfg)

	artifacts, err := listVoucherAnalyticsExportArtifacts(cfg)
	require.NoError(t, err)
	require.Len(t, artifacts, 1)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/voucher-analytics-exports/download?name="+artifacts[0].Name, nil)
	rec := httptest.NewRecorder()
	HandleDownloadVoucherAnalyticsExport(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Header().Get("Content-Disposition"), artifacts[0].Name)
	assert.Contains(t, rec.Body.String(), `"summary"`)
	assert.Contains(t, rec.Body.String(), `"total_vouchers"`)
}
