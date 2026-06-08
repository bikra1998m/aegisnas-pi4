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

func seedVoucherRedemptionAnalyticsExportTestData(t *testing.T) {
	t.Helper()

	base := time.Now().UTC()
	_, err := db.DB.Exec(`INSERT INTO vouchers (
		code, role, duration_minutes, usage_limit, used_count, expires_at, created_at
	) VALUES
		(?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?)`,
		"VR-001", "guest-basic", 1440, 1, 1, base.Add(48*time.Hour).Format(time.RFC3339), base.Add(-26*time.Hour).Format(time.RFC3339),
		"VR-002", "guest-basic", 720, 5, 2, base.Add(24*time.Hour).Format(time.RFC3339), base.Add(-27*time.Hour).Format(time.RFC3339),
		"VR-003", "guest-vip", 60, 2, 2, base.Add(24*time.Hour).Format(time.RFC3339), base.Add(-24*time.Hour).Add(-30*time.Minute).Format(time.RFC3339),
		"VR-004", "guest-basic", 1440, 1, 0, base.Add(-28*time.Hour).Format(time.RFC3339), base.Add(-29*time.Hour).Format(time.RFC3339),
		"VR-005", "guest-standard", 30, 3, 0, base.Add(72*time.Hour).Format(time.RFC3339), base.Add(-3*time.Hour).Format(time.RFC3339),
	)
	require.NoError(t, err)

	_, err = db.DB.Exec(`INSERT INTO sessions (
		id, username, mac, ip, auth_method, role, start_time, last_activity, end_time, bytes_in, bytes_out, acct_session_time
	) VALUES
		(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"vrs1", "voucher_VR-001", "aa:bb:cc:10:00:01", "192.168.50.20", "voucher", "guest-basic", base.Add(-24*time.Hour).Format(time.RFC3339), base.Add(-23*time.Hour).Add(-35*time.Minute).Format(time.RFC3339), base.Add(-23*time.Hour).Add(-30*time.Minute).Format(time.RFC3339), 100, 200, 1800,
		"vrs2", "voucher_VR-002", "aa:bb:cc:10:00:02", "192.168.50.21", "voucher", "guest-basic", base.Add(-26*time.Hour).Format(time.RFC3339), base.Add(-25*time.Hour).Add(-50*time.Minute).Format(time.RFC3339), base.Add(-25*time.Hour).Add(-40*time.Minute).Format(time.RFC3339), 50, 75, 1200,
		"vrs3", "voucher_VR-002", "aa:bb:cc:10:00:03", "192.168.50.22", "voucher", "guest-basic", base.Add(-2*time.Hour).Format(time.RFC3339), base.Add(-100*time.Minute).Format(time.RFC3339), "", 0, 0, 0,
		"vrs4", "voucher_VR-003", "aa:bb:cc:10:00:04", "192.168.50.23", "voucher", "guest-vip", base.Add(-20*time.Hour).Format(time.RFC3339), base.Add(-19*time.Hour).Add(-57*time.Minute).Format(time.RFC3339), base.Add(-19*time.Hour).Add(-55*time.Minute).Format(time.RFC3339), 500, 700, 300,
	)
	require.NoError(t, err)
}

func TestRunVoucherRedemptionAnalyticsExportCycleAndListVoucherRedemptionAnalyticsExports(t *testing.T) {
	prepareSupportBundleTestConfig(t)
	cfg := config.Get()
	require.NotNil(t, cfg)
	exportDir := filepath.Join(t.TempDir(), "voucher-redemption-analytics-exports")
	cfg.Telemetry.VoucherRedemptionAnalyticsExports = config.DiagnosticsExportConfig{
		Enabled:         true,
		Directory:       exportDir,
		Format:          "both",
		IntervalMinutes: 60,
		RetentionCount:  2,
	}

	seedVoucherRedemptionAnalyticsExportTestData(t)

	now := time.Date(2026, 6, 8, 11, 45, 0, 0, time.UTC)
	origNow := voucherRedemptionAnalyticsExportNow
	voucherRedemptionAnalyticsExportNow = func() time.Time { return now }
	t.Cleanup(func() {
		voucherRedemptionAnalyticsExportNow = origNow
	})

	runVoucherRedemptionAnalyticsExportCycle(context.Background(), cfg)

	runtimeStatus, err := db.GetRuntimeStatus(voucherRedemptionAnalyticsExportsComponent)
	require.NoError(t, err)
	require.NotNil(t, runtimeStatus)
	assert.Equal(t, "ok", runtimeStatus.Status)
	assert.Equal(t, now.Format(time.RFC3339), runtimeStatus.Details["last_export_at"])
	assert.EqualValues(t, defaultVoucherAnalyticsWindowHours, runtimeStatus.Details["window_hours"])
	assert.EqualValues(t, defaultVoucherAnalyticsBucketCount, runtimeStatus.Details["bucket_count"])

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/voucher-redemption-analytics-exports", nil)
	rec := httptest.NewRecorder()
	HandleListVoucherRedemptionAnalyticsExports(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var payload struct {
		Runtime *db.RuntimeStatus                          `json:"runtime"`
		Exports []VoucherRedemptionAnalyticsExportArtifact `json:"exports"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	require.NotNil(t, payload.Runtime)
	require.Len(t, payload.Exports, 2)
	assert.Equal(t, "ok", payload.Runtime.Status)
}

func TestHandleDownloadVoucherRedemptionAnalyticsExport(t *testing.T) {
	prepareSupportBundleTestConfig(t)
	cfg := config.Get()
	require.NotNil(t, cfg)
	exportDir := filepath.Join(t.TempDir(), "voucher-redemption-analytics-export-downloads")
	cfg.Telemetry.VoucherRedemptionAnalyticsExports = config.DiagnosticsExportConfig{
		Enabled:         true,
		Directory:       exportDir,
		Format:          "json",
		IntervalMinutes: 60,
		RetentionCount:  2,
	}

	seedVoucherRedemptionAnalyticsExportTestData(t)

	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	origNow := voucherRedemptionAnalyticsExportNow
	voucherRedemptionAnalyticsExportNow = func() time.Time { return now }
	t.Cleanup(func() {
		voucherRedemptionAnalyticsExportNow = origNow
	})

	runVoucherRedemptionAnalyticsExportCycle(context.Background(), cfg)

	artifacts, err := listVoucherRedemptionAnalyticsExportArtifacts(cfg)
	require.NoError(t, err)
	require.Len(t, artifacts, 1)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/voucher-redemption-analytics-exports/download?name="+artifacts[0].Name, nil)
	rec := httptest.NewRecorder()
	HandleDownloadVoucherRedemptionAnalyticsExport(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Header().Get("Content-Disposition"), artifacts[0].Name)
	assert.Contains(t, rec.Body.String(), `"summary"`)
	assert.Contains(t, rec.Body.String(), `"redeemed_voucher_count"`)
}
