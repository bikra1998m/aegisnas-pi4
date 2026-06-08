package adminapi

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestHandleGetVoucherRedemptionAnalytics(t *testing.T) {
	seedVoucherRedemptionAnalyticsRows(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/voucher-redemption-analytics?window_hours=48&bucket_count=4", nil)
	rec := httptest.NewRecorder()
	HandleGetVoucherRedemptionAnalytics(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var payload struct {
		WindowHours int                         `json:"window_hours"`
		BucketCount int                         `json:"bucket_count"`
		Summary     db.VoucherRedemptionSummary `json:"summary"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, 48, payload.WindowHours)
	assert.Equal(t, 4, payload.BucketCount)
	assert.Equal(t, 3, payload.Summary.RedeemedVoucherCount)
	assert.Equal(t, 2, payload.Summary.NeverRedeemedCount)
	assert.Equal(t, 1, payload.Summary.ActiveSessionCount)
	assert.Equal(t, 3, payload.Summary.FirstRedeemedInWindowCount)
}

func TestHandleExportVoucherRedemptionAnalyticsCSV(t *testing.T) {
	seedVoucherRedemptionAnalyticsRows(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/voucher-redemption-analytics/export?format=csv&window_hours=48&bucket_count=4", nil)
	rec := httptest.NewRecorder()
	HandleExportVoucherRedemptionAnalytics(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/csv; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Header().Get("Content-Disposition"), "aegisnas-voucher-redemption-analytics-48h.csv")

	rows, err := csv.NewReader(strings.NewReader(rec.Body.String())).ReadAll()
	require.NoError(t, err)
	require.NotEmpty(t, rows)
	assert.Contains(t, rec.Body.String(), "summary,redeemed_voucher_count")
	assert.Contains(t, rec.Body.String(), "role,guest-basic")
	assert.Contains(t, rec.Body.String(), "bucket,first_redeemed_count")
}

func TestHandleExportVoucherRedemptionAnalyticsRejectsUnsupportedFormat(t *testing.T) {
	seedVoucherRedemptionAnalyticsRows(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/voucher-redemption-analytics/export?format=xml", nil)
	rec := httptest.NewRecorder()
	HandleExportVoucherRedemptionAnalytics(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "unsupported export format")
}

func seedVoucherRedemptionAnalyticsRows(t *testing.T) {
	t.Helper()

	tmpfile, err := os.CreateTemp("", "voucher-redemption-analytics-adminapi-*.db")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = os.Remove(tmpfile.Name())
	})
	require.NoError(t, tmpfile.Close())

	require.NoError(t, db.Init(tmpfile.Name()))
	t.Cleanup(func() {
		_ = db.Close()
	})
	require.NoError(t, db.Migrate())

	now := time.Now().UTC()

	_, err = db.DB.Exec(`INSERT INTO vouchers (
		code, role, duration_minutes, usage_limit, used_count, expires_at, created_at
	) VALUES
		(?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?)`,
		"V-001", "guest-basic", 1440, 1, 1, now.Add(48*time.Hour).Format(time.RFC3339), now.Add(-26*time.Hour).Format(time.RFC3339),
		"V-002", "guest-basic", 720, 5, 2, now.Add(24*time.Hour).Format(time.RFC3339), now.Add(-27*time.Hour).Format(time.RFC3339),
		"V-003", "guest-vip", 60, 2, 2, now.Add(24*time.Hour).Format(time.RFC3339), now.Add(-24*time.Hour).Add(-30*time.Minute).Format(time.RFC3339),
		"V-004", "guest-basic", 1440, 1, 0, now.Add(-28*time.Hour).Format(time.RFC3339), now.Add(-29*time.Hour).Format(time.RFC3339),
		"V-005", "guest-standard", 30, 3, 0, now.Add(72*time.Hour).Format(time.RFC3339), now.Add(-3*time.Hour).Format(time.RFC3339),
	)
	require.NoError(t, err)

	_, err = db.DB.Exec(`INSERT INTO sessions (
		id, username, mac, ip, auth_method, role, start_time, last_activity, end_time, bytes_in, bytes_out, acct_session_time
	) VALUES
		(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"s1", "voucher_V-001", "aa:bb:cc:00:00:01", "192.168.50.10", "voucher", "guest-basic", now.Add(-24*time.Hour).Format(time.RFC3339), now.Add(-23*time.Hour).Add(-35*time.Minute).Format(time.RFC3339), now.Add(-23*time.Hour).Add(-30*time.Minute).Format(time.RFC3339), 100, 200, 1800,
		"s2", "voucher_V-002", "aa:bb:cc:00:00:02", "192.168.50.11", "voucher", "guest-basic", now.Add(-26*time.Hour).Format(time.RFC3339), now.Add(-25*time.Hour).Add(-50*time.Minute).Format(time.RFC3339), now.Add(-25*time.Hour).Add(-40*time.Minute).Format(time.RFC3339), 50, 75, 1200,
		"s3", "voucher_V-002", "aa:bb:cc:00:00:03", "192.168.50.12", "voucher", "guest-basic", now.Add(-2*time.Hour).Format(time.RFC3339), now.Add(-100*time.Minute).Format(time.RFC3339), "", 0, 0, 0,
		"s4", "voucher_V-003", "aa:bb:cc:00:00:04", "192.168.50.13", "voucher", "guest-vip", now.Add(-20*time.Hour).Format(time.RFC3339), now.Add(-19*time.Hour).Add(-57*time.Minute).Format(time.RFC3339), now.Add(-19*time.Hour).Add(-55*time.Minute).Format(time.RFC3339), 500, 700, 300,
	)
	require.NoError(t, err)
}
