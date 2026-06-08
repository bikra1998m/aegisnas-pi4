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

func TestHandleGetVoucherExpiryAnalytics(t *testing.T) {
	seedVoucherExpiryAnalyticsRows(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/voucher-expiry-analytics?window_hours=168&bucket_count=7", nil)
	rec := httptest.NewRecorder()
	HandleGetVoucherExpiryAnalytics(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var payload struct {
		WindowHours int                     `json:"window_hours"`
		BucketCount int                     `json:"bucket_count"`
		Summary     db.VoucherExpirySummary `json:"summary"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, 168, payload.WindowHours)
	assert.Equal(t, 7, payload.BucketCount)
	assert.Equal(t, 3, payload.Summary.ExpiringInWindowCount)
	assert.Equal(t, 1, payload.Summary.UnusedExpiringInWindowCount)
	assert.Equal(t, 1, payload.Summary.ExpiredUnusedCount)
}

func TestHandleExportVoucherExpiryAnalyticsCSV(t *testing.T) {
	seedVoucherExpiryAnalyticsRows(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/voucher-expiry-analytics/export?format=csv&window_hours=168&bucket_count=7", nil)
	rec := httptest.NewRecorder()
	HandleExportVoucherExpiryAnalytics(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/csv; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Header().Get("Content-Disposition"), "aegisnas-voucher-expiry-analytics-168h.csv")

	rows, err := csv.NewReader(strings.NewReader(rec.Body.String())).ReadAll()
	require.NoError(t, err)
	require.NotEmpty(t, rows)
	assert.Contains(t, rec.Body.String(), "summary,expiring_in_window_count")
	assert.Contains(t, rec.Body.String(), "unused_role,guest-basic")
	assert.Contains(t, rec.Body.String(), "bucket,remaining_uses")
}

func TestHandleExportVoucherExpiryAnalyticsRejectsUnsupportedFormat(t *testing.T) {
	seedVoucherExpiryAnalyticsRows(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/voucher-expiry-analytics/export?format=xml", nil)
	rec := httptest.NewRecorder()
	HandleExportVoucherExpiryAnalytics(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "unsupported export format")
}

func seedVoucherExpiryAnalyticsRows(t *testing.T) {
	t.Helper()

	tmpfile, err := os.CreateTemp("", "voucher-expiry-analytics-adminapi-*.db")
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
		(?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?)`,
		"VE-001", "guest-basic", 1440, 1, 0, now.Add(6*time.Hour).Format(time.RFC3339), now.Add(-24*time.Hour).Format(time.RFC3339),
		"VE-002", "guest-basic", 720, 5, 2, now.Add(48*time.Hour).Format(time.RFC3339), now.Add(-48*time.Hour).Format(time.RFC3339),
		"VE-003", "guest-vip", 60, 2, 2, now.Add(72*time.Hour).Format(time.RFC3339), now.Add(-72*time.Hour).Format(time.RFC3339),
		"VE-004", "guest-basic", 1440, 1, 0, now.Add(-6*time.Hour).Format(time.RFC3339), now.Add(-96*time.Hour).Format(time.RFC3339),
		"VE-005", "guest-standard", 30, 3, 1, "", now.Add(-3*time.Hour).Format(time.RFC3339),
		"VE-006", "guest-basic", 1440, 3, 1, now.Add(20*24*time.Hour).Format(time.RFC3339), now.Add(-12*time.Hour).Format(time.RFC3339),
	)
	require.NoError(t, err)
}
