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

func TestHandleGetVoucherAgingAnalytics(t *testing.T) {
	seedVoucherAgingAnalyticsRows(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/voucher-aging-analytics?window_hours=168&bucket_count=7", nil)
	rec := httptest.NewRecorder()
	HandleGetVoucherAgingAnalytics(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var payload struct {
		WindowHours int                    `json:"window_hours"`
		BucketCount int                    `json:"bucket_count"`
		Summary     db.VoucherAgingSummary `json:"summary"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, 168, payload.WindowHours)
	assert.Equal(t, 7, payload.BucketCount)
	assert.Equal(t, 3, payload.Summary.OlderThanWindowCount)
	assert.Equal(t, 2, payload.Summary.UnusedOlderThanWindowCount)
	assert.Equal(t, 1, payload.Summary.UnusedOlder30DaysCount)
}

func TestHandleExportVoucherAgingAnalyticsCSV(t *testing.T) {
	seedVoucherAgingAnalyticsRows(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/voucher-aging-analytics/export?format=csv&window_hours=168&bucket_count=7", nil)
	rec := httptest.NewRecorder()
	HandleExportVoucherAgingAnalytics(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/csv; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Header().Get("Content-Disposition"), "aegisnas-voucher-aging-analytics-168h.csv")

	rows, err := csv.NewReader(strings.NewReader(rec.Body.String())).ReadAll()
	require.NoError(t, err)
	require.NotEmpty(t, rows)
	assert.Contains(t, rec.Body.String(), "summary,older_than_window_count")
	assert.Contains(t, rec.Body.String(), "unused_older_role,guest-standard")
	assert.Contains(t, rec.Body.String(), "bucket,voucher_count")
}

func TestHandleExportVoucherAgingAnalyticsRejectsUnsupportedFormat(t *testing.T) {
	seedVoucherAgingAnalyticsRows(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/voucher-aging-analytics/export?format=xml", nil)
	rec := httptest.NewRecorder()
	HandleExportVoucherAgingAnalytics(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "unsupported export format")
}

func seedVoucherAgingAnalyticsRows(t *testing.T) {
	t.Helper()

	tmpfile, err := os.CreateTemp("", "voucher-aging-analytics-adminapi-*.db")
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
		"VA-001", "guest-basic", 1440, 1, 0, now.Add(48*time.Hour).Format(time.RFC3339), now.Add(-3*time.Hour).Format(time.RFC3339),
		"VA-002", "guest-basic", 720, 5, 2, now.Add(24*time.Hour).Format(time.RFC3339), now.Add(-48*time.Hour).Format(time.RFC3339),
		"VA-003", "guest-vip", 60, 2, 2, now.Add(-72*time.Hour).Format(time.RFC3339), now.Add(-13*24*time.Hour).Format(time.RFC3339),
		"VA-004", "guest-basic", 1440, 1, 0, now.Add(8*24*time.Hour).Format(time.RFC3339), now.Add(-8*24*time.Hour).Format(time.RFC3339),
		"VA-005", "guest-standard", 30, 3, 0, "", now.Add(-32*24*time.Hour).Format(time.RFC3339),
		"VA-006", "guest-basic", 1440, 3, 1, now.Add(18*24*time.Hour).Format(time.RFC3339), now.Add(-72*time.Hour).Format(time.RFC3339),
	)
	require.NoError(t, err)
}
