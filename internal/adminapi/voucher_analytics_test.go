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

func TestHandleGetVoucherAnalytics(t *testing.T) {
	seedVoucherAnalyticsRows(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/voucher-analytics?window_hours=48&bucket_count=4", nil)
	rec := httptest.NewRecorder()
	HandleGetVoucherAnalytics(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var payload struct {
		WindowHours int                        `json:"window_hours"`
		BucketCount int                        `json:"bucket_count"`
		Summary     db.VoucherAnalyticsSummary `json:"summary"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, 48, payload.WindowHours)
	assert.Equal(t, 4, payload.BucketCount)
	assert.Equal(t, 5, payload.Summary.TotalVouchers)
	assert.Equal(t, 2, payload.Summary.ActiveCount)
	assert.Equal(t, 1, payload.Summary.ExhaustedCount)
	assert.Equal(t, 2, payload.Summary.ExpiredCount)
}

func TestHandleExportVoucherAnalyticsCSV(t *testing.T) {
	seedVoucherAnalyticsRows(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/voucher-analytics/export?format=csv&window_hours=48&bucket_count=4", nil)
	rec := httptest.NewRecorder()
	HandleExportVoucherAnalytics(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/csv; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Header().Get("Content-Disposition"), "aegisnas-voucher-analytics-48h.csv")

	rows, err := csv.NewReader(strings.NewReader(rec.Body.String())).ReadAll()
	require.NoError(t, err)
	require.NotEmpty(t, rows)
	assert.Contains(t, rec.Body.String(), "summary,total_vouchers")
	assert.Contains(t, rec.Body.String(), "role,guest-basic")
	assert.Contains(t, rec.Body.String(), "state,active")
	assert.Contains(t, rec.Body.String(), "bucket,created_count")
}

func TestHandleExportVoucherAnalyticsRejectsUnsupportedFormat(t *testing.T) {
	seedVoucherAnalyticsRows(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/voucher-analytics/export?format=xml", nil)
	rec := httptest.NewRecorder()
	HandleExportVoucherAnalytics(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "unsupported export format")
}

func seedVoucherAnalyticsRows(t *testing.T) {
	t.Helper()

	tmpfile, err := os.CreateTemp("", "voucher-analytics-adminapi-*.db")
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
		"V-001", "guest-basic", 1440, 1, 0, now.Add(48*time.Hour).Format(time.RFC3339), now.Add(-3*time.Hour).Format(time.RFC3339),
		"V-002", "guest-basic", 720, 5, 2, now.Add(24*time.Hour).Format(time.RFC3339), now.Add(-6*time.Hour).Format(time.RFC3339),
		"V-003", "guest-vip", 60, 2, 2, now.Add(24*time.Hour).Format(time.RFC3339), now.Add(-21*time.Hour).Format(time.RFC3339),
		"V-004", "guest-basic", 1440, 1, 0, now.Add(-28*time.Hour).Format(time.RFC3339), now.Add(-29*time.Hour).Format(time.RFC3339),
		"V-005", "guest-standard", 30, 3, 3, now.Add(-1*time.Hour).Format(time.RFC3339), now.Add(-13*time.Hour).Format(time.RFC3339),
	)
	require.NoError(t, err)
}
