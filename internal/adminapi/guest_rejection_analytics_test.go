package adminapi

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestHandleGetGuestRejectionAnalytics(t *testing.T) {
	_ = prepareSupportBundleTestConfig(t)
	seedGuestLifecycleTestRows(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/guest-rejection-analytics?window_hours=4&bucket_count=4", nil)
	rec := httptest.NewRecorder()
	HandleGetGuestRejectionAnalytics(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var payload struct {
		Status      string                            `json:"status"`
		Summary     db.GuestRejectionAnalyticsSummary `json:"summary"`
		GeneratedAt string                            `json:"generated_at"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, "", payload.Status)
	assert.Equal(t, 3, payload.Summary.TotalRecords)
	assert.Equal(t, 1, payload.Summary.RejectedCount)
	assert.Equal(t, 1, payload.Summary.RejectedWithSponsorCount)
	assert.Equal(t, 1, payload.Summary.UniqueRejectionReasonsWindow)
	assert.NotEmpty(t, payload.GeneratedAt)
}

func TestHandleExportGuestRejectionAnalyticsCSV(t *testing.T) {
	_ = prepareSupportBundleTestConfig(t)
	seedGuestLifecycleTestRows(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/guest-rejection-analytics/export?format=csv&window_hours=4&bucket_count=4", nil)
	rec := httptest.NewRecorder()
	HandleExportGuestRejectionAnalytics(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/csv; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Header().Get("Content-Disposition"), "aegisnas-guest-rejection-analytics-4h.csv")

	rows, err := csv.NewReader(strings.NewReader(rec.Body.String())).ReadAll()
	require.NoError(t, err)
	require.NotEmpty(t, rows)
	assert.Contains(t, rec.Body.String(), "summary,rejected_count")
	assert.Contains(t, rec.Body.String(), "reason,")
	assert.Contains(t, rec.Body.String(), "bucket,rejected_after_approval_count")
}

func TestHandleExportGuestRejectionAnalyticsRejectsUnsupportedFormat(t *testing.T) {
	_ = prepareSupportBundleTestConfig(t)
	seedGuestLifecycleTestRows(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/guest-rejection-analytics/export?format=xml", nil)
	rec := httptest.NewRecorder()
	HandleExportGuestRejectionAnalytics(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "unsupported export format")
}
