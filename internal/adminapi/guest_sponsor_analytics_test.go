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

func TestHandleGetGuestSponsorAnalytics(t *testing.T) {
	_ = prepareSupportBundleTestConfig(t)
	seedGuestLifecycleTestRows(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/guest-sponsor-analytics?window_hours=4&bucket_count=4", nil)
	rec := httptest.NewRecorder()
	HandleGetGuestSponsorAnalytics(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var payload struct {
		Status      string                         `json:"status"`
		Summary     db.GuestSponsorApprovalSummary `json:"summary"`
		GeneratedAt string                         `json:"generated_at"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, "", payload.Status)
	assert.Equal(t, 3, payload.Summary.TotalRecords)
	assert.Equal(t, 3, payload.Summary.SponsorApprovalRequiredCount)
	assert.Equal(t, 1, payload.Summary.PendingSponsorApprovalCount)
	assert.Equal(t, 1, payload.Summary.ApprovedWithSponsorCount)
	assert.Equal(t, 1, payload.Summary.RejectedWithSponsorCount)
	assert.NotEmpty(t, payload.GeneratedAt)
}

func TestHandleExportGuestSponsorAnalyticsCSV(t *testing.T) {
	_ = prepareSupportBundleTestConfig(t)
	seedGuestLifecycleTestRows(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/guest-sponsor-analytics/export?format=csv&window_hours=4&bucket_count=4", nil)
	rec := httptest.NewRecorder()
	HandleExportGuestSponsorAnalytics(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/csv; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Header().Get("Content-Disposition"), "aegisnas-guest-sponsor-analytics-4h.csv")

	rows, err := csv.NewReader(strings.NewReader(rec.Body.String())).ReadAll()
	require.NoError(t, err)
	require.NotEmpty(t, rows)
	assert.Contains(t, rec.Body.String(), "summary,pending_sponsor_approval_count")
	assert.Contains(t, rec.Body.String(), "sponsor,pending_count")
	assert.Contains(t, rec.Body.String(), "bucket,pending_older_than_4_hours_count")
}

func TestHandleExportGuestSponsorAnalyticsRejectsUnsupportedFormat(t *testing.T) {
	_ = prepareSupportBundleTestConfig(t)
	seedGuestLifecycleTestRows(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/guest-sponsor-analytics/export?format=xml", nil)
	rec := httptest.NewRecorder()
	HandleExportGuestSponsorAnalytics(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "unsupported export format")
}
