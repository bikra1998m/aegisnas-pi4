package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestHandleGetGuestConversionAnalytics(t *testing.T) {
	_ = prepareSupportBundleTestConfig(t)
	seedGuestLifecycleTestRows(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/guest-conversion-analytics?window_hours=4&bucket_count=4", nil)
	rec := httptest.NewRecorder()
	HandleGetGuestConversionAnalytics(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var payload struct {
		WindowHours int                          `json:"window_hours"`
		BucketCount int                          `json:"bucket_count"`
		Summary     db.GuestConversionSummary    `json:"summary"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, 4, payload.WindowHours)
	assert.Equal(t, 4, payload.BucketCount)
	assert.Equal(t, 3, payload.Summary.TotalRecords)
	assert.Equal(t, 1, payload.Summary.OpenPendingCount)
	assert.Equal(t, 1, payload.Summary.ApprovedStageCount)
	assert.Equal(t, 1, payload.Summary.RejectedStageCount)
	assert.Equal(t, 1, payload.Summary.InviteQueuedCount)
	assert.Equal(t, 1, payload.Summary.InviteSentCount)
	assert.Equal(t, 0, payload.Summary.ApprovedWithoutSuccessfulInviteCount)
	assert.Equal(t, 1, payload.Summary.InvitedNotCompletedCount)
}

func TestHandleExportGuestConversionAnalyticsCSV(t *testing.T) {
	_ = prepareSupportBundleTestConfig(t)
	seedGuestLifecycleTestRows(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/guest-conversion-analytics/export?format=csv&window_hours=4&bucket_count=4", nil)
	rec := httptest.NewRecorder()
	HandleExportGuestConversionAnalytics(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/csv; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Header().Get("Content-Disposition"), "aegisnas-guest-conversion-analytics-4h.csv")
	assert.Contains(t, rec.Body.String(), "approved_without_successful_invite_count")
	assert.Contains(t, rec.Body.String(), "invite_completion_rate_percent")
}

func TestHandleExportGuestConversionAnalyticsRejectsUnsupportedFormat(t *testing.T) {
	_ = prepareSupportBundleTestConfig(t)
	seedGuestLifecycleTestRows(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/guest-conversion-analytics/export?format=xml", nil)
	rec := httptest.NewRecorder()
	HandleExportGuestConversionAnalytics(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "unsupported export format")
}
