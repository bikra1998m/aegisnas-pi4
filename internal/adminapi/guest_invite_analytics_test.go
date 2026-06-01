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

func TestHandleGetGuestInviteAnalytics(t *testing.T) {
	_ = prepareSupportBundleTestConfig(t)
	seedGuestLifecycleTestRows(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/guest-invite-analytics?window_hours=4&bucket_count=4", nil)
	rec := httptest.NewRecorder()
	HandleGetGuestInviteAnalytics(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var payload struct {
		WindowHours int                            `json:"window_hours"`
		BucketCount int                            `json:"bucket_count"`
		Summary     db.GuestInviteAnalyticsSummary `json:"summary"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, 4, payload.WindowHours)
	assert.Equal(t, 4, payload.BucketCount)
	assert.Equal(t, 3, payload.Summary.TotalRecords)
	assert.Equal(t, 2, payload.Summary.TrackedInviteRecordsCount)
	assert.Equal(t, 1, payload.Summary.InviteQueuedCount)
	assert.Equal(t, 1, payload.Summary.InviteSentCount)
	assert.Equal(t, 1, payload.Summary.InviteNotRequestedCount)
}

func TestHandleExportGuestInviteAnalyticsCSV(t *testing.T) {
	_ = prepareSupportBundleTestConfig(t)
	seedGuestLifecycleTestRows(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/guest-invite-analytics/export?format=csv&window_hours=4&bucket_count=4", nil)
	rec := httptest.NewRecorder()
	HandleExportGuestInviteAnalytics(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/csv; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Header().Get("Content-Disposition"), "aegisnas-guest-invite-analytics-4h.csv")
	assert.Contains(t, rec.Body.String(), "tracked_invite_records_count")
	assert.Contains(t, rec.Body.String(), "invite_status")
}

func TestHandleExportGuestInviteAnalyticsRejectsUnsupportedFormat(t *testing.T) {
	_ = prepareSupportBundleTestConfig(t)
	seedGuestLifecycleTestRows(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/guest-invite-analytics/export?format=xml", nil)
	rec := httptest.NewRecorder()
	HandleExportGuestInviteAnalytics(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "unsupported export format")
}
