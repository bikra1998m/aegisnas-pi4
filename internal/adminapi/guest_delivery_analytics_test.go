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

func TestHandleGetGuestDeliveryAnalytics(t *testing.T) {
	_ = prepareSupportBundleTestConfig(t)
	seedGuestLifecycleTestRows(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/guest-delivery-analytics?window_hours=4&bucket_count=4", nil)
	rec := httptest.NewRecorder()
	HandleGetGuestDeliveryAnalytics(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var payload struct {
		Status      string                           `json:"status"`
		Summary     db.GuestDeliveryAnalyticsSummary `json:"summary"`
		GeneratedAt string                           `json:"generated_at"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, "", payload.Status)
	assert.Equal(t, 3, payload.Summary.TotalRecords)
	assert.Equal(t, 1, payload.Summary.PendingSponsorApprovalCount)
	assert.Equal(t, 1, payload.Summary.ApprovalDeliveryFailedCount)
	assert.Equal(t, 1, payload.Summary.InviteQueuedCount)
	assert.Equal(t, 1, payload.Summary.InviteSentCount)
	assert.Equal(t, 2, payload.Summary.ApprovalDeliverySentCount)
	assert.NotEmpty(t, payload.GeneratedAt)
}

func TestHandleExportGuestDeliveryAnalyticsCSV(t *testing.T) {
	_ = prepareSupportBundleTestConfig(t)
	seedGuestLifecycleTestRows(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/guest-delivery-analytics/export?format=csv&window_hours=4&bucket_count=4", nil)
	rec := httptest.NewRecorder()
	HandleExportGuestDeliveryAnalytics(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/csv; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Header().Get("Content-Disposition"), "aegisnas-guest-delivery-analytics-4h.csv")

	rows, err := csv.NewReader(strings.NewReader(rec.Body.String())).ReadAll()
	require.NoError(t, err)
	require.NotEmpty(t, rows)
	assert.Contains(t, rec.Body.String(), "summary,pending_sponsor_approval_count")
	assert.Contains(t, rec.Body.String(), "approval_status,sent")
	assert.Contains(t, rec.Body.String(), "invite_status,queued")
	assert.Contains(t, rec.Body.String(), "bucket,invite_sent_count")
}

func TestHandleExportGuestDeliveryAnalyticsRejectsUnsupportedFormat(t *testing.T) {
	_ = prepareSupportBundleTestConfig(t)
	seedGuestLifecycleTestRows(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/guest-delivery-analytics/export?format=xml", nil)
	rec := httptest.NewRecorder()
	HandleExportGuestDeliveryAnalytics(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "unsupported export format")
}
