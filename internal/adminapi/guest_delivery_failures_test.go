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

func TestHandleGetGuestDeliveryFailures(t *testing.T) {
	_ = prepareSupportBundleTestConfig(t)
	seedGuestLifecycleTestRows(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/guest-delivery-failures?window_hours=4&bucket_count=4", nil)
	rec := httptest.NewRecorder()
	HandleGetGuestDeliveryFailures(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var payload struct {
		Status      string                                  `json:"status"`
		Summary     db.GuestDeliveryFailureAnalyticsSummary `json:"summary"`
		GeneratedAt string                                  `json:"generated_at"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, "", payload.Status)
	assert.Equal(t, 3, payload.Summary.TotalRecords)
	assert.Equal(t, 1, payload.Summary.ApprovalDeliveryFailedCount)
	assert.Equal(t, 1, payload.Summary.PendingInviteQueueCount)
	assert.NotEmpty(t, payload.GeneratedAt)
}

func TestHandleExportGuestDeliveryFailuresCSV(t *testing.T) {
	_ = prepareSupportBundleTestConfig(t)
	seedGuestLifecycleTestRows(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/guest-delivery-failures/export?format=csv&window_hours=4&bucket_count=4", nil)
	rec := httptest.NewRecorder()
	HandleExportGuestDeliveryFailures(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/csv; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Header().Get("Content-Disposition"), "aegisnas-guest-delivery-failures-4h.csv")

	rows, err := csv.NewReader(strings.NewReader(rec.Body.String())).ReadAll()
	require.NoError(t, err)
	require.NotEmpty(t, rows)
	assert.Contains(t, rec.Body.String(), "summary,approval_delivery_failed_count")
	assert.Contains(t, rec.Body.String(), "approval_error,unspecified")
	assert.Contains(t, rec.Body.String(), "bucket,pending_invite_queue_count")
}

func TestHandleExportGuestDeliveryFailuresRejectsUnsupportedFormat(t *testing.T) {
	_ = prepareSupportBundleTestConfig(t)
	seedGuestLifecycleTestRows(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/guest-delivery-failures/export?format=xml", nil)
	rec := httptest.NewRecorder()
	HandleExportGuestDeliveryFailures(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "unsupported export format")
}
