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

func TestHandleGetGuestLifecycle(t *testing.T) {
	_ = prepareSupportBundleTestConfig(t)
	seedGuestLifecycleTestRows(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/guest-lifecycle?window_hours=4&bucket_count=4", nil)
	rec := httptest.NewRecorder()
	HandleGetGuestLifecycle(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var payload struct {
		Status      string                   `json:"status"`
		Count       int                      `json:"count"`
		History     []map[string]any         `json:"history"`
		Summary     db.GuestLifecycleSummary `json:"summary"`
		GeneratedAt string                   `json:"generated_at"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, "", payload.Status)
	assert.Equal(t, 3, payload.Count)
	require.Len(t, payload.History, 3)
	assert.Equal(t, 3, payload.Summary.TotalRecords)
	assert.Equal(t, 1, payload.Summary.PendingCount)
	assert.Equal(t, 1, payload.Summary.ApprovedCount)
	assert.Equal(t, 1, payload.Summary.RejectedCount)
	assert.Equal(t, 0, payload.Summary.CompletedCount)
	assert.Equal(t, 2, payload.Summary.ApprovalDeliverySentCount)
	assert.Equal(t, 1, payload.Summary.InviteSentCount)
	assert.NotEmpty(t, payload.GeneratedAt)
}

func TestHandleExportGuestLifecycleCSV(t *testing.T) {
	_ = prepareSupportBundleTestConfig(t)
	seedGuestLifecycleTestRows(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/guest-lifecycle/export?format=csv&window_hours=4&bucket_count=4", nil)
	rec := httptest.NewRecorder()
	HandleExportGuestLifecycle(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/csv; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Header().Get("Content-Disposition"), "aegisnas-guest-lifecycle-4h.csv")

	rows, err := csv.NewReader(strings.NewReader(rec.Body.String())).ReadAll()
	require.NoError(t, err)
	require.NotEmpty(t, rows)
	assert.Contains(t, rec.Body.String(), "summary,total_records")
	assert.Contains(t, rec.Body.String(), "bucket,submitted_count")
	assert.Contains(t, rec.Body.String(), "history,,,,,,guest-1,pending,Alice Guest")
}

func TestHandleExportGuestLifecycleRejectsUnsupportedFormat(t *testing.T) {
	_ = prepareSupportBundleTestConfig(t)
	seedGuestLifecycleTestRows(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/guest-lifecycle/export?format=xml", nil)
	rec := httptest.NewRecorder()
	HandleExportGuestLifecycle(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "unsupported export format")
}

func seedGuestLifecycleTestRows(t *testing.T) {
	t.Helper()

	_, err := db.DB.Exec(`INSERT INTO guest_registrations (
		id, status, tenant, full_name, email, sponsor_name, sponsor_email, role,
		guest_token_hash, approval_delivery_status, invite_delivery_status,
		created_at, approved_at, rejected_at, expires_at
	) VALUES
		(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"guest-1", "pending", "tenant-a", "Alice Guest", "alice@example.test", "Sam Sponsor", "sam@example.test", "guest-basic",
		"hash-1", "sent", "queued", "2026-05-25T11:30:00Z", "", "", "2026-05-26T11:30:00Z",
		"guest-2", "approved", "tenant-a", "Bob Visitor", "bob@example.test", "Taylor Sponsor", "taylor@example.test", "guest-basic",
		"hash-2", "sent", "sent", "2026-05-25T10:05:00Z", "2026-05-25T10:25:00Z", "", "2026-05-26T10:05:00Z",
		"guest-3", "rejected", "tenant-b", "Carla Declined", "carla@example.test", "Jordan Sponsor", "jordan@example.test", "guest-standard",
		"hash-3", "failed", "not_requested", "2026-05-25T09:10:00Z", "", "2026-05-25T09:20:00Z", "2026-05-26T09:10:00Z",
	)
	require.NoError(t, err)
}
