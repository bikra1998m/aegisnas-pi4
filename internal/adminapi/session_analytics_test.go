package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestHandleGetSessionAnalytics(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "session-analytics-api-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	require.NoError(t, db.Init(tmpfile.Name()))
	defer db.Close()
	require.NoError(t, db.Migrate())

	now := time.Now().UTC().Truncate(time.Second)
	startOne := now.Add(-50 * time.Minute).Format(time.RFC3339)
	lastOne := now.Add(-21 * time.Minute).Format(time.RFC3339)
	endOne := now.Add(-20 * time.Minute).Format(time.RFC3339)
	startTwo := now.Add(-40 * time.Minute).Format(time.RFC3339)
	lastTwo := now.Add(-5 * time.Minute).Format(time.RFC3339)

	_, err = db.DB.Exec(`INSERT INTO sessions (
		id, username, mac, ip, auth_method, role, vlan, start_time, last_activity, end_time, bytes_in, bytes_out, acct_session_time
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"session-1", "alice", "aa:bb:cc:dd:ee:01", "192.168.50.101", "dot1x", "employee", 20,
		startOne, lastOne, endOne, 1024, 2048, 1800,
	)
	require.NoError(t, err)
	_, err = db.DB.Exec(`INSERT INTO sessions (
		id, username, mac, ip, auth_method, role, vlan, start_time, last_activity, bytes_in, bytes_out, acct_session_time
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"session-2", "bob", "aa:bb:cc:dd:ee:02", "192.168.50.102", "mab", "guest-basic", 30,
		startTwo, lastTwo, 512, 1024, 1200,
	)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/session-analytics?window_hours=2&bucket_count=4", nil)
	rec := httptest.NewRecorder()
	HandleGetSessionAnalytics(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var payload struct {
		WindowHours int                        `json:"window_hours"`
		BucketCount int                        `json:"bucket_count"`
		Summary     db.SessionAnalyticsSummary `json:"summary"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, 2, payload.WindowHours)
	assert.Equal(t, 4, payload.BucketCount)
	assert.Equal(t, 2, payload.Summary.TotalRecords)
	assert.Equal(t, 1, payload.Summary.ActiveNow)
	assert.Equal(t, 2, payload.Summary.StartedCount)
	assert.Equal(t, 1, payload.Summary.EndedCount)
	assert.Equal(t, int64(3072), payload.Summary.EndedTrafficTotal)
	require.Len(t, payload.Summary.Buckets, 4)
	totalStarted := 0
	for _, bucket := range payload.Summary.Buckets {
		totalStarted += bucket.StartedCount
	}
	assert.Equal(t, 2, totalStarted)
}

func TestHandleExportSessionAnalyticsCSV(t *testing.T) {
	summary := db.SessionAnalyticsSummary{
		WindowHours:       24,
		BucketCount:       2,
		BucketMinutes:     720,
		TotalRecords:      3,
		StartedCount:      2,
		EndedCount:        1,
		ActiveNow:         2,
		UniqueUsersWindow: 2,
		AuthMethods: []db.SessionAnalyticsCount{
			{Name: "dot1x", Count: 2},
		},
		Buckets: []db.SessionAnalyticsBucket{
			{Start: "2026-05-24T12:00:00Z", End: "2026-05-25T00:00:00Z", StartedCount: 1},
			{Start: "2026-05-25T00:00:00Z", End: "2026-05-25T12:00:00Z", EndedCount: 1, EndedTrafficTotal: 3072, EndedSessionSecondsTotal: 1800},
		},
	}

	payload, err := sessionAnalyticsCSV(summary)
	require.NoError(t, err)
	assert.Contains(t, string(payload), "summary,total_records")
	assert.Contains(t, string(payload), "auth_method,dot1x")
	assert.Contains(t, string(payload), "bucket,ended_traffic_total,2026-05-25T00:00:00Z,2026-05-25T12:00:00Z,,3072,")
}

func TestHandleExportSessionAnalyticsRejectsUnsupportedFormat(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "session-analytics-export-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	require.NoError(t, db.Init(tmpfile.Name()))
	defer db.Close()
	require.NoError(t, db.Migrate())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/session-analytics/export?format=xml", nil)
	rec := httptest.NewRecorder()
	HandleExportSessionAnalytics(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "unsupported export format")
}
