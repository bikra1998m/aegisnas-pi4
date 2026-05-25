package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestHandleListSessionHistory(t *testing.T) {
	_ = prepareSupportBundleTestConfig(t)

	_, err := db.DB.Exec(`INSERT INTO sessions (
		id, username, mac, ip, auth_method, identity_source, vlan, role, bandwidth_profile, filter_id, radius_class,
		session_timeout, idle_timeout, acct_session_time, called_station_id, nas_identifier, radius_session_id,
		start_time, last_activity, end_time, stop_reason, bytes_in, bytes_out
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"session-1", "alice", "aa:bb:cc:dd:ee:01", "192.168.50.101", "dot1x", "ldap", 20, "employee", "gold", "corp", "class-1",
		3600, 600, 1800, "AP-1", "nas-1", "radius-1", "2026-05-25T08:00:00Z", "2026-05-25T08:20:00Z", "2026-05-25T08:30:00Z", "User-Request", 1024, 2048,
	)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/session-history?username=alice&auth_method=dot1x&active=false&limit=10", nil)
	rec := httptest.NewRecorder()
	HandleListSessionHistory(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var payload struct {
		GeneratedAt string                    `json:"generated_at"`
		Username    string                    `json:"username"`
		AuthMethod  string                    `json:"auth_method"`
		Active      *bool                     `json:"active"`
		History     []db.SessionHistoryRecord `json:"history"`
		Count       int                       `json:"count"`
		Stats       db.SessionHistoryStats    `json:"stats"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	require.NotEmpty(t, payload.GeneratedAt)
	assert.Equal(t, "alice", payload.Username)
	assert.Equal(t, "dot1x", payload.AuthMethod)
	require.NotNil(t, payload.Active)
	assert.False(t, *payload.Active)
	require.Len(t, payload.History, 1)
	assert.Equal(t, "session-1", payload.History[0].ID)
	assert.Equal(t, int64(3072), payload.History[0].TotalBytes)
	assert.Equal(t, 1, payload.Stats.TotalRecords)
	assert.Equal(t, 1, payload.Stats.EndedCount)
}

func TestHandleExportSessionHistoryCSV(t *testing.T) {
	_ = prepareSupportBundleTestConfig(t)

	_, err := db.DB.Exec(`INSERT INTO sessions (
		id, username, mac, ip, auth_method, identity_source, vlan, role, bandwidth_profile, radius_session_id,
		start_time, last_activity, bytes_in, bytes_out
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"session-2", "guest1", "aa:bb:cc:dd:ee:02", "192.168.50.102", "mab", "local", 30, "guest-basic", "bronze", "radius-2",
		"2026-05-25T09:00:00Z", "2026-05-25T09:05:00Z", 512, 256,
	)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/session-history/export?format=csv", nil)
	rec := httptest.NewRecorder()
	HandleExportSessionHistory(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/csv; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Header().Get("Content-Disposition"), "aegisnas-session-history")
	assert.Contains(t, rec.Body.String(), "radius_session_id")
	assert.Contains(t, rec.Body.String(), "session-2")
}

func TestHandleExportSessionHistoryRejectsUnsupportedFormat(t *testing.T) {
	_ = prepareSupportBundleTestConfig(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/session-history/export?format=xml", nil)
	rec := httptest.NewRecorder()
	HandleExportSessionHistory(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, strings.TrimSpace(rec.Body.String()), "unsupported export format")
}

func TestParseSessionHistoryActiveQueryValue(t *testing.T) {
	trueValue := parseSessionHistoryActiveQueryValue("true")
	require.NotNil(t, trueValue)
	assert.True(t, *trueValue)

	falseValue := parseSessionHistoryActiveQueryValue("false")
	require.NotNil(t, falseValue)
	assert.False(t, *falseValue)

	assert.Nil(t, parseSessionHistoryActiveQueryValue("maybe"))
}

func TestSessionHistoryJSONPayload(t *testing.T) {
	payload, err := sessionHistoryJSONPayload(
		db.SessionHistoryQuery{Username: "alice"},
		[]db.SessionHistoryRecord{{ID: "session-1", Username: "alice", StartTime: time.Now().UTC().Format(time.RFC3339)}},
		db.SessionHistoryStats{TotalRecords: 1},
	)
	require.NoError(t, err)
	assert.Contains(t, string(payload), `"username": "alice"`)
	assert.Contains(t, string(payload), `"total_records": 1`)
}
