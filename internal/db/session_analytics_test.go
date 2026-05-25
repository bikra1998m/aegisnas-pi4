package db

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetSessionAnalytics(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "session-analytics-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	require.NoError(t, Init(tmpfile.Name()))
	defer Close()
	require.NoError(t, Migrate())

	originalNow := sessionAnalyticsNow
	sessionAnalyticsNow = func() time.Time {
		return time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC)
	}
	defer func() {
		sessionAnalyticsNow = originalNow
	}()

	_, err = DB.Exec(`INSERT INTO local_users (username, password_hash, role, tenant) VALUES (?, ?, ?, ?)`, "alice", "hash", "employee", "tenant-a")
	require.NoError(t, err)
	_, err = DB.Exec(`INSERT INTO device_inventory (mac, friendly_name, tenant, compliance_status, last_seen) VALUES (?, ?, ?, ?, datetime('now'))`, "aa:bb:cc:dd:ee:02", "tablet", "tenant-b", "compliant")
	require.NoError(t, err)

	_, err = DB.Exec(`INSERT INTO sessions (
		id, username, mac, ip, auth_method, role, vlan, start_time, last_activity, end_time, bytes_in, bytes_out, acct_session_time
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"session-1", "alice", "aa:bb:cc:dd:ee:01", "192.168.50.101", "dot1x", "employee", 20,
		"2026-05-25T11:10:00Z", "2026-05-25T11:39:00Z", "2026-05-25T11:40:00Z", 1024, 2048, 1800,
	)
	require.NoError(t, err)
	_, err = DB.Exec(`INSERT INTO sessions (
		id, username, mac, ip, auth_method, role, vlan, start_time, last_activity, bytes_in, bytes_out, acct_session_time
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"session-2", "bob", "aa:bb:cc:dd:ee:02", "192.168.50.102", "mab", "guest-basic", 30,
		"2026-05-25T11:20:00Z", "2026-05-25T11:55:00Z", 512, 1024, 1200,
	)
	require.NoError(t, err)
	_, err = DB.Exec(`INSERT INTO sessions (
		id, username, mac, ip, auth_method, role, vlan, start_time, last_activity, end_time, bytes_in, bytes_out, acct_session_time
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"session-3", "carol", "aa:bb:cc:dd:ee:03", "192.168.50.103", "dot1x", "employee", 20,
		"2026-05-25T08:00:00Z", "2026-05-25T08:30:00Z", "2026-05-25T08:45:00Z", 300, 700, 2700,
	)
	require.NoError(t, err)

	summary, err := GetSessionAnalytics(SessionAnalyticsQuery{
		Window:      2 * time.Hour,
		BucketCount: 4,
	})
	require.NoError(t, err)

	assert.Equal(t, 2, summary.WindowHours)
	assert.Equal(t, 4, summary.BucketCount)
	assert.Equal(t, 30, summary.BucketMinutes)
	assert.Equal(t, 2, summary.TotalRecords)
	assert.Equal(t, 2, summary.StartedCount)
	assert.Equal(t, 1, summary.EndedCount)
	assert.Equal(t, 1, summary.ActiveNow)
	assert.Equal(t, 2, summary.UniqueUsersWindow)
	assert.Equal(t, 2, summary.UniqueMACsWindow)
	assert.Equal(t, 2, summary.UniqueIPsWindow)
	assert.Equal(t, int64(3072), summary.EndedTrafficTotal)
	assert.Equal(t, int64(1800), summary.EndedSessionSecondsTotal)
	assert.Equal(t, int64(1800), summary.AvgEndedSessionSeconds)
	assert.Equal(t, int64(1800), summary.MaxEndedSessionSeconds)
	assert.Equal(t, int64(2400), summary.LongestActiveSessionSeconds)
	assert.Equal(t, 2, summary.PeakConcurrentSessions)
	assert.Equal(t, "2026-05-25T11:20:00Z", summary.LatestStartAt)
	assert.Equal(t, "2026-05-25T11:40:00Z", summary.LatestEndAt)
	require.Len(t, summary.AuthMethods, 2)
	assert.Equal(t, "dot1x", summary.AuthMethods[0].Name)
	assert.Equal(t, 1, summary.AuthMethods[0].Count)
	require.Len(t, summary.Buckets, 4)
	assert.Equal(t, 0, summary.Buckets[0].StartedCount)
	assert.Equal(t, 0, summary.Buckets[1].StartedCount)
	assert.Equal(t, 2, summary.Buckets[2].StartedCount)
	assert.Equal(t, 1, summary.Buckets[3].EndedCount)
	assert.Equal(t, int64(3072), summary.Buckets[3].EndedTrafficTotal)
	assert.Equal(t, int64(1800), summary.Buckets[3].EndedSessionSecondsTotal)

	tenantOnly, err := GetSessionAnalytics(SessionAnalyticsQuery{
		TenantScopes: []string{"tenant-a"},
		Window:       2 * time.Hour,
		BucketCount:  4,
	})
	require.NoError(t, err)
	assert.Equal(t, 1, tenantOnly.TotalRecords)
	assert.Equal(t, 1, tenantOnly.EndedCount)
	assert.Equal(t, 0, tenantOnly.ActiveNow)
}
