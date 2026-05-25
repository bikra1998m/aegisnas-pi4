package db

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionHistoryRoundTripAndStats(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "session-history-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	require.NoError(t, Init(tmpfile.Name()))
	defer Close()
	require.NoError(t, Migrate())

	_, err = DB.Exec(`INSERT INTO local_users (username, password_hash, role, tenant) VALUES (?, ?, ?, ?)`, "alice", "hash", "guest-basic", "tenant-a")
	require.NoError(t, err)
	_, err = DB.Exec(`INSERT INTO device_inventory (mac, friendly_name, tenant, compliance_status, last_seen) VALUES (?, ?, ?, ?, datetime('now'))`, "aa:bb:cc:dd:ee:02", "tablet", "tenant-b", "compliant")
	require.NoError(t, err)

	_, err = DB.Exec(`INSERT INTO sessions (
		id, username, mac, ip, auth_method, identity_source, vlan, role, bandwidth_profile, filter_id, radius_class,
		session_timeout, idle_timeout, acct_session_time, called_station_id, nas_identifier, radius_session_id,
		start_time, last_activity, end_time, stop_reason, bytes_in, bytes_out
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"session-1", "alice", "aa:bb:cc:dd:ee:01", "192.168.50.101", "dot1x", "ldap", 20, "employee", "gold", "corp", "radius-class-1",
		3600, 600, 1800, "AP-1", "nas-1", "radius-1", "2026-05-25T08:00:00Z", "2026-05-25T08:30:00Z", "2026-05-25T08:31:00Z", "User-Request", 1024, 2048,
	)
	require.NoError(t, err)
	_, err = DB.Exec(`INSERT INTO sessions (
		id, username, mac, ip, auth_method, identity_source, vlan, role, bandwidth_profile, filter_id, radius_class,
		session_timeout, idle_timeout, acct_session_time, called_station_id, nas_identifier, radius_session_id,
		start_time, last_activity, bytes_in, bytes_out
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"session-2", "guest1", "aa:bb:cc:dd:ee:02", "192.168.50.102", "mab", "local", 30, "guest-basic", "bronze", "", "",
		1800, 300, 0, "AP-2", "nas-2", "radius-2", "2026-05-25T09:00:00Z", "2026-05-25T09:05:00Z", 0, 0,
	)
	require.NoError(t, err)

	history, err := ListSessionHistory(SessionHistoryQuery{Limit: 10})
	require.NoError(t, err)
	require.Len(t, history, 2)
	assert.Equal(t, "session-2", history[0].ID)
	assert.Equal(t, int64(3072), history[1].TotalBytes)
	assert.Equal(t, "ldap", history[1].IdentitySource)
	assert.Equal(t, "User-Request", history[1].StopReason)

	activeOnly := true
	activeHistory, err := ListSessionHistory(SessionHistoryQuery{ActiveOnly: &activeOnly, Limit: 10})
	require.NoError(t, err)
	require.Len(t, activeHistory, 1)
	assert.Equal(t, "session-2", activeHistory[0].ID)

	filtered, err := ListSessionHistory(SessionHistoryQuery{
		Username:     "alice",
		AuthMethod:   "dot1x",
		TenantScopes: []string{"tenant-a"},
		Limit:        10,
	})
	require.NoError(t, err)
	require.Len(t, filtered, 1)
	assert.Equal(t, "session-1", filtered[0].ID)

	tenantBStats, err := GetSessionHistoryStats(SessionHistoryQuery{TenantScopes: []string{"tenant-b"}})
	require.NoError(t, err)
	assert.Equal(t, 1, tenantBStats.TotalRecords)
	assert.Equal(t, 1, tenantBStats.ActiveCount)
	assert.Equal(t, int64(0), tenantBStats.TrafficTotal)

	stats, err := GetSessionHistoryStats(SessionHistoryQuery{})
	require.NoError(t, err)
	assert.Equal(t, 2, stats.TotalRecords)
	assert.Equal(t, 1, stats.ActiveCount)
	assert.Equal(t, 1, stats.EndedCount)
	assert.Equal(t, 1, stats.AccountedRecordCount)
	assert.Equal(t, int64(1024), stats.BytesInTotal)
	assert.Equal(t, int64(2048), stats.BytesOutTotal)
	assert.Equal(t, int64(3072), stats.TrafficTotal)
	assert.Equal(t, int64(1800), stats.AcctSessionSecondsTotal)
	assert.Equal(t, int64(900), stats.AvgAcctSessionSeconds)
	assert.Equal(t, int64(1800), stats.MaxAcctSessionSeconds)
	assert.Equal(t, "2026-05-25T09:00:00Z", stats.LastStartedAt)
	assert.Equal(t, "2026-05-25T08:31:00Z", stats.LastEndedAt)
}

func TestEmptySessionHistoryStats(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "session-history-empty-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	require.NoError(t, Init(tmpfile.Name()))
	defer Close()
	require.NoError(t, Migrate())

	history, err := ListSessionHistory(SessionHistoryQuery{Limit: 10})
	require.NoError(t, err)
	assert.Empty(t, history)

	stats, err := GetSessionHistoryStats(SessionHistoryQuery{})
	require.NoError(t, err)
	assert.Equal(t, 0, stats.TotalRecords)
	assert.Equal(t, 0, stats.ActiveCount)
	assert.Equal(t, 0, stats.EndedCount)
	assert.Equal(t, int64(0), stats.TrafficTotal)
	assert.Empty(t, stats.LastStartedAt)
	assert.Empty(t, stats.LastEndedAt)
}
