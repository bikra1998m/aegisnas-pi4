package db

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuditHistoryRoundTripAndStats(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "audit-history-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	require.NoError(t, tmpfile.Close())

	require.NoError(t, Init(tmpfile.Name()))
	defer Close()
	require.NoError(t, Migrate())

	now := time.Date(2026, 5, 21, 8, 0, 0, 0, time.UTC)
	_, err = DB.Exec(`INSERT INTO audit_logs (timestamp, user, action, details, result, ip_address) VALUES (?, ?, ?, ?, ?, ?)`,
		now, "ops-admin", "download_support_bundle", "bundle-1", "downloaded", "192.168.50.10")
	require.NoError(t, err)
	_, err = DB.Exec(`INSERT INTO audit_logs (timestamp, user, action, details, result, ip_address) VALUES (?, ?, ?, ?, ?, ?)`,
		now.Add(time.Minute), "ops-admin", "apply_network_services", "config.yaml", "applied", "192.168.50.10")
	require.NoError(t, err)
	_, err = DB.Exec(`INSERT INTO audit_logs (timestamp, user, action, details, result, ip_address) VALUES (?, ?, ?, ?, ?, ?)`,
		now.Add(2*time.Minute), "guest-admin", "guest_registration_approved", "guest-1", "approved", "192.168.50.11")
	require.NoError(t, err)

	history, err := ListAuditHistory("", "", 10)
	require.NoError(t, err)
	require.Len(t, history, 3)
	assert.Equal(t, "guest_registration_approved", history[0].Action)

	filtered, err := ListAuditHistory("ops-admin", "download_", 10)
	require.NoError(t, err)
	require.Len(t, filtered, 1)
	assert.Equal(t, "download_support_bundle", filtered[0].Action)

	stats, err := GetAuditHistoryStats()
	require.NoError(t, err)
	assert.Equal(t, 3, stats.TotalRecords)
	assert.Equal(t, 2, stats.UniqueUsers)
	assert.Equal(t, 1, stats.ExportActionCount)
	assert.Equal(t, 1, stats.NetworkActionCount)
	assert.Equal(t, 1, stats.GuestActionCount)
	assert.NotEmpty(t, stats.LastRecordedAt)
}
