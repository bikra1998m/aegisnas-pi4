package db

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecordAndListNetworkApplyHistory(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "network-history-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	require.NoError(t, Init(tmpfile.Name()))
	defer Close()
	require.NoError(t, Migrate())

	require.NoError(t, RecordNetworkApplyHistory("apply", "success", "all validation checks passed", "backup-1", "", "tester", map[string]any{
		"validation": map[string]any{"healthy": true},
	}))

	history, err := ListNetworkApplyHistory(10)
	require.NoError(t, err)
	require.Len(t, history, 1)
	assert.Equal(t, "apply", history[0].Action)
	assert.Equal(t, "success", history[0].Status)
	assert.Equal(t, "backup-1", history[0].BackupID)
	assert.NotEmpty(t, history[0].Details)

	require.NoError(t, RecordNetworkApplyHistory("apply", "failed", "validation failed", "backup-2", "", "tester", nil))
	require.NoError(t, RecordNetworkApplyHistory("apply", "pending_confirmation", "waiting for confirmation", "backup-3", "", "tester", nil))
	require.NoError(t, RecordNetworkApplyHistory("apply", "confirmed", "confirmed from UI", "backup-3", "", "tester", nil))
	require.NoError(t, RecordNetworkApplyHistory("rollback", "success", "restored snapshot", "", "backup-3", "tester", nil))
	require.NoError(t, RecordNetworkApplyHistory("apply", "auto_rolled_back", "restored after timeout", "backup-4", "backup-4", "system:auto-revert", nil))

	stats, err := GetNetworkApplyStats()
	require.NoError(t, err)
	assert.Equal(t, 6, stats.TotalRecords)
	assert.Equal(t, 1, stats.ApplySuccessCount)
	assert.Equal(t, 1, stats.ApplyFailureCount)
	assert.Equal(t, 1, stats.PendingConfirmationCount)
	assert.Equal(t, 1, stats.ConfirmedCount)
	assert.Equal(t, 1, stats.RollbackCount)
	assert.Equal(t, 1, stats.AutoRollbackCount)
}

func TestStoreAndListDHCPLeaseHistory(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "lease-history-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	require.NoError(t, Init(tmpfile.Name()))
	defer Close()
	require.NoError(t, Migrate())

	observedAt := time.Now().UTC().Add(-30 * time.Minute).Truncate(time.Second)
	require.NoError(t, StoreDHCPLeaseObservations(observedAt, []DHCPLeaseObservation{
		{
			MAC:              "aa:bb:cc:dd:ee:ff",
			IP:               "192.168.50.101",
			Hostname:         "guest-phone",
			ClientID:         "01:aa:bb:cc:dd:ee:ff",
			Reservation:      false,
			Expired:          false,
			ExpiresAt:        observedAt.Add(2 * time.Hour).Format(time.RFC3339),
			RemainingSeconds: 7200,
		},
	}))

	history, err := ListDHCPLeaseHistory(10)
	require.NoError(t, err)
	require.Len(t, history, 1)
	assert.Equal(t, observedAt.Format(time.RFC3339), history[0].ObservedAt)
	assert.Equal(t, "192.168.50.101", history[0].IP)
	assert.Equal(t, "guest-phone", history[0].Hostname)
	assert.False(t, history[0].Reservation)

	require.NoError(t, StoreDHCPLeaseObservations(observedAt.Add(30*time.Minute), []DHCPLeaseObservation{
		{
			MAC:              "aa:bb:cc:dd:ee:11",
			IP:               "192.168.50.102",
			Hostname:         "guest-laptop",
			ClientID:         "01:aa:bb:cc:dd:ee:11",
			Reservation:      true,
			Expired:          false,
			ExpiresAt:        observedAt.Add(3 * time.Hour).Format(time.RFC3339),
			RemainingSeconds: 9000,
		},
		{
			MAC:              "aa:bb:cc:dd:ee:ff",
			IP:               "192.168.50.101",
			Hostname:         "guest-phone",
			ClientID:         "01:aa:bb:cc:dd:ee:ff",
			Reservation:      false,
			Expired:          true,
			ExpiresAt:        observedAt.Add(-10 * time.Minute).Format(time.RFC3339),
			RemainingSeconds: 0,
		},
	}))

	summary, err := GetDHCPLeaseTrendSummary(24 * time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 3, summary.TotalRecords)
	assert.Equal(t, 2, summary.UniqueMACsWindow)
	assert.Equal(t, 2, summary.UniqueIPsWindow)
	assert.Equal(t, 2, summary.ActiveObservationsWindow)
	assert.Equal(t, 1, summary.ExpiredObservationsWindow)
	assert.Equal(t, 1, summary.ReservationObservationsWindow)
	assert.Equal(t, 2, summary.PeakConcurrentLeasesWindow)
}

func TestEmptyNetworkHistoryStats(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "network-history-empty-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	require.NoError(t, Init(tmpfile.Name()))
	defer Close()
	require.NoError(t, Migrate())

	stats, err := GetNetworkApplyStats()
	require.NoError(t, err)
	assert.Equal(t, 0, stats.TotalRecords)
	assert.Equal(t, 0, stats.ApplySuccessCount)
	assert.Equal(t, 0, stats.ApplyFailureCount)
	assert.Equal(t, 0, stats.RollbackCount)
	assert.Equal(t, 0, stats.AutoRollbackCount)

	summary, err := GetDHCPLeaseTrendSummary(24 * time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 0, summary.TotalRecords)
	assert.Equal(t, 0, summary.UniqueMACsWindow)
	assert.Equal(t, 0, summary.PeakConcurrentLeasesWindow)
}
