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
}

func TestStoreAndListDHCPLeaseHistory(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "lease-history-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	require.NoError(t, Init(tmpfile.Name()))
	defer Close()
	require.NoError(t, Migrate())

	observedAt := time.Date(2026, 5, 4, 1, 2, 3, 0, time.UTC)
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
}
