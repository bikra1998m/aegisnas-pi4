package db

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHAHistoryRoundTripAndStats(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "ha-history-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	require.NoError(t, tmpfile.Close())

	require.NoError(t, Init(tmpfile.Name()))
	defer Close()
	require.NoError(t, Migrate())

	require.NoError(t, RecordHAHistory("peer_health", "failed", "Peer health probe failed.", "standby", "", map[string]any{"peer": "https://peer.example.test"}))
	require.NoError(t, RecordHAHistory("failover", "promoted", "Standby promoted after peer timeout.", "standby", "", map[string]any{"vip": "192.168.50.2"}))
	require.NoError(t, RecordHAHistory("vip_announcement", "sent", "Sent gratuitous ARP refresh for the HA virtual IP.", "active", "", map[string]any{"vip": "192.168.50.2"}))
	require.NoError(t, RecordHAHistory("replication_publish", "success", "Published shared HA replication package.", "active", "", map[string]any{"source_node": "active-node"}))
	require.NoError(t, RecordHAHistory("replication_stage", "staged", "Shared package staged on standby.", "standby", "ops-admin", map[string]any{"stage_id": "stage-001"}))
	require.NoError(t, RecordHAHistory("replication_activate", "activated", "Shared package activated on standby.", "standby", "ops-admin", map[string]any{"stage_id": "stage-001"}))

	history, err := ListHAHistory(10)
	require.NoError(t, err)
	require.Len(t, history, 6)
	assert.Equal(t, "replication_activate", history[0].EventType)

	stats, err := GetHAHistoryStats()
	require.NoError(t, err)
	assert.Equal(t, 6, stats.TotalRecords)
	assert.Equal(t, 1, stats.PeerFailures)
	assert.Equal(t, 1, stats.FailoverPromotions)
	assert.Equal(t, 1, stats.VIPAnnouncements)
	assert.Equal(t, 1, stats.ReplicationPublishes)
	assert.Equal(t, 1, stats.SharedStages)
	assert.Equal(t, 1, stats.Activations)
	assert.NotEmpty(t, stats.LastEventAt)
}

func TestEmptyHAHistoryStats(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "ha-history-empty-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	require.NoError(t, tmpfile.Close())

	require.NoError(t, Init(tmpfile.Name()))
	defer Close()
	require.NoError(t, Migrate())

	stats, err := GetHAHistoryStats()
	require.NoError(t, err)
	assert.Equal(t, 0, stats.TotalRecords)
	assert.Equal(t, 0, stats.FailoverPromotions)
	assert.Equal(t, 0, stats.VIPAnnouncements)
	assert.Equal(t, 0, stats.ReplicationFailures)
	assert.Empty(t, stats.LastEventAt)
}
