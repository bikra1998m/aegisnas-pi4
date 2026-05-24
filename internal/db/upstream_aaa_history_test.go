package db

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpstreamAAAHistoryRoundTripAndStats(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "upstream-aaa-history-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	require.NoError(t, tmpfile.Close())

	require.NoError(t, Init(tmpfile.Name()))
	defer Close()
	require.NoError(t, Migrate())

	require.NoError(t, RecordUpstreamAAAHistory("primary", "10.0.0.10", 1812, 1813, "ok", "upstream alive", "Access-Accept", 14, true, "2026-05-23T10:00:00Z"))
	require.NoError(t, RecordUpstreamAAAHistory("primary", "10.0.0.10", 1812, 1813, "degraded", "unexpected response", "Access-Reject", 18, true, "2026-05-23T10:05:00Z"))
	require.NoError(t, RecordUpstreamAAAHistory("secondary", "10.0.0.11", 1812, 1813, "down", "i/o timeout", "", 0, true, "2026-05-23T10:06:00Z"))
	require.NoError(t, RecordUpstreamAAAHistory("secondary", "10.0.0.11", 1812, 1813, "disabled", "status-server disabled", "", 0, false, "2026-05-23T10:07:00Z"))

	history, err := ListUpstreamAAAHistory("", "", 10)
	require.NoError(t, err)
	require.Len(t, history, 4)
	assert.Equal(t, "secondary", history[0].ServerName)
	assert.Equal(t, "disabled", history[0].Status)

	primaryHistory, err := ListUpstreamAAAHistory("primary", "", 10)
	require.NoError(t, err)
	require.Len(t, primaryHistory, 2)

	degradedHistory, err := ListUpstreamAAAHistory("", "degraded", 10)
	require.NoError(t, err)
	require.Len(t, degradedHistory, 1)
	assert.Equal(t, "primary", degradedHistory[0].ServerName)

	stats, err := GetUpstreamAAAHistoryStats()
	require.NoError(t, err)
	assert.Equal(t, 4, stats.TotalRecords)
	assert.Equal(t, 1, stats.OKCount)
	assert.Equal(t, 1, stats.DegradedCount)
	assert.Equal(t, 1, stats.DownCount)
	assert.Equal(t, 1, stats.DisabledCount)
	assert.Equal(t, int64(16), stats.AvgLatencyMs)
	assert.Equal(t, "2026-05-23T10:07:00Z", stats.LastCheckedAt)
}

func TestTrimUpstreamAAAHistory(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "upstream-aaa-history-trim-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	require.NoError(t, tmpfile.Close())

	require.NoError(t, Init(tmpfile.Name()))
	defer Close()
	require.NoError(t, Migrate())

	for idx := 0; idx < 12; idx++ {
		require.NoError(t, RecordUpstreamAAAHistory("primary", "10.0.0.10", 1812, 1813, "ok", "upstream alive", "Access-Accept", int64(idx+1), true, "2026-05-23T10:00:00Z"))
	}
	require.NoError(t, trimUpstreamAAAHistory(5))

	count, err := countUpstreamAAAHistoryRows()
	require.NoError(t, err)
	assert.Equal(t, 5, count)
}
