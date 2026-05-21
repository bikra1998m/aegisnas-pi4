package db

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntegrationHistoryRoundTripAndStats(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "integration-history-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	require.NoError(t, tmpfile.Close())

	require.NoError(t, Init(tmpfile.Name()))
	defer Close()
	require.NoError(t, Migrate())

	require.NoError(t, RecordIntegrationHistory("controller_automation", "ok", "Controller sync completed.", map[string]any{"adapter": "cisco-ise"}))
	require.NoError(t, RecordIntegrationHistory("controller_automation", "degraded", "Controller sync failed.", map[string]any{"error": "401"}))
	require.NoError(t, RecordIntegrationHistory("mdm_sync", "ok", "MDM sync completed.", map[string]any{"provider": "intune"}))
	require.NoError(t, RecordIntegrationHistory("posture_checks", "degraded", "Compliance webhook failed.", map[string]any{"source": "webhook"}))

	history, err := ListIntegrationHistory("", 10)
	require.NoError(t, err)
	require.Len(t, history, 4)
	assert.Equal(t, "posture_checks", history[0].Component)

	controllerHistory, err := ListIntegrationHistory("controller_automation", 10)
	require.NoError(t, err)
	require.Len(t, controllerHistory, 2)

	var details map[string]any
	require.NoError(t, json.Unmarshal(controllerHistory[0].Details, &details))
	assert.NotEmpty(t, details)

	stats, err := GetIntegrationHistoryStats()
	require.NoError(t, err)
	assert.Equal(t, 4, stats.TotalRecords)
	assert.Equal(t, 2, stats.ControllerEventCount)
	assert.Equal(t, 1, stats.ControllerSuccessCount)
	assert.Equal(t, 1, stats.ControllerFailureCount)
	assert.Equal(t, 1, stats.MDMSyncEventCount)
	assert.Equal(t, 1, stats.MDMSyncSuccessCount)
	assert.Equal(t, 0, stats.MDMSyncFailureCount)
	assert.Equal(t, 1, stats.PostureEventCount)
	assert.Equal(t, 0, stats.PostureSuccessCount)
	assert.Equal(t, 1, stats.PostureFailureCount)
	assert.NotEmpty(t, stats.LastEventAt)
}

func TestTrimIntegrationHistory(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "integration-history-trim-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	require.NoError(t, tmpfile.Close())

	require.NoError(t, Init(tmpfile.Name()))
	defer Close()
	require.NoError(t, Migrate())

	for idx := 0; idx < 12; idx++ {
		_, err := DB.Exec(`INSERT INTO integration_history (component, status, summary, details_json)
			VALUES (?, ?, ?, ?)`, "mdm_sync", "ok", "sync ok", `{"index":1}`)
		require.NoError(t, err)
	}
	require.NoError(t, trimIntegrationHistory(5))

	count, err := countIntegrationHistoryRows()
	require.NoError(t, err)
	assert.Equal(t, 5, count)
}
