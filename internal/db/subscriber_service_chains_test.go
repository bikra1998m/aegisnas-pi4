package db

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSubscriberServiceChainActivationAndRollback(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "subscriber-services-*.db")
	require.NoError(t, err)
	require.NoError(t, tmpfile.Close())
	defer os.Remove(tmpfile.Name())

	require.NoError(t, Init(tmpfile.Name()))
	defer Close()
	_, _ = DB.Exec("PRAGMA synchronous = OFF")
	_, _ = DB.Exec("PRAGMA journal_mode = MEMORY")
	require.NoError(t, Migrate())

	servicesJSON := `[{"key":"data","type":"data","sequence":10,"accounting_class":"internet"},{"key":"qos","type":"qos","sequence":20,"optional":true}]`
	record, err := ActivateSubscriberServiceChain(SubscriberServiceActivationRequest{
		SessionID:        "sess-1",
		Username:         "Alice@example.com",
		CallingStationID: "AA:BB:CC:DD:EE:FF",
		Tenant:           "corp",
		PolicySetHash:    strings.Repeat("a", 64),
		RequestHash:      strings.Repeat("b", 64),
		ServiceChainHash: strings.Repeat("c", 64),
		ServiceCount:     2,
		RequiredCount:    1,
		OptionalCount:    1,
		DecisionJSON:     `{"allow":true}`,
		ServicesJSON:     servicesJSON,
		Actor:            "ops",
	})
	require.NoError(t, err)
	assert.Equal(t, SubscriberServiceChainStatusActive, record.Status)
	assert.Equal(t, 2, record.ActivatedCount)
	assert.NotEqual(t, "alice@example.com", record.UsernameHash)
	assert.NotEqual(t, "aa:bb:cc:dd:ee:ff", record.CallingStationHash)

	events, err := ListSubscriberServiceEvents(record.ChainID, 10)
	require.NoError(t, err)
	require.Len(t, events, 2)
	assert.Equal(t, "activate", events[0].EventType)

	summary, err := SummarizeSubscriberServiceChains()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TotalChains)
	assert.Equal(t, 2, summary.StartedAccounting)

	rolledBack, err := RollbackSubscriberServiceChain(record.ChainID, "super", "test rollback")
	require.NoError(t, err)
	assert.Equal(t, SubscriberServiceChainStatusRolledBack, rolledBack.Status)
	assert.Equal(t, 2, rolledBack.RolledBackCount)

	summary, err = SummarizeSubscriberServiceChains()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.RolledBackChains)
	assert.Equal(t, 0, summary.StartedAccounting)

	var accountingRows int
	require.NoError(t, DB.QueryRow(`SELECT COUNT(*) FROM subscriber_service_accounting WHERE chain_id = ? AND status = 'stopped'`, record.ChainID).Scan(&accountingRows))
	assert.Equal(t, 2, accountingRows)

	var stored []map[string]any
	require.NoError(t, json.Unmarshal([]byte(rolledBack.ServicesJSON), &stored))
	require.Len(t, stored, 2)
}
