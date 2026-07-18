package db

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMachineUserCorrelationsRecordListSummarizeAndState(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "eap-machine-user-*.db")
	require.NoError(t, err)
	dbPath := tmpfile.Name()
	require.NoError(t, tmpfile.Close())
	defer os.Remove(dbPath)
	require.NoError(t, Init(dbPath))
	defer Close()
	require.NoError(t, Migrate())

	event := MachineUserCorrelationEvent{
		ObservedAt:                time.Now().UTC(),
		Decision:                  "accepted",
		Reason:                    "machine and user authentication are correlated",
		CorrelationIDHash:         HashEAPIdentity("acct-123"),
		CorrelationMode:           "machine_then_user",
		CorrelationState:          "complete",
		NASIdentifier:             "ap-1",
		NASType:                   "cisco",
		CallingStationHash:        HashEAPIdentity("00-11-22-33-44-55"),
		MachineCallingStationHash: HashEAPIdentity("00-11-22-33-44-55"),
		UserCallingStationHash:    HashEAPIdentity("00-11-22-33-44-55"),
		OuterIdentityHash:         HashEAPIdentity("anonymous@example.com"),
		MachineIdentityHash:       HashEAPIdentity("host/laptop01.example.com"),
		UserIdentityHash:          HashEAPIdentity("alice@example.com"),
		IdentitySource:            "identity-failover",
		MachineMethod:             "teap",
		UserMethod:                "teap",
		MachineAuthenticated:      true,
		UserAuthenticated:         true,
		SameCallingStation:        true,
		SameNAS:                   true,
		MachineBeforeUser:         true,
		MachineAuthAgeSeconds:     300,
		UserAuthAgeSeconds:        30,
		MachineRole:               "managed-device",
		UserRole:                  "employee",
		EffectiveRole:             "employee",
		TEAPChainComplete:         true,
		IdentityTypePresent:       true,
		CryptoBindingValid:        true,
		PolicyMode:                "enforce",
		Details:                   map[string]string{"case": "accept"},
	}
	event.CorrelationKey = BuildMachineUserCorrelationKey(event.CorrelationIDHash, event.MachineIdentityHash, event.UserIdentityHash, event.CallingStationHash)
	require.NoError(t, RecordMachineUserCorrelationEvent(event, 10, 10))
	require.NoError(t, RecordMachineUserCorrelationEvent(MachineUserCorrelationEvent{
		ObservedAt:           time.Now().UTC().Add(time.Second),
		Decision:             "rejected",
		Reason:               "machine authentication evidence is stale",
		CorrelationMode:      "machine_then_user",
		CorrelationState:     "rejected",
		MachineIdentityHash:  HashEAPIdentity("host/laptop02.example.com"),
		UserIdentityHash:     HashEAPIdentity("bob@example.com"),
		CallingStationHash:   HashEAPIdentity("00-11-22-33-44-66"),
		StaleMachineAuth:     true,
		MachineAuthenticated: true,
		UserAuthenticated:    true,
		PolicyMode:           "enforce",
	}, 10, 10))

	events, err := ListMachineUserCorrelationEvents(MachineUserCorrelationFilter{Decision: "accepted", NASType: "cisco", Limit: 10})
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "accepted", events[0].Decision)
	assert.NotContains(t, events[0].UserIdentityHash, "alice")
	assert.True(t, events[0].MachineBeforeUser)

	state, err := ListMachineUserCorrelationState(10)
	require.NoError(t, err)
	require.Len(t, state, 2)
	assert.NotEmpty(t, state[0].CorrelationKey)

	summary, err := SummarizeMachineUserCorrelations(10)
	require.NoError(t, err)
	assert.Equal(t, 2, summary.TotalEvents)
	assert.Equal(t, 1, summary.Accepted)
	assert.Equal(t, 1, summary.Rejected)
	assert.Equal(t, 1, summary.StaleMachineAuth)
	assert.Equal(t, 2, summary.ActiveCorrelations)
	assert.Equal(t, 2, summary.ByCorrelationMode["machine_then_user"])
}

func TestMachineUserCorrelationRetention(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "eap-machine-user-retention-*.db")
	require.NoError(t, err)
	dbPath := tmpfile.Name()
	require.NoError(t, tmpfile.Close())
	defer os.Remove(dbPath)
	require.NoError(t, Init(dbPath))
	defer Close()
	require.NoError(t, Migrate())

	for i := 0; i < 4; i++ {
		require.NoError(t, RecordMachineUserCorrelationEvent(MachineUserCorrelationEvent{
			ObservedAt:          time.Now().UTC().Add(time.Duration(i) * time.Second),
			Decision:            "accepted",
			Reason:              "machine and user authentication are correlated",
			CorrelationMode:     "machine_then_user",
			CorrelationState:    "complete",
			MachineIdentityHash: HashEAPIdentity("host/laptop"),
			UserIdentityHash:    HashEAPIdentity("user"),
			CallingStationHash:  HashEAPIdentity("mac"),
		}, 2, 1))
	}
	summary, err := SummarizeMachineUserCorrelations(10)
	require.NoError(t, err)
	assert.Equal(t, 2, summary.TotalEvents)
	assert.Equal(t, 1, summary.ActiveCorrelations)
}
