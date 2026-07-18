package db

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTEAPChainEventsRecordFilterSummarizeAndTrim(t *testing.T) {
	tmp, err := os.CreateTemp("", "aegis-teap-chain-*.db")
	require.NoError(t, err)
	path := tmp.Name()
	require.NoError(t, tmp.Close())
	t.Cleanup(func() { _ = os.Remove(path) })
	require.NoError(t, Init(path))
	t.Cleanup(func() { _ = Close() })
	require.NoError(t, Migrate())

	now := time.Now().UTC()
	require.NoError(t, RecordTEAPChainEvent(TEAPChainEvent{
		ObservedAt:          now.Add(-1 * time.Minute),
		Decision:            "rejected",
		Reason:              "TEAP Crypto-Binding TLV is required and must validate",
		ChainMode:           "machine_then_user",
		ChainState:          "rejected",
		NASIdentifier:       "ap-1",
		NASType:             "cisco",
		OuterIdentityHash:   HashEAPIdentity("anonymous@example.com"),
		UserIdentityHash:    HashEAPIdentity("alice@example.com"),
		MachineIdentityHash: HashEAPIdentity("host/laptop.example.com"),
		InnerMethod:         "mschapv2",
		IdentityTypePresent: true,
		EAPPayloadPresent:   true,
		StepCount:           2,
		TLSVersion:          "1.3",
		PolicyMode:          "enforce",
		Details:             map[string]string{"vector": "missing-cryptobinding"},
	}, 10))
	require.NoError(t, RecordTEAPChainEvent(TEAPChainEvent{
		ObservedAt:                now,
		Decision:                  "accepted",
		Reason:                    "TEAP chain satisfies policy",
		ChainMode:                 "machine_then_user",
		ChainState:                "complete",
		NASIdentifier:             "ap-1",
		NASType:                   "cisco",
		OuterIdentityHash:         HashEAPIdentity("anonymous@example.com"),
		UserIdentityHash:          HashEAPIdentity("alice@example.com"),
		MachineIdentityHash:       HashEAPIdentity("host/laptop.example.com"),
		InnerMethod:               "mschapv2",
		CryptoBindingValid:        true,
		IdentityTypePresent:       true,
		EAPPayloadPresent:         true,
		IntermediateResultPresent: true,
		IntermediateResultSuccess: true,
		FinalResultPresent:        true,
		FinalResultSuccess:        true,
		StepCount:                 2,
		TLSVersion:                "1.3",
		PolicyMode:                "enforce",
	}, 1))

	events, err := ListTEAPChainEvents(TEAPChainEventFilter{Decision: "accepted", NASType: "cisco", Limit: 5})
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "accepted", events[0].Decision)
	assert.Equal(t, "machine_then_user", events[0].ChainMode)
	assert.NotContains(t, events[0].UserIdentityHash, "alice")

	summary, err := SummarizeTEAPChainEvents(10)
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TotalEvents)
	assert.Equal(t, 1, summary.Accepted)
	assert.Equal(t, 0, summary.InvalidCryptoBinding)
}
