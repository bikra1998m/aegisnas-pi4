package db

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEAPMethodEventsRecordFilterAndSummarize(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "eap-framework-*.db")
	require.NoError(t, err)
	dbPath := tmpfile.Name()
	require.NoError(t, tmpfile.Close())
	t.Cleanup(func() {
		Close()
		_ = os.Remove(dbPath)
	})
	require.NoError(t, Init(dbPath))
	require.NoError(t, Migrate())

	require.NoError(t, RecordEAPMethodEvent(EAPMethodEvent{
		ObservedAt:                  time.Now().UTC().Add(-time.Minute),
		Method:                      "peap",
		InnerMethod:                 "mschapv2",
		Decision:                    "accepted",
		Reason:                      "allowed",
		NASIdentifier:               "ap-1",
		NASType:                     "cisco",
		UserNameHash:                HashEAPIdentity("Alice@example.com"),
		CallingStationHash:          HashEAPIdentity("aa:bb:cc:dd:ee:ff"),
		IdentitySource:              "identity-failover",
		EAPMessagePresent:           true,
		MessageAuthenticatorPresent: true,
		PolicyMode:                  "enforce",
		Details:                     map[string]string{"test": "yes"},
	}, 10))
	require.NoError(t, RecordEAPMethodEvent(EAPMethodEvent{
		ObservedAt: time.Now().UTC(),
		Method:     "teap",
		Decision:   "unsupported",
		Reason:     "planned method",
		NASType:    "cisco",
		PolicyMode: "enforce",
	}, 10))

	events, err := ListEAPMethodEvents(EAPMethodEventFilter{Method: "peap", Limit: 10})
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "accepted", events[0].Decision)
	assert.Equal(t, "yes", events[0].Details["test"])
	assert.NotEmpty(t, events[0].UserNameHash)
	assert.NotContains(t, events[0].UserNameHash, "Alice")

	summary, err := SummarizeEAPMethodEvents(10)
	require.NoError(t, err)
	assert.Equal(t, 2, summary.TotalEvents)
	assert.Equal(t, 1, summary.Accepted)
	assert.Equal(t, 1, summary.Unsupported)
	assert.Equal(t, 1, summary.ByMethod["peap"])
	assert.Equal(t, "planned method", summary.LastRejectedReason)
}

func TestEAPMethodEventRetention(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "eap-framework-retention-*.db")
	require.NoError(t, err)
	dbPath := tmpfile.Name()
	require.NoError(t, tmpfile.Close())
	t.Cleanup(func() {
		Close()
		_ = os.Remove(dbPath)
	})
	require.NoError(t, Init(dbPath))
	require.NoError(t, Migrate())

	for i := 0; i < 5; i++ {
		require.NoError(t, RecordEAPMethodEvent(EAPMethodEvent{
			ObservedAt: time.Now().UTC().Add(time.Duration(i) * time.Second),
			Method:     "peap",
			Decision:   "accepted",
			Reason:     "allowed",
		}, 3))
	}
	events, err := ListEAPMethodEvents(EAPMethodEventFilter{Limit: 10})
	require.NoError(t, err)
	assert.Len(t, events, 3)
}
