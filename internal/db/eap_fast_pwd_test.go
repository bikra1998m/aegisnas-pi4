package db

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFASTPWDEventsRecordListAndSummarize(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "eap-fast-pwd-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	require.NoError(t, tmpfile.Close())

	require.NoError(t, Init(tmpfile.Name()))
	defer Close()
	require.NoError(t, Migrate())

	now := time.Now().UTC()
	require.NoError(t, RecordFASTPWDEvent(FASTPWDEvent{
		ObservedAt:               now.Add(-time.Second),
		Method:                   "fast",
		Decision:                 "rejected",
		Reason:                   "EAP-FAST PAC is required",
		NASIdentifier:            "ap-1",
		NASType:                  "cisco",
		IdentityHash:             HashEAPIdentity("alice@example.com"),
		CallingStationHash:       HashEAPIdentity("aa:bb:cc:dd:ee:ff"),
		IdentitySource:           "identity-failover",
		InnerMethod:              "mschapv2",
		CryptoBindingValid:       true,
		PACProvisioningRequested: true,
		Details:                  map[string]string{"test": "fast"},
	}, 10))
	require.NoError(t, RecordFASTPWDEvent(FASTPWDEvent{
		ObservedAt:         now,
		Method:             "pwd",
		Decision:           "accepted",
		Reason:             "EAP-PWD exchange satisfies policy",
		NASIdentifier:      "ap-2",
		NASType:            "aruba",
		IdentityHash:       HashEAPIdentity("bob@example.com"),
		IdentitySource:     "identity-failover",
		PasswordProofValid: true,
		PWDGroup:           19,
		PWDServerIDHash:    HashEAPIdentity("aegisnas-pwd"),
		PolicyMode:         "enforce",
		Details:            map[string]string{"test": "pwd"},
	}, 10))

	events, err := ListFASTPWDEvents(FASTPWDEventFilter{Method: "fast", Limit: 10})
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "fast", events[0].Method)
	assert.Equal(t, "rejected", events[0].Decision)
	assert.Equal(t, "fast", events[0].Details["test"])
	assert.NotContains(t, events[0].IdentityHash, "alice")

	summary, err := SummarizeFASTPWDEvents(10)
	require.NoError(t, err)
	assert.Equal(t, 2, summary.TotalEvents)
	assert.Equal(t, 1, summary.Accepted)
	assert.Equal(t, 1, summary.Rejected)
	assert.Equal(t, 1, summary.ByMethod["fast"])
	assert.Equal(t, 1, summary.ByMethod["pwd"])
	assert.Equal(t, 1, summary.MissingPAC)
	assert.NotEmpty(t, summary.LastEventAt)
}

func TestFASTPWDEventsRetention(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "eap-fast-pwd-retention-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	require.NoError(t, tmpfile.Close())

	require.NoError(t, Init(tmpfile.Name()))
	defer Close()
	require.NoError(t, Migrate())

	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		require.NoError(t, RecordFASTPWDEvent(FASTPWDEvent{
			ObservedAt: now.Add(time.Duration(i) * time.Second),
			Method:     "pwd",
			Decision:   "accepted",
			Reason:     "EAP-PWD exchange satisfies policy",
		}, 2))
	}
	summary, err := SummarizeFASTPWDEvents(10)
	require.NoError(t, err)
	assert.Equal(t, 2, summary.TotalEvents)
}
