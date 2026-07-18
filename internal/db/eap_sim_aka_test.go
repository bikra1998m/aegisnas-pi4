package db

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSIMAKAEventsRecordListAndSummarize(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "eap-sim-aka-*.db")
	require.NoError(t, err)
	dbPath := tmpfile.Name()
	require.NoError(t, tmpfile.Close())
	defer os.Remove(dbPath)
	require.NoError(t, Init(dbPath))
	defer Close()
	require.NoError(t, Migrate())

	require.NoError(t, RecordSIMAKAEvent(SIMAKAEvent{
		ObservedAt:              time.Now().UTC().Add(-time.Minute),
		Method:                  "sim",
		Decision:                "rejected",
		Reason:                  "SIM/AKA authentication vector is missing",
		NASIdentifier:           "ap-1",
		NASType:                 "carrier-offload",
		IdentityHash:            HashEAPIdentity("001010123456789"),
		PermanentIdentityHash:   HashEAPIdentity("001010123456789"),
		VectorProvider:          "external-http",
		VectorProviderAvailable: true,
		VectorFresh:             true,
		TripletCount:            1,
		PolicyMode:              "enforce",
		Details:                 map[string]string{"case": "missing-vector"},
	}, 10))
	require.NoError(t, RecordSIMAKAEvent(SIMAKAEvent{
		ObservedAt:              time.Now().UTC(),
		Method:                  "aka-prime",
		Decision:                "accepted",
		Reason:                  "SIM/AKA exchange satisfies policy",
		NASIdentifier:           "ap-2",
		NASType:                 "carrier-offload",
		IdentityHash:            HashEAPIdentity("anonymous@realm.example"),
		PseudonymIdentityHash:   HashEAPIdentity("pseudonym-1"),
		VectorProvider:          "external-http",
		VectorProviderAvailable: true,
		VectorAvailable:         true,
		VectorFresh:             true,
		QuintupletCount:         1,
		RESValid:                true,
		MACValid:                true,
		AUTNValid:               true,
		NetworkNameHash:         HashEAPIdentity("wlan.mnc001.mcc001.3gppnetwork.org"),
		KDFValid:                true,
		PolicyMode:              "enforce",
	}, 10))

	events, err := ListSIMAKAEvents(SIMAKAEventFilter{Method: "aka-prime", Limit: 10})
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "accepted", events[0].Decision)
	assert.NotContains(t, events[0].IdentityHash, "anonymous")
	assert.True(t, events[0].KDFValid)

	summary, err := SummarizeSIMAKAEvents(10)
	require.NoError(t, err)
	assert.Equal(t, 2, summary.TotalEvents)
	assert.Equal(t, 1, summary.Accepted)
	assert.Equal(t, 1, summary.Rejected)
	assert.Equal(t, 1, summary.MissingVector)
	assert.Equal(t, "SIM/AKA authentication vector is missing", summary.LastRejectedReason)
	assert.Equal(t, 1, summary.ByMethod["sim"])
	assert.Equal(t, 1, summary.ByMethod["aka-prime"])
}

func TestSIMAKAEventsRetention(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "eap-sim-aka-retention-*.db")
	require.NoError(t, err)
	dbPath := tmpfile.Name()
	require.NoError(t, tmpfile.Close())
	defer os.Remove(dbPath)
	require.NoError(t, Init(dbPath))
	defer Close()
	require.NoError(t, Migrate())

	for i := 0; i < 4; i++ {
		require.NoError(t, RecordSIMAKAEvent(SIMAKAEvent{
			ObservedAt: time.Now().UTC().Add(time.Duration(i) * time.Second),
			Method:     "sim",
			Decision:   "accepted",
			Reason:     "SIM/AKA exchange satisfies policy",
		}, 2))
	}
	summary, err := SummarizeSIMAKAEvents(10)
	require.NoError(t, err)
	assert.Equal(t, 2, summary.TotalEvents)
}
