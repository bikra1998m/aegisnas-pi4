package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPasspointLifecycleEventRecordListSummary(t *testing.T) {
	previousDB := DB
	require.NoError(t, Init(":memory:"))
	DB.SetMaxOpenConns(1)
	require.NoError(t, Migrate())
	t.Cleanup(func() {
		_ = Close()
		DB = previousDB
	})

	eventID, err := RecordPasspointLifecycleEvent(PasspointLifecycleEventInput{
		Operation:                 "apply",
		Status:                    "applied",
		ConfigPath:                "/tmp/hostapd.conf",
		HostapdConfigSHA256:       "sha256:abc",
		PlanFingerprint:           "sha256:def",
		SSIDCount:                 2,
		PasspointSSIDCount:        1,
		InterworkingSSIDCount:     1,
		HS20SSIDCount:             1,
		OSUProviderCount:          1,
		DomainNameCount:           2,
		RoamingConsortiumCount:    1,
		NAIRealmCount:             1,
		CellularNetworkCount:      1,
		ConnectionCapabilityCount: 1,
		DiagnosticCount:           0,
		SummaryJSON:               `{"passpoint_ssid_count":1}`,
		ReportJSON:                `{"feature_id":"NAS-0076"}`,
		Actor:                     "ops",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, eventID)

	events, err := ListPasspointLifecycleEvents(10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, eventID, events[0].EventID)
	assert.Equal(t, "apply", events[0].Operation)
	assert.Equal(t, "applied", events[0].Status)
	assert.Equal(t, 1, events[0].PasspointSSIDCount)
	assert.Equal(t, "ops", events[0].Actor)

	summary, err := GetPasspointLifecycleSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TotalEvents)
	assert.Equal(t, 1, summary.ApplyEvents)
	assert.Equal(t, 1, summary.AppliedCount)
	assert.Equal(t, 1, summary.LastPasspointSSIDCount)
	assert.Equal(t, 1, summary.LastHS20SSIDCount)
	assert.Equal(t, 1, summary.LastOSUProviderCount)
	assert.Equal(t, "sha256:def", summary.LastFingerprint)
}
