package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWirelessRoamingLifecycleEventSummary(t *testing.T) {
	require.NoError(t, Init(":memory:"))
	DB.SetMaxOpenConns(1)
	t.Cleanup(func() { Close() })
	require.NoError(t, Migrate())

	eventID, err := RecordWirelessRoamingLifecycleEvent(WirelessRoamingLifecycleEventInput{
		Operation:           "preview",
		Status:              "previewed",
		ConfigPath:          "/etc/hostapd/hostapd.conf",
		HostapdConfigSHA256: "sha256:hostapd",
		PlanFingerprint:     "sha256:roaming-plan",
		SSIDCount:           2,
		RoamingSSIDCount:    2,
		FTSSIDCount:         2,
		KSSIDCount:          1,
		VSSIDCount:          1,
		ProfileCount:        1,
		NeighborCount:       1,
		KeyRefCount:         1,
		StagedKeyRefCount:   0,
		DiagnosticCount:     0,
		SummaryJSON:         `{"roaming_ssid_count":2}`,
		ReportJSON:          `{"feature_id":"NAS-0075"}`,
		Actor:               "ops",
	})
	require.NoError(t, err)
	assert.Contains(t, eventID, "wifi-roam-")

	_, err = RecordWirelessRoamingLifecycleEvent(WirelessRoamingLifecycleEventInput{
		Operation:           "apply",
		Status:              "applied",
		ConfigPath:          "/etc/hostapd/hostapd.conf",
		HostapdConfigSHA256: "sha256:hostapd-2",
		PlanFingerprint:     "sha256:roaming-plan-2",
		SSIDCount:           2,
		RoamingSSIDCount:    1,
		FTSSIDCount:         1,
		KSSIDCount:          1,
		VSSIDCount:          1,
		ProfileCount:        1,
		NeighborCount:       1,
		KeyRefCount:         1,
		SummaryJSON:         `{"roaming_ssid_count":1}`,
		ReportJSON:          `{"feature_id":"NAS-0075","status":"applied"}`,
		Actor:               "ops",
	})
	require.NoError(t, err)

	events, err := ListWirelessRoamingLifecycleEvents(5)
	require.NoError(t, err)
	require.Len(t, events, 2)
	assert.Equal(t, "apply", events[0].Operation)
	assert.Equal(t, "applied", events[0].Status)
	assert.Equal(t, "ops", events[0].Actor)

	summary, err := GetWirelessRoamingLifecycleSummary()
	require.NoError(t, err)
	assert.Equal(t, 2, summary.TotalEvents)
	assert.Equal(t, 1, summary.PreviewEvents)
	assert.Equal(t, 1, summary.ApplyEvents)
	assert.Equal(t, 1, summary.PreviewedCount)
	assert.Equal(t, 1, summary.AppliedCount)
	assert.Equal(t, "sha256:roaming-plan-2", summary.LastFingerprint)
	assert.Equal(t, "sha256:hostapd-2", summary.LastConfigSHA256)
	assert.Equal(t, 1, summary.LastRoamingSSIDCount)
	assert.Equal(t, 1, summary.LastFTSSIDCount)
	assert.Equal(t, 1, summary.LastNeighborCount)
}
