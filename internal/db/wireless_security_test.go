package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWirelessSecurityLifecycleEventLedger(t *testing.T) {
	previousDB := DB
	require.NoError(t, Init(":memory:"))
	DB.SetMaxOpenConns(1)
	require.NoError(t, Migrate())
	t.Cleanup(func() {
		_ = Close()
		DB = previousDB
	})

	eventID, err := RecordWirelessSecurityLifecycleEvent(WirelessSecurityLifecycleEventInput{
		Operation:                "preview",
		Status:                   "previewed",
		PlanFingerprint:          "sha256:wireless-security",
		Mode:                     "monitor",
		ControllerPlatform:       "generic",
		SensorCount:              2,
		RoguePolicyCount:         3,
		WIPSDetectionCount:       7,
		SpectrumChannelCount:     4,
		LocationZoneCount:        2,
		MulticastPolicyCount:     5,
		ContainmentGuardCount:    2,
		PrivacyCheckCount:        3,
		ComplianceCheckCount:     8,
		PassedCheckCount:         8,
		WarningCount:             0,
		BlockerCount:             0,
		ExternalRequirementCount: 9,
		SummaryJSON:              `{"sensor_count":2}`,
		ReportJSON:               `{"status":"ready"}`,
		Actor:                    "ops@example.test",
	})
	require.NoError(t, err)
	require.NotEmpty(t, eventID)

	events, err := ListWirelessSecurityLifecycleEvents(10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "previewed", events[0].Status)
	assert.Equal(t, "monitor", events[0].Mode)
	assert.Equal(t, 2, events[0].SensorCount)
	assert.Equal(t, 7, events[0].WIPSDetectionCount)
	assert.Equal(t, 5, events[0].MulticastPolicyCount)
	assert.Equal(t, "ops@example.test", events[0].Actor)

	summary, err := GetWirelessSecurityLifecycleSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TotalEvents)
	assert.Equal(t, 1, summary.PreviewedCount)
	assert.Equal(t, 2, summary.LastSensorCount)
	assert.Equal(t, 3, summary.LastRoguePolicyCount)
	assert.Equal(t, 7, summary.LastWIPSDetectionCount)
	assert.Equal(t, 4, summary.LastSpectrumChannelCount)
	assert.Equal(t, 2, summary.LastLocationZoneCount)
	assert.Equal(t, 5, summary.LastMulticastPolicyCount)
}
