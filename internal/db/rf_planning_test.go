package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRFPlanningLifecycleEventLedger(t *testing.T) {
	previousDB := DB
	require.NoError(t, Init(":memory:"))
	DB.SetMaxOpenConns(1)
	require.NoError(t, Migrate())
	t.Cleanup(func() {
		_ = Close()
		DB = previousDB
	})

	eventID, err := RecordRFPlanningLifecycleEvent(RFPlanningLifecycleEventInput{
		Operation:                "preview",
		Status:                   "previewed",
		PlanFingerprint:          "sha256:rf-plan",
		CountryCode:              "us",
		ControllerPlatform:       "unifi",
		ChannelPlanMode:          "auto",
		APCount:                  2,
		RadioCount:               4,
		BandCount:                2,
		ChannelPlanCount:         4,
		PowerPlanCount:           4,
		MeshLinkCount:            1,
		SteeringPolicyCount:      2,
		ChannelConflictCount:     1,
		CapacityWarningCount:     0,
		ComplianceCheckCount:     7,
		PassedCheckCount:         6,
		WarningCount:             1,
		BlockerCount:             0,
		ExternalRequirementCount: 10,
		SummaryJSON:              `{"radio_count":4}`,
		ReportJSON:               `{"feature_id":"NAS-0079"}`,
		Actor:                    "operator",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, eventID)

	events, err := ListRFPlanningLifecycleEvents(10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "preview", events[0].Operation)
	assert.Equal(t, "previewed", events[0].Status)
	assert.Equal(t, "US", events[0].CountryCode)
	assert.Equal(t, "unifi", events[0].ControllerPlatform)
	assert.Equal(t, 4, events[0].RadioCount)
	assert.Equal(t, 1, events[0].MeshLinkCount)
	assert.Equal(t, 2, events[0].SteeringPolicyCount)
	assert.Equal(t, 10, events[0].ExternalRequirementCount)
	assert.Equal(t, "operator", events[0].Actor)

	summary, err := GetRFPlanningLifecycleSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TotalEvents)
	assert.Equal(t, 1, summary.PreviewEvents)
	assert.Equal(t, 1, summary.PreviewedCount)
	assert.Equal(t, "sha256:rf-plan", summary.LastFingerprint)
	assert.Equal(t, 4, summary.LastRadioCount)
	assert.Equal(t, 4, summary.LastChannelPlanCount)
	assert.Equal(t, 4, summary.LastPowerPlanCount)
	assert.Equal(t, 1, summary.LastMeshLinkCount)
	assert.Equal(t, 2, summary.LastSteeringPolicyCount)
	assert.Equal(t, 1, summary.LastChannelConflictCount)
}
