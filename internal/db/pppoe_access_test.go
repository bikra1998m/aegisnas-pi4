package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPPPoEAccessLifecycleEventLedger(t *testing.T) {
	previousDB := DB
	require.NoError(t, Init(":memory:"))
	DB.SetMaxOpenConns(1)
	require.NoError(t, Migrate())
	t.Cleanup(func() {
		_ = Close()
		DB = previousDB
	})

	eventID, err := RecordPPPoEAccessLifecycleEvent(PPPoEAccessLifecycleEventInput{
		Operation:                "preview",
		Status:                   "previewed",
		PlanFingerprint:          "pppoe-plan-1",
		Mode:                     "enforce",
		AccessConcentratorName:   "aegisnas-bng-01",
		ServiceName:              "internet",
		InterfaceCount:           2,
		ProfileCount:             3,
		SessionLimit:             4096,
		RadiusAttributeCount:     17,
		PacketStageCount:         11,
		EnforcementActionCount:   8,
		ComplianceCheckCount:     9,
		PassedCheckCount:         9,
		ExternalRequirementCount: 10,
		SummaryJSON:              `{"enabled_interface_count":2}`,
		ReportJSON:               `{"feature_id":"NAS-0082"}`,
		Actor:                    "ops@example.test",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, eventID)

	events, err := ListPPPoEAccessLifecycleEvents(10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, eventID, events[0].EventID)
	assert.Equal(t, "previewed", events[0].Status)
	assert.Equal(t, 2, events[0].InterfaceCount)
	assert.Equal(t, 3, events[0].ProfileCount)
	assert.Equal(t, "ops@example.test", events[0].Actor)

	summary, err := GetPPPoEAccessLifecycleSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TotalEvents)
	assert.Equal(t, 1, summary.PreviewEvents)
	assert.Equal(t, 1, summary.PreviewedCount)
	assert.Equal(t, 2, summary.LastInterfaceCount)
	assert.Equal(t, 3, summary.LastProfileCount)
	assert.Equal(t, 4096, summary.LastSessionLimit)
	assert.Equal(t, "pppoe-plan-1", summary.LastFingerprint)
}
