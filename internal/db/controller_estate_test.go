package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestControllerEstateLifecycleEventLedger(t *testing.T) {
	previousDB := DB
	require.NoError(t, Init(":memory:"))
	DB.SetMaxOpenConns(1)
	require.NoError(t, Migrate())
	t.Cleanup(func() {
		_ = Close()
		DB = previousDB
	})

	eventID, err := RecordControllerEstateLifecycleEvent(ControllerEstateLifecycleEventInput{
		Operation:                "preview",
		Status:                   "previewed",
		Adapter:                  "unifi-network",
		Platform:                 "unifi",
		Endpoint:                 "https://controller.example.test",
		Site:                     "default",
		SyncMode:                 "monitor",
		DesiredStateHash:         "hash-1",
		PlanFingerprint:          "sha256:fingerprint",
		InventoryObjectCount:     5,
		TemplateCount:            2,
		WLANTemplateCount:        2,
		ManagedObjectCount:       7,
		DeleteGuardCount:         8,
		ComplianceCheckCount:     9,
		PassedCheckCount:         7,
		WarningCount:             1,
		ExternalRequirementCount: 9,
		SummaryJSON:              `{"ok":true}`,
		ReportJSON:               `{"report":true}`,
		Actor:                    "operator",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, eventID)

	events, err := ListControllerEstateLifecycleEvents(10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "unifi-network", events[0].Adapter)
	assert.Equal(t, "unifi", events[0].Platform)
	assert.Equal(t, 5, events[0].InventoryObjectCount)
	assert.Equal(t, 8, events[0].DeleteGuardCount)
	assert.Equal(t, "operator", events[0].Actor)

	summary, err := GetControllerEstateLifecycleSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TotalEvents)
	assert.Equal(t, 1, summary.PreviewEvents)
	assert.Equal(t, 1, summary.PreviewedCount)
	assert.Equal(t, "unifi-network", summary.LastAdapter)
	assert.Equal(t, "unifi", summary.LastPlatform)
	assert.Equal(t, "hash-1", summary.LastDesiredStateHash)
	assert.Equal(t, "sha256:fingerprint", summary.LastFingerprint)
	assert.Equal(t, 2, summary.LastWLANTemplateCount)
	assert.Equal(t, 9, summary.LastExternalRequirementCount)
}
