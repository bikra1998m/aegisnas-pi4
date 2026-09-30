package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCWAPortalLifecycleEventLedger(t *testing.T) {
	previousDB := DB
	require.NoError(t, Init(":memory:"))
	DB.SetMaxOpenConns(1)
	require.NoError(t, Migrate())
	t.Cleanup(func() {
		_ = Close()
		DB = previousDB
	})

	eventID, err := RecordCWAPortalLifecycleEvent(CWAPortalLifecycleEventInput{
		Operation:                "preview",
		Status:                   "previewed",
		PlanFingerprint:          "cwa-plan-1",
		Mode:                     "enforce",
		PortalBaseURL:            "https://portal.example.test",
		ControllerPlatform:       "cisco",
		GuestSSIDCount:           2,
		WalledGardenCount:        3,
		ControllerPolicyCount:    1,
		RedirectRuleCount:        2,
		CoAActionCount:           2,
		ComplianceCheckCount:     7,
		PassedCheckCount:         7,
		ExternalRequirementCount: 8,
		SummaryJSON:              `{"guest_ssid_count":2}`,
		ReportJSON:               `{"feature_id":"NAS-0081"}`,
		Actor:                    "ops@example.test",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, eventID)

	events, err := ListCWAPortalLifecycleEvents(10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, eventID, events[0].EventID)
	assert.Equal(t, "previewed", events[0].Status)
	assert.Equal(t, 3, events[0].WalledGardenCount)
	assert.Equal(t, "ops@example.test", events[0].Actor)

	summary, err := GetCWAPortalLifecycleSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TotalEvents)
	assert.Equal(t, 1, summary.PreviewEvents)
	assert.Equal(t, 1, summary.PreviewedCount)
	assert.Equal(t, 2, summary.LastGuestSSIDCount)
	assert.Equal(t, 2, summary.LastRedirectRuleCount)
	assert.Equal(t, "cwa-plan-1", summary.LastFingerprint)
}
