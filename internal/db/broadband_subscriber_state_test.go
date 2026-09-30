package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBroadbandSubscriberStateEventLedger(t *testing.T) {
	previousDB := DB
	require.NoError(t, Init(":memory:"))
	DB.SetMaxOpenConns(1)
	require.NoError(t, Migrate())
	t.Cleanup(func() {
		_ = Close()
		DB = previousDB
	})

	eventID, err := RecordBroadbandSubscriberStateEvent(BroadbandSubscriberStateEventInput{
		Operation:                 "preview",
		Status:                    "previewed",
		PlanFingerprint:           "fp-state",
		Mode:                      "enforce",
		AccessMethod:              "pppoe",
		ProductCount:              2,
		ServicePolicyCount:        3,
		FailurePolicyCount:        1,
		StateCount:                15,
		TransitionCount:           22,
		RequiredTransitionCount:   10,
		AccountingTransitionCount: 5,
		RecoveryTransitionCount:   4,
		ComplianceCheckCount:      8,
		PassedCheckCount:          8,
		ExternalRequirementCount:  10,
		SummaryJSON:               `{"mode":"enforce"}`,
		ReportJSON:                `{"status":"ready"}`,
		Actor:                     "ops@example.test",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, eventID)

	events, err := ListBroadbandSubscriberStateEvents(10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, eventID, events[0].EventID)
	assert.Equal(t, "pppoe", events[0].AccessMethod)
	assert.Equal(t, 22, events[0].TransitionCount)

	summary, err := GetBroadbandSubscriberStateSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TotalEvents)
	assert.Equal(t, 1, summary.PreviewedCount)
	assert.Equal(t, "fp-state", summary.LastFingerprint)
	assert.Equal(t, 2, summary.LastProductCount)
}
