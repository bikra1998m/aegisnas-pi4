package db

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRuntimeFirewallSnapshotEventSummary(t *testing.T) {
	require.NoError(t, Init(":memory:"))
	DB.SetMaxOpenConns(1)
	defer Close()
	require.NoError(t, Migrate())

	appliedAt := time.Now().UTC()
	firstID, err := RecordRuntimeFirewallSnapshot(RuntimeFirewallSnapshotInput{
		Operation:              "apply",
		Status:                 "applied",
		Active:                 true,
		SessionCount:           2,
		ManagedSessionCount:    1,
		QuarantineSessionCount: 1,
		IPv4SessionCount:       1,
		IPv6SessionCount:       1,
		RuleCount:              2,
		AppliedRuleCount:       6,
		DiagnosticsJSON:        "[]",
		RulesetFingerprint:     "sha256:first",
		RulesetText:            "table inet aegis_runtime {}",
		Actor:                  "ops",
		AppliedAt:              &appliedAt,
	})
	require.NoError(t, err)
	require.NotEmpty(t, firstID)
	secondID, err := RecordRuntimeFirewallSnapshot(RuntimeFirewallSnapshotInput{
		Operation:           "rollback",
		Status:              "rolled_back",
		Active:              true,
		SessionCount:        1,
		ManagedSessionCount: 1,
		RulesetFingerprint:  "sha256:second",
		RulesetText:         "table inet aegis_runtime {}",
		PreviousSnapshotID:  firstID,
		Actor:               "ops",
		AppliedAt:           &appliedAt,
		RolledBackAt:        &appliedAt,
	})
	require.NoError(t, err)

	_, err = RecordRuntimeFirewallEvent(RuntimeFirewallEventInput{
		Operation:              "apply",
		Status:                 "applied",
		SnapshotID:             firstID,
		SessionCount:           2,
		ManagedSessionCount:    1,
		QuarantineSessionCount: 1,
		IPv4SessionCount:       1,
		IPv6SessionCount:       1,
		RuleCount:              2,
		AppliedRuleCount:       6,
		DiagnosticsJSON:        "[]",
		DetailsJSON:            "{}",
		Actor:                  "ops",
	})
	require.NoError(t, err)
	_, err = RecordRuntimeFirewallEvent(RuntimeFirewallEventInput{
		Operation:          "rollback",
		Status:             "rolled_back",
		SnapshotID:         secondID,
		PreviousSnapshotID: firstID,
		DetailsJSON:        "{}",
		Actor:              "ops",
	})
	require.NoError(t, err)

	active, found, err := GetActiveRuntimeFirewallSnapshot()
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, secondID, active.SnapshotID)
	assert.True(t, active.Active)

	snapshots, err := ListRuntimeFirewallSnapshots(10)
	require.NoError(t, err)
	require.Len(t, snapshots, 2)

	summary, err := GetRuntimeFirewallEventSummary()
	require.NoError(t, err)
	assert.Equal(t, 2, summary.TotalEvents)
	assert.Equal(t, 1, summary.ApplyEvents)
	assert.Equal(t, 1, summary.RollbackEvents)
	assert.Equal(t, 1, summary.RolledBackCount)
	assert.Equal(t, secondID, summary.ActiveSnapshotID)
	assert.Equal(t, "rolled_back", summary.ActiveStatus)
	assert.Equal(t, "sha256:second", summary.ActiveRulesetFingerprint)
}
