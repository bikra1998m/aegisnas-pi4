package db

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRuntimeQoSSchedulerProfileSnapshotEventSummary(t *testing.T) {
	require.NoError(t, Init(":memory:"))
	DB.SetMaxOpenConns(1)
	defer Close()
	require.NoError(t, Migrate())

	dscp := 46
	require.NoError(t, UpsertQoSSchedulerProfile(QoSSchedulerProfileInput{
		ProfileName:          "voice",
		Enabled:              true,
		Scheduler:            "htb",
		Priority:             1,
		DSCPMark:             &dscp,
		DownloadCeilRateKbps: 20000,
		UploadCeilRateKbps:   10000,
		BurstKB:              128,
		CBurstKB:             128,
		MetadataJSON:         `{"owner":"test"}`,
	}))
	profiles, err := ListQoSSchedulerProfiles()
	require.NoError(t, err)
	require.Len(t, profiles, 1)
	assert.Equal(t, "voice", profiles[0].ProfileName)
	require.NotNil(t, profiles[0].DSCPMark)
	assert.Equal(t, 46, *profiles[0].DSCPMark)

	appliedAt := time.Now().UTC()
	firstID, err := RecordRuntimeQoSSnapshot(RuntimeQoSSnapshotInput{
		Operation:          "apply",
		Status:             "applied",
		Active:             true,
		InterfaceName:      "eth1",
		IFBDevice:          "ifb-aegis0",
		ProfileCount:       1,
		ClassCount:         4,
		SessionCount:       1,
		ShapedSessionCount: 1,
		CommandCount:       12,
		DiagnosticCount:    0,
		PlanFingerprint:    "sha256:first",
		CommandText:        "tc qdisc replace dev eth1 root handle 1: htb default 999",
		DiagnosticsJSON:    "[]",
		SummaryJSON:        `{"profile_count":1}`,
		Actor:              "ops",
		AppliedAt:          &appliedAt,
	})
	require.NoError(t, err)
	secondID, err := RecordRuntimeQoSSnapshot(RuntimeQoSSnapshotInput{
		Operation:          "rollback",
		Status:             "rolled_back",
		Active:             true,
		InterfaceName:      "eth1",
		IFBDevice:          "ifb-aegis0",
		ProfileCount:       1,
		ClassCount:         4,
		ShapedSessionCount: 1,
		CommandCount:       12,
		PlanFingerprint:    "sha256:second",
		CommandText:        "tc qdisc replace dev eth1 root handle 1: htb default 999",
		PreviousSnapshotID: firstID,
		Actor:              "ops",
		AppliedAt:          &appliedAt,
		RolledBackAt:       &appliedAt,
	})
	require.NoError(t, err)

	_, err = RecordRuntimeQoSEvent(RuntimeQoSEventInput{
		Operation:          "apply",
		Status:             "applied",
		SnapshotID:         firstID,
		InterfaceName:      "eth1",
		IFBDevice:          "ifb-aegis0",
		ProfileCount:       1,
		ClassCount:         4,
		SessionCount:       1,
		ShapedSessionCount: 1,
		CommandCount:       12,
		PlanFingerprint:    "sha256:first",
		DiagnosticsJSON:    "[]",
		DetailsJSON:        "{}",
		Actor:              "ops",
	})
	require.NoError(t, err)
	_, err = RecordRuntimeQoSEvent(RuntimeQoSEventInput{
		Operation:          "rollback",
		Status:             "rolled_back",
		SnapshotID:         secondID,
		PreviousSnapshotID: firstID,
		DetailsJSON:        "{}",
		Actor:              "ops",
	})
	require.NoError(t, err)

	active, found, err := GetActiveRuntimeQoSSnapshot()
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, secondID, active.SnapshotID)
	assert.True(t, active.Active)

	snapshots, err := ListRuntimeQoSSnapshots(10)
	require.NoError(t, err)
	require.Len(t, snapshots, 2)

	summary, err := GetRuntimeQoSEventSummary()
	require.NoError(t, err)
	assert.Equal(t, 2, summary.TotalEvents)
	assert.Equal(t, 1, summary.ApplyEvents)
	assert.Equal(t, 1, summary.RollbackEvents)
	assert.Equal(t, 1, summary.RolledBackCount)
	assert.Equal(t, secondID, summary.ActiveSnapshotID)
	assert.Equal(t, "rolled_back", summary.ActiveStatus)
	assert.Equal(t, "sha256:second", summary.ActiveFingerprint)
	assert.Equal(t, 12, summary.ActiveCommandCount)
}
