package db

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVLANLifecycleSnapshotEventSummary(t *testing.T) {
	require.NoError(t, Init(":memory:"))
	DB.SetMaxOpenConns(1)
	defer Close()
	require.NoError(t, Migrate())

	appliedAt := time.Now().UTC()
	firstID, err := RecordVLANLifecycleSnapshot(VLANLifecycleSnapshotInput{
		Operation:             "apply",
		Status:                "applied",
		Active:                true,
		ParentInterface:       "eth1",
		VLANCount:             2,
		BridgeCount:           2,
		SubinterfaceCount:     2,
		HostapdVLANEntryCount: 2,
		CommandCount:          7,
		PlanFingerprint:       "sha256:first",
		CommandText:           "ip link set dev eth1 up",
		HostapdVLANFilePath:   "/tmp/aegisnas-vlans.conf",
		HostapdVLANFileText:   "20 br-vlan20\n30 br-vlan30\n",
		HostapdVLANFileSHA256: "sha256:file",
		DiagnosticsJSON:       "[]",
		SummaryJSON:           `{"vlan_count":2}`,
		PlanJSON:              `{"schema_version":1,"status":"applied"}`,
		Actor:                 "ops",
		AppliedAt:             &appliedAt,
	})
	require.NoError(t, err)
	secondID, err := RecordVLANLifecycleSnapshot(VLANLifecycleSnapshotInput{
		Operation:          "rollback",
		Status:             "rolled_back",
		Active:             true,
		ParentInterface:    "eth1",
		VLANCount:          1,
		BridgeCount:        1,
		SubinterfaceCount:  1,
		CommandCount:       4,
		PlanFingerprint:    "sha256:second",
		CommandText:        "ip link set dev eth1 up",
		PreviousSnapshotID: firstID,
		Actor:              "ops",
		AppliedAt:          &appliedAt,
		RolledBackAt:       &appliedAt,
	})
	require.NoError(t, err)

	_, err = RecordVLANLifecycleEvent(VLANLifecycleEventInput{
		Operation:             "apply",
		Status:                "applied",
		SnapshotID:            firstID,
		ParentInterface:       "eth1",
		VLANCount:             2,
		BridgeCount:           2,
		SubinterfaceCount:     2,
		HostapdVLANEntryCount: 2,
		CommandCount:          7,
		PlanFingerprint:       "sha256:first",
		DiagnosticsJSON:       "[]",
		DetailsJSON:           "{}",
		Actor:                 "ops",
	})
	require.NoError(t, err)
	_, err = RecordVLANLifecycleEvent(VLANLifecycleEventInput{
		Operation:          "rollback",
		Status:             "rolled_back",
		SnapshotID:         secondID,
		PreviousSnapshotID: firstID,
		DetailsJSON:        "{}",
		Actor:              "ops",
	})
	require.NoError(t, err)

	active, found, err := GetActiveVLANLifecycleSnapshot()
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, secondID, active.SnapshotID)
	assert.True(t, active.Active)

	snapshots, err := ListVLANLifecycleSnapshots(10)
	require.NoError(t, err)
	require.Len(t, snapshots, 2)
	assert.Equal(t, "/tmp/aegisnas-vlans.conf", snapshots[1].HostapdVLANFilePath)
	assert.Contains(t, snapshots[1].PlanJSON, `"schema_version":1`)

	summary, err := GetVLANLifecycleEventSummary()
	require.NoError(t, err)
	assert.Equal(t, 2, summary.TotalEvents)
	assert.Equal(t, 1, summary.ApplyEvents)
	assert.Equal(t, 1, summary.RollbackEvents)
	assert.Equal(t, 1, summary.RolledBackCount)
	assert.Equal(t, secondID, summary.ActiveSnapshotID)
	assert.Equal(t, "rolled_back", summary.ActiveStatus)
	assert.Equal(t, "sha256:second", summary.ActiveFingerprint)
	assert.Equal(t, 4, summary.ActiveCommandCount)
	assert.Equal(t, 1, summary.VLANCount)
}
