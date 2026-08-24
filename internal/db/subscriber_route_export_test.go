package db

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSubscriberRouteExportSnapshotEventSummary(t *testing.T) {
	require.NoError(t, Init(":memory:"))
	DB.SetMaxOpenConns(1)
	defer Close()
	require.NoError(t, Migrate())

	now := time.Now().UTC()
	snapshotID, err := RecordSubscriberRouteExportSnapshot(SubscriberRouteExportSnapshotInput{
		Operation:          "apply",
		Status:             "applied",
		Active:             true,
		Driver:             "file",
		ProtocolCount:      1,
		RouteCount:         2,
		IPv4RouteCount:     1,
		IPv6RouteCount:     1,
		WithdrawRouteCount: 0,
		CommandCount:       1,
		PlanFingerprint:    "sha256:route-export",
		ArtifactPath:       "/tmp/subscriber-routes.frr",
		ArtifactSHA256:     "sha256:artifact",
		ArtifactText:       "ip route 10.80.0.0/16 192.0.2.1\n",
		CommandText:        "write-file /tmp/subscriber-routes.frr sha256:artifact",
		PlanJSON:           `{"status":"ready"}`,
		DiagnosticsJSON:    "[]",
		SummaryJSON:        `{"route_count":2}`,
		Actor:              "ops",
		AppliedAt:          &now,
	})
	require.NoError(t, err)
	require.NotEmpty(t, snapshotID)

	eventID, err := RecordSubscriberRouteExportEvent(SubscriberRouteExportEventInput{
		Operation:          "apply",
		Status:             "applied",
		SnapshotID:         snapshotID,
		Driver:             "file",
		ProtocolCount:      1,
		RouteCount:         2,
		IPv4RouteCount:     1,
		IPv6RouteCount:     1,
		WithdrawRouteCount: 0,
		CommandCount:       1,
		PlanFingerprint:    "sha256:route-export",
		ArtifactSHA256:     "sha256:artifact",
		DiagnosticsJSON:    "[]",
		DetailsJSON:        "{}",
		Actor:              "ops",
	})
	require.NoError(t, err)
	require.NotEmpty(t, eventID)

	active, found, err := GetActiveSubscriberRouteExportSnapshot()
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, snapshotID, active.SnapshotID)
	assert.Equal(t, "sha256:route-export", active.PlanFingerprint)
	assert.Equal(t, 2, active.RouteCount)

	summary, err := GetSubscriberRouteExportSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TotalEvents)
	assert.Equal(t, 1, summary.ApplyEvents)
	assert.Equal(t, 1, summary.AppliedCount)
	assert.Equal(t, snapshotID, summary.ActiveSnapshotID)
	assert.Equal(t, "sha256:route-export", summary.ActiveFingerprint)
	assert.Equal(t, 2, summary.ActiveRouteCount)
}

func TestSubscriberRouteExportValidation(t *testing.T) {
	require.NoError(t, Init(":memory:"))
	DB.SetMaxOpenConns(1)
	defer Close()
	require.NoError(t, Migrate())

	_, err := RecordSubscriberRouteExportEvent(SubscriberRouteExportEventInput{
		Operation: "unknown",
		Status:    "applied",
	})
	assert.ErrorContains(t, err, "operation and status are required")

	_, err = RecordSubscriberRouteExportSnapshot(SubscriberRouteExportSnapshotInput{
		Operation: "apply",
		Status:    "applied",
	})
	assert.ErrorContains(t, err, "plan fingerprint is required")
}
