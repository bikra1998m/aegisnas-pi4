package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBroadbandAddressLeaseEventLedger(t *testing.T) {
	previousDB := DB
	require.NoError(t, Init(":memory:"))
	DB.SetMaxOpenConns(1)
	require.NoError(t, Migrate())
	t.Cleanup(func() {
		_ = Close()
		DB = previousDB
	})

	eventID, err := RecordBroadbandAddressLeaseEvent(BroadbandAddressLeaseEventInput{
		Operation:                "apply",
		Status:                   "applied",
		PlanFingerprint:          "lease-fp-1",
		Mode:                     "enforce",
		PoolCount:                3,
		IPv4PoolCount:            1,
		IPv6PoolCount:            1,
		DelegatedPoolCount:       1,
		ReservationCount:         1,
		LeaseIntentCount:         2,
		ComplianceCheckCount:     5,
		PassedCheckCount:         5,
		ExternalRequirementCount: 9,
		SummaryJSON:              `{"pool_count":3}`,
		ReportJSON:               `{"feature_id":"NAS-0086"}`,
		Actor:                    "ops@example.test",
		Leases: []BroadbandAddressLeaseInput{
			{LeaseKey: "lease-v4-1", SubscriberID: "sub-1", Username: "sub-1@example.net", Product: "fiber", Role: "residential", Family: "ipv4", AssignmentType: "address", PoolName: "pppoe-v4", Address: "100.64.0.20", Status: "reserved", Sticky: true, Owner: "aegisnas"},
			{LeaseKey: "lease-pd-1", SubscriberID: "sub-1", Username: "sub-1@example.net", Product: "fiber", Role: "residential", Family: "ipv6", AssignmentType: "delegated-prefix", PoolName: "pppoe-pd", Prefix: "2001:db8:200:100::/56", Status: "planned", Sticky: true, Owner: "aegisnas"},
		},
	})
	require.NoError(t, err)
	assert.NotEmpty(t, eventID)

	events, err := ListBroadbandAddressLeaseEvents(10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "apply", events[0].Operation)
	assert.Equal(t, "applied", events[0].Status)
	assert.Equal(t, 2, events[0].LeaseIntentCount)

	leases, err := ListBroadbandAddressLeases(10, "")
	require.NoError(t, err)
	require.Len(t, leases, 2)
	reserved, err := ListBroadbandAddressLeases(10, "reserved")
	require.NoError(t, err)
	require.Len(t, reserved, 1)
	assert.Equal(t, "lease-v4-1", reserved[0].LeaseKey)
	assert.True(t, reserved[0].Sticky)

	_, err = RecordBroadbandAddressLeaseEvent(BroadbandAddressLeaseEventInput{
		Operation:        "reconcile",
		Status:           "reconciled",
		PlanFingerprint:  "lease-fp-2",
		Mode:             "enforce",
		LeaseIntentCount: 1,
		SummaryJSON:      `{}`,
		ReportJSON:       `{}`,
		Actor:            "reconciler",
		Leases: []BroadbandAddressLeaseInput{
			{LeaseKey: "lease-v4-1", SubscriberID: "sub-1", Family: "ipv4", AssignmentType: "address", PoolName: "pppoe-v4", Address: "100.64.0.20", Status: "active", Sticky: true, Owner: "aegisnas"},
		},
	})
	require.NoError(t, err)

	summary, err := GetBroadbandAddressLeaseSummary()
	require.NoError(t, err)
	assert.Equal(t, 2, summary.TotalEvents)
	assert.Equal(t, 1, summary.AppliedCount)
	assert.Equal(t, 1, summary.ReconciledCount)
	assert.Equal(t, 1, summary.ActiveLeases)
	assert.Equal(t, 1, summary.PlannedLeases)
	assert.Equal(t, 1, summary.DelegatedPrefixLeases)
	assert.Equal(t, "lease-fp-2", summary.LastFingerprint)

	active, err := ListBroadbandAddressLeases(10, "active")
	require.NoError(t, err)
	require.Len(t, active, 1)
	assert.GreaterOrEqual(t, active[0].Revision, 2)
}

func TestBroadbandAddressLeaseEventValidation(t *testing.T) {
	previousDB := DB
	require.NoError(t, Init(":memory:"))
	DB.SetMaxOpenConns(1)
	require.NoError(t, Migrate())
	t.Cleanup(func() {
		_ = Close()
		DB = previousDB
	})

	_, err := RecordBroadbandAddressLeaseEvent(BroadbandAddressLeaseEventInput{
		Operation:       "apply",
		Status:          "applied",
		PlanFingerprint: "",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "plan fingerprint")

	_, err = RecordBroadbandAddressLeaseEvent(BroadbandAddressLeaseEventInput{
		Operation:       "apply",
		Status:          "applied",
		PlanFingerprint: "lease-fp",
		Leases: []BroadbandAddressLeaseInput{
			{Family: "ipv4", AssignmentType: "address", Status: "active"},
		},
	})
	require.NoError(t, err)
	leases, err := ListBroadbandAddressLeases(10, "active")
	require.NoError(t, err)
	require.Len(t, leases, 1)
	assert.NotEmpty(t, leases[0].LeaseKey)
}
