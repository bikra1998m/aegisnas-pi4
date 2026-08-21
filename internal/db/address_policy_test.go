package db

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAddressPolicyEventSummaryOwnershipAndWithdrawal(t *testing.T) {
	require.NoError(t, Init(":memory:"))
	DB.SetMaxOpenConns(1)
	defer Close()
	require.NoError(t, Migrate())

	eventID, err := RecordAddressPolicyEvent(AddressPolicyEventInput{
		Operation:            "compile",
		Status:               "compiled",
		Role:                 "branch-dualstack",
		SessionID:            "session-1",
		AcctSessionID:        "acct-1",
		Owner:                "address-team",
		Revision:             "sha256:address",
		IPv4AssignmentCount:  1,
		IPv6AssignmentCount:  1,
		DelegatedPrefixCount: 1,
		RAPrefixCount:        1,
		AttributeCount:       12,
		Fingerprint:          "sha256:compiled",
		RequestJSON:          "{}",
		ResponseJSON:         "{}",
		DiagnosticsJSON:      "[]",
		Actor:                "ops",
		Ownership: []AddressPolicyOwnershipInput{
			{Family: "ipv4", AssignmentType: "address", PoolName: "branch-v4", Address: "198.51.100.2"},
			{Family: "ipv6", AssignmentType: "address", PoolName: "branch-v6", Address: "2001:db8:10::10"},
			{Family: "ipv6", AssignmentType: "delegated_prefix", PoolName: "branch-pd", Prefix: "2001:db8:100::/56"},
			{Family: "ipv6", AssignmentType: "ra_prefix", PoolName: "branch-ra", Prefix: "2001:db8:200::/64"},
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, eventID)

	summary, err := GetAddressPolicyEventSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TotalEvents)
	assert.Equal(t, 1, summary.CompiledCount)
	assert.Equal(t, 4, summary.ActiveAssignments)
	assert.Equal(t, 1, summary.IPv4ActiveAssignments)
	assert.Equal(t, 3, summary.IPv6ActiveAssignments)
	assert.Equal(t, 1, summary.DelegatedPrefixes)
	assert.Equal(t, 1, summary.RAPrefixes)
	assert.Equal(t, "branch-dualstack", summary.LastRole)

	ownership, err := ListAddressPolicyOwnership(10, "active")
	require.NoError(t, err)
	require.Len(t, ownership, 4)
	assert.Equal(t, "address-team", ownership[0].Owner)

	affected, err := WithdrawAddressPolicyOwnershipForSession(context.Background(), "session-1", "", "acct-stop-1", "accounting-stop")
	require.NoError(t, err)
	assert.Equal(t, int64(4), affected)

	summary, err = GetAddressPolicyEventSummary()
	require.NoError(t, err)
	assert.Equal(t, 2, summary.TotalEvents)
	assert.Equal(t, 2, summary.CompiledCount)
	assert.Equal(t, 0, summary.ActiveAssignments)
	assert.Equal(t, 4, summary.WithdrawnAssignments)
}

func TestAddressPolicyEventValidation(t *testing.T) {
	require.NoError(t, Init(":memory:"))
	DB.SetMaxOpenConns(1)
	defer Close()
	require.NoError(t, Migrate())

	_, err := RecordAddressPolicyEvent(AddressPolicyEventInput{
		Operation:       "unknown",
		Status:          "compiled",
		RequestJSON:     "{}",
		ResponseJSON:    "{}",
		DiagnosticsJSON: "[]",
	})
	assert.ErrorContains(t, err, "operation and status are required")
}
