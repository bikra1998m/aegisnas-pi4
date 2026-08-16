package db

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRoutePolicyEventSummaryOwnershipAndWithdrawal(t *testing.T) {
	require.NoError(t, Init(":memory:"))
	DB.SetMaxOpenConns(1)
	defer Close()
	require.NoError(t, Migrate())

	eventID, err := RecordRoutePolicyEvent(RoutePolicyEventInput{
		Operation:       "compile",
		Status:          "compiled",
		Role:            "branch-vpn",
		SessionID:       "session-1",
		AcctSessionID:   "acct-1",
		VRF:             "corp",
		Owner:           "network-team",
		Revision:        "sha256:route",
		IPv4RouteCount:  1,
		IPv6RouteCount:  1,
		AttributeCount:  8,
		Fingerprint:     "sha256:compiled",
		RequestJSON:     "{}",
		ResponseJSON:    "{}",
		DiagnosticsJSON: "[]",
		Actor:           "ops",
		Ownership: []RoutePolicyOwnershipInput{
			{Family: "ipv4", Destination: "10.80.0.0/16", Gateway: "192.0.2.1", Metric: 10, Source: "role"},
			{Family: "ipv6", Destination: "2001:db8:80::/48", Gateway: "2001:db8::1", Metric: 20, Source: "role"},
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, eventID)

	summary, err := GetRoutePolicyEventSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TotalEvents)
	assert.Equal(t, 1, summary.CompiledCount)
	assert.Equal(t, 2, summary.ActiveRoutes)
	assert.Equal(t, 1, summary.IPv4ActiveRoutes)
	assert.Equal(t, 1, summary.IPv6ActiveRoutes)
	assert.Equal(t, 1, summary.VRFCount)
	assert.Equal(t, "branch-vpn", summary.LastRole)
	assert.Equal(t, "corp", summary.LastVRF)

	ownership, err := ListRoutePolicyOwnership(10, "active")
	require.NoError(t, err)
	require.Len(t, ownership, 2)
	assert.Equal(t, "corp", ownership[0].VRF)
	assert.Equal(t, "network-team", ownership[0].Owner)

	affected, err := WithdrawRoutePolicyOwnershipForSession(context.Background(), "session-1", "", "acct-stop-1", "accounting-stop")
	require.NoError(t, err)
	assert.Equal(t, int64(2), affected)

	summary, err = GetRoutePolicyEventSummary()
	require.NoError(t, err)
	assert.Equal(t, 2, summary.TotalEvents)
	assert.Equal(t, 2, summary.CompiledCount)
	assert.Equal(t, 0, summary.ActiveRoutes)
	assert.Equal(t, 2, summary.WithdrawnRoutes)
}

func TestRoutePolicyEventValidation(t *testing.T) {
	require.NoError(t, Init(":memory:"))
	DB.SetMaxOpenConns(1)
	defer Close()
	require.NoError(t, Migrate())

	_, err := RecordRoutePolicyEvent(RoutePolicyEventInput{
		Operation:       "unknown",
		Status:          "compiled",
		RequestJSON:     "{}",
		ResponseJSON:    "{}",
		DiagnosticsJSON: "[]",
	})
	assert.ErrorContains(t, err, "operation and status are required")
}
