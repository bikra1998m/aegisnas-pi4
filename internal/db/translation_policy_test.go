package db

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTranslationPolicyEventSummaryOwnershipAndWithdrawal(t *testing.T) {
	require.NoError(t, Init(":memory:"))
	DB.SetMaxOpenConns(1)
	defer Close()
	require.NoError(t, Migrate())

	eventID, err := RecordTranslationPolicyEvent(TranslationPolicyEventInput{
		Operation:            "compile",
		Status:               "compiled",
		Role:                 "branch-dualstack",
		SessionID:            "session-1",
		AcctSessionID:        "acct-1",
		Owner:                "nat-team",
		Revision:             "sha256:translation",
		TranslationMode:      "dual-stack",
		PublicPool:           "cgnat-public",
		PublicIPv4:           "198.51.100.2",
		PrivateIPv4Prefix:    "100.64.1.0/24",
		SubscriberIPv6Prefix: "2001:db8:57::/64",
		NAT64Prefix:          "64:ff9b::/96",
		PortBlockStart:       10000,
		PortBlockEnd:         10511,
		PortBlockSize:        512,
		MappingCount:         6,
		PortBlockCount:       1,
		AttributeCount:       18,
		Fingerprint:          "sha256:compiled",
		RequestJSON:          "{}",
		ResponseJSON:         "{}",
		DiagnosticsJSON:      "[]",
		Actor:                "ops",
		Ownership: []TranslationPolicyOwnershipInput{
			{OwnershipKey: "owner-1", TranslationMode: "dual-stack", PublicPool: "cgnat-public", PublicIPv4: "198.51.100.2", PrivateIPv4Prefix: "100.64.1.0/24", SubscriberIPv6Prefix: "2001:db8:57::/64", NAT64Prefix: "64:ff9b::/96", PortBlockStart: 10000, PortBlockEnd: 10511, PortBlockSize: 512},
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, eventID)

	summary, err := GetTranslationPolicyEventSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TotalEvents)
	assert.Equal(t, 1, summary.CompiledCount)
	assert.Equal(t, 1, summary.ActiveMappings)
	assert.Equal(t, 1, summary.ActivePortBlocks)
	assert.Equal(t, 1, summary.ActiveNAT64Mappings)
	assert.Equal(t, 1, summary.ActiveCGNATMappings)
	assert.Equal(t, "branch-dualstack", summary.LastRole)
	assert.Equal(t, "dual-stack", summary.LastTranslationMode)

	ownership, err := ListTranslationPolicyOwnership(10, "active")
	require.NoError(t, err)
	require.Len(t, ownership, 1)
	assert.Equal(t, "nat-team", ownership[0].Owner)
	assert.Equal(t, "198.51.100.2", ownership[0].PublicIPv4)

	affected, err := WithdrawTranslationPolicyOwnershipForSession(context.Background(), "session-1", "", "acct-stop-1", "accounting-stop")
	require.NoError(t, err)
	assert.Equal(t, int64(1), affected)

	summary, err = GetTranslationPolicyEventSummary()
	require.NoError(t, err)
	assert.Equal(t, 2, summary.TotalEvents)
	assert.Equal(t, 2, summary.CompiledCount)
	assert.Equal(t, 0, summary.ActiveMappings)
	assert.Equal(t, 1, summary.WithdrawnMappings)
}

func TestTranslationPolicyEventValidation(t *testing.T) {
	require.NoError(t, Init(":memory:"))
	DB.SetMaxOpenConns(1)
	defer Close()
	require.NoError(t, Migrate())

	_, err := RecordTranslationPolicyEvent(TranslationPolicyEventInput{
		Operation:       "unknown",
		Status:          "compiled",
		RequestJSON:     "{}",
		ResponseJSON:    "{}",
		DiagnosticsJSON: "[]",
	})
	assert.ErrorContains(t, err, "operation and status are required")
}
