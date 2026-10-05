package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBroadbandDHCPSecurityEvidenceLifecycle(t *testing.T) {
	previousDB := DB
	require.NoError(t, Init(":memory:"))
	DB.SetMaxOpenConns(1)
	require.NoError(t, Migrate())
	t.Cleanup(func() {
		_ = Close()
		DB = previousDB
	})

	emptySummary, err := GetBroadbandDHCPSecuritySummary()
	require.NoError(t, err)
	assert.Equal(t, 0, emptySummary.TotalEvents)

	eventID, err := RecordBroadbandDHCPSecurityEvent(BroadbandDHCPSecurityEventInput{
		Operation:                "apply",
		Status:                   "applied",
		PlanFingerprint:          "sha256:test",
		Mode:                     "enforce",
		RelayAgentCount:          1,
		PortCount:                1,
		TrustedPortCount:         1,
		Option82RuleCount:        1,
		SourceGuardPolicyCount:   1,
		RADIUSCorrelationCount:   1,
		CompiledOptionCount:      6,
		ComplianceCheckCount:     10,
		PassedCheckCount:         10,
		ExternalRequirementCount: 1,
		SummaryJSON:              `{"status":"ready"}`,
		ReportJSON:               `{"feature_id":"NAS-0089"}`,
		Actor:                    "ops@example.test",
		Bindings: []BroadbandDHCPSecurityBindingInput{
			{
				BindingKey:          "bdhcp-test",
				PortName:            "subscriber-port-1",
				Interface:           "eth1.100",
				VLAN:                100,
				Role:                "access",
				Trusted:             false,
				CircuitID:           "olt1/1/1",
				RemoteID:            "retail",
				SubscriberProduct:   "residential-fiber",
				Tenant:              "retail",
				RelayAgent:          "relay-vlan100",
				SourceGuardPolicy:   "strict-access",
				Status:              "active",
				CompiledOptionsJSON: `[{"name":"Agent-Circuit-Id","value":"olt1/1/1"}]`,
				PlanFingerprint:     "sha256:test",
			},
		},
	})
	require.NoError(t, err)
	assert.NotEmpty(t, eventID)

	events, err := ListBroadbandDHCPSecurityEvents(5)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "applied", events[0].Status)
	assert.Equal(t, 1, events[0].PortCount)
	assert.Equal(t, "ops@example.test", events[0].Actor)

	bindings, err := ListBroadbandDHCPSecurityBindings(5, "active")
	require.NoError(t, err)
	require.Len(t, bindings, 1)
	assert.Equal(t, "subscriber-port-1", bindings[0].PortName)
	assert.Equal(t, "strict-access", bindings[0].SourceGuardPolicy)
	assert.Equal(t, "sha256:test", bindings[0].PlanFingerprint)

	summary, err := GetBroadbandDHCPSecuritySummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TotalEvents)
	assert.Equal(t, 1, summary.ApplyEvents)
	assert.Equal(t, 1, summary.AppliedCount)
	assert.Equal(t, 1, summary.ActiveBindings)
	assert.Equal(t, "sha256:test", summary.LastFingerprint)
	assert.Equal(t, 1, summary.LastPortCount)
	assert.Equal(t, 6, summary.LastCompiledOptionCount)
}
