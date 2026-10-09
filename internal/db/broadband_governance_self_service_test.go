package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBroadbandGovernanceSelfServiceEvidenceLifecycle(t *testing.T) {
	previousDB := DB
	require.NoError(t, Init(":memory:"))
	DB.SetMaxOpenConns(1)
	require.NoError(t, Migrate())
	t.Cleanup(func() {
		_ = Close()
		DB = previousDB
	})

	emptySummary, err := GetBroadbandGovernanceSelfServiceSummary()
	require.NoError(t, err)
	assert.Equal(t, 0, emptySummary.TotalEvents)

	eventID, err := RecordBroadbandGovernanceSelfServiceEvent(BroadbandGovernanceSelfServiceEventInput{
		Operation:                "apply",
		Status:                   "applied",
		PlanFingerprint:          "sha256:test",
		Mode:                     "enforce",
		CaseCount:                1,
		SelfServiceActionCount:   1,
		PrivacyPolicyCount:       1,
		ApprovalPolicyCount:      1,
		CompiledAttributeCount:   9,
		ComplianceCheckCount:     12,
		PassedCheckCount:         12,
		ExternalRequirementCount: 1,
		SummaryJSON:              `{"status":"ready"}`,
		ReportJSON:               `{"feature_id":"NAS-0091"}`,
		Actor:                    "ops@example.test",
		Cases: []BroadbandGovernanceCaseInput{
			{
				CaseKey:         "li-2026-001",
				Name:            "court-order-1",
				CaseID:          "LI-2026-001",
				LegalAuthority:  "court-order",
				SubscriberID:    "sub-lab-cpe-01",
				Username:        "lab-cpe-01@example.net",
				Tenant:          "retail",
				Scope:           "accounting-metadata",
				Status:          "ready",
				AttributesJSON:  `[{"name":"Class","value":"aegisnas:li:li-2026-001"}]`,
				PlanFingerprint: "sha256:test",
			},
		},
		Requests: []BroadbandSelfServiceRequestInput{
			{
				RequestKey:       "plan-change",
				Action:           "plan_change",
				Name:             "plan-change",
				Status:           "ready",
				RequiresApproval: true,
				RequiresMFA:      true,
				AttributesJSON:   `[{"name":"Chargeable-User-Identity","value":"plan-change"}]`,
				PlanFingerprint:  "sha256:test",
			},
		},
	})
	require.NoError(t, err)
	assert.NotEmpty(t, eventID)

	events, err := ListBroadbandGovernanceSelfServiceEvents(5)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "applied", events[0].Status)
	assert.Equal(t, 1, events[0].CaseCount)
	assert.Equal(t, 1, events[0].SelfServiceActionCount)
	assert.Equal(t, "ops@example.test", events[0].Actor)

	cases, err := ListBroadbandGovernanceCases(5, "ready")
	require.NoError(t, err)
	require.Len(t, cases, 1)
	assert.Equal(t, "li-2026-001", cases[0].CaseKey)
	assert.Equal(t, "sub-lab-cpe-01", cases[0].SubscriberID)
	assert.Equal(t, "sha256:test", cases[0].PlanFingerprint)

	requests, err := ListBroadbandSelfServiceRequests(5, "ready")
	require.NoError(t, err)
	require.Len(t, requests, 1)
	assert.Equal(t, "plan-change", requests[0].RequestKey)
	assert.True(t, requests[0].RequiresApproval)
	assert.True(t, requests[0].RequiresMFA)

	summary, err := GetBroadbandGovernanceSelfServiceSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TotalEvents)
	assert.Equal(t, 1, summary.ApplyEvents)
	assert.Equal(t, 1, summary.AppliedCount)
	assert.Equal(t, 1, summary.ActiveCaseCount)
	assert.Equal(t, 1, summary.ActiveSelfServiceRequests)
	assert.Equal(t, "sha256:test", summary.LastFingerprint)
	assert.Equal(t, 1, summary.LastCaseCount)
	assert.Equal(t, 1, summary.LastSelfServiceActionCount)
	assert.Equal(t, 1, summary.LastPrivacyPolicyCount)
	assert.Equal(t, 9, summary.LastCompiledAttributeCount)
}
