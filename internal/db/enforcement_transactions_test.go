package db

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnforcementTransactionLedgerSummaryAndRollbackCandidate(t *testing.T) {
	require.NoError(t, Init(":memory:"))
	DB.SetMaxOpenConns(1)
	defer Close()
	require.NoError(t, Migrate())

	started := time.Now().UTC().Add(-time.Minute)
	completed := time.Now().UTC()
	transactionID, err := RecordEnforcementTransaction(EnforcementTransactionInput{
		TransactionID:   "enf-apply-test",
		Operation:       "apply",
		Status:          "applied",
		Actor:           "ops",
		TargetCount:     2,
		AppliedCount:    2,
		PlanFingerprint: "sha256:plan",
		Summary:         "applied",
		RequestJSON:     `{"targets":["runtime_qos","runtime_firewall"]}`,
		PlanJSON:        `{"status":"ready"}`,
		ResultJSON:      `{"status":"applied"}`,
		DiagnosticsJSON: `[]`,
		StartedAt:       &started,
		CompletedAt:     &completed,
		Steps: []EnforcementTransactionStepInput{
			{
				StepOrder:          1,
				Target:             "runtime_qos",
				Operation:          "apply",
				Status:             "applied",
				DesiredFingerprint: "sha256:qos-desired",
				ActiveFingerprint:  "sha256:qos-active",
				PreviousSnapshotID: "qos-prev",
				SnapshotID:         "qos-new",
				RollbackSupported:  true,
				DetailsJSON:        `{"commands":4}`,
				StartedAt:          &started,
				CompletedAt:        &completed,
			},
			{
				StepOrder:          2,
				Target:             "runtime_firewall",
				Operation:          "apply",
				Status:             "applied",
				DesiredFingerprint: "sha256:fw-desired",
				ActiveFingerprint:  "sha256:fw-active",
				PreviousSnapshotID: "fw-prev",
				SnapshotID:         "fw-new",
				RollbackSupported:  true,
				DetailsJSON:        `{"rules":8}`,
				StartedAt:          &started,
				CompletedAt:        &completed,
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "enf-apply-test", transactionID)

	driftID, err := RecordEnforcementDriftEvent(EnforcementDriftEventInput{
		TransactionID:      transactionID,
		Target:             "runtime_firewall",
		Status:             "drifted",
		DesiredFingerprint: "sha256:fw-desired",
		ActiveFingerprint:  "sha256:other",
		Message:            "ruleset changed outside transaction",
		DetailsJSON:        `{"source":"test"}`,
		Actor:              "ops",
		ObservedAt:         &completed,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, driftID)

	transactions, err := ListEnforcementTransactions(10)
	require.NoError(t, err)
	require.Len(t, transactions, 1)
	assert.Equal(t, "apply", transactions[0].Operation)
	assert.Equal(t, "sha256:plan", transactions[0].PlanFingerprint)

	record, steps, found, err := GetEnforcementTransaction(transactionID)
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, transactionID, record.TransactionID)
	require.Len(t, steps, 2)
	assert.Equal(t, "runtime_qos", steps[0].Target)
	assert.JSONEq(t, `{"commands":4}`, string(steps[0].DetailsJSON))

	candidate, candidateSteps, found, err := GetLatestEnforcementRollbackCandidate()
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, transactionID, candidate.TransactionID)
	require.Len(t, candidateSteps, 2)

	drifts, err := ListEnforcementDriftEvents(10)
	require.NoError(t, err)
	require.Len(t, drifts, 1)
	assert.Equal(t, "drifted", drifts[0].Status)

	summary, err := GetEnforcementTransactionSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TotalTransactions)
	assert.Equal(t, 1, summary.ApplyTransactions)
	assert.Equal(t, 1, summary.AppliedCount)
	assert.Equal(t, 2, summary.TotalSteps)
	assert.Equal(t, 1, summary.DriftEvents)
	assert.Equal(t, 1, summary.OpenDriftEvents)
	assert.Equal(t, transactionID, summary.LastTransactionID)

	require.NoError(t, TrimEnforcementTransactionHistory(100, 100))
}
