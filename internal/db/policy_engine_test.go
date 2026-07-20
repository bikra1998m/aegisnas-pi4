package db

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicyEngineEvaluationPersistenceAndRetention(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "policy-engine-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	require.NoError(t, Init(tmpfile.Name()))
	defer Close()
	require.NoError(t, Migrate())

	now := time.Now().UTC()
	require.NoError(t, RecordPolicyEngineEvaluation(PolicyEngineEvaluation{
		EvaluationID:       "eval-1",
		EvaluatedAt:        now.Add(-time.Minute).Format(time.RFC3339Nano),
		PolicySetHash:      "policy-hash",
		RequestHash:        "request-hash-1",
		UsernameHash:       "Alice@example.com",
		CallingStationHash: "AA:BB:CC:DD:EE:FF",
		Tenant:             "corp",
		Decision:           "allow",
		Allowed:            true,
		MatchedRulesJSON:   `[{"name":"allow-corp"}]`,
		ConflictsJSON:      `[]`,
		TraceJSON:          `[{"matched":true}]`,
		RequestSummaryJSON: `{"role":"employee"}`,
		TypedRuleCount:     1,
	}, 2))
	require.NoError(t, RecordPolicyEngineEvaluation(PolicyEngineEvaluation{
		EvaluationID:       "eval-2",
		EvaluatedAt:        now.Format(time.RFC3339Nano),
		PolicySetHash:      "policy-hash",
		RequestHash:        "request-hash-2",
		UsernameHash:       "Bob@example.com",
		Decision:           "deny",
		MatchedRulesJSON:   `[{"name":"deny"}]`,
		ConflictsJSON:      `["deny override"]`,
		TraceJSON:          `[]`,
		RequestSummaryJSON: `{}`,
		LegacyRuleCount:    1,
		InvalidRuleCount:   1,
	}, 1))

	records, err := ListPolicyEngineEvaluations(10)
	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Equal(t, "eval-2", records[0].EvaluationID)
	assert.NotEqual(t, "Bob@example.com", records[0].UsernameHash)

	summary, err := SummarizePolicyEngine(100)
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TotalRecords)
	assert.Equal(t, 1, summary.DeniedCount)
	assert.Equal(t, "deny", summary.LastDecision)
	assert.Equal(t, "eval-2", summary.LastEvaluationID)
	assert.Equal(t, 1, summary.LastConflictCount)
	assert.Equal(t, 1, summary.InvalidRuleCount)
}
