package db

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicySimulationAnalysisPersistenceAndReplaySamples(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "policy-simulation-analysis-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	require.NoError(t, tmpfile.Close())
	require.NoError(t, Init(tmpfile.Name()))
	t.Cleanup(func() { _ = Close() })
	require.NoError(t, Migrate())

	contentJSON := `{"schema_version":1,"key":"default","name":"Default","enabled":true,"rules":[{"name":"allow-employees","priority":100,"enabled":true,"match_conditions":{"field":"groups","op":"contains","value":"employees"},"action":"allow"}]}`
	version, err := CreatePolicySetVersion(context.Background(), CreatePolicySetVersionRequest{
		SetKey:           "default",
		ContentJSON:      contentJSON,
		ContentSHA256:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		PolicySHA256:     "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		RuleCount:        1,
		MaxDepth:         1,
		ApprovalRequired: true,
		MinApprovals:     1,
		CreatedBy:        "maker",
		Status:           PolicySetStatusApproved,
	})
	require.NoError(t, err)

	require.NoError(t, RecordPolicyEngineEvaluation(PolicyEngineEvaluation{
		EvaluationID:       "eval-replay-1",
		PolicySetHash:      version.PolicySHA256,
		RequestHash:        "request-hash-1",
		Decision:           "allow",
		Allowed:            true,
		MatchedRulesJSON:   `[{"name":"allow-employees","priority":100,"action":"allow"}]`,
		ConflictsJSON:      `[]`,
		TraceJSON:          `[]`,
		RequestSummaryJSON: `{"tenant":"corp","groups":1,"authenticated":true}`,
		RequestReplayJSON:  `{"tenant":"corp","groups":["employees"],"authenticated":true}`,
	}, 100))

	samples, err := ListPolicyEngineReplaySamples(10)
	require.NoError(t, err)
	require.Len(t, samples, 1)
	assert.Contains(t, samples[0].RequestReplayJSON, "employees")

	require.NoError(t, RecordPolicySimulationAnalysis(PolicySimulationAnalysisRecord{
		AnalysisID:            "psa-test",
		VersionID:             version.ID,
		ActiveVersionID:       version.ID,
		ActivePolicySHA256:    version.PolicySHA256,
		CandidatePolicySHA256: version.PolicySHA256,
		SampleSource:          "history",
		SampleCount:           1,
		DecisionChangeCount:   0,
		ShadowedRuleCount:     1,
		IneffectiveRuleCount:  1,
		RiskLevel:             "medium",
		SummaryJSON:           `{"risk_level":"medium"}`,
		ResultJSON:            `{"schema_version":1,"risk_level":"medium"}`,
	}, 100))

	records, err := ListPolicySimulationAnalyses(10)
	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Equal(t, "psa-test", records[0].AnalysisID)

	summary, err := SummarizePolicySimulationAnalyses()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TotalAnalyses)
	assert.Equal(t, "medium", summary.LastRiskLevel)
	assert.Equal(t, 1, summary.MediumCount)
	assert.Equal(t, 1, summary.LastShadowedRuleCount)
	assert.Equal(t, 1, summary.LastIneffectiveRuleCount)
}
