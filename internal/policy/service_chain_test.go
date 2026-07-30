package policy

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestServiceChainValidationEnforcesOrderingAndLimits(t *testing.T) {
	vlan := 42
	chain := []ServiceIntent{
		{Key: "data", Type: "data", Sequence: 10, VLAN: &vlan},
		{Key: "qos", Type: "qos", Sequence: 20, DependsOn: []string{"data"}, Optional: true},
	}
	require.NoError(t, ValidateServiceChainWithLimit(chain, 2))
	summary := SummarizeServiceChain(chain)
	assert.True(t, summary.Valid)
	assert.Equal(t, 2, summary.ServiceCount)
	assert.Equal(t, 1, summary.Required)
	assert.Equal(t, 1, summary.Optional)
	assert.Len(t, summary.ChainHash, 64)

	err := ValidateServiceChain([]ServiceIntent{
		{Key: "qos", Sequence: 10, DependsOn: []string{"data"}},
		{Key: "data", Sequence: 20},
	})
	assert.ErrorContains(t, err, "must have a lower sequence")

	err = ValidateServiceChain([]ServiceIntent{{Key: "data"}, {Key: "DATA"}})
	assert.ErrorContains(t, err, "duplicates service key")
}

func TestServiceChainEvaluationAndMerge(t *testing.T) {
	data := []ServiceIntent{{Key: "data", Type: "data", Sequence: 10}}
	qos := []ServiceIntent{{Key: "qos", Type: "qos", Sequence: 20, DependsOn: []string{"data"}}}
	result := EvaluateRules(&Request{Authenticated: true}, []Rule{
		{
			ID:              1,
			Name:            "base-data-service",
			Priority:        100,
			Enabled:         true,
			MatchConditions: json.RawMessage(`{"field":"authenticated","op":"eq","value":true}`),
			Action:          "allow",
			ServiceChain:    data,
		},
		{
			ID:              2,
			Name:            "qos-service",
			Priority:        90,
			Enabled:         true,
			MatchConditions: json.RawMessage(`{"field":"authenticated","op":"eq","value":true}`),
			Action:          "allow",
			ServiceChain:    qos,
		},
	}, zap.NewNop())

	require.True(t, result.Decision.Allow)
	require.Len(t, result.Decision.ServiceChain, 2)
	assert.Equal(t, "data", result.Decision.ServiceChain[0].Key)
	assert.Equal(t, "qos", result.Decision.ServiceChain[1].Key)
	assert.Empty(t, result.Conflicts)
}

func TestServiceChainPolicyAnalysisDetectsDecisionChange(t *testing.T) {
	active := []Rule{{
		ID:              1,
		Name:            "allow-base",
		Priority:        100,
		Enabled:         true,
		MatchConditions: json.RawMessage(`{"field":"authenticated","op":"eq","value":true}`),
		Action:          "allow",
	}}
	candidate := []Rule{{
		ID:              1,
		Name:            "allow-base",
		Priority:        100,
		Enabled:         true,
		MatchConditions: json.RawMessage(`{"field":"authenticated","op":"eq","value":true}`),
		Action:          "allow",
		ServiceChain:    []ServiceIntent{{Key: "data", Type: "data", Sequence: 10}},
	}}
	analysis := AnalyzePolicySimulation(active, candidate, []ReplaySample{{
		Source:  "manual",
		Request: Request{Authenticated: true},
	}}, SimulationAnalysisOptions{}, zap.NewNop())

	assert.Equal(t, 1, analysis.DecisionChangeCount)
	assert.Equal(t, 1, analysis.ServiceChainChangeCount)
	assert.NotEmpty(t, analysis.RiskLevel)
}
