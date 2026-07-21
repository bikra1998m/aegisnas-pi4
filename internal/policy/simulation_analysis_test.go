package policy

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnalyzePolicySimulationReportsBlastRadiusAndShadowedRules(t *testing.T) {
	active := []Rule{{
		Name:            "employees-vlan10",
		Priority:        100,
		Enabled:         true,
		MatchConditions: json.RawMessage(`{"field":"groups","op":"contains","value":"employees"}`),
		Action:          "allow",
		VLAN:            intPtr(10),
	}}
	candidate := []Rule{{
		Name:            "employees-vlan20",
		Priority:        100,
		Enabled:         true,
		MatchConditions: json.RawMessage(`{"field":"groups","op":"contains","value":"employees"}`),
		Action:          "allow",
		VLAN:            intPtr(20),
	}, {
		Name:            "employees-ineffective",
		Priority:        95,
		Enabled:         true,
		MatchConditions: json.RawMessage(`{"field":"groups","op":"contains","value":"employees"}`),
		Action:          "allow",
	}, {
		Name:            "contractors-shadowed",
		Priority:        90,
		Enabled:         true,
		MatchConditions: json.RawMessage(`{"field":"groups","op":"contains","value":"contractors"}`),
		Action:          "allow",
		VLAN:            intPtr(30),
	}}
	samples := []ReplaySample{{
		Source: "manual",
		Request: Request{
			Authenticated: true,
			Groups:        []string{"employees"},
		},
	}}

	analysis := AnalyzePolicySimulation(active, candidate, samples, SimulationAnalysisOptions{}, nil)

	assert.Equal(t, 1, analysis.SampleCount)
	assert.Equal(t, 1, analysis.DecisionChangeCount)
	assert.Equal(t, 1, analysis.VLANChangeCount)
	assert.Equal(t, "critical", analysis.RiskLevel)
	require.Len(t, analysis.Deltas, 1)
	assert.Contains(t, analysis.Deltas[0].ChangedFields, "vlan")
	require.Len(t, analysis.ShadowedRules, 1)
	assert.Equal(t, "contractors-shadowed", analysis.ShadowedRules[0].Name)
	require.Len(t, analysis.IneffectiveRules, 1)
	assert.Equal(t, "employees-ineffective", analysis.IneffectiveRules[0].Name)
}

func TestAnalyzePolicySimulationClassifiesDenyToAllowCritical(t *testing.T) {
	active := []Rule{{
		Name:            "default-deny",
		Priority:        100,
		Enabled:         true,
		MatchConditions: json.RawMessage(`{"field":"authenticated","op":"eq","value":true}`),
		Action:          "deny",
	}}
	candidate := []Rule{{
		Name:            "allow-authenticated",
		Priority:        100,
		Enabled:         true,
		MatchConditions: json.RawMessage(`{"field":"authenticated","op":"eq","value":true}`),
		Action:          "allow",
	}}

	analysis := AnalyzePolicySimulation(active, candidate, []ReplaySample{{Request: Request{Authenticated: true}}}, SimulationAnalysisOptions{}, nil)

	assert.Equal(t, 1, analysis.DenyToAllowCount)
	assert.Equal(t, "critical", analysis.RiskLevel)
	assert.NotEmpty(t, analysis.AnalysisID)
}

func intPtr(value int) *int {
	return &value
}
