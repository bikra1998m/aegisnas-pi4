package policy

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicySetFlattensNestedRulesWithStablePaths(t *testing.T) {
	enabled := true
	set := PolicySet{
		Key:     "default",
		Name:    "Default",
		Enabled: &enabled,
		Rules: []Rule{{
			Name:            "base",
			Priority:        10,
			Enabled:         true,
			MatchConditions: json.RawMessage(`{"field":"authenticated","op":"eq","value":true}`),
			Action:          "allow",
		}},
		Children: []PolicySet{{
			Key:      "corp",
			Name:     "Corporate",
			Priority: 100,
			Enabled:  &enabled,
			Rules: []Rule{{
				Name:            "employees",
				Priority:        20,
				Enabled:         true,
				MatchConditions: json.RawMessage(`{"field":"groups","op":"contains","value":"employees"}`),
				Action:          "allow",
			}},
		}},
	}

	rules, err := FlattenPolicySet(set, 8)
	require.NoError(t, err)
	require.Len(t, rules, 2)
	assert.Equal(t, "default/corp/employees", rules[0].Name)
	assert.Equal(t, 120, rules[0].Priority)
	assert.Equal(t, "default/base", rules[1].Name)
	assert.NotEmpty(t, PolicySetContentHash(set))
}

func TestPolicySetCompareFindsAddedRemovedAndChangedRules(t *testing.T) {
	enabled := true
	from := PolicySetFromRules("default", "Default", "", []Rule{{
		Name:            "base",
		Priority:        10,
		Enabled:         true,
		MatchConditions: json.RawMessage(`{"field":"authenticated","op":"eq","value":true}`),
		Action:          "allow",
	}})
	to := PolicySet{
		Key:     "default",
		Name:    "Default",
		Enabled: &enabled,
		Rules: []Rule{{
			Name:            "base",
			Priority:        20,
			Enabled:         true,
			MatchConditions: json.RawMessage(`{"field":"authenticated","op":"eq","value":true}`),
			Action:          "allow",
		}, {
			Name:            "deny-risky",
			Priority:        100,
			Enabled:         true,
			MatchConditions: json.RawMessage(`{"field":"risk_score","op":"gte","value":90}`),
			Action:          "deny",
		}},
	}

	diff, err := ComparePolicySets(from, to, 8)
	require.NoError(t, err)
	assert.Len(t, diff.AddedRules, 1)
	assert.Len(t, diff.ChangedRules, 1)
	assert.Empty(t, diff.RemovedRules)
	assert.Equal(t, "default/deny-risky", diff.AddedRules[0].Name)
	assert.Equal(t, "default/base", diff.ChangedRules[0].Name)
}

func TestPolicySetRejectsExcessiveDepth(t *testing.T) {
	enabled := true
	set := PolicySet{Key: "root", Name: "Root", Enabled: &enabled}
	cursor := &set
	for i := 0; i < 4; i++ {
		cursor.Children = []PolicySet{{Key: "child" + string(rune('a'+i)), Name: "Child", Enabled: &enabled}}
		cursor = &cursor.Children[0]
	}

	err := ValidatePolicySet(set, 3)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "maximum nesting depth")
}
