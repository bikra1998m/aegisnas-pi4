package policy

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestTypedPolicyExpressionMatchesNestedRequest(t *testing.T) {
	expr := TypedExpression{
		All: []TypedExpression{
			{Field: "authenticated", Op: "eq", Value: true},
			{Field: "groups", Op: "contains", Value: "engineering"},
			{Any: []TypedExpression{
				{Field: "risk_score", Op: "lte", Value: 40},
				{Field: "auth_method", Op: "eq", Value: "eap-tls"},
			}},
			{Not: &TypedExpression{Field: "posture", Op: "eq", Value: "infected"}},
		},
	}
	require.NoError(t, ValidateExpression(expr))
	matched, trace := EvaluateTypedExpression(expr, &Request{
		Authenticated: true,
		Groups:        []string{"staff", "engineering"},
		AuthMethod:    "peap",
		RiskScore:     20,
		Posture:       "healthy",
	})
	assert.True(t, matched)
	assert.NotEmpty(t, trace)
}

func TestTypedPolicyLegacyConditionsCompileToTypedExpression(t *testing.T) {
	expr, legacy, err := CompileMatchConditions(json.RawMessage(`{"authenticated": true, "group": ["staff", "engineering"], "blacklisted": false}`))
	require.NoError(t, err)
	assert.True(t, legacy)
	require.Len(t, expr.All, 3)

	matched, _ := EvaluateTypedExpression(expr, &Request{
		Authenticated: true,
		Groups:        []string{"engineering"},
		Attributes:    map[string]string{"blacklisted": "false"},
	})
	assert.True(t, matched)
}

func TestTypedPolicySupportsCIDRTimeAndNumericOperators(t *testing.T) {
	evaluatedAt := time.Date(2026, 7, 20, 9, 30, 0, 0, time.UTC)
	expr := TypedExpression{All: []TypedExpression{
		{Field: "source_ip", Op: "cidr", Value: "10.20.0.0/16"},
		{Field: "hour", Op: "between", Values: []any{8, 17}},
		{Field: "time_of_day", Op: "time_between", Value: "09:00-10:00"},
	}}
	require.NoError(t, ValidateExpression(expr))
	matched, _ := EvaluateTypedExpression(expr, &Request{
		SourceIP:    "10.20.30.40",
		EvaluatedAt: evaluatedAt,
	})
	assert.True(t, matched)
}

func TestTypedPolicyEvaluateRulesExplainsConflictsAndDeny(t *testing.T) {
	vlan20 := 20
	vlan30 := 30
	result := EvaluateRules(&Request{Authenticated: true}, []Rule{
		{
			ID:              1,
			Name:            "base",
			Priority:        100,
			Enabled:         true,
			MatchConditions: json.RawMessage(`{"field":"authenticated","op":"eq","value":true}`),
			Action:          "allow",
			VLAN:            &vlan20,
		},
		{
			ID:              2,
			Name:            "override",
			Priority:        90,
			Enabled:         true,
			MatchConditions: json.RawMessage(`{"field":"authenticated","op":"eq","value":true}`),
			Action:          "allow",
			VLAN:            &vlan30,
		},
		{
			ID:              3,
			Name:            "deny",
			Priority:        80,
			Enabled:         true,
			MatchConditions: json.RawMessage(`{"field":"authenticated","op":"eq","value":true}`),
			Action:          "deny",
		},
	}, zap.NewNop())
	assert.False(t, result.Decision.Allow)
	require.Len(t, result.MatchedRules, 3)
	assert.Contains(t, result.Conflicts[0], "overrides VLAN")
	assert.NotEmpty(t, result.PolicySetHash)
	assert.NotEmpty(t, result.RequestHash)
}

func TestTypedPolicyRejectsInvalidExpression(t *testing.T) {
	err := ValidateExpression(TypedExpression{Field: "risk_score", Op: "between", Values: []any{1}})
	assert.ErrorContains(t, err, "values")

	err = ValidateExpression(TypedExpression{Field: "unknown_field", Op: "eq", Value: "x"})
	assert.ErrorContains(t, err, "not supported")
}
