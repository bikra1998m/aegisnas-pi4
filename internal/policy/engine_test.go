package policy

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestEngine_Evaluate(t *testing.T) {
	logger := zap.NewNop()
	engine := NewEngine(logger)

	// Insert test rules into DB (setup DB before test)
	// For simplicity, we'll mock the rule loading by directly testing matches function.

	req := &Request{
		Authenticated: true,
		Role:          "guest-basic",
		AuthMethod:    "pap",
	}

	// Create a rule that matches
	rule := Rule{
		Name:            "test-rule",
		Priority:        10,
		Enabled:         true,
		MatchConditions: json.RawMessage(`{"authenticated": true, "role": "guest-basic"}`),
		Action:          "allow",
	}
	var vlan int = 20
	rule.VLAN = &vlan
	aclPolicyName := "guest-internet"
	rule.ACLPolicyName = &aclPolicyName

	match, err := engine.matches(req, rule)
	require.NoError(t, err)
	assert.True(t, match)

	dec := ruleToDecision(&rule)
	assert.True(t, dec.Allow)
	assert.Equal(t, 20, *dec.VLAN)
	assert.Equal(t, "guest-internet", *dec.ACLPolicyName)
}

func TestMatches_MultipleConditions(t *testing.T) {
	logger := zap.NewNop()
	engine := NewEngine(logger)

	req := &Request{
		Authenticated: true,
		Role:          "corp-standard",
		Groups:        []string{"engineering", "staff"},
		SSID:          "CorpWiFi",
	}

	rule := Rule{
		MatchConditions: json.RawMessage(`{"authenticated": true, "group": "engineering", "ssid": "CorpWiFi"}`),
	}
	match, err := engine.matches(req, rule)
	require.NoError(t, err)
	assert.True(t, match)

	// Negative case
	rule2 := Rule{
		MatchConditions: json.RawMessage(`{"authenticated": true, "group": "marketing"}`),
	}
	match, err = engine.matches(req, rule2)
	require.NoError(t, err)
	assert.False(t, match)
}
