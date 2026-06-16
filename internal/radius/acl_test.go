package radius

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRenderACLRulesForNASFilterAndCiscoAVPair(t *testing.T) {
	rules := []ACLRule{
		{
			Action:          "permit",
			Direction:       "in",
			Protocol:        "tcp",
			Source:          "any",
			Destination:     "any",
			DestinationPort: "443",
			Log:             true,
		},
		{
			Action:          "deny",
			Direction:       "out",
			Protocol:        "udp",
			Source:          "any",
			Destination:     "10.0.0.0/24",
			DestinationPort: "53",
		},
	}

	require.NoError(t, ValidateACLRules(rules))
	assert.Equal(t, []string{
		"permit in tcp from any to any 443 log",
		"deny out udp from any to 10.0.0.0/24 53",
	}, renderNASFilterRules(rules))
	assert.Equal(t, []string{
		"ip:inacl#1=permit tcp any any eq 443 log",
		"ip:outacl#1=deny udp any 10.0.0.0/24 eq 53",
	}, renderCiscoAVPairACLRules(rules))
}

func TestValidateACLRulesRejectsUnsafeTokens(t *testing.T) {
	err := ValidateACLRules([]ACLRule{{
		Action:      "permit",
		Direction:   "in",
		Protocol:    "tcp",
		Source:      "any",
		Destination: "any\"",
	}})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "acl_rules[0]")
}
