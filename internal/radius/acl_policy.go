package radius

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yourorg/aegisnas-pi4/internal/db"
)

// StoredACLPolicy is an enabled vendor-neutral ACL policy loaded from the
// configuration database.
type StoredACLPolicy struct {
	Name        string
	Description string
	InboundACL  string
	OutboundACL string
	Rules       []ACLRule
}

// LoadACLPolicy loads and validates an enabled ACL policy by name.
func LoadACLPolicy(name string) (StoredACLPolicy, bool, error) {
	name = strings.TrimSpace(name)
	if db.DB == nil || name == "" {
		return StoredACLPolicy{}, false, nil
	}

	var policy StoredACLPolicy
	var rulesJSON string
	err := db.DB.QueryRow(`SELECT name, COALESCE(description, ''), COALESCE(inbound_acl, ''), COALESCE(outbound_acl, ''), rules_json
		FROM acl_policies WHERE name = ? AND enabled = 1`, name).Scan(
		&policy.Name, &policy.Description, &policy.InboundACL, &policy.OutboundACL, &rulesJSON,
	)
	if err == sql.ErrNoRows {
		return StoredACLPolicy{}, false, nil
	}
	if err != nil {
		return StoredACLPolicy{}, false, err
	}
	if err := json.Unmarshal([]byte(rulesJSON), &policy.Rules); err != nil {
		return StoredACLPolicy{}, false, fmt.Errorf("decode ACL policy %q: %w", name, err)
	}
	policy.Rules, err = NormalizeACLRules(policy.Rules)
	if err != nil {
		return StoredACLPolicy{}, false, fmt.Errorf("ACL policy %q: %w", name, err)
	}
	return policy, true, nil
}

// ApplyStoredACLPolicy adds a persisted ACL policy to reply attributes.
func ApplyStoredACLPolicy(attrs *ReplyAttributes, name string) (bool, error) {
	if attrs == nil {
		return false, fmt.Errorf("reply attributes are required")
	}
	policy, found, err := LoadACLPolicy(name)
	if err != nil || !found {
		return found, err
	}
	attrs.ACLPolicyName = policy.Name
	attrs.InboundACL = policy.InboundACL
	attrs.OutboundACL = policy.OutboundACL
	attrs.ACLRules = append([]ACLRule(nil), policy.Rules...)
	return true, nil
}
