package policy

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/ldap"
	"go.uber.org/zap"
)

// Engine evaluates policy rules against a request.
type Engine struct {
	logger *zap.Logger
}

func NewEngine(logger *zap.Logger) *Engine {
	return &Engine{logger: logger}
}

// EnrichRequest populates missing fields like Groups from LDAP if available.
func (e *Engine) EnrichRequest(req *Request) error {
	cfg := config.Get()
	if cfg == nil || !cfg.LDAP.Enabled || len(req.Groups) > 0 || req.Username == "" {
		return nil
	}
	client, err := ldap.NewClient(&cfg.LDAP, e.logger)
	if err != nil {
		return err
	}
	defer client.Close()
	groups, err := client.GetUserGroups(req.Username)
	if err != nil {
		return err
	}
	req.Groups = groups
	return nil
}

// Evaluate processes all enabled rules in priority order and returns the final decision.
func (e *Engine) Evaluate(req *Request) (*Decision, error) {

	// Optionally enrich request with LDAP groups if missing
	if err := e.EnrichRequest(req); err != nil {
		e.logger.Warn("failed to enrich request with LDAP groups", zap.Error(err))
		// Continue anyway
	}

	// Load rules from DB
	rules, err := e.loadRules()
	if err != nil {
		return nil, err
	}

	final := &Decision{
		Allow:      false, // default deny if no rule matches
		Quarantine: false,
	}

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		match, err := e.matches(req, rule)
		if err != nil {
			e.logger.Error("rule match error", zap.String("rule", rule.Name), zap.Error(err))
			continue
		}
		if match {
			dec := ruleToDecision(&rule)
			e.logger.Debug("rule matched", zap.String("rule", rule.Name))
			final.Merge(dec)
			// If rule action is deny, stop processing further rules (explicit deny)
			if rule.Action == "deny" {
				final.Allow = false
				break
			}
		}
	}
	return final, nil
}

func (e *Engine) loadRules() ([]Rule, error) {
	rows, err := db.DB.Query(`SELECT id, name, description, priority, enabled, match_conditions, action,
		vlan, bandwidth_profile, session_timeout, idle_timeout, portal_profile, acl_policy_name, quarantine
		FROM policy_rules WHERE enabled = 1 ORDER BY priority DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []Rule
	for rows.Next() {
		var r Rule
		var vlan sql.NullInt32
		var description, bwProfile, portalProfile, aclPolicyName sql.NullString
		var sessionTO, idleTO sql.NullInt32
		var matchConditions string
		err := rows.Scan(&r.ID, &r.Name, &description, &r.Priority, &r.Enabled, &matchConditions, &r.Action,
			&vlan, &bwProfile, &sessionTO, &idleTO, &portalProfile, &aclPolicyName, &r.Quarantine)
		if err != nil {
			return nil, err
		}
		if description.Valid {
			r.Description = description.String
		}
		r.MatchConditions = json.RawMessage(matchConditions)
		if vlan.Valid {
			v := int(vlan.Int32)
			r.VLAN = &v
		}
		if bwProfile.Valid {
			s := bwProfile.String
			r.BandwidthProfile = &s
		}
		if sessionTO.Valid {
			s := int(sessionTO.Int32)
			r.SessionTimeout = &s
		}
		if idleTO.Valid {
			i := int(idleTO.Int32)
			r.IdleTimeout = &i
		}
		if portalProfile.Valid {
			p := portalProfile.String
			r.PortalProfile = &p
		}
		if aclPolicyName.Valid {
			p := aclPolicyName.String
			r.ACLPolicyName = &p
		}
		rules = append(rules, r)
	}
	// Sort by priority descending (already done by ORDER BY, but just in case)
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Priority > rules[j].Priority
	})
	return rules, nil
}

// matches checks if a request satisfies the rule's conditions.
func (e *Engine) matches(req *Request, rule Rule) (bool, error) {
	var conds map[string]interface{}
	if err := json.Unmarshal(rule.MatchConditions, &conds); err != nil {
		return false, fmt.Errorf("invalid match_conditions JSON: %w", err)
	}

	for key, expected := range conds {
		switch key {
		case "authenticated":
			if val, ok := expected.(bool); ok {
				if req.Authenticated != val {
					return false, nil
				}
			}
		case "role":
			if val, ok := expected.(string); ok {
				if req.Role != val {
					return false, nil
				}
			} else if vals, ok := expected.([]interface{}); ok {
				found := false
				for _, v := range vals {
					if s, ok := v.(string); ok && req.Role == s {
						found = true
						break
					}
				}
				if !found {
					return false, nil
				}
			}
		case "auth_method":
			if val, ok := expected.(string); ok {
				if req.AuthMethod != val {
					return false, nil
				}
			}
		case "identity_source":
			if val, ok := expected.(string); ok {
				if req.IdentitySource != val {
					return false, nil
				}
			}
		case "ssid":
			if val, ok := expected.(string); ok {
				if req.SSID != val {
					return false, nil
				}
			}
		case "nas_identifier":
			if val, ok := expected.(string); ok {
				if req.NASIdentifier != val {
					return false, nil
				}
			}
		case "site":
			if val, ok := expected.(string); ok {
				if req.Site != val {
					return false, nil
				}
			}
		case "group":
			if val, ok := expected.(string); ok {
				found := false
				for _, g := range req.Groups {
					if g == val {
						found = true
						break
					}
				}
				if !found {
					return false, nil
				}
			} else if vals, ok := expected.([]interface{}); ok {
				found := false
				for _, v := range vals {
					if s, ok := v.(string); ok {
						for _, g := range req.Groups {
							if g == s {
								found = true
								break
							}
						}
					}
				}
				if !found {
					return false, nil
				}
			}
		// Additional conditions can be added as needed
		default:
			// Unknown condition key; ignore or log? For determinism, treat as not matched.
			e.logger.Warn("unknown policy condition", zap.String("key", key))
			return false, nil
		}
	}
	return true, nil
}

func ruleToDecision(rule *Rule) *Decision {
	dec := &Decision{
		Allow:            rule.Action == "allow",
		Quarantine:       rule.Quarantine,
		VLAN:             rule.VLAN,
		BandwidthProfile: rule.BandwidthProfile,
		SessionTimeout:   rule.SessionTimeout,
		IdleTimeout:      rule.IdleTimeout,
		PortalProfile:    rule.PortalProfile,
		ACLPolicyName:    rule.ACLPolicyName,
		MatchedRule:      rule.Name,
	}
	if rule.Action == "deny" {
		dec.Allow = false
	}
	return dec
}
