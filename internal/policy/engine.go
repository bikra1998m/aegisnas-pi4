package policy

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

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
	result, err := e.EvaluateDetailed(req)
	if err != nil {
		return nil, err
	}
	return &result.Decision, nil
}

// EvaluateDetailed processes all enabled rules and returns an explainable policy result.
func (e *Engine) EvaluateDetailed(req *Request) (*EvaluationResult, error) {
	// Optionally enrich request with LDAP groups if missing
	if err := e.EnrichRequest(req); err != nil {
		e.logger.Warn("failed to enrich request with LDAP groups", zap.Error(err))
		// Continue anyway
	}

	// Load rules from DB
	rules, err := e.loadRulesForTenant(req.Tenant)
	if err != nil {
		return nil, err
	}

	return EvaluateRules(req, rules, e.logger), nil
}

func (e *Engine) LoadRules() ([]Rule, error) {
	return e.loadRulesForTenant("")
}

// EvaluateRules evaluates a caller-provided policy set. It is intentionally
// independent from database access so tests, simulations, and future approval
// workflows can replay exact rule sets.
func EvaluateRules(req *Request, rules []Rule, logger *zap.Logger) *EvaluationResult {
	if logger == nil {
		logger = zap.NewNop()
	}
	evaluatedAt := time.Now().UTC()
	if req != nil && !req.EvaluatedAt.IsZero() {
		evaluatedAt = req.EvaluatedAt.UTC()
	}
	policySetHash := PolicySetHash(rules)
	requestHash := RequestHash(req)
	final := &Decision{
		Allow:      false, // default deny if no rule matches
		Quarantine: false,
	}
	result := &EvaluationResult{
		SchemaVersion: TypedPolicySchemaVersion,
		EvaluatedAt:   evaluatedAt.Format(time.RFC3339Nano),
		PolicySetHash: policySetHash,
		RequestHash:   requestHash,
		EvaluationID:  NewEvaluationID(policySetHash, requestHash, evaluatedAt),
		Decision:      *final,
	}

	for _, rule := range rules {
		if !rule.Enabled {
			result.SkippedRules = append(result.SkippedRules, RuleDiagnostic{ID: rule.ID, Name: rule.Name, Priority: rule.Priority, Status: "disabled", Message: "rule disabled"})
			continue
		}
		expr, legacy, err := CompileMatchConditions(rule.MatchConditions)
		if err != nil {
			result.InvalidRuleCount++
			result.SkippedRules = append(result.SkippedRules, RuleDiagnostic{ID: rule.ID, Name: rule.Name, Priority: rule.Priority, Status: "invalid", Message: err.Error()})
			logger.Error("rule match error", zap.String("rule", rule.Name), zap.Error(err))
			continue
		}
		if legacy {
			result.LegacyRuleCount++
		} else {
			result.TypedRuleCount++
		}
		match, trace := EvaluateTypedExpression(expr, req)
		for i := range trace {
			trace[i].Path = fmt.Sprintf("rule[%s].%s", rule.Name, strings.TrimPrefix(trace[i].Path, "$"))
		}
		result.Trace = append(result.Trace, trace...)
		if match {
			dec := ruleToDecision(&rule)
			result.Conflicts = append(result.Conflicts, decisionConflicts(final, dec, rule.Name)...)
			logger.Debug("rule matched", zap.String("rule", rule.Name))
			final.Merge(dec)
			result.MatchedRules = append(result.MatchedRules, MatchedRule{ID: rule.ID, Name: rule.Name, Priority: rule.Priority, Action: normalizedAction(rule.Action), Notes: dec.Notes})
			// If rule action is deny, stop processing further rules (explicit deny)
			if normalizedAction(rule.Action) == "deny" {
				final.Allow = false
				break
			}
		}
	}
	result.Decision = *final
	return result
}

func (e *Engine) loadRules() ([]Rule, error) {
	return e.loadRulesForTenant("")
}

func (e *Engine) loadRulesForTenant(tenant string) ([]Rule, error) {
	cfg := config.Get()
	if cfg != nil && cfg.Governance.MultiTenantEnabled && strings.TrimSpace(tenant) != "" {
		active, err := db.GetActivePolicySetVersionForTenant("default", tenant)
		if err != nil {
			return nil, err
		}
		if active == nil {
			return nil, nil
		}
		set, err := ParsePolicySet(active.ContentJSON)
		if err != nil {
			return nil, fmt.Errorf("active tenant policy set version %d is invalid: %w", active.ID, err)
		}
		return FlattenPolicySet(set, cfg.Policy.MaxPolicySetDepth)
	}
	if active, err := db.GetActivePolicySetVersion("default"); err != nil {
		return nil, err
	} else if active != nil {
		set, err := ParsePolicySet(active.ContentJSON)
		if err != nil {
			return nil, fmt.Errorf("active policy set version %d is invalid: %w", active.ID, err)
		}
		maxDepth := 0
		if cfg := config.Get(); cfg != nil {
			maxDepth = cfg.Policy.MaxPolicySetDepth
		}
		return FlattenPolicySet(set, maxDepth)
	}
	if cfg != nil && cfg.Governance.MultiTenantEnabled && strings.TrimSpace(tenant) != "" {
		return nil, nil
	}
	rows, err := db.DB.Query(`SELECT id, name, description, priority, enabled, match_conditions, action,
		vlan, bandwidth_profile, session_timeout, idle_timeout, portal_profile, acl_policy_name, quarantine, COALESCE(service_chain_json, '[]')
		FROM policy_rules ORDER BY priority DESC, name`)
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
		var matchConditions, serviceChainJSON string
		err := rows.Scan(&r.ID, &r.Name, &description, &r.Priority, &r.Enabled, &matchConditions, &r.Action,
			&vlan, &bwProfile, &sessionTO, &idleTO, &portalProfile, &aclPolicyName, &r.Quarantine, &serviceChainJSON)
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
		if err := json.Unmarshal([]byte(serviceChainJSON), &r.ServiceChain); err != nil {
			return nil, fmt.Errorf("decode service_chain for policy rule %q: %w", r.Name, err)
		}
		r.ServiceChain = NormalizeServiceChain(r.ServiceChain)
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
	expr, _, err := CompileMatchConditions(rule.MatchConditions)
	if err != nil {
		return false, fmt.Errorf("invalid match_conditions JSON: %w", err)
	}
	matched, _ := EvaluateTypedExpression(expr, req)
	return matched, nil
}

func ruleToDecision(rule *Rule) *Decision {
	action := normalizedAction(rule.Action)
	dec := &Decision{
		Allow:            action == "allow" || action == "quarantine",
		Quarantine:       rule.Quarantine || action == "quarantine",
		VLAN:             rule.VLAN,
		BandwidthProfile: rule.BandwidthProfile,
		SessionTimeout:   rule.SessionTimeout,
		IdleTimeout:      rule.IdleTimeout,
		PortalProfile:    rule.PortalProfile,
		ACLPolicyName:    rule.ACLPolicyName,
		ServiceChain:     NormalizeServiceChain(rule.ServiceChain),
		MatchedRule:      rule.Name,
	}
	if action == "deny" {
		dec.Allow = false
		dec.Notes = append(dec.Notes, "explicit deny")
	}
	if action == "quarantine" {
		dec.Notes = append(dec.Notes, "quarantine action")
	}
	return dec
}

func normalizedAction(action string) string {
	action = strings.ToLower(strings.TrimSpace(action))
	if action == "" {
		return "allow"
	}
	return action
}

func decisionConflicts(current, next *Decision, ruleName string) []string {
	if current == nil || next == nil {
		return nil
	}
	var conflicts []string
	if current.VLAN != nil && next.VLAN != nil && *current.VLAN != *next.VLAN {
		conflicts = append(conflicts, fmt.Sprintf("rule %s overrides VLAN %d with %d", ruleName, *current.VLAN, *next.VLAN))
	}
	if current.BandwidthProfile != nil && next.BandwidthProfile != nil && !strings.EqualFold(*current.BandwidthProfile, *next.BandwidthProfile) {
		conflicts = append(conflicts, fmt.Sprintf("rule %s overrides bandwidth profile %s with %s", ruleName, *current.BandwidthProfile, *next.BandwidthProfile))
	}
	if current.ACLPolicyName != nil && next.ACLPolicyName != nil && !strings.EqualFold(*current.ACLPolicyName, *next.ACLPolicyName) {
		conflicts = append(conflicts, fmt.Sprintf("rule %s overrides ACL policy %s with %s", ruleName, *current.ACLPolicyName, *next.ACLPolicyName))
	}
	if current.PortalProfile != nil && next.PortalProfile != nil && !strings.EqualFold(*current.PortalProfile, *next.PortalProfile) {
		conflicts = append(conflicts, fmt.Sprintf("rule %s overrides portal profile %s with %s", ruleName, *current.PortalProfile, *next.PortalProfile))
	}
	for _, conflict := range serviceChainConflicts(current.ServiceChain, next.ServiceChain, ruleName) {
		conflicts = append(conflicts, conflict)
	}
	return conflicts
}

func serviceChainConflicts(current, next []ServiceIntent, ruleName string) []string {
	if len(current) == 0 || len(next) == 0 {
		return nil
	}
	byKey := map[string]string{}
	for _, service := range NormalizeServiceChain(current) {
		byKey[service.Key] = ServiceChainHash([]ServiceIntent{service})
	}
	var conflicts []string
	for _, service := range NormalizeServiceChain(next) {
		if existing, ok := byKey[service.Key]; ok && existing != ServiceChainHash([]ServiceIntent{service}) {
			conflicts = append(conflicts, fmt.Sprintf("rule %s overrides service %s in subscriber service chain", ruleName, service.Key))
		}
	}
	return conflicts
}
