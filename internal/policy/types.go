package policy

import (
	"encoding/json"
	"time"
)

const TypedPolicySchemaVersion = 1
const PolicySetSchemaVersion = 1

// Request contains all attributes available for policy evaluation.
type Request struct {
	// User identity
	Username    string   `json:"username,omitempty"`
	Role        string   `json:"role,omitempty"`
	Groups      []string `json:"groups,omitempty"`
	Realm       string   `json:"realm,omitempty"`
	Tenant      string   `json:"tenant,omitempty"`
	DeviceGroup string   `json:"device_group,omitempty"`

	// Authentication context
	AuthMethod     string `json:"auth_method,omitempty"`     // "pap", "eap-peap", "eap-tls", "voucher"
	IdentitySource string `json:"identity_source,omitempty"` // "local", "ldap"

	// Network context
	SSID             string `json:"ssid,omitempty"`
	NASIdentifier    string `json:"nas_identifier,omitempty"`
	NASIPAddress     string `json:"nas_ip_address,omitempty"`
	NASPortID        string `json:"nas_port_id,omitempty"`
	NASPortType      string `json:"nas_port_type,omitempty"`
	CalledStationID  string `json:"called_station_id,omitempty"`
	CallingStationID string `json:"calling_station_id,omitempty"` // MAC address
	Site             string `json:"site,omitempty"`
	SourceIP         string `json:"source_ip,omitempty"`
	Vendor           string `json:"vendor,omitempty"`
	VLAN             int    `json:"vlan,omitempty"`

	// Other
	Authenticated bool              `json:"authenticated,omitempty"`
	TimeOfDay     string            `json:"time_of_day,omitempty"` // optional, e.g., "09:00-17:00"
	Posture       string            `json:"posture,omitempty"`
	RiskScore     int               `json:"risk_score,omitempty"`
	Attributes    map[string]string `json:"attributes,omitempty"`
	EvaluatedAt   time.Time         `json:"evaluated_at,omitempty"`
}

// Decision represents the outcome of policy evaluation.
type Decision struct {
	Allow            bool     `json:"allow"`
	Quarantine       bool     `json:"quarantine"`
	Role             *string  `json:"role,omitempty"`
	FilterID         *string  `json:"filter_id,omitempty"`
	PolicyTag        *string  `json:"policy_tag,omitempty"`
	VLAN             *int     `json:"vlan,omitempty"`
	BandwidthProfile *string  `json:"bandwidth_profile,omitempty"`
	SessionTimeout   *int     `json:"session_timeout,omitempty"`
	IdleTimeout      *int     `json:"idle_timeout,omitempty"`
	PortalProfile    *string  `json:"portal_profile,omitempty"`
	ACLPolicyName    *string  `json:"acl_policy_name,omitempty"`
	DeviceGroup      *string  `json:"device_group,omitempty"`
	Tenant           *string  `json:"tenant,omitempty"`
	Notes            []string `json:"notes,omitempty"`

	// Rule that matched (for auditing)
	MatchedRule string `json:"matched_rule,omitempty"`
}

// Merge combines two decisions, with b overriding non-zero values from a.
func (d *Decision) Merge(other *Decision) {
	if other == nil {
		return
	}
	if other.Allow {
		d.Allow = true
	}
	if other.Quarantine {
		d.Quarantine = true
	}
	if other.Role != nil {
		d.Role = other.Role
	}
	if other.FilterID != nil {
		d.FilterID = other.FilterID
	}
	if other.PolicyTag != nil {
		d.PolicyTag = other.PolicyTag
	}
	if other.VLAN != nil {
		d.VLAN = other.VLAN
	}
	if other.BandwidthProfile != nil {
		d.BandwidthProfile = other.BandwidthProfile
	}
	if other.SessionTimeout != nil {
		d.SessionTimeout = other.SessionTimeout
	}
	if other.IdleTimeout != nil {
		d.IdleTimeout = other.IdleTimeout
	}
	if other.PortalProfile != nil {
		d.PortalProfile = other.PortalProfile
	}
	if other.ACLPolicyName != nil {
		d.ACLPolicyName = other.ACLPolicyName
	}
	if other.DeviceGroup != nil {
		d.DeviceGroup = other.DeviceGroup
	}
	if other.Tenant != nil {
		d.Tenant = other.Tenant
	}
	if other.MatchedRule != "" {
		if d.MatchedRule == "" {
			d.MatchedRule = other.MatchedRule
		} else {
			d.MatchedRule = d.MatchedRule + "," + other.MatchedRule
		}
	}
	d.Notes = append(d.Notes, other.Notes...)
}

// Rule represents a stored policy rule.
type Rule struct {
	ID               int             `json:"id,omitempty"`
	Name             string          `json:"name"`
	Description      string          `json:"description,omitempty"`
	Priority         int             `json:"priority"`
	Enabled          bool            `json:"enabled"`
	MatchConditions  json.RawMessage `json:"match_conditions"`
	Action           string          `json:"action"`
	VLAN             *int            `json:"vlan,omitempty"`
	BandwidthProfile *string         `json:"bandwidth_profile,omitempty"`
	SessionTimeout   *int            `json:"session_timeout,omitempty"`
	IdleTimeout      *int            `json:"idle_timeout,omitempty"`
	PortalProfile    *string         `json:"portal_profile,omitempty"`
	ACLPolicyName    *string         `json:"acl_policy_name,omitempty"`
	Quarantine       bool            `json:"quarantine"`
}

// PolicySet is the NAS-0030 immutable policy tree. A version stores exactly
// one root set; child sets inherit disabled state and contribute priority.
type PolicySet struct {
	SchemaVersion int         `json:"schema_version,omitempty"`
	Key           string      `json:"key"`
	Name          string      `json:"name"`
	Description   string      `json:"description,omitempty"`
	Tenant        string      `json:"tenant,omitempty"`
	Priority      int         `json:"priority"`
	Enabled       *bool       `json:"enabled,omitempty"`
	Rules         []Rule      `json:"rules,omitempty"`
	Children      []PolicySet `json:"children,omitempty"`
}

type PolicySetSummary struct {
	SchemaVersion int    `json:"schema_version"`
	Key           string `json:"key"`
	Name          string `json:"name"`
	Tenant        string `json:"tenant,omitempty"`
	RuleCount     int    `json:"rule_count"`
	ChildSetCount int    `json:"child_set_count"`
	MaxDepth      int    `json:"max_depth"`
	ContentHash   string `json:"content_hash"`
	PolicyHash    string `json:"policy_hash"`
}

type PolicySetDiff struct {
	FromHash     string           `json:"from_hash"`
	ToHash       string           `json:"to_hash"`
	AddedRules   []Rule           `json:"added_rules,omitempty"`
	RemovedRules []Rule           `json:"removed_rules,omitempty"`
	ChangedRules []PolicyRuleDiff `json:"changed_rules,omitempty"`
}

type PolicyRuleDiff struct {
	Name string `json:"name"`
	From Rule   `json:"from"`
	To   Rule   `json:"to"`
}

// TypedExpression is the production policy AST used by NAS-0029. Existing
// legacy match_conditions JSON is compiled into this form before evaluation.
type TypedExpression struct {
	All    []TypedExpression `json:"all,omitempty"`
	Any    []TypedExpression `json:"any,omitempty"`
	Not    *TypedExpression  `json:"not,omitempty"`
	Field  string            `json:"field,omitempty"`
	Op     string            `json:"op,omitempty"`
	Value  any               `json:"value,omitempty"`
	Values []any             `json:"values,omitempty"`
}

type TraceEntry struct {
	Path     string `json:"path"`
	Field    string `json:"field,omitempty"`
	Operator string `json:"operator,omitempty"`
	Expected any    `json:"expected,omitempty"`
	Actual   any    `json:"actual,omitempty"`
	Matched  bool   `json:"matched"`
	Message  string `json:"message,omitempty"`
}

type MatchedRule struct {
	ID       int      `json:"id"`
	Name     string   `json:"name"`
	Priority int      `json:"priority"`
	Action   string   `json:"action"`
	Notes    []string `json:"notes,omitempty"`
}

type RuleDiagnostic struct {
	ID       int    `json:"id,omitempty"`
	Name     string `json:"name,omitempty"`
	Priority int    `json:"priority,omitempty"`
	Status   string `json:"status"`
	Message  string `json:"message"`
}

type EvaluationResult struct {
	SchemaVersion    int              `json:"schema_version"`
	EvaluationID     string           `json:"evaluation_id"`
	EvaluatedAt      string           `json:"evaluated_at"`
	PolicySetHash    string           `json:"policy_set_hash"`
	RequestHash      string           `json:"request_hash"`
	Decision         Decision         `json:"decision"`
	MatchedRules     []MatchedRule    `json:"matched_rules"`
	SkippedRules     []RuleDiagnostic `json:"skipped_rules,omitempty"`
	Conflicts        []string         `json:"conflicts,omitempty"`
	Trace            []TraceEntry     `json:"trace"`
	LegacyRuleCount  int              `json:"legacy_rule_count"`
	TypedRuleCount   int              `json:"typed_rule_count"`
	InvalidRuleCount int              `json:"invalid_rule_count"`
}

type ReplaySample struct {
	Source                   string            `json:"source,omitempty"`
	EvaluationID             string            `json:"evaluation_id,omitempty"`
	EvaluatedAt              string            `json:"evaluated_at,omitempty"`
	HistoricalPolicySetHash  string            `json:"historical_policy_set_hash,omitempty"`
	HistoricalDecision       string            `json:"historical_decision,omitempty"`
	HistoricalAllowed        bool              `json:"historical_allowed,omitempty"`
	HistoricalQuarantine     bool              `json:"historical_quarantine,omitempty"`
	HistoricalMatchedRules   []MatchedRule     `json:"historical_matched_rules,omitempty"`
	HistoricalConflictCount  int               `json:"historical_conflict_count,omitempty"`
	HistoricalTraceNodeCount int               `json:"historical_trace_node_count,omitempty"`
	Request                  Request           `json:"request"`
	RequestSummary           map[string]any    `json:"request_summary,omitempty"`
	Labels                   map[string]string `json:"labels,omitempty"`
}

type SimulationAnalysisOptions struct {
	MaxSamples        int  `json:"max_samples,omitempty"`
	MaxExamples       int  `json:"max_examples,omitempty"`
	IncludeTrace      bool `json:"include_trace,omitempty"`
	AnalyzeRuleImpact bool `json:"analyze_rule_impact,omitempty"`
}

type PolicySimulationAnalysis struct {
	SchemaVersion               int             `json:"schema_version"`
	AnalysisID                  string          `json:"analysis_id"`
	GeneratedAt                 string          `json:"generated_at"`
	ActivePolicySetHash         string          `json:"active_policy_set_hash"`
	CandidatePolicySetHash      string          `json:"candidate_policy_set_hash"`
	SampleCount                 int             `json:"sample_count"`
	DecisionChangeCount         int             `json:"decision_change_count"`
	AllowToDenyCount            int             `json:"allow_to_deny_count"`
	DenyToAllowCount            int             `json:"deny_to_allow_count"`
	QuarantineChangeCount       int             `json:"quarantine_change_count"`
	VLANChangeCount             int             `json:"vlan_change_count"`
	BandwidthProfileChangeCount int             `json:"bandwidth_profile_change_count"`
	ACLPolicyChangeCount        int             `json:"acl_policy_change_count"`
	PortalProfileChangeCount    int             `json:"portal_profile_change_count"`
	SessionTimeoutChangeCount   int             `json:"session_timeout_change_count"`
	ConflictCount               int             `json:"conflict_count"`
	InvalidRuleCount            int             `json:"invalid_rule_count"`
	ShadowedRules               []RuleImpact    `json:"shadowed_rules,omitempty"`
	IneffectiveRules            []RuleImpact    `json:"ineffective_rules,omitempty"`
	Deltas                      []DecisionDelta `json:"deltas,omitempty"`
	RiskLevel                   string          `json:"risk_level"`
	Recommendation              string          `json:"recommendation"`
}

type DecisionDelta struct {
	Index              int               `json:"index"`
	Source             string            `json:"source,omitempty"`
	EvaluationID       string            `json:"evaluation_id,omitempty"`
	RequestHash        string            `json:"request_hash"`
	ChangedFields      []string          `json:"changed_fields"`
	ActiveDecision     Decision          `json:"active_decision"`
	CandidateDecision  Decision          `json:"candidate_decision"`
	ActiveMatched      []MatchedRule     `json:"active_matched_rules,omitempty"`
	CandidateMatched   []MatchedRule     `json:"candidate_matched_rules,omitempty"`
	ActiveConflicts    []string          `json:"active_conflicts,omitempty"`
	CandidateConflicts []string          `json:"candidate_conflicts,omitempty"`
	Labels             map[string]string `json:"labels,omitempty"`
}

type RuleImpact struct {
	Name         string `json:"name"`
	Priority     int    `json:"priority"`
	Enabled      bool   `json:"enabled"`
	MatchedCount int    `json:"matched_count"`
	ImpactCount  int    `json:"impact_count"`
	Reason       string `json:"reason"`
}

type FieldSpec struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description"`
}

type OperatorSpec struct {
	Name        string   `json:"name"`
	Types       []string `json:"types"`
	Description string   `json:"description"`
}
