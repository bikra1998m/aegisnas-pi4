package policy

import (
	"encoding/json"
	"time"
)

const TypedPolicySchemaVersion = 1

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
	ID               int
	Name             string
	Description      string
	Priority         int
	Enabled          bool
	MatchConditions  json.RawMessage
	Action           string
	VLAN             *int
	BandwidthProfile *string
	SessionTimeout   *int
	IdleTimeout      *int
	PortalProfile    *string
	ACLPolicyName    *string
	Quarantine       bool
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
