package policy

import "encoding/json"

// Request contains all attributes available for policy evaluation.
type Request struct {
	// User identity
	Username       string
	Role           string
	Groups         []string
	
	// Authentication context
	AuthMethod     string   // "pap", "eap-peap", "eap-tls", "voucher"
	IdentitySource string   // "local", "ldap"
	
	// Network context
	SSID           string
	NASIdentifier  string
	NASIPAddress   string
	Site           string
	CallingStationID string // MAC address
	
	// Other
	Authenticated  bool
	TimeOfDay      string // optional, e.g., "09:00-17:00"
}

// Decision represents the outcome of policy evaluation.
type Decision struct {
	Allow           bool     `json:"allow"`
	Quarantine      bool     `json:"quarantine"`
	VLAN            *int     `json:"vlan,omitempty"`
	BandwidthProfile *string `json:"bandwidth_profile,omitempty"`
	SessionTimeout  *int    `json:"session_timeout,omitempty"`
	IdleTimeout     *int    `json:"idle_timeout,omitempty"`
	PortalProfile   *string `json:"portal_profile,omitempty"`
	Notes           []string `json:"notes,omitempty"`
	
	// Rule that matched (for auditing)
	MatchedRule     string   `json:"matched_rule,omitempty"`
}

// Merge combines two decisions, with b overriding non‑zero values from a.
func (d *Decision) Merge(other *Decision) {
	if other.Allow {
		d.Allow = true
	}
	if other.Quarantine {
		d.Quarantine = true
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
	Quarantine       bool
}