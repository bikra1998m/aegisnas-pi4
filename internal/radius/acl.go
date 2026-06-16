package radius

import (
	"fmt"
	"strings"
)

type ACLRule struct {
	Action          string `json:"action"`
	Direction       string `json:"direction"`
	Protocol        string `json:"protocol"`
	Source          string `json:"source"`
	SourcePort      string `json:"source_port,omitempty"`
	Destination     string `json:"destination"`
	DestinationPort string `json:"destination_port,omitempty"`
	Remark          string `json:"remark,omitempty"`
	Log             bool   `json:"log,omitempty"`
}

func ValidateACLRules(rules []ACLRule) error {
	for idx, rule := range rules {
		if _, ok := normalizeACLRule(rule); !ok {
			return fmt.Errorf("acl_rules[%d] is invalid", idx)
		}
	}
	return nil
}

func renderNASFilterRules(rules []ACLRule) []string {
	out := make([]string, 0, len(rules))
	for _, rule := range rules {
		normalized, ok := normalizeACLRule(rule)
		if !ok {
			continue
		}
		parts := []string{
			normalized.Action,
			normalized.Direction,
			normalized.Protocol,
			"from",
			normalized.Source,
		}
		if normalized.SourcePort != "" {
			parts = append(parts, normalized.SourcePort)
		}
		parts = append(parts, "to", normalized.Destination)
		if normalized.DestinationPort != "" {
			parts = append(parts, normalized.DestinationPort)
		}
		if normalized.Log {
			parts = append(parts, "log")
		}
		out = append(out, strings.Join(parts, " "))
	}
	return out
}

func renderCiscoAVPairACLRules(rules []ACLRule) []string {
	var out []string
	directionCounts := map[string]int{}
	for _, rule := range rules {
		normalized, ok := normalizeACLRule(rule)
		if !ok {
			continue
		}
		ciscoDirection := "inacl"
		if normalized.Direction == "out" {
			ciscoDirection = "outacl"
		}
		directionCounts[ciscoDirection]++
		out = append(out, fmt.Sprintf("ip:%s#%d=%s", ciscoDirection, directionCounts[ciscoDirection], renderCiscoACLRule(normalized)))
	}
	return out
}

func renderCiscoACLRule(rule ACLRule) string {
	parts := []string{
		rule.Action,
		rule.Protocol,
		rule.Source,
	}
	if rule.SourcePort != "" {
		parts = append(parts, ciscoACLPort(rule.SourcePort)...)
	}
	parts = append(parts, rule.Destination)
	if rule.DestinationPort != "" {
		parts = append(parts, ciscoACLPort(rule.DestinationPort)...)
	}
	if rule.Log {
		parts = append(parts, "log")
	}
	return strings.Join(parts, " ")
}

func ciscoACLPort(port string) []string {
	if port == "" || strings.EqualFold(port, "any") {
		return nil
	}
	return []string{"eq", port}
}

func normalizeACLRule(rule ACLRule) (ACLRule, bool) {
	rule.Action = strings.ToLower(strings.TrimSpace(rule.Action))
	if rule.Action == "" {
		rule.Action = "permit"
	}
	if rule.Action != "permit" && rule.Action != "deny" {
		return ACLRule{}, false
	}

	rule.Direction = strings.ToLower(strings.TrimSpace(rule.Direction))
	if rule.Direction == "" {
		rule.Direction = "in"
	}
	if rule.Direction != "in" && rule.Direction != "out" {
		return ACLRule{}, false
	}

	rule.Protocol = strings.ToLower(strings.TrimSpace(rule.Protocol))
	if rule.Protocol == "" {
		rule.Protocol = "ip"
	}
	rule.Source = normalizeACLAddress(rule.Source)
	rule.Destination = normalizeACLAddress(rule.Destination)
	rule.SourcePort = normalizeACLToken(rule.SourcePort)
	rule.DestinationPort = normalizeACLToken(rule.DestinationPort)
	rule.Remark = strings.TrimSpace(rule.Remark)

	for _, token := range []string{rule.Protocol, rule.Source, rule.Destination, rule.SourcePort, rule.DestinationPort} {
		if token != "" && !validACLToken(token) {
			return ACLRule{}, false
		}
	}
	return rule, true
}

func normalizeACLAddress(value string) string {
	value = normalizeACLToken(value)
	if value == "" {
		return "any"
	}
	return value
}

func normalizeACLToken(value string) string {
	return strings.TrimSpace(value)
}

func validACLToken(value string) bool {
	if value == "" {
		return true
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case strings.ContainsRune("._:/,-", r):
		default:
			return false
		}
	}
	return true
}
