package radius

import (
	"fmt"
	"strings"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
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

type ACLVendorExport struct {
	PackKey    string               `json:"pack_key"`
	PackLabel  string               `json:"pack_label"`
	ExportMode string               `json:"export_mode"`
	Attributes []ReplyAttributeItem `json:"attributes"`
	FreeRADIUS string               `json:"freeradius"`
	Warnings   []string             `json:"warnings,omitempty"`
}

func ValidateACLRules(rules []ACLRule) error {
	_, err := NormalizeACLRules(rules)
	return err
}

func NormalizeACLRules(rules []ACLRule) ([]ACLRule, error) {
	out := make([]ACLRule, 0, len(rules))
	for idx, rule := range rules {
		normalized, ok := normalizeACLRule(rule)
		if !ok {
			return nil, fmt.Errorf("acl_rules[%d] is invalid", idx)
		}
		out = append(out, normalized)
	}
	return out, nil
}

func BuildACLVendorExports(policyName, inboundACL, outboundACL string, rules []ACLRule, packKeys []string) []ACLVendorExport {
	normalizedRules, err := NormalizeACLRules(rules)
	if err != nil {
		return nil
	}
	policyName = strings.TrimSpace(policyName)
	inboundACL = strings.TrimSpace(inboundACL)
	outboundACL = strings.TrimSpace(outboundACL)

	var out []ACLVendorExport
	for _, packKey := range normalizeReplyPackKeys(packKeys) {
		export := buildACLVendorExport(policyName, inboundACL, outboundACL, normalizedRules, packKey)
		if len(export.Attributes) == 0 && len(export.Warnings) == 0 {
			continue
		}
		out = append(out, export)
	}
	return out
}

func buildACLVendorExport(policyName, inboundACL, outboundACL string, rules []ACLRule, packKey string) ACLVendorExport {
	pack, _ := productconfigs.VendorCompatibilityPackByKey(packKey)
	export := ACLVendorExport{
		PackKey:    packKey,
		PackLabel:  pack.Label,
		ExportMode: "rules",
	}
	if export.PackLabel == "" {
		export.PackLabel = packKey
	}
	appendItem := func(name, value string, quoted bool) {
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if name == "" || value == "" {
			return
		}
		export.Attributes = append(export.Attributes, ReplyAttributeItem{Name: name, Value: value, Quoted: quoted})
	}
	appendRuleItems := func(attribute string, values []string) {
		for _, value := range values {
			appendItem(attribute, value, true)
		}
	}
	profileName := firstReplyValue(policyName, inboundACL, outboundACL)

	switch packKey {
	case productconfigs.VendorPackStandard:
		appendRuleItems("NAS-Filter-Rule", renderNASFilterRules(rules))
	case productconfigs.VendorPackAegisNAS:
		appendItem("AegisNAS-ACL-Name", policyName, true)
		appendRuleItems("AegisNAS-ACL-Rule", renderNASFilterRules(rules))
	case productconfigs.VendorPackCisco:
		appendItem("Cisco-In-ACL", inboundACL, true)
		appendItem("Cisco-Out-ACL", outboundACL, true)
		appendRuleItems("Cisco-AVPair", renderCiscoAVPairACLRules(rules))
	case productconfigs.VendorPackAruba:
		appendRuleItems("Aruba-NAS-Filter-Rule", renderNASFilterRules(rules))
	case productconfigs.VendorPackMikroTik:
		export.ExportMode = "profile"
		appendItem("Mikrotik-Address-List", profileName, true)
		if len(rules) > 0 {
			export.Warnings = append(export.Warnings, "MikroTik export uses an address-list/profile hint; line rules require RouterOS-side policy.")
		}
	case productconfigs.VendorPackFortinet:
		export.ExportMode = "profile"
		appendItem("Fortinet-Access-Profile", profileName, true)
		if len(rules) > 0 {
			export.Warnings = append(export.Warnings, "Fortinet export uses an access profile name; line rules require FortiGate/FortiWLC policy.")
		}
	case productconfigs.VendorPackRuckus:
		export.ExportMode = "profile"
		appendItem("Ruckus-User-Groups", profileName, true)
		if len(rules) > 0 {
			export.Warnings = append(export.Warnings, "Ruckus export uses a user group/profile hint; line rules require controller-side policy.")
		}
	case productconfigs.VendorPackJuniper:
		export.ExportMode = "profile"
		appendItem("Juniper-Firewall-filter-name", firstReplyValue(inboundACL, outboundACL, policyName), true)
		appendItem("Juniper-Switching-Filter", firstReplyValue(inboundACL, outboundACL, policyName), true)
	case productconfigs.VendorPackHuawei:
		export.ExportMode = "profile"
		appendItem("Huawei-Data-Filter", profileName, true)
	case productconfigs.VendorPackH3C:
		export.ExportMode = "profile"
		appendItem("H3C-Ita-Policy", profileName, true)
	case productconfigs.VendorPackDLink:
		export.ExportMode = "mixed"
		appendItem("ACL-Profile", policyName, true)
		appendRuleItems("ACL-Rule", renderNASFilterRules(rules))
	case productconfigs.VendorPackPica8:
		export.ExportMode = "mixed"
		appendItem("IP-Downloadable-ACL-Name", policyName, true)
		appendRuleItems("IP-Downloadable-ACL-Rule", renderNASFilterRules(rules))
	case productconfigs.VendorPackHP:
		appendRuleItems("Ip-Filter-Raw", renderNASFilterRules(rules))
	case productconfigs.VendorPackColubris:
		export.ExportMode = "profile"
		appendItem("AVPair", profileName, true)
		export.Warnings = append(export.Warnings, "Colubris AVPair is a generic vendor-scoped attribute; validate the profile format before enabling.")
	}

	export.FreeRADIUS = renderReplyAttributeItems(export.Attributes)
	return export
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

// RenderCiscoDownloadableACL renders inbound vendor-neutral rules as Cisco ISE
// downloadable ACL lines. Outbound rules require a separate network-device
// policy and are intentionally omitted from the session DACL.
func RenderCiscoDownloadableACL(rules []ACLRule) ([]string, int, error) {
	normalized, err := NormalizeACLRules(rules)
	if err != nil {
		return nil, 0, err
	}
	lines := make([]string, 0, len(normalized))
	omittedOutbound := 0
	for _, rule := range normalized {
		if rule.Direction == "out" {
			omittedOutbound++
			continue
		}
		lines = append(lines, renderCiscoACLRule(rule))
	}
	return lines, omittedOutbound, nil
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
