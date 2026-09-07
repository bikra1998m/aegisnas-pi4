package radius

import (
	"fmt"
	"strings"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
)

type ACLRule struct {
	ID                 string   `json:"id,omitempty"`
	Sequence           int      `json:"sequence,omitempty"`
	Action             string   `json:"action"`
	Direction          string   `json:"direction"`
	AddressFamily      string   `json:"address_family,omitempty"`
	Protocol           string   `json:"protocol"`
	Source             string   `json:"source"`
	Sources            []string `json:"sources,omitempty"`
	SourceObjects      []string `json:"source_objects,omitempty"`
	SourcePort         string   `json:"source_port,omitempty"`
	SourcePorts        []string `json:"source_ports,omitempty"`
	Destination        string   `json:"destination"`
	Destinations       []string `json:"destinations,omitempty"`
	DestinationObjects []string `json:"destination_objects,omitempty"`
	DestinationPort    string   `json:"destination_port,omitempty"`
	DestinationPorts   []string `json:"destination_ports,omitempty"`
	Applications       []string `json:"applications,omitempty"`
	URLCategories      []string `json:"url_categories,omitempty"`
	States             []string `json:"states,omitempty"`
	TCPFlags           []string `json:"tcp_flags,omitempty"`
	ICMPTypes          []string `json:"icmp_types,omitempty"`
	DSCP               []string `json:"dscp,omitempty"`
	TimeRange          string   `json:"time_range,omitempty"`
	Remark             string   `json:"remark,omitempty"`
	Log                bool     `json:"log,omitempty"`
	Tags               []string `json:"tags,omitempty"`
}

type ACLVendorExport struct {
	PackKey                       string               `json:"pack_key"`
	PackLabel                     string               `json:"pack_label"`
	ExportMode                    string               `json:"export_mode"`
	CompilerStatus                string               `json:"compiler_status"`
	CompilerVersion               string               `json:"compiler_version,omitempty"`
	CertificationState            string               `json:"certification_state,omitempty"`
	ExternalCertificationRequired bool                 `json:"external_certification_required"`
	Attributes                    []ReplyAttributeItem `json:"attributes"`
	FreeRADIUS                    string               `json:"freeradius"`
	ASTFingerprint                string               `json:"ast_fingerprint,omitempty"`
	ArtifactFingerprint           string               `json:"artifact_fingerprint,omitempty"`
	Lossless                      bool                 `json:"lossless"`
	DecompileSupported            bool                 `json:"decompile_supported"`
	Limits                        ACLCompilerLimits    `json:"limits"`
	Diagnostics                   []ACLDiagnostic      `json:"diagnostics,omitempty"`
	Warnings                      []string             `json:"warnings,omitempty"`
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
	return BuildACLVendorExportsForAST(policyName, inboundACL, outboundACL, rules, nil, packKeys)
}

func BuildACLVendorExportsForAST(policyName, inboundACL, outboundACL string, rules []ACLRule, ast *ACLPolicyAST, packKeys []string) []ACLVendorExport {
	run, err := CompileACLPolicyForPacks(ACLCompilerRequest{
		PolicyName:  policyName,
		InboundACL:  inboundACL,
		OutboundACL: outboundACL,
		Rules:       rules,
		ACLAST:      ast,
		PackKeys:    packKeys,
	})
	if err != nil {
		return nil
	}
	out := make([]ACLVendorExport, 0, len(run.Results))
	for _, result := range run.Results {
		if len(result.Attributes) == 0 && len(result.Warnings) == 0 && len(result.Diagnostics) == 0 {
			continue
		}
		out = append(out, ACLVendorExport{
			PackKey:                       result.PackKey,
			PackLabel:                     result.PackLabel,
			ExportMode:                    result.OutputMode,
			CompilerStatus:                result.Status,
			CompilerVersion:               result.CompilerVersion,
			CertificationState:            result.CertificationState,
			ExternalCertificationRequired: result.ExternalCertificationRequired,
			Attributes:                    result.Attributes,
			FreeRADIUS:                    result.FreeRADIUS,
			ASTFingerprint:                result.ASTFingerprint,
			ArtifactFingerprint:           result.ArtifactFingerprint,
			Lossless:                      result.Lossless,
			DecompileSupported:            result.DecompileSupported,
			Limits:                        result.Limits,
			Diagnostics:                   result.Diagnostics,
			Warnings:                      result.Warnings,
		})
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
	case productconfigs.VendorPackNokia:
		export.ExportMode = "profile"
		appendItem("Nokia-AVPair", "acl="+profileName, true)
		if len(rules) > 0 {
			export.Warnings = append(export.Warnings, "Nokia export uses an AVPair ACL profile hint; SR OS line-rule behavior requires device-side policy certification.")
		}
	case productconfigs.VendorPackAlcatel:
		export.ExportMode = "profile"
		appendItem("AAT-Filter", profileName, true)
		appendItem("AAT-Data-Filter", profileName, true)
		if len(rules) > 0 {
			export.Warnings = append(export.Warnings, "Alcatel AAT export uses filter profile names; line rules require device-side policy certification.")
		}
	case productconfigs.VendorPackALUSR:
		appendRuleItems("Alc-Nas-Filter-Rule-Shared", renderNASFilterRules(rules))
	case productconfigs.VendorPackALUAAA:
		appendRuleItems("ALU-AAA-Access-Rule", renderNASFilterRules(rules))
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
	rule.ID = normalizeACLToken(rule.ID)
	rule.AddressFamily = normalizeACLAddressFamily(rule.AddressFamily)
	if !validACLAddressFamily(rule.AddressFamily) {
		return ACLRule{}, false
	}
	rule.Source = normalizeACLAddress(rule.Source)
	rule.Destination = normalizeACLAddress(rule.Destination)
	rule.SourcePort = normalizeACLToken(rule.SourcePort)
	rule.DestinationPort = normalizeACLToken(rule.DestinationPort)
	rule.Sources = normalizeACLTokenList(rule.Sources, 32)
	rule.SourceObjects = normalizeACLTokenList(rule.SourceObjects, 32)
	rule.SourcePorts = normalizeACLTokenList(rule.SourcePorts, 32)
	rule.Destinations = normalizeACLTokenList(rule.Destinations, 32)
	rule.DestinationObjects = normalizeACLTokenList(rule.DestinationObjects, 32)
	rule.DestinationPorts = normalizeACLTokenList(rule.DestinationPorts, 32)
	rule.Applications = normalizeACLTokenList(rule.Applications, 32)
	rule.URLCategories = normalizeACLTokenList(rule.URLCategories, 32)
	rule.States = normalizeACLTokenList(rule.States, 16)
	rule.TCPFlags = normalizeACLTokenList(rule.TCPFlags, 16)
	rule.ICMPTypes = normalizeACLTokenList(rule.ICMPTypes, 16)
	rule.DSCP = normalizeACLTokenList(rule.DSCP, 16)
	rule.TimeRange = normalizeACLToken(rule.TimeRange)
	rule.Remark = strings.TrimSpace(rule.Remark)
	rule.Tags = normalizeACLTokenList(rule.Tags, 16)

	for _, token := range aclRuleTokens(rule) {
		if token != "" && !validACLToken(token) {
			return ACLRule{}, false
		}
	}
	return rule, true
}

func aclRuleTokens(rule ACLRule) []string {
	tokens := []string{
		rule.ID,
		rule.AddressFamily,
		rule.Protocol,
		rule.Source,
		rule.Destination,
		rule.SourcePort,
		rule.DestinationPort,
		rule.TimeRange,
	}
	for _, values := range [][]string{
		rule.Sources,
		rule.SourceObjects,
		rule.SourcePorts,
		rule.Destinations,
		rule.DestinationObjects,
		rule.DestinationPorts,
		rule.Applications,
		rule.URLCategories,
		rule.States,
		rule.TCPFlags,
		rule.ICMPTypes,
		rule.DSCP,
		rule.Tags,
	} {
		tokens = append(tokens, values...)
	}
	return tokens
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

func normalizeACLTokenList(values []string, limit int) []string {
	if limit <= 0 {
		limit = len(values)
	}
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = normalizeACLToken(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func normalizeACLAddressFamily(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "any":
		return ""
	case "ipv4", "ipv6":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func validACLAddressFamily(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "ipv4", "ipv6":
		return true
	default:
		return false
	}
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
