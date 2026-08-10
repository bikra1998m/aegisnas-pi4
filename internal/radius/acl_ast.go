package radius

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

const (
	ACLASTSchemaVersion = 1
	maxACLASTRules      = 256
	maxACLASTObjects    = 256
)

type ACLDiagnostic struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Path     string `json:"path,omitempty"`
	Message  string `json:"message"`
}

type ACLRoundTrip struct {
	Lossless          bool     `json:"lossless"`
	ASTFingerprint    string   `json:"ast_fingerprint"`
	ASTRuleCount      int      `json:"ast_rule_count"`
	RuleCount         int      `json:"rule_count"`
	UnsupportedFields []string `json:"unsupported_fields,omitempty"`
}

type ACLPolicyNormalization struct {
	AST         ACLPolicyAST    `json:"acl_ast"`
	Rules       []ACLRule       `json:"normalized_rules"`
	Fingerprint string          `json:"ast_fingerprint"`
	Diagnostics []ACLDiagnostic `json:"diagnostics,omitempty"`
	RoundTrip   ACLRoundTrip    `json:"round_trip"`
}

type ACLPolicyAST struct {
	SchemaVersion     int               `json:"schema_version"`
	Name              string            `json:"name,omitempty"`
	Description       string            `json:"description,omitempty"`
	DefaultAction     string            `json:"default_action,omitempty"`
	ObjectGroups      []ACLObjectGroup  `json:"object_groups,omitempty"`
	ServiceGroups     []ACLServiceGroup `json:"service_groups,omitempty"`
	ApplicationGroups []ACLNamedValues  `json:"application_groups,omitempty"`
	URLCategoryGroups []ACLNamedValues  `json:"url_category_groups,omitempty"`
	Rules             []ACLASTRule      `json:"rules"`
	Tags              []string          `json:"tags,omitempty"`
	Metadata          map[string]string `json:"metadata,omitempty"`
}

type ACLObjectGroup struct {
	Name          string   `json:"name"`
	AddressFamily string   `json:"address_family,omitempty"`
	Type          string   `json:"type,omitempty"`
	Values        []string `json:"values"`
	Description   string   `json:"description,omitempty"`
}

type ACLServiceGroup struct {
	Name         string   `json:"name"`
	Protocols    []string `json:"protocols,omitempty"`
	Ports        []string `json:"ports,omitempty"`
	Applications []string `json:"applications,omitempty"`
	Description  string   `json:"description,omitempty"`
}

type ACLNamedValues struct {
	Name        string   `json:"name"`
	Values      []string `json:"values"`
	Description string   `json:"description,omitempty"`
}

type ACLASTRule struct {
	ID          string            `json:"id"`
	Sequence    int               `json:"sequence"`
	Enabled     *bool             `json:"enabled,omitempty"`
	Action      string            `json:"action"`
	Direction   string            `json:"direction"`
	Description string            `json:"description,omitempty"`
	Match       ACLASTMatch       `json:"match"`
	Log         bool              `json:"log,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

type ACLASTMatch struct {
	AddressFamily string      `json:"address_family,omitempty"`
	Protocols     []string    `json:"protocols,omitempty"`
	Source        ACLEndpoint `json:"source"`
	Destination   ACLEndpoint `json:"destination"`
	Applications  []string    `json:"applications,omitempty"`
	URLCategories []string    `json:"url_categories,omitempty"`
	States        []string    `json:"states,omitempty"`
	TCPFlags      []string    `json:"tcp_flags,omitempty"`
	ICMPTypes     []string    `json:"icmp_types,omitempty"`
	DSCP          []string    `json:"dscp,omitempty"`
	TimeRange     string      `json:"time_range,omitempty"`
}

type ACLEndpoint struct {
	Any          bool     `json:"any,omitempty"`
	Addresses    []string `json:"addresses,omitempty"`
	ObjectGroups []string `json:"object_groups,omitempty"`
	Ports        []string `json:"ports,omitempty"`
	PortGroups   []string `json:"port_groups,omitempty"`
}

func NormalizeACLPolicyIntent(policyName, description, inboundACL, outboundACL string, rules []ACLRule, ast *ACLPolicyAST) (ACLPolicyNormalization, error) {
	var diagnostics []ACLDiagnostic
	normalizedRules, err := NormalizeACLRules(rules)
	if err != nil {
		return ACLPolicyNormalization{}, err
	}

	var normalizedAST ACLPolicyAST
	if ast != nil && aclASTHasContent(*ast) {
		normalizedAST, diagnostics, err = NormalizeACLPolicyAST(*ast)
		if err != nil {
			return ACLPolicyNormalization{}, err
		}
		derivedRules, flattenDiagnostics := FlattenACLPolicyAST(normalizedAST)
		diagnostics = append(diagnostics, flattenDiagnostics...)
		if len(normalizedRules) == 0 {
			normalizedRules = derivedRules
		} else if aclRulesFingerprint(normalizedRules) != aclRulesFingerprint(derivedRules) {
			diagnostics = append(diagnostics, ACLDiagnostic{
				Severity: "warning",
				Code:     "compatibility_rules_differ",
				Path:     "rules",
				Message:  "provided flat rules differ from the ACL AST compatibility projection; the AST remains the source of truth",
			})
			normalizedRules = derivedRules
		}
	} else {
		normalizedAST = BuildACLPolicyASTFromRules(policyName, description, inboundACL, outboundACL, normalizedRules)
	}
	normalizedAST.Name = firstReplyValue(strings.TrimSpace(normalizedAST.Name), strings.TrimSpace(policyName))
	normalizedAST.Description = firstReplyValue(strings.TrimSpace(normalizedAST.Description), strings.TrimSpace(description))

	fingerprint := FingerprintACLPolicyAST(normalizedAST)
	unsupported := aclUnsupportedRoundTripFields(diagnostics)
	roundTrip := ACLRoundTrip{
		Lossless:          len(unsupported) == 0,
		ASTFingerprint:    fingerprint,
		ASTRuleCount:      len(normalizedAST.Rules),
		RuleCount:         len(normalizedRules),
		UnsupportedFields: unsupported,
	}
	return ACLPolicyNormalization{
		AST:         normalizedAST,
		Rules:       normalizedRules,
		Fingerprint: fingerprint,
		Diagnostics: diagnostics,
		RoundTrip:   roundTrip,
	}, nil
}

func BuildACLPolicyASTFromRules(policyName, description, inboundACL, outboundACL string, rules []ACLRule) ACLPolicyAST {
	ast := ACLPolicyAST{
		SchemaVersion: ACLASTSchemaVersion,
		Name:          strings.TrimSpace(policyName),
		Description:   strings.TrimSpace(description),
		DefaultAction: "deny",
		Rules:         make([]ACLASTRule, 0, len(rules)),
		Metadata: map[string]string{
			"compatibility_projection": "rules_json",
			"inbound_acl":              strings.TrimSpace(inboundACL),
			"outbound_acl":             strings.TrimSpace(outboundACL),
		},
	}
	for idx, rule := range rules {
		normalized, ok := normalizeACLRule(rule)
		if !ok {
			continue
		}
		sequence := normalized.Sequence
		if sequence <= 0 {
			sequence = (idx + 1) * 10
		}
		id := normalized.ID
		if id == "" {
			id = fmt.Sprintf("rule-%04d", sequence)
		}
		protocols := []string{normalized.Protocol}
		source := ACLEndpoint{Addresses: firstNonEmptyACLList(normalized.Sources, []string{normalized.Source}), ObjectGroups: normalized.SourceObjects, Ports: firstNonEmptyACLList(normalized.SourcePorts, optionalACLList(normalized.SourcePort))}
		destination := ACLEndpoint{Addresses: firstNonEmptyACLList(normalized.Destinations, []string{normalized.Destination}), ObjectGroups: normalized.DestinationObjects, Ports: firstNonEmptyACLList(normalized.DestinationPorts, optionalACLList(normalized.DestinationPort))}
		source.Any = aclEndpointIsAny(source)
		destination.Any = aclEndpointIsAny(destination)
		ast.Rules = append(ast.Rules, ACLASTRule{
			ID:        id,
			Sequence:  sequence,
			Enabled:   boolPointer(true),
			Action:    normalized.Action,
			Direction: normalized.Direction,
			Match: ACLASTMatch{
				AddressFamily: firstReplyValue(normalized.AddressFamily, aclRuleAddressFamily(normalized)),
				Protocols:     protocols,
				Source:        source,
				Destination:   destination,
				Applications:  normalized.Applications,
				URLCategories: normalized.URLCategories,
				States:        normalized.States,
				TCPFlags:      normalized.TCPFlags,
				ICMPTypes:     normalized.ICMPTypes,
				DSCP:          normalized.DSCP,
				TimeRange:     normalized.TimeRange,
			},
			Log:  normalized.Log,
			Tags: normalized.Tags,
		})
	}
	return ast
}

func NormalizeACLPolicyAST(input ACLPolicyAST) (ACLPolicyAST, []ACLDiagnostic, error) {
	var diagnostics []ACLDiagnostic
	if input.SchemaVersion == 0 {
		input.SchemaVersion = ACLASTSchemaVersion
	}
	if input.SchemaVersion != ACLASTSchemaVersion {
		return ACLPolicyAST{}, nil, fmt.Errorf("acl_ast.schema_version %d is not supported", input.SchemaVersion)
	}
	input.Name = strings.TrimSpace(input.Name)
	input.Description = strings.TrimSpace(input.Description)
	input.DefaultAction = normalizeACLASTAction(input.DefaultAction)
	if input.DefaultAction == "" {
		input.DefaultAction = "deny"
	}
	input.Tags = normalizeACLTokenList(input.Tags, 32)
	input.Metadata = normalizeACLMetadata(input.Metadata)
	if len(input.ObjectGroups) > maxACLASTObjects || len(input.ServiceGroups) > maxACLASTObjects || len(input.ApplicationGroups) > maxACLASTObjects || len(input.URLCategoryGroups) > maxACLASTObjects {
		return ACLPolicyAST{}, nil, fmt.Errorf("acl_ast cannot contain more than %d object, service, application, or URL category groups", maxACLASTObjects)
	}
	if len(input.Rules) > maxACLASTRules {
		return ACLPolicyAST{}, nil, fmt.Errorf("acl_ast.rules cannot contain more than %d rules", maxACLASTRules)
	}

	objectNames := map[string]struct{}{}
	for idx := range input.ObjectGroups {
		group, err := normalizeACLObjectGroup(input.ObjectGroups[idx], fmt.Sprintf("acl_ast.object_groups[%d]", idx))
		if err != nil {
			return ACLPolicyAST{}, nil, err
		}
		if _, exists := objectNames[strings.ToLower(group.Name)]; exists {
			return ACLPolicyAST{}, nil, fmt.Errorf("duplicate ACL object group %q", group.Name)
		}
		objectNames[strings.ToLower(group.Name)] = struct{}{}
		input.ObjectGroups[idx] = group
	}
	serviceNames := map[string]struct{}{}
	for idx := range input.ServiceGroups {
		group, err := normalizeACLServiceGroup(input.ServiceGroups[idx], fmt.Sprintf("acl_ast.service_groups[%d]", idx))
		if err != nil {
			return ACLPolicyAST{}, nil, err
		}
		if _, exists := serviceNames[strings.ToLower(group.Name)]; exists {
			return ACLPolicyAST{}, nil, fmt.Errorf("duplicate ACL service group %q", group.Name)
		}
		serviceNames[strings.ToLower(group.Name)] = struct{}{}
		input.ServiceGroups[idx] = group
	}
	if err := normalizeACLNamedValueGroups(input.ApplicationGroups, "acl_ast.application_groups"); err != nil {
		return ACLPolicyAST{}, nil, err
	}
	if err := normalizeACLNamedValueGroups(input.URLCategoryGroups, "acl_ast.url_category_groups"); err != nil {
		return ACLPolicyAST{}, nil, err
	}

	seenRuleIDs := map[string]struct{}{}
	for idx := range input.Rules {
		rule, ruleDiagnostics, err := normalizeACLASTRule(input.Rules[idx], idx, objectNames, serviceNames)
		if err != nil {
			return ACLPolicyAST{}, nil, err
		}
		if _, exists := seenRuleIDs[strings.ToLower(rule.ID)]; exists {
			return ACLPolicyAST{}, nil, fmt.Errorf("duplicate ACL AST rule id %q", rule.ID)
		}
		seenRuleIDs[strings.ToLower(rule.ID)] = struct{}{}
		input.Rules[idx] = rule
		diagnostics = append(diagnostics, ruleDiagnostics...)
	}
	sort.SliceStable(input.Rules, func(i, j int) bool {
		return input.Rules[i].Sequence < input.Rules[j].Sequence
	})
	return input, diagnostics, nil
}

func FlattenACLPolicyAST(ast ACLPolicyAST) ([]ACLRule, []ACLDiagnostic) {
	objectGroups := map[string]ACLObjectGroup{}
	for _, group := range ast.ObjectGroups {
		objectGroups[strings.ToLower(group.Name)] = group
	}
	serviceGroups := map[string]ACLServiceGroup{}
	for _, group := range ast.ServiceGroups {
		serviceGroups[strings.ToLower(group.Name)] = group
	}
	var rules []ACLRule
	var diagnostics []ACLDiagnostic
	for idx, astRule := range ast.Rules {
		if astRule.Enabled != nil && !*astRule.Enabled {
			continue
		}
		action := astRule.Action
		if action == "reject" || action == "drop" {
			diagnostics = append(diagnostics, ACLDiagnostic{Severity: "warning", Code: "action_degraded", Path: fmt.Sprintf("acl_ast.rules[%d].action", idx), Message: fmt.Sprintf("action %q is preserved in the AST but rendered as deny in flat RADIUS ACL rules", action)})
			action = "deny"
		}
		if astRule.Direction == "both" {
			diagnostics = append(diagnostics, ACLDiagnostic{Severity: "warning", Code: "direction_expanded", Path: fmt.Sprintf("acl_ast.rules[%d].direction", idx), Message: "direction both is expanded into separate in and out compatibility rules"})
		}
		directions := []string{astRule.Direction}
		if astRule.Direction == "both" {
			directions = []string{"in", "out"}
		}
		protocols := firstNonEmptyACLList(astRule.Match.Protocols, []string{"ip"})
		sources, sourceDiagnostics := flattenACLEndpoint(astRule.Match.Source, objectGroups, serviceGroups, "source", idx)
		destinations, destinationDiagnostics := flattenACLEndpoint(astRule.Match.Destination, objectGroups, serviceGroups, "destination", idx)
		diagnostics = append(diagnostics, sourceDiagnostics...)
		diagnostics = append(diagnostics, destinationDiagnostics...)
		for _, field := range aclRichMatchFields(astRule.Match) {
			diagnostics = append(diagnostics, ACLDiagnostic{Severity: "warning", Code: "field_not_rendered", Path: fmt.Sprintf("acl_ast.rules[%d].match.%s", idx, field), Message: fmt.Sprintf("match field %s is preserved in the AST but not represented in flat RADIUS ACL syntax", field)})
		}
		for _, direction := range directions {
			for _, protocol := range protocols {
				for _, source := range sources {
					for _, destination := range destinations {
						rule := ACLRule{
							ID:                 astRule.ID,
							Sequence:           astRule.Sequence,
							Action:             action,
							Direction:          direction,
							AddressFamily:      astRule.Match.AddressFamily,
							Protocol:           protocol,
							Source:             source.Address,
							SourcePort:         source.Port,
							SourceObjects:      astRule.Match.Source.ObjectGroups,
							Destination:        destination.Address,
							DestinationPort:    destination.Port,
							DestinationObjects: astRule.Match.Destination.ObjectGroups,
							Applications:       astRule.Match.Applications,
							URLCategories:      astRule.Match.URLCategories,
							States:             astRule.Match.States,
							TCPFlags:           astRule.Match.TCPFlags,
							ICMPTypes:          astRule.Match.ICMPTypes,
							DSCP:               astRule.Match.DSCP,
							TimeRange:          astRule.Match.TimeRange,
							Remark:             firstReplyValue(astRule.Description, astRule.Metadata["remark"]),
							Log:                astRule.Log,
							Tags:               astRule.Tags,
						}
						rules = append(rules, rule)
						if len(rules) >= 64 {
							diagnostics = append(diagnostics, ACLDiagnostic{Severity: "warning", Code: "flat_rule_limit", Path: "rules", Message: "flat compatibility rules were truncated at 64 entries"})
							normalized, _ := NormalizeACLRules(rules)
							return normalized, diagnostics
						}
					}
				}
			}
		}
	}
	normalized, err := NormalizeACLRules(rules)
	if err != nil {
		diagnostics = append(diagnostics, ACLDiagnostic{Severity: "error", Code: "flat_rule_invalid", Path: "rules", Message: err.Error()})
		return nil, diagnostics
	}
	return normalized, diagnostics
}

func FingerprintACLPolicyAST(ast ACLPolicyAST) string {
	payload, _ := json.Marshal(ast)
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func aclASTHasContent(ast ACLPolicyAST) bool {
	return strings.TrimSpace(ast.Name) != "" || strings.TrimSpace(ast.Description) != "" || len(ast.Rules) > 0 ||
		len(ast.ObjectGroups) > 0 || len(ast.ServiceGroups) > 0 ||
		len(ast.ApplicationGroups) > 0 || len(ast.URLCategoryGroups) > 0 ||
		len(ast.Tags) > 0 || len(ast.Metadata) > 0
}

func aclExportDiagnosticsForPack(packKey string, normalized ACLPolicyNormalization) []ACLDiagnostic {
	out := append([]ACLDiagnostic(nil), normalized.Diagnostics...)
	switch strings.ToLower(strings.TrimSpace(packKey)) {
	case "standard", "cisco", "aruba", "hp", "dlink", "pica8", "aegisnas":
	default:
		if len(normalized.Rules) > 0 {
			out = append(out, ACLDiagnostic{Severity: "warning", Code: "profile_only_export", Path: "acl_exports." + packKey, Message: "selected vendor pack exports only a profile or policy name; line-rule AST enforcement requires a controller or later vendor compiler"})
		}
	}
	return out
}

func aclUnsupportedRoundTripFields(diagnostics []ACLDiagnostic) []string {
	seen := map[string]struct{}{}
	for _, diagnostic := range diagnostics {
		if diagnostic.Severity == "error" {
			seen[diagnostic.Path] = struct{}{}
			continue
		}
		switch diagnostic.Code {
		case "field_not_rendered", "action_degraded", "object_group_expanded", "service_group_expanded", "profile_only_export", "direction_expanded", "compatibility_rules_differ", "flat_rule_limit":
			seen[diagnostic.Path] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for field := range seen {
		if strings.TrimSpace(field) != "" {
			out = append(out, field)
		}
	}
	sort.Strings(out)
	return out
}

func normalizeACLASTRule(rule ACLASTRule, idx int, objectNames, serviceNames map[string]struct{}) (ACLASTRule, []ACLDiagnostic, error) {
	var diagnostics []ACLDiagnostic
	rule.ID = normalizeACLToken(rule.ID)
	if rule.ID == "" {
		rule.ID = fmt.Sprintf("rule-%04d", idx+1)
	}
	if !validACLToken(rule.ID) {
		return ACLASTRule{}, nil, fmt.Errorf("acl_ast.rules[%d].id is invalid", idx)
	}
	if rule.Sequence <= 0 {
		rule.Sequence = (idx + 1) * 10
	}
	if rule.Enabled == nil {
		rule.Enabled = boolPointer(true)
	}
	rule.Action = normalizeACLASTAction(rule.Action)
	if rule.Action == "" {
		return ACLASTRule{}, nil, fmt.Errorf("acl_ast.rules[%d].action is invalid", idx)
	}
	rule.Direction = strings.ToLower(strings.TrimSpace(rule.Direction))
	if rule.Direction == "" {
		rule.Direction = "in"
	}
	if rule.Direction != "in" && rule.Direction != "out" && rule.Direction != "both" {
		return ACLASTRule{}, nil, fmt.Errorf("acl_ast.rules[%d].direction is invalid", idx)
	}
	rule.Description = strings.TrimSpace(rule.Description)
	rule.Tags = normalizeACLTokenList(rule.Tags, 32)
	rule.Metadata = normalizeACLMetadata(rule.Metadata)
	match, matchDiagnostics, err := normalizeACLASTMatch(rule.Match, fmt.Sprintf("acl_ast.rules[%d].match", idx), objectNames, serviceNames)
	if err != nil {
		return ACLASTRule{}, nil, err
	}
	rule.Match = match
	diagnostics = append(diagnostics, matchDiagnostics...)
	return rule, diagnostics, nil
}

func normalizeACLASTMatch(match ACLASTMatch, path string, objectNames, serviceNames map[string]struct{}) (ACLASTMatch, []ACLDiagnostic, error) {
	match.AddressFamily = normalizeACLAddressFamily(match.AddressFamily)
	if !validACLAddressFamily(match.AddressFamily) {
		return ACLASTMatch{}, nil, fmt.Errorf("%s.address_family is invalid", path)
	}
	match.Protocols = normalizeACLTokenListLower(match.Protocols, 32)
	if len(match.Protocols) == 0 {
		match.Protocols = []string{"ip"}
	}
	match.Applications = normalizeACLTokenList(match.Applications, 64)
	match.URLCategories = normalizeACLTokenList(match.URLCategories, 64)
	match.States = normalizeACLTokenListLower(match.States, 32)
	match.TCPFlags = normalizeACLTokenListLower(match.TCPFlags, 32)
	match.ICMPTypes = normalizeACLTokenListLower(match.ICMPTypes, 32)
	match.DSCP = normalizeACLTokenListLower(match.DSCP, 32)
	match.TimeRange = normalizeACLToken(match.TimeRange)
	source, err := normalizeACLEndpoint(match.Source, path+".source", objectNames, serviceNames)
	if err != nil {
		return ACLASTMatch{}, nil, err
	}
	destination, err := normalizeACLEndpoint(match.Destination, path+".destination", objectNames, serviceNames)
	if err != nil {
		return ACLASTMatch{}, nil, err
	}
	match.Source = source
	match.Destination = destination
	for _, token := range append([]string{match.AddressFamily, match.TimeRange}, append(append(append(append(append(match.Protocols, match.Applications...), match.URLCategories...), match.States...), match.TCPFlags...), append(match.ICMPTypes, match.DSCP...)...)...) {
		if token != "" && !validACLToken(token) {
			return ACLASTMatch{}, nil, fmt.Errorf("%s contains invalid token %q", path, token)
		}
	}
	return match, nil, nil
}

func normalizeACLEndpoint(endpoint ACLEndpoint, path string, objectNames, serviceNames map[string]struct{}) (ACLEndpoint, error) {
	endpoint.Addresses = normalizeACLTokenList(endpoint.Addresses, 64)
	endpoint.ObjectGroups = normalizeACLTokenList(endpoint.ObjectGroups, 64)
	endpoint.Ports = normalizeACLTokenList(endpoint.Ports, 64)
	endpoint.PortGroups = normalizeACLTokenList(endpoint.PortGroups, 64)
	if endpoint.Any || (len(endpoint.Addresses) == 0 && len(endpoint.ObjectGroups) == 0) {
		endpoint.Any = true
		if len(endpoint.Addresses) == 0 {
			endpoint.Addresses = []string{"any"}
		}
	}
	for _, value := range endpoint.Addresses {
		if !validACLToken(value) {
			return ACLEndpoint{}, fmt.Errorf("%s.addresses contains invalid token %q", path, value)
		}
	}
	for _, value := range endpoint.ObjectGroups {
		if !validACLToken(value) {
			return ACLEndpoint{}, fmt.Errorf("%s.object_groups contains invalid token %q", path, value)
		}
		if _, ok := objectNames[strings.ToLower(value)]; !ok {
			return ACLEndpoint{}, fmt.Errorf("%s.object_groups references unknown object group %q", path, value)
		}
	}
	for _, value := range endpoint.Ports {
		if !validACLToken(value) {
			return ACLEndpoint{}, fmt.Errorf("%s.ports contains invalid token %q", path, value)
		}
	}
	for _, value := range endpoint.PortGroups {
		if !validACLToken(value) {
			return ACLEndpoint{}, fmt.Errorf("%s.port_groups contains invalid token %q", path, value)
		}
		if _, ok := serviceNames[strings.ToLower(value)]; !ok {
			return ACLEndpoint{}, fmt.Errorf("%s.port_groups references unknown service group %q", path, value)
		}
	}
	return endpoint, nil
}

func normalizeACLObjectGroup(group ACLObjectGroup, path string) (ACLObjectGroup, error) {
	group.Name = normalizeACLToken(group.Name)
	group.Type = strings.ToLower(normalizeACLToken(group.Type))
	group.AddressFamily = normalizeACLAddressFamily(group.AddressFamily)
	if !validACLAddressFamily(group.AddressFamily) {
		return ACLObjectGroup{}, fmt.Errorf("%s.address_family is invalid", path)
	}
	group.Values = normalizeACLTokenList(group.Values, 1024)
	group.Description = strings.TrimSpace(group.Description)
	if group.Name == "" || !validACLToken(group.Name) {
		return ACLObjectGroup{}, fmt.Errorf("%s.name is invalid", path)
	}
	if len(group.Values) == 0 {
		return ACLObjectGroup{}, fmt.Errorf("%s.values is required", path)
	}
	for _, value := range group.Values {
		if !validACLToken(value) {
			return ACLObjectGroup{}, fmt.Errorf("%s.values contains invalid token %q", path, value)
		}
	}
	return group, nil
}

func normalizeACLServiceGroup(group ACLServiceGroup, path string) (ACLServiceGroup, error) {
	group.Name = normalizeACLToken(group.Name)
	group.Protocols = normalizeACLTokenListLower(group.Protocols, 32)
	group.Ports = normalizeACLTokenList(group.Ports, 1024)
	group.Applications = normalizeACLTokenList(group.Applications, 1024)
	group.Description = strings.TrimSpace(group.Description)
	if group.Name == "" || !validACLToken(group.Name) {
		return ACLServiceGroup{}, fmt.Errorf("%s.name is invalid", path)
	}
	if len(group.Protocols) == 0 && len(group.Ports) == 0 && len(group.Applications) == 0 {
		return ACLServiceGroup{}, fmt.Errorf("%s requires protocols, ports, or applications", path)
	}
	for _, token := range append(append(group.Protocols, group.Ports...), group.Applications...) {
		if !validACLToken(token) {
			return ACLServiceGroup{}, fmt.Errorf("%s contains invalid token %q", path, token)
		}
	}
	return group, nil
}

func normalizeACLNamedValueGroups(groups []ACLNamedValues, path string) error {
	seen := map[string]struct{}{}
	for idx := range groups {
		groups[idx].Name = normalizeACLToken(groups[idx].Name)
		groups[idx].Values = normalizeACLTokenList(groups[idx].Values, 1024)
		groups[idx].Description = strings.TrimSpace(groups[idx].Description)
		if groups[idx].Name == "" || !validACLToken(groups[idx].Name) {
			return fmt.Errorf("%s[%d].name is invalid", path, idx)
		}
		if _, ok := seen[strings.ToLower(groups[idx].Name)]; ok {
			return fmt.Errorf("%s[%d].name is duplicated", path, idx)
		}
		seen[strings.ToLower(groups[idx].Name)] = struct{}{}
		for _, value := range groups[idx].Values {
			if !validACLToken(value) {
				return fmt.Errorf("%s[%d].values contains invalid token %q", path, idx, value)
			}
		}
	}
	return nil
}

type flattenedACLEndpoint struct {
	Address string
	Port    string
}

func flattenACLEndpoint(endpoint ACLEndpoint, objectGroups map[string]ACLObjectGroup, serviceGroups map[string]ACLServiceGroup, name string, ruleIdx int) ([]flattenedACLEndpoint, []ACLDiagnostic) {
	var diagnostics []ACLDiagnostic
	addresses := append([]string(nil), endpoint.Addresses...)
	if len(addresses) == 0 || endpoint.Any {
		addresses = []string{"any"}
	}
	for _, groupName := range endpoint.ObjectGroups {
		if group, ok := objectGroups[strings.ToLower(groupName)]; ok {
			addresses = append(addresses, group.Values...)
			diagnostics = append(diagnostics, ACLDiagnostic{Severity: "warning", Code: "object_group_expanded", Path: fmt.Sprintf("acl_ast.rules[%d].match.%s.object_groups", ruleIdx, name), Message: fmt.Sprintf("object group %q is expanded into flat compatibility rules", groupName)})
		}
	}
	ports := append([]string(nil), endpoint.Ports...)
	for _, groupName := range endpoint.PortGroups {
		if group, ok := serviceGroups[strings.ToLower(groupName)]; ok {
			ports = append(ports, group.Ports...)
			diagnostics = append(diagnostics, ACLDiagnostic{Severity: "warning", Code: "service_group_expanded", Path: fmt.Sprintf("acl_ast.rules[%d].match.%s.port_groups", ruleIdx, name), Message: fmt.Sprintf("service group %q is expanded into flat compatibility rules", groupName)})
		}
	}
	if len(ports) == 0 {
		ports = []string{""}
	}
	out := make([]flattenedACLEndpoint, 0, len(addresses)*len(ports))
	for _, address := range addresses {
		if strings.TrimSpace(address) == "" {
			address = "any"
		}
		for _, port := range ports {
			out = append(out, flattenedACLEndpoint{Address: address, Port: port})
		}
	}
	return out, diagnostics
}

func aclRichMatchFields(match ACLASTMatch) []string {
	var fields []string
	if len(match.Applications) > 0 {
		fields = append(fields, "applications")
	}
	if len(match.URLCategories) > 0 {
		fields = append(fields, "url_categories")
	}
	if len(match.States) > 0 {
		fields = append(fields, "states")
	}
	if len(match.TCPFlags) > 0 {
		fields = append(fields, "tcp_flags")
	}
	if len(match.ICMPTypes) > 0 {
		fields = append(fields, "icmp_types")
	}
	if len(match.DSCP) > 0 {
		fields = append(fields, "dscp")
	}
	if strings.TrimSpace(match.TimeRange) != "" {
		fields = append(fields, "time_range")
	}
	return fields
}

func normalizeACLASTAction(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "", "permit", "allow":
		return "permit"
	case "deny", "drop", "reject":
		return strings.ToLower(strings.TrimSpace(action))
	default:
		return ""
	}
}

func normalizeACLTokenListLower(values []string, limit int) []string {
	out := normalizeACLTokenList(values, limit)
	for idx := range out {
		out[idx] = strings.ToLower(out[idx])
	}
	return out
}

func normalizeACLMetadata(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := map[string]string{}
	for key, value := range values {
		key = normalizeACLToken(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" || !validACLToken(key) {
			continue
		}
		if len(value) > 2048 {
			value = value[:2048]
		}
		out[key] = value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func firstNonEmptyACLList(primary, fallback []string) []string {
	if len(primary) > 0 {
		return append([]string(nil), primary...)
	}
	out := []string{}
	for _, value := range fallback {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func optionalACLList(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return []string{value}
}

func aclEndpointIsAny(endpoint ACLEndpoint) bool {
	if len(endpoint.ObjectGroups) > 0 {
		return false
	}
	for _, address := range endpoint.Addresses {
		if strings.EqualFold(strings.TrimSpace(address), "any") {
			return true
		}
	}
	return len(endpoint.Addresses) == 0
}

func aclRuleAddressFamily(rule ACLRule) string {
	for _, value := range append(append([]string{rule.Source, rule.Destination}, rule.Sources...), rule.Destinations...) {
		switch aclAddressFamily(value) {
		case "ipv6":
			return "ipv6"
		case "ipv4":
			if rule.AddressFamily == "" {
				return "ipv4"
			}
		}
	}
	return rule.AddressFamily
}

func aclAddressFamily(value string) string {
	value = strings.TrimSpace(strings.TrimPrefix(value, "host:"))
	if value == "" || strings.EqualFold(value, "any") {
		return ""
	}
	if prefix, err := netip.ParsePrefix(value); err == nil {
		if prefix.Addr().Is6() {
			return "ipv6"
		}
		if prefix.Addr().Is4() {
			return "ipv4"
		}
	}
	if addr, err := netip.ParseAddr(value); err == nil {
		if addr.Is6() {
			return "ipv6"
		}
		if addr.Is4() {
			return "ipv4"
		}
	}
	return ""
}

func aclRulesFingerprint(rules []ACLRule) string {
	payload, _ := json.Marshal(rules)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func boolPointer(value bool) *bool {
	return &value
}
