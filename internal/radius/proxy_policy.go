package radius

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	layehradius "layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

const ProxyPolicySchemaVersion = 1

type ProxyPolicy struct {
	SchemaVersion    int                `json:"schema_version"`
	Enabled          bool               `json:"enabled"`
	FailClosed       bool               `json:"fail_closed"`
	DefaultAction    string             `json:"default_action"`
	LoopMarker       string             `json:"loop_marker"`
	AddLoopMarker    bool               `json:"add_loop_marker"`
	RejectLoopMarker bool               `json:"reject_loop_marker"`
	MaxHops          int                `json:"max_hops"`
	RoutePolicies    []ProxyRoutePolicy `json:"route_policies"`
	Warnings         []string           `json:"warnings,omitempty"`
}

type ProxyRoutePolicy struct {
	Route                 string                         `json:"route"`
	Direction             string                         `json:"direction"`
	Realm                 string                         `json:"realm"`
	MatchRealms           []string                       `json:"match_realms"`
	TrustedSourceRealms   []string                       `json:"trusted_source_realms"`
	AllowStandard         []ProxyStandardAttribute       `json:"allow_standard"`
	DenyStandard          []ProxyStandardAttribute       `json:"deny_standard"`
	AllowVendorIDs        []uint32                       `json:"allow_vendor_ids"`
	DenyVendorIDs         []uint32                       `json:"deny_vendor_ids"`
	AllowVendorAttributes []ProxyVendorAttributeSelector `json:"allow_vendor_attributes"`
	DenyVendorAttributes  []ProxyVendorAttributeSelector `json:"deny_vendor_attributes"`
	RewriteRules          []ProxyRewriteRule             `json:"rewrite_rules"`
	Description           string                         `json:"description,omitempty"`
	Implicit              bool                           `json:"implicit"`
}

type ProxyStandardAttribute struct {
	Type int    `json:"type"`
	Name string `json:"name"`
}

type ProxyVendorAttributeSelector struct {
	VendorID    uint32 `json:"vendor_id"`
	Type        uint32 `json:"type"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

type ProxyRewriteRule struct {
	Attribute   ProxyStandardAttribute `json:"attribute"`
	Action      string                 `json:"action"`
	MatchRealm  string                 `json:"match_realm,omitempty"`
	Replacement string                 `json:"replacement,omitempty"`
	Description string                 `json:"description,omitempty"`
}

type ProxyPolicyReport struct {
	SchemaVersion int                `json:"schema_version"`
	Enabled       bool               `json:"enabled"`
	Status        string             `json:"status"`
	Message       string             `json:"message"`
	Policy        ProxyPolicy        `json:"policy"`
	Summary       ProxyPolicySummary `json:"summary"`
	FreeRADIUS    ProxyPolicyRADIUS  `json:"freeradius"`
	RFCs          []string           `json:"rfcs"`
	Warnings      []string           `json:"warnings,omitempty"`
}

type ProxyPolicySummary struct {
	RoutePolicyCount          int `json:"route_policy_count"`
	ImplicitRoutePolicyCount  int `json:"implicit_route_policy_count"`
	AllowStandardCount        int `json:"allow_standard_count"`
	DenyStandardCount         int `json:"deny_standard_count"`
	AllowVendorIDCount        int `json:"allow_vendor_id_count"`
	DenyVendorIDCount         int `json:"deny_vendor_id_count"`
	AllowVendorAttributeCount int `json:"allow_vendor_attribute_count"`
	DenyVendorAttributeCount  int `json:"deny_vendor_attribute_count"`
	RewriteRuleCount          int `json:"rewrite_rule_count"`
	TrustedRealmCount         int `json:"trusted_realm_count"`
}

type ProxyPolicyRADIUS struct {
	GeneratedPreProxyPolicy  bool     `json:"generated_pre_proxy_policy"`
	GeneratedPostProxyPolicy bool     `json:"generated_post_proxy_policy"`
	LoopMarkerEnforced       bool     `json:"loop_marker_enforced"`
	Sections                 []string `json:"sections"`
}

type ProxyPolicyContext struct {
	Route       string
	Direction   string
	SourceRealm string
	ProxyState  []string
}

type ProxyPolicyDecision struct {
	Allowed        bool                     `json:"allowed"`
	Decision       string                   `json:"decision"`
	Reason         string                   `json:"reason"`
	Route          string                   `json:"route"`
	Direction      string                   `json:"direction"`
	SourceRealm    string                   `json:"source_realm,omitempty"`
	Accepted       []ProxyAttributeDecision `json:"accepted,omitempty"`
	Dropped        []ProxyAttributeDecision `json:"dropped,omitempty"`
	Rejected       []ProxyAttributeDecision `json:"rejected,omitempty"`
	RewriteActions []ProxyRewriteAction     `json:"rewrite_actions,omitempty"`
}

type ProxyAttributeDecision struct {
	Kind       string `json:"kind"`
	Type       int    `json:"type,omitempty"`
	Name       string `json:"name,omitempty"`
	VendorID   uint32 `json:"vendor_id,omitempty"`
	VendorType uint32 `json:"vendor_type,omitempty"`
	Action     string `json:"action"`
	Reason     string `json:"reason"`
}

type ProxyRewriteAction struct {
	Attribute string `json:"attribute"`
	Before    string `json:"before"`
	After     string `json:"after"`
	Action    string `json:"action"`
}

func DefaultProxyPolicy() ProxyPolicy {
	return ProxyPolicy{
		SchemaVersion:    ProxyPolicySchemaVersion,
		Enabled:          true,
		FailClosed:       true,
		DefaultAction:    "drop",
		LoopMarker:       "aegisnas",
		AddLoopMarker:    true,
		RejectLoopMarker: true,
		MaxHops:          8,
	}
}

func ProxyPolicyFromConfig(cfg *config.Config) (ProxyPolicy, error) {
	policy := DefaultProxyPolicy()
	if cfg == nil {
		return policy, nil
	}
	raw := cfg.Radius.Upstream.ProxyPolicy
	rawEmpty := !raw.Enabled && !raw.FailClosed && strings.TrimSpace(raw.DefaultAction) == "" &&
		strings.TrimSpace(raw.LoopMarker) == "" && !raw.AddLoopMarker && !raw.RejectLoopMarker &&
		raw.MaxHops == 0 && len(raw.RoutePolicies) == 0
	if !rawEmpty {
		policy.Enabled = raw.Enabled
		policy.FailClosed = raw.FailClosed
		policy.DefaultAction = strings.ToLower(defaultString(raw.DefaultAction, "drop"))
		policy.LoopMarker = defaultString(raw.LoopMarker, "aegisnas")
		policy.AddLoopMarker = raw.AddLoopMarker
		policy.RejectLoopMarker = raw.RejectLoopMarker
		policy.MaxHops = raw.MaxHops
		if policy.MaxHops == 0 {
			policy.MaxHops = 8
		}
	}
	if !cfg.Radius.Upstream.Enabled {
		policy.RoutePolicies = nil
		return policy, policy.Validate()
	}
	routes, err := EffectiveProxyRoutes(cfg)
	if err != nil {
		return policy, err
	}
	policy.RoutePolicies = implicitProxyRoutePolicies(routes)
	for _, rawPolicy := range raw.RoutePolicies {
		route, ok := routeByName(routes, rawPolicy.Route)
		if !ok {
			return policy, fmt.Errorf("proxy policy route %q is not enabled", rawPolicy.Route)
		}
		converted, err := proxyRoutePolicyFromConfig(rawPolicy, route)
		if err != nil {
			return policy, err
		}
		policy.RoutePolicies = append(policy.RoutePolicies, converted)
	}
	return policy, policy.Validate()
}

func (p ProxyPolicy) Validate() error {
	if p.SchemaVersion == 0 {
		p.SchemaVersion = ProxyPolicySchemaVersion
	}
	if p.SchemaVersion != ProxyPolicySchemaVersion {
		return fmt.Errorf("proxy policy schema %d is unsupported", p.SchemaVersion)
	}
	if p.DefaultAction == "" {
		p.DefaultAction = "drop"
	}
	switch strings.ToLower(strings.TrimSpace(p.DefaultAction)) {
	case "drop", "reject":
	default:
		return fmt.Errorf("proxy policy default action must be drop or reject")
	}
	if p.LoopMarker == "" {
		p.LoopMarker = "aegisnas"
	}
	if strings.ContainsAny(p.LoopMarker, "\r\n\x00/\\") || len(p.LoopMarker) > 64 {
		return fmt.Errorf("proxy policy loop marker is invalid")
	}
	if p.MaxHops <= 0 {
		p.MaxHops = 8
	}
	if p.MaxHops > 32 {
		return fmt.Errorf("proxy policy max hops must be <= 32")
	}
	return nil
}

func BuildProxyPolicyReport(cfg *config.Config) ProxyPolicyReport {
	policy, err := ProxyPolicyFromConfig(cfg)
	report := ProxyPolicyReport{
		SchemaVersion: ProxyPolicySchemaVersion,
		Enabled:       policy.Enabled,
		Status:        "ready",
		Message:       "Proxy loop prevention and attribute policy is active.",
		Policy:        policy,
		FreeRADIUS: ProxyPolicyRADIUS{
			GeneratedPreProxyPolicy:  policy.Enabled,
			GeneratedPostProxyPolicy: policy.Enabled,
			LoopMarkerEnforced:       policy.Enabled && policy.RejectLoopMarker,
			Sections:                 []string{"sites-enabled/default:pre-proxy", "sites-enabled/default:post-proxy", "sites-enabled/inner-tunnel:pre-proxy", "sites-enabled/inner-tunnel:post-proxy"},
		},
		RFCs: []string{"RFC 2865", "RFC 2866", "RFC 2869", "RFC 5176"},
	}
	if cfg == nil {
		report.Status = "blocked"
		report.Message = "Configuration is not loaded."
		return report
	}
	if !cfg.Radius.Upstream.Enabled {
		report.Status = "disabled"
		report.Message = "Upstream AAA proxying is disabled; proxy attribute policy is not applied."
		report.FreeRADIUS.GeneratedPreProxyPolicy = false
		report.FreeRADIUS.GeneratedPostProxyPolicy = false
		report.FreeRADIUS.LoopMarkerEnforced = false
	}
	if err != nil {
		report.Status = "blocked"
		report.Message = err.Error()
		report.Warnings = append(report.Warnings, err.Error())
	}
	if !policy.Enabled && cfg.Radius.Upstream.Enabled {
		report.Status = "degraded"
		report.Message = "Upstream AAA proxying is enabled but proxy loop and attribute policy is disabled."
		report.Warnings = append(report.Warnings, "Enable radius.upstream.proxy_policy before production proxy operation.")
	}
	for _, route := range policy.RoutePolicies {
		report.Summary.RoutePolicyCount++
		if route.Implicit {
			report.Summary.ImplicitRoutePolicyCount++
		}
		report.Summary.AllowStandardCount += len(route.AllowStandard)
		report.Summary.DenyStandardCount += len(route.DenyStandard)
		report.Summary.AllowVendorIDCount += len(route.AllowVendorIDs)
		report.Summary.DenyVendorIDCount += len(route.DenyVendorIDs)
		report.Summary.AllowVendorAttributeCount += len(route.AllowVendorAttributes)
		report.Summary.DenyVendorAttributeCount += len(route.DenyVendorAttributes)
		report.Summary.RewriteRuleCount += len(route.RewriteRules)
		report.Summary.TrustedRealmCount += len(route.TrustedSourceRealms)
	}
	if cfg.Radius.Upstream.Enabled && report.Summary.RoutePolicyCount == 0 && report.Status == "ready" {
		report.Status = "blocked"
		report.Message = "Upstream AAA proxying is enabled but no effective route policies are available."
	}
	report.Policy.RoutePolicies = sortedProxyRoutePolicies(report.Policy.RoutePolicies)
	return report
}

func EvaluateProxyPolicy(packet *layehradius.Packet, ctx ProxyPolicyContext, policy ProxyPolicy) ProxyPolicyDecision {
	if strings.TrimSpace(ctx.Direction) == "" {
		ctx.Direction = "proxy_request"
	} else {
		ctx.Direction = normalizeProxyPolicyDirection(ctx.Direction)
	}
	ctx.Route = strings.TrimSpace(ctx.Route)
	ctx.SourceRealm = strings.TrimSpace(ctx.SourceRealm)
	decision := ProxyPolicyDecision{
		Allowed:     true,
		Decision:    "accepted",
		Reason:      "policy_allow",
		Route:       ctx.Route,
		Direction:   ctx.Direction,
		SourceRealm: ctx.SourceRealm,
	}
	if !policy.Enabled {
		decision.Reason = "policy_disabled"
		return decision
	}
	if packet == nil {
		return rejectProxyDecision(decision, "nil_packet")
	}
	proxyState := append([]string(nil), ctx.ProxyState...)
	for _, avp := range packet.Attributes {
		if int(avp.Type) == radiusTypeProxyState {
			proxyState = append(proxyState, string(avp.Attribute))
		}
	}
	if policy.MaxHops > 0 && len(proxyState) > policy.MaxHops {
		return rejectProxyDecision(decision, "max_hops_exceeded")
	}
	if policy.RejectLoopMarker {
		for _, state := range proxyState {
			if strings.Contains(strings.ToLower(state), strings.ToLower(policy.LoopMarker)) {
				return rejectProxyDecision(decision, "loop_marker_detected")
			}
		}
	}
	applicable := matchingProxyPolicies(policy, ctx)
	if len(applicable) == 0 {
		if policy.FailClosed {
			return rejectProxyDecision(decision, "missing_route_policy")
		}
		return decision
	}
	if !sourceRealmAllowed(ctx.SourceRealm, applicable) {
		return rejectProxyDecision(decision, "untrusted_source_realm")
	}
	aggregate := aggregateProxyRoutePolicies(applicable)
	for _, action := range evaluateProxyRewrites(packet, aggregate.RewriteRules) {
		decision.RewriteActions = append(decision.RewriteActions, action)
	}
	for _, avp := range packet.Attributes {
		if avp.Type == rfc2865.VendorSpecific_Type {
			continue
		}
		attr := standardAttributeByType(int(avp.Type))
		item := ProxyAttributeDecision{Kind: "standard", Type: attr.Type, Name: attr.Name}
		switch {
		case aggregate.denyStandard[attr.Type]:
			item.Action = "reject"
			item.Reason = "explicit_standard_deny"
			decision.Rejected = append(decision.Rejected, item)
			return rejectProxyDecision(decision, "attribute_denied")
		case aggregate.allowStandard[attr.Type]:
			item.Action = "allow"
			item.Reason = "standard_allow"
			decision.Accepted = append(decision.Accepted, item)
		default:
			item.Action = policy.DefaultAction
			item.Reason = "default_" + policy.DefaultAction
			if policy.DefaultAction == "reject" {
				decision.Rejected = append(decision.Rejected, item)
				return rejectProxyDecision(decision, "attribute_not_allowed")
			}
			decision.Dropped = append(decision.Dropped, item)
		}
	}
	decoded, errs := DecodeVendorAttributes(packet, VSADecodeOptions{})
	if len(errs) > 0 && policy.FailClosed {
		return rejectProxyDecision(decision, "malformed_vendor_attribute")
	}
	for _, attr := range decoded {
		item := ProxyAttributeDecision{Kind: "vendor_attribute", VendorID: attr.VendorID, VendorType: attr.Type}
		key := vendorAttrKey(attr.VendorID, attr.Type)
		switch {
		case aggregate.denyVendorAttributes[key] || aggregate.denyVendorIDs[attr.VendorID]:
			item.Action = "reject"
			item.Reason = "explicit_vendor_deny"
			decision.Rejected = append(decision.Rejected, item)
			return rejectProxyDecision(decision, "attribute_denied")
		case aggregate.allowVendorAttributes[key] || aggregate.allowVendorIDs[attr.VendorID]:
			item.Action = "allow"
			item.Reason = "vendor_allow"
			decision.Accepted = append(decision.Accepted, item)
		default:
			item.Action = policy.DefaultAction
			item.Reason = "default_" + policy.DefaultAction
			if policy.DefaultAction == "reject" {
				decision.Rejected = append(decision.Rejected, item)
				return rejectProxyDecision(decision, "attribute_not_allowed")
			}
			decision.Dropped = append(decision.Dropped, item)
		}
	}
	return decision
}

func FreeRADIUSProxyPolicyUnlang(cfg *config.Config, listName string) (string, error) {
	policy, err := ProxyPolicyFromConfig(cfg)
	if err != nil {
		return "", err
	}
	if !policy.Enabled || cfg == nil || !cfg.Radius.Upstream.Enabled {
		return "\t\t# Proxy loop and attribute policy disabled.\n", nil
	}
	var b strings.Builder
	b.WriteString("\t\t# NAS-0011 proxy loop prevention and route attribute policy.\n")
	if policy.RejectLoopMarker {
		fmt.Fprintf(&b, "\t\tif (&%s:Proxy-State[*] =~ /%s/) {\n\t\t\treject\n\t\t}\n", listName, regexp.QuoteMeta(policy.LoopMarker))
	}
	for _, route := range routePoliciesForUnlang(policy) {
		condition := realmCondition(route.MatchRealms)
		if condition == "" {
			continue
		}
		fmt.Fprintf(&b, "\t\tif (%%{control:Proxy-To-Realm} =~ /%s/) {\n", condition)
		if policy.AddLoopMarker {
			fmt.Fprintf(&b, "\t\t\tupdate %s {\n\t\t\t\tProxy-State += \"%s:%s:%%{Packet-Src-IP-Address}:%%{Realm}\"\n\t\t\t}\n", listName, policy.LoopMarker, route.Route)
		}
		if len(route.TrustedSourceRealms) > 0 {
			fmt.Fprintf(&b, "\t\t\tif (!%%{Realm} || (%%{Realm} !~ /%s/)) {\n\t\t\t\treject\n\t\t\t}\n", realmCondition(route.TrustedSourceRealms))
		}
		for _, attr := range route.DenyStandard {
			fmt.Fprintf(&b, "\t\t\tif (&%s:%s) {\n\t\t\t\treject\n\t\t\t}\n", listName, attr.Name)
		}
		for _, rewrite := range route.RewriteRules {
			writeRewriteUnlang(&b, listName, route, rewrite)
		}
		if len(route.DenyVendorIDs) > 0 || len(route.DenyVendorAttributes) > 0 || len(route.AllowVendorIDs) > 0 || len(route.AllowVendorAttributes) > 0 {
			b.WriteString("\t\t\t# Vendor-Specific allow/deny selectors are enforced by AegisNAS policy evaluation and audited through /api/v1/system/proxy-policy.\n")
		}
		b.WriteString("\t\t}\n")
	}
	return b.String(), nil
}

func implicitProxyRoutePolicies(routes []EffectiveProxyRoute) []ProxyRoutePolicy {
	policies := make([]ProxyRoutePolicy, 0, len(routes))
	for _, route := range routes {
		policies = append(policies, ProxyRoutePolicy{
			Route:               route.Name,
			Direction:           "any",
			Realm:               route.Realm,
			MatchRealms:         append([]string(nil), route.MatchRealms...),
			TrustedSourceRealms: append([]string(nil), route.MatchRealms...),
			AllowStandard:       defaultProxyStandardAllowList(),
			Description:         "Implicit standards-safe proxy policy for the route.",
			Implicit:            true,
		})
	}
	return policies
}

func proxyRoutePolicyFromConfig(raw config.RadiusProxyRoutePolicyConfig, route EffectiveProxyRoute) (ProxyRoutePolicy, error) {
	policy := ProxyRoutePolicy{
		Route:               strings.TrimSpace(raw.Route),
		Direction:           normalizeProxyPolicyDirection(raw.Direction),
		Realm:               route.Realm,
		MatchRealms:         append([]string(nil), route.MatchRealms...),
		TrustedSourceRealms: uniqueNonEmptyStrings(raw.TrustedSourceRealms),
		Description:         strings.TrimSpace(raw.Description),
	}
	for _, attr := range raw.AllowStandard {
		standard, err := parseStandardAttribute(attr)
		if err != nil {
			return policy, err
		}
		policy.AllowStandard = append(policy.AllowStandard, standard)
	}
	for _, attr := range raw.DenyStandard {
		standard, err := parseStandardAttribute(attr)
		if err != nil {
			return policy, err
		}
		policy.DenyStandard = append(policy.DenyStandard, standard)
	}
	for _, vendorID := range raw.AllowVendorIDs {
		policy.AllowVendorIDs = append(policy.AllowVendorIDs, uint32(vendorID))
	}
	for _, vendorID := range raw.DenyVendorIDs {
		policy.DenyVendorIDs = append(policy.DenyVendorIDs, uint32(vendorID))
	}
	for _, selector := range raw.AllowVendorAttributes {
		policy.AllowVendorAttributes = append(policy.AllowVendorAttributes, proxySelectorFromConfig(selector))
	}
	for _, selector := range raw.DenyVendorAttributes {
		policy.DenyVendorAttributes = append(policy.DenyVendorAttributes, proxySelectorFromConfig(selector))
	}
	for _, rewrite := range raw.RewriteRules {
		converted, err := proxyRewriteFromConfig(rewrite, route)
		if err != nil {
			return policy, err
		}
		policy.RewriteRules = append(policy.RewriteRules, converted)
	}
	return policy, nil
}

func proxySelectorFromConfig(selector config.RadiusProxyVendorAttributeSelector) ProxyVendorAttributeSelector {
	return ProxyVendorAttributeSelector{
		VendorID:    uint32(selector.VendorID),
		Type:        uint32(selector.Type),
		Name:        strings.TrimSpace(selector.Name),
		Description: strings.TrimSpace(selector.Description),
	}
}

func proxyRewriteFromConfig(raw config.RadiusProxyRewriteRuleConfig, route EffectiveProxyRoute) (ProxyRewriteRule, error) {
	attr, err := parseStandardAttribute(defaultString(raw.Attribute, "User-Name"))
	if err != nil {
		return ProxyRewriteRule{}, err
	}
	rule := ProxyRewriteRule{
		Attribute:   attr,
		Action:      strings.ToLower(strings.TrimSpace(raw.Action)),
		MatchRealm:  strings.TrimSpace(raw.MatchRealm),
		Replacement: strings.TrimSpace(raw.Replacement),
		Description: strings.TrimSpace(raw.Description),
	}
	if rule.MatchRealm == "" {
		rule.MatchRealm = route.Realm
	}
	return rule, nil
}

func routeByName(routes []EffectiveProxyRoute, name string) (EffectiveProxyRoute, bool) {
	name = strings.TrimSpace(name)
	for _, route := range routes {
		if route.Name == name {
			return route, true
		}
	}
	return EffectiveProxyRoute{}, false
}

type aggregateProxyPolicy struct {
	allowStandard         map[int]bool
	denyStandard          map[int]bool
	allowVendorIDs        map[uint32]bool
	denyVendorIDs         map[uint32]bool
	allowVendorAttributes map[string]bool
	denyVendorAttributes  map[string]bool
	RewriteRules          []ProxyRewriteRule
	TrustedSourceRealms   []string
}

func aggregateProxyRoutePolicies(policies []ProxyRoutePolicy) aggregateProxyPolicy {
	aggregate := aggregateProxyPolicy{
		allowStandard:         map[int]bool{},
		denyStandard:          map[int]bool{},
		allowVendorIDs:        map[uint32]bool{},
		denyVendorIDs:         map[uint32]bool{},
		allowVendorAttributes: map[string]bool{},
		denyVendorAttributes:  map[string]bool{},
	}
	for _, policy := range policies {
		for _, attr := range policy.AllowStandard {
			aggregate.allowStandard[attr.Type] = true
		}
		for _, attr := range policy.DenyStandard {
			aggregate.denyStandard[attr.Type] = true
		}
		for _, vendorID := range policy.AllowVendorIDs {
			aggregate.allowVendorIDs[vendorID] = true
		}
		for _, vendorID := range policy.DenyVendorIDs {
			aggregate.denyVendorIDs[vendorID] = true
		}
		for _, selector := range policy.AllowVendorAttributes {
			aggregate.allowVendorAttributes[vendorAttrKey(selector.VendorID, selector.Type)] = true
		}
		for _, selector := range policy.DenyVendorAttributes {
			aggregate.denyVendorAttributes[vendorAttrKey(selector.VendorID, selector.Type)] = true
		}
		aggregate.RewriteRules = append(aggregate.RewriteRules, policy.RewriteRules...)
		aggregate.TrustedSourceRealms = append(aggregate.TrustedSourceRealms, policy.TrustedSourceRealms...)
	}
	return aggregate
}

func matchingProxyPolicies(policy ProxyPolicy, ctx ProxyPolicyContext) []ProxyRoutePolicy {
	var out []ProxyRoutePolicy
	for _, routePolicy := range policy.RoutePolicies {
		if routePolicy.Route != ctx.Route {
			continue
		}
		if routePolicy.Direction == "any" || routePolicy.Direction == ctx.Direction {
			out = append(out, routePolicy)
		}
	}
	return out
}

func sourceRealmAllowed(sourceRealm string, policies []ProxyRoutePolicy) bool {
	allowed := map[string]struct{}{}
	for _, policy := range policies {
		for _, realm := range policy.TrustedSourceRealms {
			allowed[strings.ToLower(strings.TrimSpace(realm))] = struct{}{}
		}
	}
	if len(allowed) == 0 {
		return true
	}
	_, ok := allowed[strings.ToLower(strings.TrimSpace(sourceRealm))]
	return ok
}

func evaluateProxyRewrites(packet *layehradius.Packet, rules []ProxyRewriteRule) []ProxyRewriteAction {
	if len(rules) == 0 || packet == nil {
		return nil
	}
	username, err := rfc2865.UserName_LookupString(packet)
	if err != nil || username == "" {
		return nil
	}
	var actions []ProxyRewriteAction
	for _, rule := range rules {
		if rule.Attribute.Type != 1 {
			continue
		}
		before := username
		after := username
		suffix := "@" + rule.MatchRealm
		switch rule.Action {
		case "strip_realm_from_user_name":
			if strings.HasSuffix(strings.ToLower(username), strings.ToLower(suffix)) {
				after = username[:len(username)-len(suffix)]
			}
		case "replace_realm":
			if strings.HasSuffix(strings.ToLower(username), strings.ToLower(suffix)) {
				after = username[:len(username)-len(rule.MatchRealm)] + rule.Replacement
			}
		}
		if after != before {
			actions = append(actions, ProxyRewriteAction{Attribute: "User-Name", Before: before, After: after, Action: rule.Action})
			username = after
		}
	}
	return actions
}

func rejectProxyDecision(decision ProxyPolicyDecision, reason string) ProxyPolicyDecision {
	decision.Allowed = false
	decision.Decision = "rejected"
	decision.Reason = reason
	return decision
}

func parseStandardAttribute(value string) (ProxyStandardAttribute, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return ProxyStandardAttribute{}, fmt.Errorf("standard attribute is required")
	}
	if number, err := strconv.Atoi(value); err == nil {
		if number < 1 || number > 255 {
			return ProxyStandardAttribute{}, fmt.Errorf("standard attribute type %d is outside 1..255", number)
		}
		return standardAttributeByType(number), nil
	}
	if typ, ok := standardAttributeNameToType[strings.ToLower(value)]; ok {
		return standardAttributeByType(typ), nil
	}
	if !validGeneratedAttributeName(value) {
		return ProxyStandardAttribute{}, fmt.Errorf("standard attribute %q is invalid", value)
	}
	return ProxyStandardAttribute{Name: value}, nil
}

func standardAttributeByType(typ int) ProxyStandardAttribute {
	if name, ok := standardAttributeTypeToName[typ]; ok {
		return ProxyStandardAttribute{Type: typ, Name: name}
	}
	return ProxyStandardAttribute{Type: typ, Name: fmt.Sprintf("Type-%d", typ)}
}

func defaultProxyStandardAllowList() []ProxyStandardAttribute {
	names := []string{
		"User-Name", "User-Password", "CHAP-Password", "NAS-IP-Address", "NAS-Port",
		"Service-Type", "Framed-Protocol", "Framed-IP-Address", "Filter-Id", "State",
		"Class", "Vendor-Specific", "Session-Timeout", "Idle-Timeout", "Called-Station-Id",
		"Calling-Station-Id", "NAS-Identifier", "Proxy-State", "Acct-Status-Type",
		"Acct-Delay-Time", "Acct-Input-Octets", "Acct-Output-Octets", "Acct-Session-Id",
		"Acct-Authentic", "Acct-Session-Time", "Acct-Input-Packets", "Acct-Output-Packets",
		"Acct-Terminate-Cause", "CHAP-Challenge", "NAS-Port-Type", "Tunnel-Type",
		"Tunnel-Medium-Type", "Tunnel-Client-Endpoint", "Tunnel-Server-Endpoint",
		"Tunnel-Private-Group-Id", "Acct-Interim-Interval", "NAS-Port-Id", "Framed-Pool",
		"CUI", "NAS-IPv6-Address", "Framed-Interface-Id", "Framed-IPv6-Prefix",
		"Framed-IPv6-Route", "Framed-IPv6-Pool", "Error-Cause", "EAP-Message",
		"Message-Authenticator", "EAP-Key-Name",
	}
	out := make([]ProxyStandardAttribute, 0, len(names))
	for _, name := range names {
		attr, _ := parseStandardAttribute(name)
		out = append(out, attr)
	}
	return out
}

func sortedProxyRoutePolicies(policies []ProxyRoutePolicy) []ProxyRoutePolicy {
	out := append([]ProxyRoutePolicy(nil), policies...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Route != out[j].Route {
			return out[i].Route < out[j].Route
		}
		if out[i].Implicit != out[j].Implicit {
			return out[i].Implicit
		}
		return out[i].Direction < out[j].Direction
	})
	return out
}

func routePoliciesForUnlang(policy ProxyPolicy) []ProxyRoutePolicy {
	byRoute := map[string]ProxyRoutePolicy{}
	for _, routePolicy := range policy.RoutePolicies {
		current := byRoute[routePolicy.Route]
		if current.Route == "" {
			current = ProxyRoutePolicy{
				Route:               routePolicy.Route,
				Direction:           "any",
				Realm:               routePolicy.Realm,
				MatchRealms:         append([]string(nil), routePolicy.MatchRealms...),
				TrustedSourceRealms: append([]string(nil), routePolicy.TrustedSourceRealms...),
				Description:         routePolicy.Description,
				Implicit:            routePolicy.Implicit,
			}
		}
		current.DenyStandard = append(current.DenyStandard, routePolicy.DenyStandard...)
		current.DenyVendorIDs = append(current.DenyVendorIDs, routePolicy.DenyVendorIDs...)
		current.DenyVendorAttributes = append(current.DenyVendorAttributes, routePolicy.DenyVendorAttributes...)
		current.AllowVendorIDs = append(current.AllowVendorIDs, routePolicy.AllowVendorIDs...)
		current.AllowVendorAttributes = append(current.AllowVendorAttributes, routePolicy.AllowVendorAttributes...)
		current.RewriteRules = append(current.RewriteRules, routePolicy.RewriteRules...)
		if len(routePolicy.TrustedSourceRealms) > 0 {
			current.TrustedSourceRealms = routePolicy.TrustedSourceRealms
		}
		byRoute[routePolicy.Route] = current
	}
	out := make([]ProxyRoutePolicy, 0, len(byRoute))
	for _, routePolicy := range byRoute {
		out = append(out, routePolicy)
	}
	return sortedProxyRoutePolicies(out)
}

func realmCondition(realms []string) string {
	realms = uniqueNonEmptyStrings(realms)
	if len(realms) == 0 {
		return ""
	}
	escaped := make([]string, 0, len(realms))
	for _, realm := range realms {
		escaped = append(escaped, regexp.QuoteMeta(realm))
	}
	return "^(" + strings.Join(escaped, "|") + ")$"
}

func writeRewriteUnlang(b *strings.Builder, listName string, route ProxyRoutePolicy, rewrite ProxyRewriteRule) {
	matchRealm := rewrite.MatchRealm
	if matchRealm == "" {
		matchRealm = route.Realm
	}
	switch rewrite.Action {
	case "strip_realm_from_user_name":
		fmt.Fprintf(b, "\t\t\tif (&%s:User-Name =~ /^(.*)@%s$/) {\n\t\t\t\tupdate %s {\n\t\t\t\t\tUser-Name := \"%%{1}\"\n\t\t\t\t}\n\t\t\t}\n", listName, regexp.QuoteMeta(matchRealm), listName)
	case "replace_realm":
		fmt.Fprintf(b, "\t\t\tif (&%s:User-Name =~ /^(.*)@%s$/) {\n\t\t\t\tupdate %s {\n\t\t\t\t\tUser-Name := \"%%{1}@%s\"\n\t\t\t\t}\n\t\t\t}\n", listName, regexp.QuoteMeta(matchRealm), listName, rewrite.Replacement)
	}
}

func vendorAttrKey(vendorID, typ uint32) string {
	return fmt.Sprintf("%d/%d", vendorID, typ)
}

func normalizeProxyPolicyDirection(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "", "any":
		return "any"
	case "proxy_response":
		return "proxy_response"
	default:
		return "proxy_request"
	}
}

func validGeneratedAttributeName(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 96 {
		return false
	}
	for i, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case i > 0 && r >= '0' && r <= '9':
		case i > 0 && (r == '-' || r == '_' || r == '.'):
		default:
			return false
		}
	}
	return true
}

var standardAttributeTypeToName = map[int]string{
	1: "User-Name", 2: "User-Password", 3: "CHAP-Password", 4: "NAS-IP-Address",
	5: "NAS-Port", 6: "Service-Type", 7: "Framed-Protocol", 8: "Framed-IP-Address",
	9: "Framed-IP-Netmask", 10: "Framed-Routing", 11: "Filter-Id", 12: "Framed-MTU",
	13: "Framed-Compression", 14: "Login-IP-Host", 15: "Login-Service", 16: "Login-TCP-Port",
	18: "Reply-Message", 19: "Callback-Number", 20: "Callback-Id", 22: "Framed-Route",
	23: "Framed-IPX-Network", 24: "State", 25: "Class", 26: "Vendor-Specific",
	27: "Session-Timeout", 28: "Idle-Timeout", 29: "Termination-Action",
	30: "Called-Station-Id", 31: "Calling-Station-Id", 32: "NAS-Identifier",
	33: "Proxy-State", 34: "Login-LAT-Service", 35: "Login-LAT-Node",
	36: "Login-LAT-Group", 37: "Framed-AppleTalk-Link", 38: "Framed-AppleTalk-Network",
	39: "Framed-AppleTalk-Zone", 40: "Acct-Status-Type", 41: "Acct-Delay-Time",
	42: "Acct-Input-Octets", 43: "Acct-Output-Octets", 44: "Acct-Session-Id",
	45: "Acct-Authentic", 46: "Acct-Session-Time", 47: "Acct-Input-Packets",
	48: "Acct-Output-Packets", 49: "Acct-Terminate-Cause", 50: "Acct-Multi-Session-Id",
	51: "Acct-Link-Count", 60: "CHAP-Challenge", 61: "NAS-Port-Type", 62: "Port-Limit",
	63: "Login-LAT-Port", 64: "Tunnel-Type", 65: "Tunnel-Medium-Type",
	66: "Tunnel-Client-Endpoint", 67: "Tunnel-Server-Endpoint",
	68: "Acct-Tunnel-Connection", 69: "Tunnel-Password", 70: "ARAP-Password",
	71: "ARAP-Features", 72: "ARAP-Zone-Access", 73: "ARAP-Security",
	74: "ARAP-Security-Data", 75: "Password-Retry", 76: "Prompt", 77: "Connect-Info",
	78: "Configuration-Token", 79: "EAP-Message", 80: "Message-Authenticator",
	81: "Tunnel-Private-Group-Id", 82: "Tunnel-Assignment-Id", 83: "Tunnel-Preference",
	84: "ARAP-Challenge-Response", 85: "Acct-Interim-Interval",
	86: "Acct-Tunnel-Packets-Lost", 87: "NAS-Port-Id", 88: "Framed-Pool",
	89: "Chargeable-User-Identity", 95: "NAS-IPv6-Address", 96: "Framed-Interface-Id",
	97: "Framed-IPv6-Prefix", 98: "Login-IPv6-Host", 99: "Framed-IPv6-Route",
	100: "Framed-IPv6-Pool", 101: "Error-Cause", 102: "EAP-Key-Name",
}

var standardAttributeNameToType = func() map[string]int {
	out := make(map[string]int, len(standardAttributeTypeToName)+4)
	for typ, name := range standardAttributeTypeToName {
		out[strings.ToLower(name)] = typ
	}
	out["cui"] = 89
	return out
}()
