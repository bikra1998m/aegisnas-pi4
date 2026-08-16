package radius

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

const RoutePolicyCompilerVersion = 1

type RoutePolicyCompileRequest struct {
	Role              string             `json:"role"`
	SessionID         string             `json:"session_id,omitempty"`
	AcctSessionID     string             `json:"acct_session_id,omitempty"`
	CallingStationID  string             `json:"calling_station_id,omitempty"`
	NASIdentifier     string             `json:"nas_identifier,omitempty"`
	NASIPAddress      string             `json:"nas_ip_address,omitempty"`
	FramedIPAddress   string             `json:"framed_ip_address,omitempty"`
	FramedIPv6Address string             `json:"framed_ipv6_address,omitempty"`
	VRF               string             `json:"vrf,omitempty"`
	Owner             string             `json:"owner,omitempty"`
	LifecycleAction   string             `json:"lifecycle_action,omitempty"`
	Routes            []RoutePolicyRoute `json:"routes,omitempty"`
	PackKeys          []string           `json:"pack_keys,omitempty"`
}

type RoutePolicyDecompileRequest struct {
	PackKey    string                 `json:"pack_key,omitempty"`
	Attributes []RoutePolicyAttribute `json:"attributes"`
	Role       string                 `json:"role,omitempty"`
	SessionID  string                 `json:"session_id,omitempty"`
}

type RoutePolicyCompileResult struct {
	CompilerVersion int                     `json:"compiler_version"`
	Status          string                  `json:"status"`
	Message         string                  `json:"message"`
	Decision        RoutePolicyDecision     `json:"decision"`
	Attributes      []RoutePolicyAttribute  `json:"attributes"`
	Summary         RoutePolicySummary      `json:"summary"`
	Diagnostics     []RoutePolicyDiagnostic `json:"diagnostics"`
	Fingerprint     string                  `json:"fingerprint"`
	RFCs            []string                `json:"rfcs"`
}

type RoutePolicyDecompileResult = RoutePolicyCompileResult

type RoutePolicyDecision struct {
	Role            string             `json:"role,omitempty"`
	SessionID       string             `json:"session_id,omitempty"`
	AcctSessionID   string             `json:"acct_session_id,omitempty"`
	PolicyMatched   bool               `json:"policy_matched"`
	PolicySource    string             `json:"policy_source"`
	LifecycleAction string             `json:"lifecycle_action"`
	VRF             string             `json:"vrf,omitempty"`
	Owner           string             `json:"owner,omitempty"`
	Revision        string             `json:"revision,omitempty"`
	OwnershipKey    string             `json:"ownership_key,omitempty"`
	IPv4Routes      []RoutePolicyRoute `json:"ipv4_routes,omitempty"`
	IPv6Routes      []RoutePolicyRoute `json:"ipv6_routes,omitempty"`
	VendorPacks     []string           `json:"vendor_packs,omitempty"`
	SelectionKey    string             `json:"selection_key,omitempty"`
	Withdraw        bool               `json:"withdraw"`
}

type RoutePolicyRoute struct {
	Family      string `json:"family"`
	Destination string `json:"destination"`
	Gateway     string `json:"gateway,omitempty"`
	Metric      int    `json:"metric,omitempty"`
	Preference  int    `json:"preference,omitempty"`
	Interface   string `json:"interface,omitempty"`
	Tag         string `json:"tag,omitempty"`
	Owner       string `json:"owner,omitempty"`
	Source      string `json:"source,omitempty"`
	Install     bool   `json:"install"`
	Withdraw    bool   `json:"withdraw"`
}

type RoutePolicyAttribute struct {
	PackKey string `json:"pack_key"`
	Name    string `json:"name"`
	Value   string `json:"value"`
	Quoted  bool   `json:"quoted"`
	Purpose string `json:"purpose"`
}

type RoutePolicySummary struct {
	PolicyCount     int `json:"policy_count"`
	VRFCount        int `json:"vrf_count"`
	RouteCount      int `json:"route_count"`
	IPv4RouteCount  int `json:"ipv4_route_count"`
	IPv6RouteCount  int `json:"ipv6_route_count"`
	WithdrawCount   int `json:"withdraw_count"`
	AttributeCount  int `json:"attribute_count"`
	DiagnosticCount int `json:"diagnostic_count"`
}

type RoutePolicyDiagnostic struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Message  string `json:"message"`
	Field    string `json:"field,omitempty"`
	PackKey  string `json:"pack_key,omitempty"`
	Route    string `json:"route,omitempty"`
	VRF      string `json:"vrf,omitempty"`
}

type RoutePolicyReport struct {
	CompilerVersion int                            `json:"compiler_version"`
	Enabled         bool                           `json:"enabled"`
	FailClosed      bool                           `json:"fail_closed"`
	MaxRoutes       int                            `json:"max_routes"`
	DefaultVRF      string                         `json:"default_vrf"`
	DefaultOwner    string                         `json:"default_owner"`
	ConflictMode    string                         `json:"conflict_mode"`
	StopWithdrawal  bool                           `json:"stop_withdrawal"`
	Summary         RoutePolicyCatalogSummary      `json:"summary"`
	Capabilities    []RoutePolicyCapability        `json:"capabilities"`
	VRFs            []config.RadiusVRFConfig       `json:"vrfs"`
	Policies        []config.RadiusRouteRolePolicy `json:"policies"`
	RFCs            []string                       `json:"rfcs"`
}

type RoutePolicyCatalogSummary struct {
	PolicyCount    int `json:"policy_count"`
	VRFCount       int `json:"vrf_count"`
	IPv4RouteCount int `json:"ipv4_route_count"`
	IPv6RouteCount int `json:"ipv6_route_count"`
}

type RoutePolicyCapability struct {
	Key        string   `json:"key"`
	Label      string   `json:"label"`
	Status     string   `json:"status"`
	Attributes []string `json:"attributes"`
	Vendors    []string `json:"vendors"`
	Notes      string   `json:"notes,omitempty"`
}

func BuildRoutePolicyReport(cfg *config.Config) RoutePolicyReport {
	policy := config.RadiusRoutePolicyConfig{}
	if cfg != nil {
		policy = cfg.Radius.RoutePolicy
	}
	report := RoutePolicyReport{
		CompilerVersion: RoutePolicyCompilerVersion,
		Enabled:         policy.Enabled,
		FailClosed:      policy.FailClosed,
		MaxRoutes:       effectiveRoutePolicyMaxRoutes(policy),
		DefaultVRF:      effectiveRoutePolicyVRF(policy.DefaultVRF),
		DefaultOwner:    effectiveRoutePolicyOwner(policy.DefaultOwner),
		ConflictMode:    effectiveRoutePolicyConflictMode(policy.ConflictMode),
		StopWithdrawal:  policy.StopWithdrawal,
		VRFs:            append([]config.RadiusVRFConfig(nil), policy.VRFs...),
		Policies:        append([]config.RadiusRouteRolePolicy(nil), policy.RolePolicies...),
		RFCs:            routePolicyRFCs(),
		Capabilities: []RoutePolicyCapability{
			{Key: "framed_route", Label: "IPv4 Framed Route", Status: "implemented", Attributes: []string{"Framed-Route", "AegisNAS-Framed-Route"}, Vendors: []string{"Cisco", "Juniper ERX", "Huawei", "Nokia", "MikroTik", "standards-based"}},
			{Key: "framed_ipv6_route", Label: "IPv6 Framed Route", Status: "implemented", Attributes: []string{"Framed-IPv6-Route", "AegisNAS-Framed-IPv6-Route"}, Vendors: []string{"Juniper ERX", "Huawei", "Nokia", "BNG/BRAS", "standards-based"}},
			{Key: "vrf_ownership", Label: "VRF Ownership", Status: "implemented", Attributes: []string{"AegisNAS-VRF", "AegisNAS-Route-Owner", "Cisco-AVPair", "Juniper-AV-Pair", "Huawei-AVpair", "Nokia-AVPair"}, Vendors: []string{"Cisco", "Juniper", "Huawei", "Nokia", "carrier access"}, Notes: "Native hardware behavior remains release-certified per vendor and firmware."},
			{Key: "route_lifecycle", Label: "CoA And Stop Route Lifecycle", Status: "implemented", Attributes: []string{"AegisNAS-Route-Policy", "AegisNAS-Route-Revision"}, Vendors: []string{"all RADIUS dynamic authorization capable NAS"}, Notes: "Software emits revisioned ownership metadata; packet captures and device withdrawals are release certification evidence."},
		},
	}
	report.Summary.PolicyCount = len(policy.RolePolicies)
	report.Summary.VRFCount = len(policy.VRFs)
	for _, rolePolicy := range policy.RolePolicies {
		report.Summary.IPv4RouteCount += len(rolePolicy.IPv4Routes)
		report.Summary.IPv6RouteCount += len(rolePolicy.IPv6Routes)
	}
	return report
}

func CompileRoutePolicy(cfg *config.Config, req RoutePolicyCompileRequest) RoutePolicyCompileResult {
	result := RoutePolicyCompileResult{
		CompilerVersion: RoutePolicyCompilerVersion,
		Status:          "ready",
		RFCs:            routePolicyRFCs(),
	}
	if cfg == nil {
		result.Status = "blocked"
		result.Message = "configuration is required"
		result.Diagnostics = append(result.Diagnostics, RoutePolicyDiagnostic{Severity: "error", Code: "missing_config", Message: result.Message})
		finalizeRoutePolicyResult(&result)
		return result
	}
	policy := cfg.Radius.RoutePolicy
	result.Summary.PolicyCount = len(policy.RolePolicies)
	result.Summary.VRFCount = len(policy.VRFs)
	if !policy.Enabled {
		result.Status = "blocked"
		result.Message = "route policy compiler is disabled"
		result.Diagnostics = append(result.Diagnostics, RoutePolicyDiagnostic{Severity: "error", Code: "disabled", Message: result.Message, Field: "radius.route_policy.enabled"})
		finalizeRoutePolicyResult(&result)
		return result
	}

	role := strings.TrimSpace(req.Role)
	if role == "" {
		role = "default"
	}
	lifecycleAction := normalizeRoutePolicyLifecycleAction(req.LifecycleAction)
	result.Decision.Role = role
	result.Decision.SessionID = strings.TrimSpace(req.SessionID)
	result.Decision.AcctSessionID = strings.TrimSpace(req.AcctSessionID)
	result.Decision.LifecycleAction = lifecycleAction
	result.Decision.VRF = firstReplyValue(strings.TrimSpace(req.VRF), effectiveRoutePolicyVRF(policy.DefaultVRF))
	result.Decision.Owner = firstReplyValue(strings.TrimSpace(req.Owner), effectiveRoutePolicyOwner(policy.DefaultOwner))
	result.Decision.PolicySource = "request"
	result.Decision.SelectionKey = routePolicySelectionKey(req, role)

	if routePolicy, matched := routePolicyForRole(policy.RolePolicies, role); matched {
		result.Decision.PolicyMatched = true
		result.Decision.PolicySource = "radius.route_policy.role_policies"
		result.Decision.VRF = firstReplyValue(strings.TrimSpace(routePolicy.VRF), result.Decision.VRF)
		result.Decision.Owner = firstReplyValue(strings.TrimSpace(routePolicy.Owner), result.Decision.Owner)
		result.Decision.VendorPacks = normalizeRoutePolicyPackKeys(routePolicy.VendorPacks)
		for idx, route := range routePolicy.IPv4Routes {
			appendConfiguredRoute(&result, route, "ipv4", fmt.Sprintf("radius.route_policy.role_policies[%s].ipv4_routes[%d]", role, idx), "role")
		}
		for idx, route := range routePolicy.IPv6Routes {
			appendConfiguredRoute(&result, route, "ipv6", fmt.Sprintf("radius.route_policy.role_policies[%s].ipv6_routes[%d]", role, idx), "role")
		}
	} else if len(req.Routes) == 0 {
		result.Diagnostics = append(result.Diagnostics, RoutePolicyDiagnostic{Severity: "warning", Code: "role_policy_missing", Message: "no route policy matched the role; no framed routes were selected", Field: "role"})
	}

	for idx, route := range req.Routes {
		appendRequestRoute(&result, route, fmt.Sprintf("routes[%d]", idx), effectiveRoutePolicyConflictMode(policy.ConflictMode))
	}

	result.Decision.IPv4Routes = normalizeCompiledRoutes(result.Decision.IPv4Routes, result.Decision.VRF, result.Decision.Owner)
	result.Decision.IPv6Routes = normalizeCompiledRoutes(result.Decision.IPv6Routes, result.Decision.VRF, result.Decision.Owner)
	applyRoutePolicyLifecycle(&result, policy)
	validateCompiledRouteDecision(&result, policy)
	result.Decision.Revision = routePolicyRevision(result.Decision)
	result.Decision.OwnershipKey = routePolicyOwnershipKey(result.Decision)
	result.Attributes = BuildRoutePolicyAttributes(result.Decision, effectiveRoutePolicyPackKeys(req.PackKeys, result.Decision.VendorPacks, cfg.Radius.Vendor.CompatibilityPacks))
	finalizeRoutePolicyResult(&result)
	return result
}

func DecompileRoutePolicyAttributes(req RoutePolicyDecompileRequest) RoutePolicyDecompileResult {
	result := RoutePolicyCompileResult{
		CompilerVersion: RoutePolicyCompilerVersion,
		Status:          "decompiled",
		RFCs:            routePolicyRFCs(),
		Attributes:      append([]RoutePolicyAttribute(nil), req.Attributes...),
	}
	packKey := productconfigs.NormalizeVendorCompatibilityPackKey(req.PackKey)
	if packKey == "" {
		packKey = productconfigs.VendorPackStandard
	}
	result.Decision.Role = strings.TrimSpace(req.Role)
	result.Decision.SessionID = strings.TrimSpace(req.SessionID)
	result.Decision.PolicySource = "decompile"
	result.Decision.LifecycleAction = "authorize"
	result.Decision.VendorPacks = []string{packKey}

	for index, attr := range req.Attributes {
		name := strings.ToLower(strings.TrimSpace(attr.Name))
		value := strings.TrimSpace(attr.Value)
		if name == "" || value == "" {
			result.Diagnostics = append(result.Diagnostics, RoutePolicyDiagnostic{Severity: "warning", Code: "empty_attribute", Message: "empty route attribute was ignored", Field: fmt.Sprintf("attributes[%d]", index), PackKey: packKey})
			continue
		}
		switch name {
		case "framed-route", "aegisnas-framed-route":
			route, diagnostics := parseFramedRouteValue(value, "ipv4", attr.Name)
			result.Diagnostics = append(result.Diagnostics, diagnostics...)
			if route.Destination != "" {
				route.Source = "decompile"
				route.Install = true
				result.Decision.IPv4Routes = append(result.Decision.IPv4Routes, route)
			}
		case "framed-ipv6-route", "aegisnas-framed-ipv6-route":
			route, diagnostics := parseFramedRouteValue(value, "ipv6", attr.Name)
			result.Diagnostics = append(result.Diagnostics, diagnostics...)
			if route.Destination != "" {
				route.Source = "decompile"
				route.Install = true
				result.Decision.IPv6Routes = append(result.Decision.IPv6Routes, route)
			}
		case "aegisnas-vrf":
			result.Decision.VRF = value
		case "aegisnas-route-owner":
			result.Decision.Owner = value
		case "aegisnas-route-policy":
			result.Decision.LifecycleAction = normalizeRoutePolicyLifecycleAction(value)
		case "aegisnas-route-revision":
			result.Decision.Revision = value
		case "cisco-avpair", "juniper-av-pair", "huawei-avpair", "h3c-av-pair", "nokia-avpair":
			decompileVendorRouteAVPair(&result, value, attr.Name)
		}
	}
	if result.Decision.VRF == "" {
		result.Decision.VRF = "default"
	}
	if result.Decision.Owner == "" {
		result.Decision.Owner = "aegisnas"
	}
	if result.Decision.LifecycleAction == "" {
		result.Decision.LifecycleAction = "authorize"
	}
	result.Decision.IPv4Routes = normalizeCompiledRoutes(result.Decision.IPv4Routes, result.Decision.VRF, result.Decision.Owner)
	result.Decision.IPv6Routes = normalizeCompiledRoutes(result.Decision.IPv6Routes, result.Decision.VRF, result.Decision.Owner)
	if result.Decision.Revision == "" {
		result.Decision.Revision = routePolicyRevision(result.Decision)
	}
	result.Decision.OwnershipKey = routePolicyOwnershipKey(result.Decision)
	validateCompiledRouteDecision(&result, config.RadiusRoutePolicyConfig{Enabled: true, MaxRoutes: 256, DefaultVRF: "default", DefaultOwner: "aegisnas", ConflictMode: "warn"})
	if len(result.Diagnostics) > 0 {
		for _, diagnostic := range result.Diagnostics {
			if diagnostic.Severity == "error" {
				result.Status = "blocked"
				break
			}
			if result.Status != "blocked" && diagnostic.Severity == "warning" {
				result.Status = "degraded"
			}
		}
	}
	result.Message = fmt.Sprintf("route policy decompiled %d attribute(s)", len(req.Attributes))
	finalizeRoutePolicyResult(&result)
	return result
}

func BuildRoutePolicyAttributes(decision RoutePolicyDecision, packKeys []string) []RoutePolicyAttribute {
	packKeys = normalizeRoutePolicyPackKeys(packKeys)
	if len(packKeys) == 0 {
		packKeys = []string{productconfigs.VendorPackStandard, productconfigs.VendorPackAegisNAS}
	}
	attrs := make([]RoutePolicyAttribute, 0, len(decision.IPv4Routes)+len(decision.IPv6Routes)+8)
	appendAttr := func(pack, name, value, purpose string, quoted bool) {
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if name == "" || value == "" {
			return
		}
		attrs = append(attrs, RoutePolicyAttribute{PackKey: pack, Name: name, Value: value, Quoted: quoted, Purpose: purpose})
	}
	withdraw := decision.Withdraw || decision.LifecycleAction == "withdraw" || decision.LifecycleAction == "accounting-stop"
	for _, pack := range packKeys {
		switch pack {
		case productconfigs.VendorPackStandard:
			if withdraw {
				continue
			}
			for _, route := range decision.IPv4Routes {
				appendAttr(pack, "Framed-Route", formatFramedRouteValue(route), "ipv4_route", true)
			}
			for _, route := range decision.IPv6Routes {
				appendAttr(pack, "Framed-IPv6-Route", formatFramedRouteValue(route), "ipv6_route", true)
			}
		case productconfigs.VendorPackAegisNAS:
			appendAttr(pack, "AegisNAS-Route-Policy", decision.LifecycleAction, "policy", true)
			appendAttr(pack, "AegisNAS-VRF", decision.VRF, "vrf", true)
			appendAttr(pack, "AegisNAS-Route-Owner", decision.Owner, "owner", true)
			appendAttr(pack, "AegisNAS-Route-Revision", firstReplyValue(decision.Revision, routePolicyRevision(decision)), "revision", true)
			if withdraw {
				continue
			}
			for _, route := range decision.IPv4Routes {
				appendAttr(pack, "AegisNAS-Framed-Route", formatFramedRouteValue(route), "ipv4_route", true)
			}
			for _, route := range decision.IPv6Routes {
				appendAttr(pack, "AegisNAS-Framed-IPv6-Route", formatFramedRouteValue(route), "ipv6_route", true)
			}
		case productconfigs.VendorPackCisco:
			appendRouteAVPairAttributes(pack, "Cisco-AVPair", "ip", decision, appendAttr)
		case productconfigs.VendorPackJuniper:
			appendRouteAVPairAttributes(pack, "Juniper-AV-Pair", "junos", decision, appendAttr)
		case productconfigs.VendorPackHuawei:
			appendRouteAVPairAttributes(pack, "Huawei-AVpair", "huawei", decision, appendAttr)
		case productconfigs.VendorPackH3C:
			appendRouteAVPairAttributes(pack, "H3C-Av-Pair", "h3c", decision, appendAttr)
		case productconfigs.VendorPackNokia:
			appendRouteAVPairAttributes(pack, "Nokia-AVPair", "nokia", decision, appendAttr)
		}
	}
	return attrs
}

func ApplyRoutePolicyToReplyAttributes(attrs *ReplyAttributes, result RoutePolicyCompileResult) {
	if attrs == nil || result.Status == "blocked" {
		return
	}
	decision := result.Decision
	attrs.VRF = decision.VRF
	attrs.RouteOwner = decision.Owner
	attrs.RouteRevision = firstReplyValue(decision.Revision, routePolicyRevision(decision))
	attrs.RoutePolicyMode = decision.LifecycleAction
	attrs.RoutePolicyFingerprint = result.Fingerprint
	attrs.FramedRoutes = routeStringsFromRoutes(decision.IPv4Routes)
	attrs.FramedIPv6Routes = routeStringsFromRoutes(decision.IPv6Routes)
}

func ApplyConfiguredRoutePolicyToReplyAttributes(cfg *config.Config, attrs *ReplyAttributes, req RoutePolicyCompileRequest) (RoutePolicyCompileResult, bool) {
	if cfg == nil || attrs == nil || !cfg.Radius.RoutePolicy.Enabled {
		return RoutePolicyCompileResult{}, false
	}
	if strings.TrimSpace(req.Role) == "" {
		req.Role = replyRole(attrs)
	}
	result := CompileRoutePolicy(cfg, req)
	if result.Status == "blocked" || result.Decision.Withdraw {
		return result, false
	}
	if !result.Decision.PolicyMatched && len(req.Routes) == 0 {
		return result, false
	}
	ApplyRoutePolicyToReplyAttributes(attrs, result)
	return result, true
}

func appendConfiguredRoute(result *RoutePolicyCompileResult, raw config.RadiusRouteConfig, family, field, source string) {
	route, diagnostics := routePolicyRouteFromConfig(raw, family, field, source)
	result.Diagnostics = append(result.Diagnostics, diagnostics...)
	if route.Destination == "" {
		return
	}
	if family == "ipv6" {
		result.Decision.IPv6Routes = append(result.Decision.IPv6Routes, route)
		return
	}
	result.Decision.IPv4Routes = append(result.Decision.IPv4Routes, route)
}

func appendRequestRoute(result *RoutePolicyCompileResult, raw RoutePolicyRoute, field, conflictMode string) {
	route, diagnostics := normalizeRoutePolicyRoute(raw, field)
	result.Diagnostics = append(result.Diagnostics, diagnostics...)
	if route.Destination == "" {
		return
	}
	route.Source = firstReplyValue(route.Source, "request")
	if route.Family == "ipv6" {
		result.Decision.IPv6Routes = mergeCompiledRoute(result.Decision.IPv6Routes, route, result, field, conflictMode)
		return
	}
	result.Decision.IPv4Routes = mergeCompiledRoute(result.Decision.IPv4Routes, route, result, field, conflictMode)
}

func routePolicyRouteFromConfig(raw config.RadiusRouteConfig, family, field, source string) (RoutePolicyRoute, []RoutePolicyDiagnostic) {
	return normalizeRoutePolicyRoute(RoutePolicyRoute{
		Family:      family,
		Destination: raw.Destination,
		Gateway:     raw.Gateway,
		Metric:      raw.Metric,
		Preference:  raw.Preference,
		Interface:   raw.Interface,
		Tag:         raw.Tag,
		Owner:       raw.Owner,
		Source:      source,
		Install:     true,
	}, field)
}

func normalizeRoutePolicyRoute(raw RoutePolicyRoute, field string) (RoutePolicyRoute, []RoutePolicyDiagnostic) {
	route := RoutePolicyRoute{
		Family:      strings.ToLower(strings.TrimSpace(raw.Family)),
		Destination: strings.TrimSpace(raw.Destination),
		Gateway:     strings.TrimSpace(raw.Gateway),
		Metric:      nonNegativeRouteInt(raw.Metric),
		Preference:  nonNegativeRouteInt(raw.Preference),
		Interface:   strings.TrimSpace(raw.Interface),
		Tag:         strings.TrimSpace(raw.Tag),
		Owner:       strings.TrimSpace(raw.Owner),
		Source:      strings.TrimSpace(raw.Source),
		Install:     raw.Install,
		Withdraw:    raw.Withdraw,
	}
	if route.Family == "" {
		if strings.Contains(route.Destination, ":") {
			route.Family = "ipv6"
		} else {
			route.Family = "ipv4"
		}
	}
	diagnostics := []RoutePolicyDiagnostic{}
	if route.Family != "ipv4" && route.Family != "ipv6" {
		return RoutePolicyRoute{}, append(diagnostics, RoutePolicyDiagnostic{Severity: "error", Code: "invalid_family", Message: "route family must be ipv4 or ipv6", Field: field, Route: raw.Destination})
	}
	prefix, err := netip.ParsePrefix(route.Destination)
	if err != nil {
		return RoutePolicyRoute{}, append(diagnostics, RoutePolicyDiagnostic{Severity: "error", Code: "invalid_destination", Message: err.Error(), Field: field + ".destination", Route: raw.Destination})
	}
	prefix = prefix.Masked()
	if route.Family == "ipv4" && !prefix.Addr().Is4() {
		return RoutePolicyRoute{}, append(diagnostics, RoutePolicyDiagnostic{Severity: "error", Code: "family_mismatch", Message: "route destination must be IPv4", Field: field + ".destination", Route: raw.Destination})
	}
	if route.Family == "ipv6" && !prefix.Addr().Is6() {
		return RoutePolicyRoute{}, append(diagnostics, RoutePolicyDiagnostic{Severity: "error", Code: "family_mismatch", Message: "route destination must be IPv6", Field: field + ".destination", Route: raw.Destination})
	}
	route.Destination = prefix.String()
	if route.Gateway != "" {
		addr, err := netip.ParseAddr(route.Gateway)
		if err != nil {
			return RoutePolicyRoute{}, append(diagnostics, RoutePolicyDiagnostic{Severity: "error", Code: "invalid_gateway", Message: err.Error(), Field: field + ".gateway", Route: raw.Gateway})
		}
		if route.Family == "ipv4" && !addr.Is4() {
			return RoutePolicyRoute{}, append(diagnostics, RoutePolicyDiagnostic{Severity: "error", Code: "gateway_family_mismatch", Message: "gateway must be IPv4", Field: field + ".gateway", Route: raw.Gateway})
		}
		if route.Family == "ipv6" && !addr.Is6() {
			return RoutePolicyRoute{}, append(diagnostics, RoutePolicyDiagnostic{Severity: "error", Code: "gateway_family_mismatch", Message: "gateway must be IPv6", Field: field + ".gateway", Route: raw.Gateway})
		}
		route.Gateway = addr.String()
	}
	return route, diagnostics
}

func mergeCompiledRoute(existing []RoutePolicyRoute, candidate RoutePolicyRoute, result *RoutePolicyCompileResult, field, conflictMode string) []RoutePolicyRoute {
	for index, route := range existing {
		if route.Family != candidate.Family || route.Destination != candidate.Destination {
			continue
		}
		if sameRoutePolicyRoute(route, candidate) {
			result.Diagnostics = append(result.Diagnostics, RoutePolicyDiagnostic{Severity: "warning", Code: "duplicate_route", Message: "duplicate route was ignored", Field: field, Route: candidate.Destination})
			return existing
		}
		switch conflictMode {
		case "prefer-request":
			result.Diagnostics = append(result.Diagnostics, RoutePolicyDiagnostic{Severity: "warning", Code: "route_conflict_replaced", Message: "request route replaced an earlier conflicting route", Field: field, Route: candidate.Destination})
			existing[index] = candidate
			return existing
		case "prefer-role":
			result.Diagnostics = append(result.Diagnostics, RoutePolicyDiagnostic{Severity: "warning", Code: "route_conflict_ignored", Message: "request route conflicted with role route and was ignored", Field: field, Route: candidate.Destination})
			return existing
		case "warn":
			result.Diagnostics = append(result.Diagnostics, RoutePolicyDiagnostic{Severity: "warning", Code: "route_conflict", Message: "route destination has conflicting next-hop metadata", Field: field, Route: candidate.Destination})
			return append(existing, candidate)
		default:
			result.Diagnostics = append(result.Diagnostics, RoutePolicyDiagnostic{Severity: "error", Code: "route_conflict", Message: "route destination has conflicting next-hop metadata", Field: field, Route: candidate.Destination})
			return existing
		}
	}
	return append(existing, candidate)
}

func normalizeCompiledRoutes(routes []RoutePolicyRoute, vrf, owner string) []RoutePolicyRoute {
	out := make([]RoutePolicyRoute, 0, len(routes))
	seen := map[string]struct{}{}
	for _, route := range routes {
		normalized, diagnostics := normalizeRoutePolicyRoute(route, "route")
		if len(diagnostics) > 0 || normalized.Destination == "" {
			continue
		}
		normalized.Owner = firstReplyValue(normalized.Owner, owner)
		normalized.Source = firstReplyValue(normalized.Source, "policy")
		normalized.Install = true
		key := normalized.Family + "\x00" + normalized.Destination + "\x00" + normalized.Gateway + "\x00" + strconv.Itoa(normalized.Metric)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, normalized)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Family != out[j].Family {
			return out[i].Family < out[j].Family
		}
		return out[i].Destination < out[j].Destination
	})
	_ = vrf
	return out
}

func applyRoutePolicyLifecycle(result *RoutePolicyCompileResult, policy config.RadiusRoutePolicyConfig) {
	if result == nil {
		return
	}
	switch result.Decision.LifecycleAction {
	case "withdraw", "accounting-stop":
		if result.Decision.LifecycleAction == "accounting-stop" && !policy.StopWithdrawal {
			result.Diagnostics = append(result.Diagnostics, RoutePolicyDiagnostic{Severity: "warning", Code: "stop_withdrawal_disabled", Message: "accounting Stop route withdrawal is disabled by policy"})
			return
		}
		result.Decision.Withdraw = true
		for i := range result.Decision.IPv4Routes {
			result.Decision.IPv4Routes[i].Withdraw = true
		}
		for i := range result.Decision.IPv6Routes {
			result.Decision.IPv6Routes[i].Withdraw = true
		}
	}
}

func validateCompiledRouteDecision(result *RoutePolicyCompileResult, policy config.RadiusRoutePolicyConfig) {
	if result == nil {
		return
	}
	addError := func(code, message, field, route string) {
		result.Diagnostics = append(result.Diagnostics, RoutePolicyDiagnostic{Severity: "error", Code: code, Message: message, Field: field, Route: route, VRF: result.Decision.VRF})
	}
	if strings.TrimSpace(result.Decision.VRF) == "" {
		addError("missing_vrf", "route policy did not resolve a VRF", "vrf", "")
	}
	if strings.TrimSpace(result.Decision.Owner) == "" {
		addError("missing_owner", "route policy did not resolve an owner", "owner", "")
	}
	total := len(result.Decision.IPv4Routes) + len(result.Decision.IPv6Routes)
	maxRoutes := effectiveRoutePolicyMaxRoutes(policy)
	if total > maxRoutes {
		addError("too_many_routes", fmt.Sprintf("route count exceeds limit %d", maxRoutes), "routes", "")
	}
	if total == 0 && result.Decision.PolicyMatched && policy.FailClosed {
		addError("missing_route", "matched route policy has no routes and fail_closed is enabled", "routes", "")
	}
	seen := map[string]RoutePolicyRoute{}
	for _, route := range append(append([]RoutePolicyRoute{}, result.Decision.IPv4Routes...), result.Decision.IPv6Routes...) {
		normalized, diagnostics := normalizeRoutePolicyRoute(route, "routes")
		for _, diagnostic := range diagnostics {
			result.Diagnostics = append(result.Diagnostics, diagnostic)
		}
		if normalized.Destination == "" {
			continue
		}
		key := normalized.Family + "\x00" + strings.ToLower(result.Decision.VRF) + "\x00" + normalized.Destination
		if previous, exists := seen[key]; exists && !sameRoutePolicyRoute(previous, normalized) {
			addError("route_conflict", "route destination has conflicting metadata in the same VRF", "routes", normalized.Destination)
		}
		seen[key] = normalized
	}
}

func finalizeRoutePolicyResult(result *RoutePolicyCompileResult) {
	if result == nil {
		return
	}
	if result.Status == "ready" && len(result.Diagnostics) > 0 {
		for _, diagnostic := range result.Diagnostics {
			if diagnostic.Severity == "error" {
				result.Status = "blocked"
				break
			}
			if diagnostic.Severity == "warning" {
				result.Status = "degraded"
			}
		}
	}
	if result.Status == "ready" {
		result.Status = "compiled"
	}
	result.Summary.IPv4RouteCount = len(result.Decision.IPv4Routes)
	result.Summary.IPv6RouteCount = len(result.Decision.IPv6Routes)
	result.Summary.RouteCount = result.Summary.IPv4RouteCount + result.Summary.IPv6RouteCount
	if result.Decision.Withdraw {
		result.Summary.WithdrawCount = result.Summary.RouteCount
	}
	result.Summary.AttributeCount = len(result.Attributes)
	result.Summary.DiagnosticCount = len(result.Diagnostics)
	if strings.TrimSpace(result.Message) == "" {
		result.Message = fmt.Sprintf("route policy compiled %d route(s) for role %s in VRF %s", result.Summary.RouteCount, firstReplyValue(result.Decision.Role, "default"), firstReplyValue(result.Decision.VRF, "default"))
	}
	payload := struct {
		Version    int                    `json:"version"`
		Status     string                 `json:"status"`
		Decision   RoutePolicyDecision    `json:"decision"`
		Attributes []RoutePolicyAttribute `json:"attributes"`
	}{
		Version:    result.CompilerVersion,
		Status:     result.Status,
		Decision:   result.Decision,
		Attributes: result.Attributes,
	}
	result.Fingerprint = "sha256:" + sha256RoutePolicyJSON(payload)
}

func parseFramedRouteValue(value, family, field string) (RoutePolicyRoute, []RoutePolicyDiagnostic) {
	value = strings.TrimSpace(strings.Trim(value, `"`))
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return RoutePolicyRoute{}, []RoutePolicyDiagnostic{{Severity: "warning", Code: "empty_route", Message: "empty framed route was ignored", Field: field}}
	}
	route := RoutePolicyRoute{Family: family, Destination: fields[0], Install: true}
	if len(fields) > 1 && routePolicyLooksLikeAddress(fields[1]) {
		route.Gateway = fields[1]
	}
	if len(fields) > 2 {
		if metric, err := strconv.Atoi(fields[2]); err == nil && metric >= 0 {
			route.Metric = metric
		}
	}
	return normalizeRoutePolicyRoute(route, field)
}

func decompileVendorRouteAVPair(result *RoutePolicyCompileResult, value, field string) {
	normalized := strings.TrimSpace(strings.Trim(value, `"`))
	lower := strings.ToLower(normalized)
	switch {
	case strings.HasPrefix(lower, "vrf="):
		result.Decision.VRF = strings.TrimSpace(normalized[4:])
	case strings.HasPrefix(lower, "routing-instance="):
		result.Decision.VRF = strings.TrimSpace(normalized[len("routing-instance="):])
	case strings.HasPrefix(lower, "route-owner="):
		result.Decision.Owner = strings.TrimSpace(normalized[len("route-owner="):])
	case strings.HasPrefix(lower, "framed-route="), strings.HasPrefix(lower, "ip:route="):
		raw := normalized[strings.Index(normalized, "=")+1:]
		route, diagnostics := parseFramedRouteValue(raw, "ipv4", field)
		result.Diagnostics = append(result.Diagnostics, diagnostics...)
		if route.Destination != "" {
			route.Source = "decompile"
			result.Decision.IPv4Routes = append(result.Decision.IPv4Routes, route)
		}
	case strings.HasPrefix(lower, "framed-ipv6-route="), strings.HasPrefix(lower, "ipv6:route="):
		raw := normalized[strings.Index(normalized, "=")+1:]
		route, diagnostics := parseFramedRouteValue(raw, "ipv6", field)
		result.Diagnostics = append(result.Diagnostics, diagnostics...)
		if route.Destination != "" {
			route.Source = "decompile"
			result.Decision.IPv6Routes = append(result.Decision.IPv6Routes, route)
		}
	}
}

func appendRouteAVPairAttributes(pack, attrName, namespace string, decision RoutePolicyDecision, appendAttr func(string, string, string, string, bool)) {
	appendAttr(pack, attrName, "vrf="+decision.VRF, "vrf", true)
	appendAttr(pack, attrName, "route-owner="+decision.Owner, "owner", true)
	appendAttr(pack, attrName, "route-revision="+firstReplyValue(decision.Revision, routePolicyRevision(decision)), "revision", true)
	if decision.Withdraw {
		appendAttr(pack, attrName, "route-policy=withdraw", "policy", true)
		return
	}
	for _, route := range decision.IPv4Routes {
		key := "framed-route"
		if namespace == "ip" {
			key = "ip:route"
		}
		appendAttr(pack, attrName, key+"="+formatFramedRouteValue(route), "ipv4_route", true)
	}
	for _, route := range decision.IPv6Routes {
		key := "framed-ipv6-route"
		if namespace == "ip" {
			key = "ipv6:route"
		}
		appendAttr(pack, attrName, key+"="+formatFramedRouteValue(route), "ipv6_route", true)
	}
}

func formatFramedRouteValue(route RoutePolicyRoute) string {
	parts := []string{strings.TrimSpace(route.Destination)}
	if strings.TrimSpace(route.Gateway) != "" {
		parts = append(parts, strings.TrimSpace(route.Gateway))
	}
	metric := firstPositiveInt(route.Metric, route.Preference)
	if metric > 0 {
		if len(parts) == 1 {
			if route.Family == "ipv6" {
				parts = append(parts, "::")
			} else {
				parts = append(parts, "0.0.0.0")
			}
		}
		parts = append(parts, strconv.Itoa(metric))
	}
	return strings.Join(parts, " ")
}

func routeStringsFromRoutes(routes []RoutePolicyRoute) []string {
	out := make([]string, 0, len(routes))
	for _, route := range routes {
		if route.Destination == "" || route.Withdraw {
			continue
		}
		out = append(out, formatFramedRouteValue(route))
	}
	return out
}

func routePolicyForRole(policies []config.RadiusRouteRolePolicy, role string) (config.RadiusRouteRolePolicy, bool) {
	for _, policy := range policies {
		if strings.EqualFold(strings.TrimSpace(policy.Role), strings.TrimSpace(role)) {
			return policy, true
		}
	}
	return config.RadiusRouteRolePolicy{}, false
}

func effectiveRoutePolicyMaxRoutes(policy config.RadiusRoutePolicyConfig) int {
	if policy.MaxRoutes <= 0 {
		return 32
	}
	return policy.MaxRoutes
}

func effectiveRoutePolicyVRF(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "default"
	}
	return value
}

func effectiveRoutePolicyOwner(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "aegisnas"
	}
	return value
}

func effectiveRoutePolicyConflictMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "prefer-role", "prefer-request", "warn":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "block"
	}
}

func normalizeRoutePolicyLifecycleAction(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "coa-update", "reauth", "withdraw", "accounting-stop":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "authorize"
	}
}

func effectiveRoutePolicyPackKeys(requested, rolePacks, configured []string) []string {
	if len(requested) > 0 {
		return normalizeRoutePolicyPackKeys(requested)
	}
	if len(rolePacks) > 0 {
		return normalizeRoutePolicyPackKeys(rolePacks)
	}
	if len(configured) > 0 {
		return normalizeRoutePolicyPackKeys(configured)
	}
	return []string{productconfigs.VendorPackStandard, productconfigs.VendorPackAegisNAS}
}

func normalizeRoutePolicyPackKeys(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		key := productconfigs.NormalizeVendorCompatibilityPackKey(value)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	return out
}

func routePolicySelectionKey(req RoutePolicyCompileRequest, role string) string {
	return firstReplyValue(strings.TrimSpace(req.SessionID), strings.TrimSpace(req.AcctSessionID), strings.TrimSpace(req.CallingStationID), strings.TrimSpace(req.NASIdentifier), role)
}

func routePolicyRevision(decision RoutePolicyDecision) string {
	payload := struct {
		Role       string             `json:"role"`
		VRF        string             `json:"vrf"`
		Owner      string             `json:"owner"`
		Action     string             `json:"action"`
		IPv4Routes []RoutePolicyRoute `json:"ipv4_routes,omitempty"`
		IPv6Routes []RoutePolicyRoute `json:"ipv6_routes,omitempty"`
	}{
		Role:       decision.Role,
		VRF:        decision.VRF,
		Owner:      decision.Owner,
		Action:     decision.LifecycleAction,
		IPv4Routes: decision.IPv4Routes,
		IPv6Routes: decision.IPv6Routes,
	}
	sum := sha256RoutePolicyJSON(payload)
	if len(sum) > 16 {
		return sum[:16]
	}
	return sum
}

func routePolicyOwnershipKey(decision RoutePolicyDecision) string {
	key := strings.Join([]string{
		firstReplyValue(decision.SessionID, decision.AcctSessionID, decision.SelectionKey, decision.Role),
		decision.VRF,
		decision.Owner,
		decision.Revision,
	}, "|")
	sum := sha256.Sum256([]byte(key))
	return "route-owner-" + hex.EncodeToString(sum[:12])
}

func routePolicyLooksLikeAddress(value string) bool {
	_, err := netip.ParseAddr(strings.TrimSpace(value))
	return err == nil
}

func sameRoutePolicyRoute(a, b RoutePolicyRoute) bool {
	return a.Family == b.Family &&
		a.Destination == b.Destination &&
		a.Gateway == b.Gateway &&
		firstPositiveInt(a.Metric, a.Preference) == firstPositiveInt(b.Metric, b.Preference) &&
		a.Interface == b.Interface &&
		a.Tag == b.Tag
}

func nonNegativeRouteInt(value int) int {
	if value < 0 {
		return 0
	}
	return value
}

func routePolicyRFCs() []string {
	return []string{"RFC 2865", "RFC 3162", "RFC 5176", "RFC 6911"}
}

func sha256RoutePolicyJSON(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		encoded = []byte(fmt.Sprint(value))
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
