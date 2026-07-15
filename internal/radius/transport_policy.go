package radius

import (
	"fmt"
	"sort"
	"strings"

	"github.com/yourorg/aegisnas-pi4/internal/config"
)

const TransportPolicySchemaVersion = 1

type TransportPolicy struct {
	SchemaVersion            int                    `json:"schema_version"`
	Enabled                  bool                   `json:"enabled"`
	Mode                     string                 `json:"mode"`
	FailClosed               bool                   `json:"fail_closed"`
	DefaultRequiredTransport string                 `json:"default_required_transport"`
	AllowMixedTransports     bool                   `json:"allow_mixed_transports"`
	RoutePolicies            []TransportRoutePolicy `json:"route_policies"`
}

type TransportRoutePolicy struct {
	Route                string `json:"route"`
	RequiredTransport    string `json:"required_transport"`
	AllowMixedTransports bool   `json:"allow_mixed_transports"`
	Description          string `json:"description,omitempty"`
	Implicit             bool   `json:"implicit"`
}

type TransportPolicyReport struct {
	SchemaVersion int                    `json:"schema_version"`
	Enabled       bool                   `json:"enabled"`
	Status        string                 `json:"status"`
	Message       string                 `json:"message"`
	Policy        TransportPolicy        `json:"policy"`
	Summary       TransportPolicySummary `json:"summary"`
	Routes        []TransportRouteReport `json:"routes"`
	RFCs          []string               `json:"rfcs"`
	Warnings      []string               `json:"warnings,omitempty"`
}

type TransportPolicySummary struct {
	RouteCount               int `json:"route_count"`
	ExplicitRoutePolicyCount int `json:"explicit_route_policy_count"`
	RadSecRequiredRoutes     int `json:"radsec_required_routes"`
	UDPRequiredRoutes        int `json:"udp_required_routes"`
	AnyTransportRoutes       int `json:"any_transport_routes"`
	MixedTransportRoutes     int `json:"mixed_transport_routes"`
	ViolationCount           int `json:"violation_count"`
	UDPServerCount           int `json:"udp_server_count"`
	RadSecServerCount        int `json:"radsec_server_count"`
}

type TransportRouteReport struct {
	Name                   string   `json:"name"`
	Realm                  string   `json:"realm"`
	ServerNames            []string `json:"server_names"`
	ObservedTransports     []string `json:"observed_transports"`
	RequiredTransport      string   `json:"required_transport"`
	AllowMixedTransports   bool     `json:"allow_mixed_transports"`
	ExplicitPolicy         bool     `json:"explicit_policy"`
	Status                 string   `json:"status"`
	Message                string   `json:"message"`
	DowngradeRisk          bool     `json:"downgrade_risk"`
	ViolatingServerNames   []string `json:"violating_server_names,omitempty"`
	ViolatingTransportList []string `json:"violating_transports,omitempty"`
	Warnings               []string `json:"warnings,omitempty"`
}

func DefaultTransportPolicy() TransportPolicy {
	return TransportPolicy{
		SchemaVersion:            TransportPolicySchemaVersion,
		Enabled:                  true,
		Mode:                     "monitor",
		FailClosed:               true,
		DefaultRequiredTransport: "any",
		AllowMixedTransports:     false,
	}
}

func TransportPolicyFromConfig(cfg *config.Config) (TransportPolicy, error) {
	policy := DefaultTransportPolicy()
	if cfg == nil {
		return policy, nil
	}
	raw := cfg.Radius.Upstream.TransportPolicy
	rawEmpty := !raw.Enabled && strings.TrimSpace(raw.Mode) == "" && !raw.FailClosed &&
		strings.TrimSpace(raw.DefaultRequiredTransport) == "" && !raw.AllowMixedTransports &&
		len(raw.RoutePolicies) == 0
	if !rawEmpty {
		policy.Enabled = raw.Enabled
		policy.Mode = strings.ToLower(defaultString(raw.Mode, "monitor"))
		policy.FailClosed = raw.FailClosed
		policy.DefaultRequiredTransport = strings.ToLower(defaultString(raw.DefaultRequiredTransport, "any"))
		policy.AllowMixedTransports = raw.AllowMixedTransports
	}
	routePolicies := make([]TransportRoutePolicy, 0, len(raw.RoutePolicies))
	for _, rawRoutePolicy := range raw.RoutePolicies {
		routePolicies = append(routePolicies, TransportRoutePolicy{
			Route:                strings.TrimSpace(rawRoutePolicy.Route),
			RequiredTransport:    strings.ToLower(defaultString(rawRoutePolicy.RequiredTransport, policy.DefaultRequiredTransport)),
			AllowMixedTransports: rawRoutePolicy.AllowMixedTransports,
			Description:          strings.TrimSpace(rawRoutePolicy.Description),
		})
	}
	policy.RoutePolicies = routePolicies
	return policy, policy.Validate()
}

func (p TransportPolicy) Validate() error {
	if p.SchemaVersion == 0 {
		p.SchemaVersion = TransportPolicySchemaVersion
	}
	if p.SchemaVersion != TransportPolicySchemaVersion {
		return fmt.Errorf("transport policy schema %d is unsupported", p.SchemaVersion)
	}
	p.Mode = strings.ToLower(defaultString(p.Mode, "monitor"))
	switch p.Mode {
	case "monitor", "enforce":
	default:
		return fmt.Errorf("transport policy mode must be monitor or enforce")
	}
	p.DefaultRequiredTransport = normalizeRequiredTransport(p.DefaultRequiredTransport)
	if !validRequiredTransport(p.DefaultRequiredTransport) {
		return fmt.Errorf("transport policy default required transport must be any, udp, or radsec")
	}
	seen := map[string]struct{}{}
	for _, route := range p.RoutePolicies {
		if strings.TrimSpace(route.Route) == "" {
			return fmt.Errorf("transport policy route cannot be empty")
		}
		key := strings.ToLower(strings.TrimSpace(route.Route))
		if _, exists := seen[key]; exists {
			return fmt.Errorf("transport policy route %q is duplicated", route.Route)
		}
		seen[key] = struct{}{}
		required := normalizeRequiredTransport(route.RequiredTransport)
		if !validRequiredTransport(required) {
			return fmt.Errorf("transport policy route %q required transport must be any, udp, or radsec", route.Route)
		}
	}
	return nil
}

func BuildTransportPolicyReport(cfg *config.Config) TransportPolicyReport {
	policy, err := TransportPolicyFromConfig(cfg)
	report := TransportPolicyReport{
		SchemaVersion: TransportPolicySchemaVersion,
		Enabled:       policy.Enabled,
		Status:        "disabled",
		Message:       "Upstream AAA proxying is disabled; transport downgrade policy is idle.",
		Policy:        policy,
		RFCs:          []string{"RFC 2865", "RFC 2866", "RFC 6614"},
	}
	if cfg == nil {
		report.Status = "blocked"
		report.Message = "Configuration is not loaded."
		report.Warnings = append(report.Warnings, report.Message)
		return report
	}
	if err != nil {
		report.Status = "blocked"
		report.Message = err.Error()
		report.Warnings = append(report.Warnings, err.Error())
		return report
	}
	for _, server := range cfg.Radius.Upstream.Servers {
		switch normalizedUpstreamTransport(server.Transport) {
		case "radsec":
			report.Summary.RadSecServerCount++
		default:
			report.Summary.UDPServerCount++
		}
	}
	if !cfg.Radius.Upstream.Enabled {
		report.Policy.RoutePolicies = sortedTransportRoutePolicies(report.Policy.RoutePolicies)
		return report
	}
	if !policy.Enabled {
		report.Message = "Upstream AAA proxying is enabled but transport downgrade policy is disabled."
		report.Warnings = append(report.Warnings, "Enable radius.upstream.transport_policy before production proxy operation.")
		report.Policy.RoutePolicies = sortedTransportRoutePolicies(report.Policy.RoutePolicies)
		return report
	}

	routes, routeErr := EffectiveProxyRoutes(cfg)
	if routeErr != nil {
		report.Status = "blocked"
		report.Message = routeErr.Error()
		report.Warnings = append(report.Warnings, routeErr.Error())
		report.Policy.RoutePolicies = sortedTransportRoutePolicies(report.Policy.RoutePolicies)
		return report
	}
	policiesByRoute := map[string]TransportRoutePolicy{}
	for _, routePolicy := range policy.RoutePolicies {
		policiesByRoute[strings.ToLower(strings.TrimSpace(routePolicy.Route))] = routePolicy
	}
	report.Summary.ExplicitRoutePolicyCount = len(policy.RoutePolicies)
	for _, route := range routes {
		routePolicy, explicit := policiesByRoute[strings.ToLower(route.Name)]
		if !explicit {
			routePolicy = TransportRoutePolicy{
				Route:                route.Name,
				RequiredTransport:    policy.DefaultRequiredTransport,
				AllowMixedTransports: policy.AllowMixedTransports,
				Implicit:             true,
			}
		}
		routeReport := evaluateTransportRoute(route, routePolicy)
		report.Routes = append(report.Routes, routeReport)
		report.Summary.RouteCount++
		switch routeReport.RequiredTransport {
		case "radsec":
			report.Summary.RadSecRequiredRoutes++
		case "udp":
			report.Summary.UDPRequiredRoutes++
		default:
			report.Summary.AnyTransportRoutes++
		}
		if len(routeReport.ObservedTransports) > 1 {
			report.Summary.MixedTransportRoutes++
		}
		if routeReport.Status != "ready" {
			report.Summary.ViolationCount++
			report.Warnings = append(report.Warnings, routeReport.Name+": "+routeReport.Message)
		}
	}
	sort.Slice(report.Routes, func(i, j int) bool { return report.Routes[i].Name < report.Routes[j].Name })
	report.Policy.RoutePolicies = sortedTransportRoutePolicies(report.Policy.RoutePolicies)

	switch {
	case report.Summary.ViolationCount == 0:
		report.Status = "ready"
		report.Message = fmt.Sprintf("Transport downgrade policy is %s for %d proxy route(s).", policy.Mode, report.Summary.RouteCount)
	case policy.Mode == "enforce" && policy.FailClosed:
		report.Status = "blocked"
		report.Message = fmt.Sprintf("Transport downgrade policy blocks %d proxy route(s).", report.Summary.ViolationCount)
	default:
		report.Status = "degraded"
		report.Message = fmt.Sprintf("Transport downgrade policy found %d route risk(s) in %s mode.", report.Summary.ViolationCount, policy.Mode)
	}
	if policy.Mode == "enforce" && !policy.FailClosed {
		if report.Status == "ready" {
			report.Status = "degraded"
			report.Message = "Transport downgrade policy is enforce mode but fail_closed is disabled."
		}
		report.Warnings = append(report.Warnings, "Transport policy fail_closed is disabled.")
	}
	return report
}

func evaluateTransportRoute(route EffectiveProxyRoute, policy TransportRoutePolicy) TransportRouteReport {
	required := normalizeRequiredTransport(policy.RequiredTransport)
	if required == "" {
		required = "any"
	}
	report := TransportRouteReport{
		Name:                 route.Name,
		Realm:                route.Realm,
		ServerNames:          append([]string(nil), route.ServerNames...),
		RequiredTransport:    required,
		AllowMixedTransports: policy.AllowMixedTransports,
		ExplicitPolicy:       !policy.Implicit,
		Status:               "ready",
		Message:              "Route transport policy is satisfied.",
	}
	transportSet := map[string]struct{}{}
	for _, server := range route.Servers {
		transport := normalizedUpstreamTransport(server.Transport)
		if transport != "radsec" {
			transport = "udp"
		}
		transportSet[transport] = struct{}{}
		if required != "any" && transport != required {
			report.ViolatingServerNames = append(report.ViolatingServerNames, strings.TrimSpace(server.Name))
			report.ViolatingTransportList = append(report.ViolatingTransportList, transport)
		}
	}
	for transport := range transportSet {
		report.ObservedTransports = append(report.ObservedTransports, transport)
	}
	sort.Strings(report.ObservedTransports)
	report.ViolatingServerNames = uniqueStrings(report.ViolatingServerNames)
	report.ViolatingTransportList = uniqueStrings(report.ViolatingTransportList)
	if len(report.ObservedTransports) > 1 && !policy.AllowMixedTransports {
		report.Status = "blocked"
		report.DowngradeRisk = true
		report.Warnings = append(report.Warnings, "route mixes UDP and RadSec home servers without explicit mixed-transport approval")
	}
	if len(report.ViolatingServerNames) > 0 {
		report.Status = "blocked"
		report.Warnings = append(report.Warnings, fmt.Sprintf("route requires %s but includes %s transport server(s)", required, strings.Join(report.ViolatingTransportList, ", ")))
	}
	if len(report.Warnings) > 0 {
		report.Message = strings.Join(report.Warnings, "; ")
	}
	return report
}

func normalizeRequiredTransport(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "any"
	}
	return value
}

func validRequiredTransport(value string) bool {
	switch normalizeRequiredTransport(value) {
	case "any", "udp", "radsec":
		return true
	default:
		return false
	}
}

func sortedTransportRoutePolicies(routePolicies []TransportRoutePolicy) []TransportRoutePolicy {
	out := append([]TransportRoutePolicy(nil), routePolicies...)
	sort.Slice(out, func(i, j int) bool { return out[i].Route < out[j].Route })
	return out
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
