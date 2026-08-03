package radius

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/secrets"
	layehradius "layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

const OutboundDACProxyRoutingSchemaVersion = 1

type OutboundDACProxyRoutingReport struct {
	SchemaVersion int                            `json:"schema_version"`
	Enabled       bool                           `json:"enabled"`
	Status        string                         `json:"status"`
	Message       string                         `json:"message"`
	Summary       OutboundDACProxyRoutingSummary `json:"summary"`
	Routes        []OutboundDACProxyRouteReport  `json:"routes"`
	RFCs          []string                       `json:"rfcs"`
	Warnings      []string                       `json:"warnings,omitempty"`
}

type OutboundDACProxyRoutingSummary struct {
	RouteCount        int `json:"route_count"`
	UDPRouteCount     int `json:"udp_route_count"`
	RadSecRouteCount  int `json:"radsec_route_count"`
	MixedRouteCount   int `json:"mixed_route_count"`
	BlockedRouteCount int `json:"blocked_route_count"`
	WarningRouteCount int `json:"warning_route_count"`
	DefaultRouteCount int `json:"default_route_count"`
	HomeServerCount   int `json:"home_server_count"`
}

type OutboundDACProxyRouteReport struct {
	Name                 string   `json:"name"`
	Realm                string   `json:"realm"`
	MatchRealms          []string `json:"match_realms"`
	Default              bool     `json:"default"`
	PoolStrategy         string   `json:"pool_strategy"`
	StatusCheck          string   `json:"status_check"`
	ServerNames          []string `json:"server_names"`
	DynamicAuthEndpoints []string `json:"dynamic_auth_endpoints"`
	Transports           []string `json:"transports"`
	Status               string   `json:"status"`
	Message              string   `json:"message"`
	Warnings             []string `json:"warnings,omitempty"`
}

func BuildOutboundDACProxyRoutingReport(cfg *config.Config) OutboundDACProxyRoutingReport {
	effective := config.EffectiveDynamicAuthConfig(dynamicAuthConfig(cfg))
	report := OutboundDACProxyRoutingReport{
		SchemaVersion: OutboundDACProxyRoutingSchemaVersion,
		Enabled:       effective.OutboundEnabled && effective.OutboundProxyEnabled,
		Status:        "disabled",
		Message:       "Outbound proxy dynamic authorization routing is disabled.",
		RFCs:          []string{"RFC 2865", "RFC 5176", "RFC 6614", "RFC 9765"},
	}
	if cfg == nil {
		report.Status = "blocked"
		report.Message = "Configuration is not loaded."
		return report
	}
	if !effective.OutboundEnabled || !effective.OutboundProxyEnabled {
		return report
	}
	if !cfg.Radius.Upstream.Enabled {
		report.Status = "blocked"
		report.Message = "Outbound proxy dynamic authorization requires radius.upstream.enabled."
		report.Warnings = append(report.Warnings, report.Message)
		return report
	}
	routes, err := EffectiveProxyRoutes(cfg)
	if err != nil {
		report.Status = "blocked"
		report.Message = err.Error()
		report.Warnings = append(report.Warnings, err.Error())
		return report
	}
	transportReport := BuildTransportPolicyReport(cfg)
	transportByRoute := map[string]TransportRouteReport{}
	for _, route := range transportReport.Routes {
		transportByRoute[strings.ToLower(route.Name)] = route
	}
	for _, route := range routes {
		item := buildOutboundDACProxyRouteReport(cfg, effective, route, transportByRoute[strings.ToLower(route.Name)])
		report.Routes = append(report.Routes, item)
		report.Summary.RouteCount++
		report.Summary.HomeServerCount += len(route.Servers)
		if item.Default {
			report.Summary.DefaultRouteCount++
		}
		if item.Status == "blocked" {
			report.Summary.BlockedRouteCount++
		}
		if len(item.Warnings) > 0 {
			report.Summary.WarningRouteCount++
		}
		hasUDP := containsString(item.Transports, "udp")
		hasRadSec := containsString(item.Transports, "radsec")
		if hasUDP {
			report.Summary.UDPRouteCount++
		}
		if hasRadSec {
			report.Summary.RadSecRouteCount++
		}
		if hasUDP && hasRadSec {
			report.Summary.MixedRouteCount++
		}
	}
	switch {
	case report.Summary.RouteCount == 0:
		report.Status = "blocked"
		report.Message = "No enabled upstream proxy routes are available for outbound dynamic authorization."
	case report.Summary.BlockedRouteCount > 0:
		report.Status = "blocked"
		report.Message = fmt.Sprintf("%d outbound proxy DAC route(s) are blocked by transport or credential policy.", report.Summary.BlockedRouteCount)
	case report.Summary.WarningRouteCount > 0:
		report.Status = "degraded"
		report.Message = fmt.Sprintf("%d outbound proxy DAC route(s) are usable with warnings.", report.Summary.WarningRouteCount)
	default:
		report.Status = "ready"
		report.Message = fmt.Sprintf("%d outbound proxy DAC route(s) are ready.", report.Summary.RouteCount)
	}
	return report
}

func buildOutboundDACProxyRouteReport(cfg *config.Config, policy config.DynamicAuthConfig, route EffectiveProxyRoute, transport TransportRouteReport) OutboundDACProxyRouteReport {
	report := OutboundDACProxyRouteReport{
		Name:         route.Name,
		Realm:        route.Realm,
		MatchRealms:  append([]string(nil), route.MatchRealms...),
		Default:      route.Default,
		PoolStrategy: route.PoolStrategy,
		StatusCheck:  route.StatusCheck,
		ServerNames:  append([]string(nil), route.ServerNames...),
		Status:       "ready",
		Message:      "Route can carry outbound proxy dynamic authorization.",
	}
	transportSet := map[string]struct{}{}
	for _, server := range route.Servers {
		transportName := normalizedUpstreamTransport(server.Transport)
		if transportName != "radsec" {
			transportName = "udp"
		}
		transportSet[transportName] = struct{}{}
		port := outboundDACProxyServerPort(cfg, policy, server, transportName)
		report.DynamicAuthEndpoints = append(report.DynamicAuthEndpoints, net.JoinHostPort(strings.TrimSpace(server.Address), strconv.Itoa(port)))
		if transportName == "udp" && !policy.OutboundProxyAllowUDP {
			report.Status = "blocked"
			report.Warnings = append(report.Warnings, "UDP proxy dynamic authorization is disabled by radius.dynamic_auth.outbound_proxy_allow_udp")
		}
		if transportName == "radsec" {
			if !policy.OutboundProxyAllowRadSec {
				report.Status = "blocked"
				report.Warnings = append(report.Warnings, "RadSec proxy dynamic authorization is disabled by radius.dynamic_auth.outbound_proxy_allow_radsec")
			}
			if server.RadSec.PSK.Enabled {
				report.Status = "blocked"
				report.Warnings = append(report.Warnings, "TLS-PSK RadSec active DAC sending requires FreeRADIUS runtime certification; the Go control path supports X.509 mTLS")
			}
			if strings.EqualFold(strings.TrimSpace(server.RadSec.RadiusV11), "require") {
				report.Status = "blocked"
				report.Warnings = append(report.Warnings, "RADIUS/1.1-required RadSec DAC requires external FreeRADIUS runtime validation")
			}
		}
	}
	for transportName := range transportSet {
		report.Transports = append(report.Transports, transportName)
	}
	report.Transports = uniqueStrings(report.Transports)
	if transport.Status == "blocked" {
		report.Status = "blocked"
		report.Warnings = append(report.Warnings, transport.Message)
	}
	if len(report.Warnings) > 0 {
		report.Message = strings.Join(uniqueStrings(report.Warnings), "; ")
		report.Warnings = uniqueStrings(report.Warnings)
	}
	return report
}

func resolveOutboundDACProxyTarget(ctx context.Context, cfg *config.Config, policy config.DynamicAuthConfig, request OutboundDACRequest) (OutboundDACTarget, string, []string, []string) {
	target := OutboundDACTarget{
		DeliveryMode: outboundDACDeliveryProxy,
		ResolvedFrom: "proxy_route",
		KnownClient:  true,
	}
	warnings := []string{}
	blockers := []string{}
	if cfg == nil {
		return target, "", warnings, []string{"config is required"}
	}
	if !policy.OutboundProxyEnabled {
		return target, "", warnings, []string{"outbound proxy dynamic authorization is disabled"}
	}
	if !cfg.Radius.Upstream.Enabled {
		return target, "", warnings, []string{"radius.upstream.enabled is required for outbound proxy dynamic authorization"}
	}
	routes, err := EffectiveProxyRoutes(cfg)
	if err != nil {
		return target, "", warnings, []string{err.Error()}
	}
	route, routeWarnings, routeBlockers := selectOutboundDACProxyRoute(routes, request)
	warnings = append(warnings, routeWarnings...)
	blockers = append(blockers, routeBlockers...)
	if len(blockers) > 0 {
		return target, "", warnings, blockers
	}
	sourceRealm := firstNonEmptyString(request.SourceRealm, request.OriginatingRealm, request.ProxyRealm, outboundDACRealmFromUserName(request.UserName), route.Realm)
	blockers = append(blockers, validateOutboundDACProxyIncomingState(policy, request.ProxyState)...)
	server, serverWarnings, serverBlockers := selectOutboundDACProxyHomeServer(route, request)
	warnings = append(warnings, serverWarnings...)
	blockers = append(blockers, serverBlockers...)
	transportName := normalizedUpstreamTransport(server.Transport)
	if transportName != "radsec" {
		transportName = "udp"
	}
	port := outboundDACProxyServerPort(cfg, policy, server, transportName)
	target.Address = strings.TrimSpace(server.Address)
	target.Port = port
	target.Transport = transportName
	target.Endpoint = net.JoinHostPort(target.Address, strconv.Itoa(target.Port))
	target.ProxyRoute = route.Name
	target.ProxyRealm = route.Realm
	target.SourceRealm = sourceRealm
	target.ProxyHomeServer = strings.TrimSpace(server.Name)
	target.PoolStrategy = route.PoolStrategy
	target.StatusCheck = route.StatusCheck
	target.NASIdentifier = cfg.Radius.NASIdentifier
	target.RadSecServerName = strings.TrimSpace(server.RadSec.ServerName)
	target.ProxyState = buildOutboundDACProxyState(cfg, policy, route, request, sourceRealm)
	target.ProxyHopCount = len(target.ProxyState)
	target.RadSecMode = "udp"
	if transportName == "radsec" {
		target.RadSecMode = "mtls"
	}
	if target.Address == "" {
		blockers = append(blockers, "selected proxy home server has no address")
	}
	if target.Port < 1 || target.Port > 65535 {
		blockers = append(blockers, "selected proxy home server dynamic authorization port is outside 1..65535")
	}
	blockers = append(blockers, validateOutboundDACProxyState(policy, target.ProxyState)...)
	if transportName == "udp" && !policy.OutboundProxyAllowUDP {
		blockers = append(blockers, "UDP proxy dynamic authorization is disabled by radius.dynamic_auth.outbound_proxy_allow_udp")
	}
	if transportName == "radsec" && !policy.OutboundProxyAllowRadSec {
		blockers = append(blockers, "RadSec proxy dynamic authorization is disabled by radius.dynamic_auth.outbound_proxy_allow_radsec")
	}
	if transportName == "radsec" {
		if server.RadSec.PSK.Enabled {
			blockers = append(blockers, "TLS-PSK RadSec active DAC sending requires FreeRADIUS runtime certification; configure an X.509 mTLS peer for the Go control path")
		}
		if strings.EqualFold(strings.TrimSpace(server.RadSec.RadiusV11), "require") {
			blockers = append(blockers, "RADIUS/1.1-required RadSec DAC requires external FreeRADIUS runtime validation")
		}
		if _, tlsErr := radSecTLSConfigForOutboundDAC(server.RadSec); tlsErr != nil {
			blockers = append(blockers, tlsErr.Error())
		}
	}
	if transportName == "udp" {
		secret := resolveOutboundDACHomeServerSecret(ctx, cfg, server)
		target.SecretReady = secret != ""
		if secret == "" {
			blockers = append(blockers, "selected UDP proxy home server has no shared secret or resolvable secret_ref")
		}
		blockers = append(blockers, enforceOutboundDACTransportPolicy(cfg, route)...)
		return target, secret, warnings, blockers
	}
	target.SecretReady = true
	blockers = append(blockers, enforceOutboundDACTransportPolicy(cfg, route)...)
	return target, radSecSharedSecret, warnings, blockers
}

func selectOutboundDACProxyRoute(routes []EffectiveProxyRoute, request OutboundDACRequest) (EffectiveProxyRoute, []string, []string) {
	routeName := strings.TrimSpace(request.ProxyRoute)
	realm := firstNonEmptyString(request.OriginatingRealm, request.ProxyRealm, outboundDACRealmFromUserName(request.UserName))
	if routeName != "" {
		for _, route := range routes {
			if strings.EqualFold(route.Name, routeName) {
				return route, nil, nil
			}
		}
		return EffectiveProxyRoute{}, nil, []string{fmt.Sprintf("proxy route %q is not configured or enabled", routeName)}
	}
	if realm != "" {
		for _, route := range routes {
			for _, candidate := range route.MatchRealms {
				if strings.EqualFold(candidate, realm) {
					return route, nil, nil
				}
			}
		}
	}
	for _, route := range routes {
		if route.Default {
			warnings := []string{}
			if realm != "" {
				warnings = append(warnings, fmt.Sprintf("realm %s did not match an explicit proxy route; using default route %s", realm, route.Name))
			}
			return route, warnings, nil
		}
	}
	if realm == "" {
		return EffectiveProxyRoute{}, nil, []string{"proxy_route or originating realm is required when no default proxy route exists"}
	}
	return EffectiveProxyRoute{}, nil, []string{fmt.Sprintf("no proxy route matches originating realm %s", realm)}
}

func selectOutboundDACProxyHomeServer(route EffectiveProxyRoute, request OutboundDACRequest) (config.RadiusHomeServer, []string, []string) {
	if len(route.Servers) == 0 {
		return config.RadiusHomeServer{}, nil, []string{fmt.Sprintf("proxy route %s has no home servers", route.Name)}
	}
	if strings.TrimSpace(request.ProxyHomeServer) != "" {
		for _, server := range route.Servers {
			if strings.EqualFold(server.Name, request.ProxyHomeServer) {
				return server, nil, nil
			}
		}
		return config.RadiusHomeServer{}, nil, []string{fmt.Sprintf("proxy home server %q is not part of route %s", request.ProxyHomeServer, route.Name)}
	}
	switch strings.TrimSpace(route.PoolStrategy) {
	case "load-balance", "client-balance", "client-port-balance", "keyed-balance":
		key := firstNonEmptyString(request.IdempotencyKey, request.CorrelationID, request.AcctSessionID, request.SessionID, request.UserName, route.Name)
		sum := sha256.Sum256([]byte(strings.ToLower(key)))
		index := int(binary.BigEndian.Uint32(sum[:4]) % uint32(len(route.Servers)))
		return route.Servers[index], nil, nil
	default:
		return route.Servers[0], nil, nil
	}
}

func outboundDACProxyServerPort(cfg *config.Config, policy config.DynamicAuthConfig, server config.RadiusHomeServer, transportName string) int {
	if transportName == "radsec" {
		return server.RadSec.Port
	}
	if server.DynamicAuthPort > 0 {
		return server.DynamicAuthPort
	}
	if policy.OutboundDefaultPort > 0 {
		return policy.OutboundDefaultPort
	}
	if cfg != nil && cfg.Radius.DynamicAuth.Port > 0 {
		return cfg.Radius.DynamicAuth.Port
	}
	return 3799
}

func enforceOutboundDACTransportPolicy(cfg *config.Config, route EffectiveProxyRoute) []string {
	policy, err := TransportPolicyFromConfig(cfg)
	if err != nil || !policy.Enabled || cfg == nil || !cfg.Radius.Upstream.Enabled {
		if err != nil {
			return []string{err.Error()}
		}
		return nil
	}
	routePolicy := TransportRoutePolicy{
		Route:                route.Name,
		RequiredTransport:    policy.DefaultRequiredTransport,
		AllowMixedTransports: policy.AllowMixedTransports,
		Implicit:             true,
	}
	for _, candidate := range policy.RoutePolicies {
		if strings.EqualFold(candidate.Route, route.Name) {
			routePolicy = candidate
			break
		}
	}
	report := evaluateTransportRoute(route, routePolicy)
	if report.Status == "blocked" && policy.Mode == "enforce" && policy.FailClosed {
		return []string{fmt.Sprintf("transport policy blocks proxy route %s: %s", route.Name, report.Message)}
	}
	return nil
}

func buildOutboundDACProxyState(cfg *config.Config, policy config.DynamicAuthConfig, route EffectiveProxyRoute, request OutboundDACRequest, sourceRealm string) []string {
	state := normalizeOutboundDACProxyState(request.ProxyState)
	loopMarker := outboundDACProxyLoopMarker(policy)
	if policy.OutboundProxyAddLoopMarker {
		marker := sanitizeOutboundDACProxyState(fmt.Sprintf("%s:%s:%s:%s", loopMarker, route.Name, outboundDACQueueOwner(cfg), sourceRealm))
		if marker != "" {
			state = append(state, marker)
		}
	}
	return state
}

func validateOutboundDACProxyState(policy config.DynamicAuthConfig, proxyState []string) []string {
	state := normalizeOutboundDACProxyState(proxyState)
	blockers := []string{}
	if len(state) > policy.OutboundProxyMaxHops {
		blockers = append(blockers, fmt.Sprintf("Proxy-State hop count %d exceeds outbound_proxy_max_hops %d", len(state), policy.OutboundProxyMaxHops))
	}
	for _, item := range state {
		if strings.ContainsAny(item, "\r\n\x00") {
			blockers = append(blockers, "Proxy-State contains invalid control characters")
			break
		}
		if len(item) > 253 {
			blockers = append(blockers, "Proxy-State value exceeds 253 octets")
			break
		}
	}
	return blockers
}

func validateOutboundDACProxyIncomingState(policy config.DynamicAuthConfig, proxyState []string) []string {
	blockers := validateOutboundDACProxyState(policy, proxyState)
	if policy.OutboundProxyRejectLoopMarker {
		marker := strings.ToLower(outboundDACProxyLoopMarker(policy))
		for _, item := range normalizeOutboundDACProxyState(proxyState) {
			if strings.Contains(strings.ToLower(item), marker) {
				blockers = append(blockers, "proxy loop marker detected in supplied Proxy-State")
				break
			}
		}
	}
	return blockers
}

func outboundDACProxyLoopMarker(policy config.DynamicAuthConfig) string {
	if strings.TrimSpace(policy.OutboundProxyLoopMarker) != "" {
		return strings.TrimSpace(policy.OutboundProxyLoopMarker)
	}
	return "aegisnas"
}

func sanitizeOutboundDACProxyState(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Map(func(r rune) rune {
		switch r {
		case '\r', '\n', '\x00':
			return -1
		default:
			return r
		}
	}, value)
	if len(value) > 253 {
		value = value[:253]
	}
	return value
}

func normalizeOutboundDACProxyState(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = sanitizeOutboundDACProxyState(value)
		if value == "" {
			continue
		}
		out = append(out, value)
		if len(out) >= 32 {
			break
		}
	}
	return out
}

func normalizeOutboundDACDeliveryMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case outboundDACDeliveryProxy:
		return outboundDACDeliveryProxy
	default:
		return outboundDACDeliveryDirect
	}
}

func outboundDACRequestDeliveryMode(request OutboundDACRequest) string {
	if strings.EqualFold(request.DeliveryMode, outboundDACDeliveryProxy) {
		return outboundDACDeliveryProxy
	}
	if strings.TrimSpace(request.ProxyRoute) != "" || strings.TrimSpace(request.ProxyRealm) != "" ||
		strings.TrimSpace(request.OriginatingRealm) != "" || strings.TrimSpace(request.ProxyHomeServer) != "" ||
		len(request.ProxyState) > 0 {
		return outboundDACDeliveryProxy
	}
	return outboundDACDeliveryDirect
}

func outboundDACRealmFromUserName(username string) string {
	username = strings.TrimSpace(username)
	at := strings.LastIndex(username, "@")
	if at < 0 || at == len(username)-1 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(username[at+1:]))
}

func resolveOutboundDACHomeServerSecret(ctx context.Context, cfg *config.Config, server config.RadiusHomeServer) string {
	value, err := secrets.ResolveConfiguredSecret(ctx, secrets.NewResolver(secrets.OptionsFromConfig(cfg)), "radius.upstream.servers."+firstNonEmptyString(server.Name, server.Address)+".secret", server.Secret, server.SecretRef)
	if err != nil {
		return ""
	}
	return strings.TrimRight(value, "\r\n")
}

func prepareOutboundDACPacketForTarget(cfg *config.Config, request OutboundDACRequest, target OutboundDACTarget, secret string, maxAttributes int) (*layehradius.Packet, []db.OutboundDACAttribute, ProxyPolicyDecision, OutboundDACVendorDecision, error) {
	vendorDecision := CompileOutboundDACVendorAction(cfg, request, target)
	if len(vendorDecision.Blockers) > 0 {
		return nil, nil, ProxyPolicyDecision{}, vendorDecision, fmt.Errorf("%s", strings.Join(vendorDecision.Blockers, "; "))
	}
	if len(vendorDecision.Attributes) > 0 {
		request.Attributes = append(request.Attributes, vendorDecision.Attributes...)
	}
	packet, attrs, err := buildOutboundDACPacket(request, secret, maxAttributes)
	if err != nil {
		return nil, nil, ProxyPolicyDecision{}, vendorDecision, err
	}
	if target.DeliveryMode != outboundDACDeliveryProxy {
		return packet, attrs, ProxyPolicyDecision{Allowed: true, Decision: "accepted", Reason: "direct_delivery", Route: "", Direction: "direct"}, vendorDecision, nil
	}
	decision := evaluateOutboundDACProxyPolicy(cfg, packet, request, target)
	if !decision.Allowed {
		return nil, nil, decision, vendorDecision, fmt.Errorf("proxy policy rejected outbound dynamic authorization: %s", decision.Reason)
	}
	attrs, err = applyOutboundDACProxyRewrites(packet, attrs, decision.RewriteActions)
	if err != nil {
		return nil, nil, decision, vendorDecision, err
	}
	attrs, err = applyOutboundDACProxyState(packet, attrs, target.ProxyState, maxAttributes)
	if err != nil {
		return nil, nil, decision, vendorDecision, err
	}
	return packet, attrs, decision, vendorDecision, nil
}

func evaluateOutboundDACProxyPolicy(cfg *config.Config, packet *layehradius.Packet, request OutboundDACRequest, target OutboundDACTarget) ProxyPolicyDecision {
	policy, err := ProxyPolicyFromConfig(cfg)
	if err != nil {
		return ProxyPolicyDecision{Allowed: false, Decision: "rejected", Reason: "invalid_proxy_policy", Route: target.ProxyRoute, Direction: "proxy_request", SourceRealm: target.SourceRealm}
	}
	if !policy.Enabled {
		return ProxyPolicyDecision{Allowed: true, Decision: "accepted", Reason: "policy_disabled", Route: target.ProxyRoute, Direction: "proxy_request", SourceRealm: target.SourceRealm}
	}
	return EvaluateProxyPolicy(packet, ProxyPolicyContext{
		Route:       target.ProxyRoute,
		Direction:   "proxy_request",
		SourceRealm: firstNonEmptyString(request.SourceRealm, request.OriginatingRealm, request.ProxyRealm, target.SourceRealm),
		ProxyState:  normalizeOutboundDACProxyState(request.ProxyState),
	}, policy)
}

func applyOutboundDACProxyRewrites(packet *layehradius.Packet, attrs []db.OutboundDACAttribute, actions []ProxyRewriteAction) ([]db.OutboundDACAttribute, error) {
	for _, action := range actions {
		if action.Attribute != "User-Name" || action.After == "" || action.After == action.Before {
			continue
		}
		if err := rfc2865.UserName_SetString(packet, action.After); err != nil {
			return nil, err
		}
		for i := range attrs {
			if strings.EqualFold(attrs[i].Name, "User-Name") {
				attrs[i].Value = action.After
				break
			}
		}
	}
	return attrs, nil
}

func applyOutboundDACProxyState(packet *layehradius.Packet, attrs []db.OutboundDACAttribute, proxyState []string, maxAttributes int) ([]db.OutboundDACAttribute, error) {
	for _, state := range normalizeOutboundDACProxyState(proxyState) {
		if len(attrs)+1 > maxAttributes {
			return nil, fmt.Errorf("outbound DAC attribute count exceeds configured limit %d after Proxy-State routing metadata", maxAttributes)
		}
		if err := rfc2865.ProxyState_AddString(packet, state); err != nil {
			return nil, fmt.Errorf("Proxy-State: %w", err)
		}
		attrs = append(attrs, db.OutboundDACAttribute{Name: "Proxy-State", Value: state})
	}
	return attrs, nil
}

func sendOutboundDACPacketToTarget(ctx context.Context, cfg *config.Config, packet *layehradius.Packet, target OutboundDACTarget, timeout time.Duration, requestWire []byte, requestHash string) outboundDACSendOutcome {
	if target.Transport == "radsec" {
		response, latency, err := sendOutboundDACRadSec(ctx, cfg, packet, target, timeout)
		outcome := outboundDACSendOutcome{Response: response, Latency: latency, Err: err, RequestWire: requestWire, RequestHash: requestHash}
		if response != nil {
			wire, wireErr := response.MarshalBinary()
			if wireErr == nil {
				outcome.ResponseHash = packetWireSHA256(wire)
			}
		}
		return outcome
	}
	return sendOutboundDACPacket(ctx, packet, target.Endpoint, timeout, requestWire, requestHash)
}

func sendOutboundDACRadSec(ctx context.Context, cfg *config.Config, packet *layehradius.Packet, target OutboundDACTarget, timeout time.Duration) (*layehradius.Packet, time.Duration, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	server, ok := outboundDACHomeServerByName(cfg, target.ProxyHomeServer)
	if !ok {
		return nil, 0, fmt.Errorf("RadSec proxy home server %q is not configured", target.ProxyHomeServer)
	}
	if server.RadSec.PSK.Enabled {
		return nil, 0, fmt.Errorf("TLS-PSK RadSec active DAC sending requires FreeRADIUS runtime certification")
	}
	tlsConfig, err := radSecTLSConfigForOutboundDAC(server.RadSec)
	if err != nil {
		return nil, 0, err
	}
	sendCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	dialer := &net.Dialer{Timeout: timeout}
	rawConn, err := dialer.DialContext(sendCtx, "tcp", target.Endpoint)
	if err != nil {
		return nil, time.Since(start), fmt.Errorf("RadSec TCP connection failed: %w", err)
	}
	tlsConn := tls.Client(rawConn, tlsConfig)
	defer tlsConn.Close()
	if deadline, ok := sendCtx.Deadline(); ok {
		_ = tlsConn.SetDeadline(deadline)
	}
	if err := tlsConn.HandshakeContext(sendCtx); err != nil {
		return nil, time.Since(start), fmt.Errorf("RadSec mutual TLS handshake failed: %w", err)
	}
	if server.RadSec.CheckCRL {
		if err := verifyRadSecPeerRevocation(tlsConn.ConnectionState(), server.RadSec.CAFile, server.RadSec.CAPath); err != nil {
			return nil, time.Since(start), fmt.Errorf("RadSec peer revocation check failed: %w", err)
		}
	}
	requestWire, err := packet.Encode()
	if err != nil {
		return nil, time.Since(start), fmt.Errorf("encode RadSec DAC packet: %w", err)
	}
	if _, err := tlsConn.Write(requestWire); err != nil {
		return nil, time.Since(start), fmt.Errorf("write RadSec DAC packet: %w", err)
	}
	header := make([]byte, 20)
	if _, err := io.ReadFull(tlsConn, header); err != nil {
		return nil, time.Since(start), fmt.Errorf("read RadSec DAC response header: %w", err)
	}
	packetLength := int(binary.BigEndian.Uint16(header[2:4]))
	if packetLength < 20 || packetLength > layehradius.MaxPacketLength {
		return nil, time.Since(start), fmt.Errorf("invalid RadSec RADIUS packet length %d", packetLength)
	}
	responseWire := append([]byte(nil), header...)
	if packetLength > 20 {
		body := make([]byte, packetLength-20)
		if _, err := io.ReadFull(tlsConn, body); err != nil {
			return nil, time.Since(start), fmt.Errorf("read RadSec DAC response body: %w", err)
		}
		responseWire = append(responseWire, body...)
	}
	if !layehradius.IsAuthenticResponse(responseWire, requestWire, []byte(radSecSharedSecret)) {
		return nil, time.Since(start), fmt.Errorf("RadSec DAC response authenticator is invalid")
	}
	response, err := layehradius.Parse(responseWire, []byte(radSecSharedSecret))
	if err != nil {
		return nil, time.Since(start), fmt.Errorf("parse RadSec DAC response: %w", err)
	}
	return response, time.Since(start), nil
}

func outboundDACHomeServerByName(cfg *config.Config, name string) (config.RadiusHomeServer, bool) {
	if cfg == nil {
		return config.RadiusHomeServer{}, false
	}
	for _, server := range cfg.Radius.Upstream.Servers {
		if strings.EqualFold(strings.TrimSpace(server.Name), strings.TrimSpace(name)) {
			return server, true
		}
	}
	return config.RadiusHomeServer{}, false
}

func radSecTLSConfigForOutboundDAC(peer config.RadiusRadSecPeerConfig) (*tls.Config, error) {
	if strings.EqualFold(strings.TrimSpace(peer.RadiusV11), "require") {
		return nil, fmt.Errorf("RADIUS/1.1-required RadSec DAC is not supported by the Go control path")
	}
	copy := peer
	if strings.EqualFold(strings.TrimSpace(copy.RadiusV11), "allow") {
		copy.RadiusV11 = "forbid"
	}
	return radSecTLSConfig(copy)
}
