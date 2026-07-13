package radius

import (
	"fmt"
	"sort"
	"strings"

	"github.com/yourorg/aegisnas-pi4/internal/config"
)

const ProxyRoutingSchemaVersion = 1

type EffectiveProxyRoute struct {
	Name         string
	Description  string
	Realm        string
	MatchRealms  []string
	Default      bool
	StripRealm   bool
	PoolStrategy string
	StatusCheck  string
	PoolName     string
	ServerNames  []string
	Servers      []config.RadiusHomeServer
}

type ProxyRoutingReport struct {
	SchemaVersion int                      `json:"schema_version"`
	Enabled       bool                     `json:"enabled"`
	Status        string                   `json:"status"`
	Message       string                   `json:"message"`
	Summary       ProxyRoutingSummary      `json:"summary"`
	Routes        []ProxyRouteReport       `json:"routes"`
	Servers       []ProxyRouteServerReport `json:"servers"`
	Warnings      []string                 `json:"warnings,omitempty"`
}

type ProxyRoutingSummary struct {
	RouteCount         int    `json:"route_count"`
	ExplicitRouteCount int    `json:"explicit_route_count"`
	DefaultRouteCount  int    `json:"default_route_count"`
	ServerCount        int    `json:"server_count"`
	RadSecServerCount  int    `json:"radsec_server_count"`
	DefaultRealm       string `json:"default_realm,omitempty"`
}

type ProxyRouteReport struct {
	Name         string   `json:"name"`
	Description  string   `json:"description,omitempty"`
	Realm        string   `json:"realm"`
	MatchRealms  []string `json:"match_realms"`
	Default      bool     `json:"default"`
	StripRealm   bool     `json:"strip_realm"`
	PoolStrategy string   `json:"pool_strategy"`
	StatusCheck  string   `json:"status_check"`
	PoolName     string   `json:"pool_name"`
	ServerNames  []string `json:"server_names"`
}

type ProxyRouteServerReport struct {
	Name      string `json:"name"`
	Address   string `json:"address"`
	AuthPort  int    `json:"auth_port"`
	AcctPort  int    `json:"acct_port"`
	Transport string `json:"transport"`
}

func EffectiveProxyRoutes(cfg *config.Config) ([]EffectiveProxyRoute, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}
	if !cfg.Radius.Upstream.Enabled {
		return nil, nil
	}

	upstream := cfg.Radius.Upstream
	serverByName := make(map[string]config.RadiusHomeServer, len(upstream.Servers))
	for _, server := range upstream.Servers {
		serverByName[strings.TrimSpace(server.Name)] = server
	}

	if len(upstream.Routes) == 0 {
		servers := append([]config.RadiusHomeServer(nil), upstream.Servers...)
		serverNames := make([]string, 0, len(servers))
		for _, server := range servers {
			serverNames = append(serverNames, strings.TrimSpace(server.Name))
		}
		route := EffectiveProxyRoute{
			Name:         "legacy-default",
			Description:  "Legacy single-realm upstream route synthesized from radius.upstream.realm",
			Realm:        strings.TrimSpace(upstream.Realm),
			MatchRealms:  uniqueNonEmptyStrings([]string{upstream.Realm}),
			Default:      true,
			StripRealm:   upstream.StripRealm,
			PoolStrategy: defaultString(upstream.PoolStrategy, "fail-over"),
			StatusCheck:  defaultString(upstream.StatusCheck, "status-server"),
			PoolName:     "aegis_upstream_pool",
			ServerNames:  serverNames,
			Servers:      servers,
		}
		return []EffectiveProxyRoute{route}, nil
	}

	routes := make([]EffectiveProxyRoute, 0, len(upstream.Routes))
	for _, route := range upstream.Routes {
		if !route.Enabled {
			continue
		}
		serverNames := uniqueNonEmptyStrings(route.Servers)
		servers := make([]config.RadiusHomeServer, 0, len(serverNames))
		for _, serverName := range serverNames {
			server, ok := serverByName[serverName]
			if !ok {
				return nil, fmt.Errorf("proxy route %q references unknown upstream server %q", route.Name, serverName)
			}
			servers = append(servers, server)
		}
		realm := strings.TrimSpace(route.Realm)
		matchRealms := uniqueNonEmptyStrings(append([]string{realm}, route.MatchRealms...))
		routes = append(routes, EffectiveProxyRoute{
			Name:         strings.TrimSpace(route.Name),
			Description:  strings.TrimSpace(route.Description),
			Realm:        realm,
			MatchRealms:  matchRealms,
			Default:      route.Default,
			StripRealm:   route.StripRealm,
			PoolStrategy: defaultString(route.PoolStrategy, upstream.PoolStrategy),
			StatusCheck:  defaultString(route.StatusCheck, upstream.StatusCheck),
			PoolName:     "aegis_route_" + freeRADIUSIdentifier(route.Name),
			ServerNames:  serverNames,
			Servers:      servers,
		})
	}
	return routes, nil
}

func BuildProxyRoutingReport(cfg *config.Config) ProxyRoutingReport {
	report := ProxyRoutingReport{
		SchemaVersion: ProxyRoutingSchemaVersion,
		Status:        "disabled",
		Message:       "Upstream AAA proxy routing is disabled.",
	}
	if cfg == nil {
		report.Status = "blocked"
		report.Message = "Configuration is not loaded."
		return report
	}

	report.Enabled = cfg.Radius.Upstream.Enabled
	report.Servers = proxyRouteServerReports(cfg)
	report.Summary.ServerCount = len(report.Servers)
	for _, server := range report.Servers {
		if server.Transport == "radsec" {
			report.Summary.RadSecServerCount++
		}
	}
	if !cfg.Radius.Upstream.Enabled {
		return report
	}

	routes, err := EffectiveProxyRoutes(cfg)
	if err != nil {
		report.Status = "blocked"
		report.Message = err.Error()
		return report
	}
	report.Summary.ExplicitRouteCount = len(cfg.Radius.Upstream.Routes)
	if len(cfg.Radius.Upstream.Routes) == 0 {
		report.Warnings = append(report.Warnings, "Using legacy single-realm upstream settings as a synthesized default proxy route.")
	}
	if len(routes) == 0 {
		report.Status = "blocked"
		report.Message = "Upstream AAA is enabled but no enabled proxy routes are available."
		return report
	}

	for _, route := range routes {
		if route.Default {
			report.Summary.DefaultRouteCount++
			report.Summary.DefaultRealm = route.Realm
		}
		report.Routes = append(report.Routes, ProxyRouteReport{
			Name:         route.Name,
			Description:  route.Description,
			Realm:        route.Realm,
			MatchRealms:  append([]string(nil), route.MatchRealms...),
			Default:      route.Default,
			StripRealm:   route.StripRealm,
			PoolStrategy: route.PoolStrategy,
			StatusCheck:  route.StatusCheck,
			PoolName:     route.PoolName,
			ServerNames:  append([]string(nil), route.ServerNames...),
		})
	}
	report.Summary.RouteCount = len(report.Routes)
	sort.Slice(report.Routes, func(i, j int) bool {
		if report.Routes[i].Default != report.Routes[j].Default {
			return report.Routes[i].Default
		}
		return report.Routes[i].Name < report.Routes[j].Name
	})

	switch {
	case report.Summary.DefaultRouteCount > 1:
		report.Status = "blocked"
		report.Message = "Multiple enabled default proxy routes were found."
	case report.Summary.RouteCount == 0:
		report.Status = "blocked"
		report.Message = "No enabled proxy routes were found."
	case report.Summary.DefaultRouteCount == 0:
		report.Status = "ready"
		report.Message = fmt.Sprintf("%d explicit proxy route(s) are configured; unmatched realms remain local.", report.Summary.RouteCount)
	default:
		report.Status = "ready"
		report.Message = fmt.Sprintf("%d proxy route(s) are configured with default realm %s.", report.Summary.RouteCount, report.Summary.DefaultRealm)
	}
	return report
}

func DefaultProxyRealm(cfg *config.Config) string {
	routes, err := EffectiveProxyRoutes(cfg)
	if err != nil {
		return ""
	}
	for _, route := range routes {
		if route.Default {
			return route.Realm
		}
	}
	return ""
}

func proxyRouteServerReports(cfg *config.Config) []ProxyRouteServerReport {
	if cfg == nil {
		return nil
	}
	servers := make([]ProxyRouteServerReport, 0, len(cfg.Radius.Upstream.Servers))
	for _, server := range cfg.Radius.Upstream.Servers {
		authPort := server.AuthPort
		if authPort == 0 {
			authPort = cfg.Radius.AuthPort
		}
		acctPort := server.AcctPort
		if acctPort == 0 {
			acctPort = cfg.Radius.AcctPort
		}
		transport := normalizedUpstreamTransport(server.Transport)
		if transport == "radsec" {
			authPort = server.RadSec.Port
			acctPort = server.RadSec.Port
		}
		servers = append(servers, ProxyRouteServerReport{
			Name:      strings.TrimSpace(server.Name),
			Address:   strings.TrimSpace(server.Address),
			AuthPort:  authPort,
			AcctPort:  acctPort,
			Transport: transport,
		})
	}
	return servers
}

func defaultString(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value != "" {
		return value
	}
	return strings.TrimSpace(fallback)
}

func uniqueNonEmptyStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
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
	return out
}

func freeRADIUSIdentifier(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "route"
	}
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_' || r == '.':
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		return "route"
	}
	return out
}
