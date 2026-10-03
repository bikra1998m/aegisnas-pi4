package config

import (
	"errors"
	"fmt"
	"strings"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
)

type BroadbandL2TPWholesaleConfig struct {
	Enabled                     bool                                `mapstructure:"enabled"`
	Mode                        string                              `mapstructure:"mode"`
	FailClosed                  bool                                `mapstructure:"fail_closed"`
	RequirePPPoE                bool                                `mapstructure:"require_pppoe"`
	RequireSubscriberState      bool                                `mapstructure:"require_subscriber_state"`
	RequireProxyRoutes          bool                                `mapstructure:"require_proxy_routes"`
	RequireAccountingDelegation bool                                `mapstructure:"require_accounting_delegation"`
	RequireTunnelFailover       bool                                `mapstructure:"require_tunnel_failover"`
	RealmIsolationRequired      bool                                `mapstructure:"realm_isolation_required"`
	StripCustomerRealm          bool                                `mapstructure:"strip_customer_realm"`
	AccountingDelegationEnabled bool                                `mapstructure:"accounting_delegation_enabled"`
	CoAOnFailover               bool                                `mapstructure:"coa_on_failover"`
	SelectionPolicy             string                              `mapstructure:"selection_policy"`
	DefaultTunnelProfile        string                              `mapstructure:"default_tunnel_profile"`
	EventRetentionLimit         int                                 `mapstructure:"event_retention_limit"`
	Realms                      []BroadbandWholesaleRealmConfig     `mapstructure:"realms"`
	TunnelProfiles              []BroadbandL2TPTunnelProfileConfig  `mapstructure:"tunnel_profiles"`
	FailoverPolicies            []BroadbandL2TPFailoverPolicyConfig `mapstructure:"failover_policies"`
}

type BroadbandWholesaleRealmConfig struct {
	Name              string   `mapstructure:"name"`
	Enabled           bool     `mapstructure:"enabled"`
	Realm             string   `mapstructure:"realm"`
	Tenant            string   `mapstructure:"tenant"`
	Partner           string   `mapstructure:"partner"`
	MatchRealms       []string `mapstructure:"match_realms"`
	AccessMethod      string   `mapstructure:"access_method"`
	TunnelProfile     string   `mapstructure:"tunnel_profile"`
	ProxyRoute        string   `mapstructure:"proxy_route"`
	AccountingRoute   string   `mapstructure:"accounting_route"`
	AddressPool       string   `mapstructure:"address_pool"`
	QoSProfile        string   `mapstructure:"qos_profile"`
	Product           string   `mapstructure:"product"`
	StripRealm        bool     `mapstructure:"strip_realm"`
	RequireAccounting bool     `mapstructure:"require_accounting"`
	VendorPacks       []string `mapstructure:"vendor_packs"`
}

type BroadbandL2TPTunnelProfileConfig struct {
	Name                 string   `mapstructure:"name"`
	Enabled              bool     `mapstructure:"enabled"`
	Mode                 string   `mapstructure:"mode"`
	LocalName            string   `mapstructure:"local_name"`
	PeerName             string   `mapstructure:"peer_name"`
	LocalAddress         string   `mapstructure:"local_address"`
	PeerAddress          string   `mapstructure:"peer_address"`
	SecretRef            string   `mapstructure:"secret_ref"`
	SourceInterface      string   `mapstructure:"source_interface"`
	TunnelGroup          string   `mapstructure:"tunnel_group"`
	WindowSize           int      `mapstructure:"window_size"`
	HelloIntervalSeconds int      `mapstructure:"hello_interval_seconds"`
	SessionLimit         int      `mapstructure:"session_limit"`
	RequireEncryption    bool     `mapstructure:"require_encryption"`
	AllowedAuth          []string `mapstructure:"allowed_auth"`
	VendorPacks          []string `mapstructure:"vendor_packs"`
}

type BroadbandL2TPFailoverPolicyConfig struct {
	Name             string   `mapstructure:"name"`
	Enabled          bool     `mapstructure:"enabled"`
	Realm            string   `mapstructure:"realm"`
	PrimaryTunnel    string   `mapstructure:"primary_tunnel"`
	BackupTunnels    []string `mapstructure:"backup_tunnels"`
	Action           string   `mapstructure:"action"`
	HoldDownSeconds  int      `mapstructure:"hold_down_seconds"`
	MaxFailures      int      `mapstructure:"max_failures"`
	AccountingReplay bool     `mapstructure:"accounting_replay"`
	CoAAction        string   `mapstructure:"coa_action"`
}

func EffectiveBroadbandL2TPWholesaleConfig(raw BroadbandL2TPWholesaleConfig) BroadbandL2TPWholesaleConfig {
	l2tp := raw
	l2tp.Mode = EffectiveBroadbandL2TPWholesaleMode(l2tp.Mode)
	l2tp.SelectionPolicy = effectiveBroadbandL2TPSelectionPolicy(l2tp.SelectionPolicy)
	if l2tp.EventRetentionLimit == 0 {
		l2tp.EventRetentionLimit = 10000
	}
	if !raw.RequirePPPoE && !raw.RequireSubscriberState && !raw.RequireProxyRoutes &&
		!raw.RequireAccountingDelegation && !raw.RequireTunnelFailover && !raw.RealmIsolationRequired &&
		!raw.StripCustomerRealm && !raw.AccountingDelegationEnabled && !raw.CoAOnFailover {
		l2tp.RequirePPPoE = true
		l2tp.RequireSubscriberState = true
		l2tp.RequireProxyRoutes = true
		l2tp.RequireAccountingDelegation = true
		l2tp.RequireTunnelFailover = true
		l2tp.RealmIsolationRequired = true
		l2tp.StripCustomerRealm = true
		l2tp.AccountingDelegationEnabled = true
		l2tp.CoAOnFailover = true
	}
	return l2tp
}

func EffectiveBroadbandL2TPWholesaleMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "monitor", "enforce":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "monitor"
	}
}

func effectiveBroadbandL2TPSelectionPolicy(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "explicit", "realm", "tenant", "load_balance", "load-balance", "failover", "fail-over":
		return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(value)), "-", "_")
	default:
		return "realm"
	}
}

func validateBroadbandL2TPWholesaleConfig(raw BroadbandL2TPWholesaleConfig, pppoeRaw BroadbandPPPoEConfig, subscriberRaw BroadbandSubscriberStateConfig, radius RadiusConfig, profile string) error {
	l2tp := EffectiveBroadbandL2TPWholesaleConfig(raw)
	if !l2tp.Enabled && len(l2tp.Realms) == 0 && len(l2tp.TunnelProfiles) == 0 && len(l2tp.FailoverPolicies) == 0 {
		return nil
	}
	if profile == "lite" && l2tp.Mode == "enforce" {
		return errors.New("broadband.l2tp_wholesale cannot use enforce mode on lite deployment profile")
	}
	if l2tp.EventRetentionLimit < 0 || l2tp.EventRetentionLimit > 1000000 {
		return errors.New("broadband.l2tp_wholesale.event_retention_limit must be between 0 and 1000000")
	}
	if effectiveBroadbandL2TPSelectionPolicy(raw.SelectionPolicy) != l2tp.SelectionPolicy {
		return fmt.Errorf("broadband.l2tp_wholesale.selection_policy %q is invalid", raw.SelectionPolicy)
	}
	pppoe := EffectiveBroadbandPPPoEConfig(pppoeRaw)
	subscriber := EffectiveBroadbandSubscriberStateConfig(subscriberRaw)
	if l2tp.Enabled && l2tp.RequirePPPoE && !pppoe.Enabled {
		return errors.New("broadband.l2tp_wholesale requires broadband.pppoe.enabled")
	}
	if l2tp.Enabled && l2tp.RequireSubscriberState && !subscriber.Enabled {
		return errors.New("broadband.l2tp_wholesale requires broadband.subscriber_state.enabled")
	}
	if l2tp.Enabled && l2tp.RequireSubscriberState && !subscriber.WholesaleEnabled {
		return errors.New("broadband.l2tp_wholesale requires broadband.subscriber_state.wholesale_enabled")
	}
	if l2tp.Enabled && l2tp.RequireAccountingDelegation {
		if !radius.SQLAccounting.Enabled || !radius.AccountingServices.Enabled {
			return errors.New("broadband.l2tp_wholesale accounting delegation requires radius.sql_accounting and radius.accounting_services")
		}
	}
	if l2tp.Enabled && l2tp.RequireProxyRoutes && !radius.Upstream.Enabled {
		return errors.New("broadband.l2tp_wholesale proxy route delegation requires radius.upstream.enabled")
	}
	if l2tp.Enabled && l2tp.CoAOnFailover && !radius.DynamicAuth.Enabled {
		return errors.New("broadband.l2tp_wholesale coa_on_failover requires radius.dynamic_auth.enabled")
	}
	tunnels, enabledTunnels, err := validateBroadbandL2TPTunnelProfiles(l2tp)
	if err != nil {
		return err
	}
	routeNames := enabledBroadbandL2TPProxyRoutes(radius.Upstream)
	productNames := broadbandSubscriberProductNames(subscriber)
	enabledRealms, err := validateBroadbandL2TPWholesaleRealms(l2tp, tunnels, routeNames, productNames)
	if err != nil {
		return err
	}
	enabledFailover, err := validateBroadbandL2TPFailoverPolicies(l2tp, tunnels)
	if err != nil {
		return err
	}
	if l2tp.Enabled && l2tp.Mode == "enforce" {
		if enabledTunnels == 0 {
			return errors.New("broadband.l2tp_wholesale enforce mode requires at least one enabled tunnel profile")
		}
		if enabledRealms == 0 {
			return errors.New("broadband.l2tp_wholesale enforce mode requires at least one enabled wholesale realm")
		}
		if l2tp.RequireTunnelFailover && enabledFailover == 0 {
			return errors.New("broadband.l2tp_wholesale require_tunnel_failover requires at least one enabled failover policy")
		}
	}
	return nil
}

func validateBroadbandL2TPTunnelProfiles(l2tp BroadbandL2TPWholesaleConfig) (map[string]struct{}, int, error) {
	seen := map[string]struct{}{}
	enabled := 0
	for i, tunnel := range l2tp.TunnelProfiles {
		name := strings.TrimSpace(tunnel.Name)
		if !validBroadbandPPPoEText(name, 128) {
			return nil, 0, fmt.Errorf("broadband.l2tp_wholesale.tunnel_profiles[%d].name is invalid", i)
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			return nil, 0, fmt.Errorf("broadband.l2tp_wholesale.tunnel_profiles[%d].name %q duplicates an earlier tunnel profile", i, name)
		}
		seen[key] = struct{}{}
		if tunnel.Enabled {
			enabled++
		}
		switch strings.ToLower(strings.TrimSpace(tunnel.Mode)) {
		case "", "lac", "lns", "lac_lns", "both":
		default:
			return nil, 0, fmt.Errorf("broadband.l2tp_wholesale.tunnel_profiles[%d].mode %q is invalid", i, tunnel.Mode)
		}
		if strings.TrimSpace(tunnel.PeerName) == "" && strings.TrimSpace(tunnel.PeerAddress) == "" {
			return nil, 0, fmt.Errorf("broadband.l2tp_wholesale.tunnel_profiles[%d] requires peer_name or peer_address", i)
		}
		for _, field := range []struct {
			name  string
			value string
			limit int
		}{
			{"local_name", tunnel.LocalName, 253},
			{"peer_name", tunnel.PeerName, 253},
			{"local_address", tunnel.LocalAddress, 128},
			{"peer_address", tunnel.PeerAddress, 128},
			{"source_interface", tunnel.SourceInterface, 64},
			{"tunnel_group", tunnel.TunnelGroup, 128},
		} {
			if strings.TrimSpace(field.value) != "" && !validBroadbandPPPoEText(field.value, field.limit) {
				return nil, 0, fmt.Errorf("broadband.l2tp_wholesale.tunnel_profiles[%d].%s is invalid", i, field.name)
			}
		}
		if tunnel.RequireEncryption && strings.TrimSpace(tunnel.SecretRef) == "" {
			return nil, 0, fmt.Errorf("broadband.l2tp_wholesale.tunnel_profiles[%d].secret_ref is required when require_encryption is true", i)
		}
		if tunnel.WindowSize < 0 || tunnel.WindowSize > 65535 {
			return nil, 0, fmt.Errorf("broadband.l2tp_wholesale.tunnel_profiles[%d].window_size must be between 0 and 65535", i)
		}
		if tunnel.HelloIntervalSeconds < 0 || tunnel.HelloIntervalSeconds > 3600 {
			return nil, 0, fmt.Errorf("broadband.l2tp_wholesale.tunnel_profiles[%d].hello_interval_seconds must be between 0 and 3600", i)
		}
		if tunnel.SessionLimit < 0 || tunnel.SessionLimit > 1000000 {
			return nil, 0, fmt.Errorf("broadband.l2tp_wholesale.tunnel_profiles[%d].session_limit must be between 0 and 1000000", i)
		}
		for authIndex, auth := range tunnel.AllowedAuth {
			switch strings.ToLower(strings.TrimSpace(auth)) {
			case "pap", "chap", "mschap", "mschapv2", "eap", "any":
			default:
				return nil, 0, fmt.Errorf("broadband.l2tp_wholesale.tunnel_profiles[%d].allowed_auth[%d] %q is invalid", i, authIndex, auth)
			}
		}
		for packIndex, pack := range tunnel.VendorPacks {
			if productconfigs.NormalizeVendorCompatibilityPackKey(pack) == "" {
				return nil, 0, fmt.Errorf("broadband.l2tp_wholesale.tunnel_profiles[%d].vendor_packs[%d] %q is unknown", i, packIndex, pack)
			}
		}
	}
	return seen, enabled, nil
}

func validateBroadbandL2TPWholesaleRealms(l2tp BroadbandL2TPWholesaleConfig, tunnels, routeNames, productNames map[string]struct{}) (int, error) {
	seen := map[string]struct{}{}
	enabled := 0
	for i, realm := range l2tp.Realms {
		name := strings.TrimSpace(realm.Name)
		if !validBroadbandPPPoEText(name, 128) {
			return 0, fmt.Errorf("broadband.l2tp_wholesale.realms[%d].name is invalid", i)
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			return 0, fmt.Errorf("broadband.l2tp_wholesale.realms[%d].name %q duplicates an earlier realm", i, name)
		}
		seen[key] = struct{}{}
		if realm.Enabled {
			enabled++
		}
		if strings.TrimSpace(realm.Realm) == "" || !validRadiusRealmName(realm.Realm) {
			return 0, fmt.Errorf("broadband.l2tp_wholesale.realms[%d].realm %q is invalid", i, realm.Realm)
		}
		for matchIndex, matchRealm := range realm.MatchRealms {
			if !validRadiusRealmName(matchRealm) {
				return 0, fmt.Errorf("broadband.l2tp_wholesale.realms[%d].match_realms[%d] %q is invalid", i, matchIndex, matchRealm)
			}
		}
		switch strings.ToLower(strings.TrimSpace(realm.AccessMethod)) {
		case "", "pppoe", "ipoe", "dhcp", "l2tp", "any":
		default:
			return 0, fmt.Errorf("broadband.l2tp_wholesale.realms[%d].access_method %q is invalid", i, realm.AccessMethod)
		}
		tunnelName := firstNonEmptyString(strings.TrimSpace(realm.TunnelProfile), strings.TrimSpace(l2tp.DefaultTunnelProfile))
		if tunnelName == "" {
			return 0, fmt.Errorf("broadband.l2tp_wholesale.realms[%d].tunnel_profile is required", i)
		}
		if _, ok := tunnels[strings.ToLower(tunnelName)]; !ok {
			return 0, fmt.Errorf("broadband.l2tp_wholesale.realms[%d].tunnel_profile %q does not match a tunnel profile", i, tunnelName)
		}
		if strings.TrimSpace(realm.ProxyRoute) != "" {
			if _, ok := routeNames[strings.ToLower(strings.TrimSpace(realm.ProxyRoute))]; !ok {
				return 0, fmt.Errorf("broadband.l2tp_wholesale.realms[%d].proxy_route %q is not configured", i, realm.ProxyRoute)
			}
		}
		if strings.TrimSpace(realm.AccountingRoute) != "" {
			if _, ok := routeNames[strings.ToLower(strings.TrimSpace(realm.AccountingRoute))]; !ok {
				return 0, fmt.Errorf("broadband.l2tp_wholesale.realms[%d].accounting_route %q is not configured", i, realm.AccountingRoute)
			}
		}
		if strings.TrimSpace(realm.Product) != "" && len(productNames) > 0 {
			if _, ok := productNames[strings.ToLower(strings.TrimSpace(realm.Product))]; !ok {
				return 0, fmt.Errorf("broadband.l2tp_wholesale.realms[%d].product %q is not configured", i, realm.Product)
			}
		}
		for _, field := range []struct {
			name  string
			value string
			limit int
		}{
			{"tenant", realm.Tenant, 128},
			{"partner", realm.Partner, 128},
			{"address_pool", realm.AddressPool, 128},
			{"qos_profile", realm.QoSProfile, 128},
			{"product", realm.Product, 128},
		} {
			if strings.TrimSpace(field.value) != "" && !validBroadbandPPPoEText(field.value, field.limit) {
				return 0, fmt.Errorf("broadband.l2tp_wholesale.realms[%d].%s is invalid", i, field.name)
			}
		}
		for packIndex, pack := range realm.VendorPacks {
			if productconfigs.NormalizeVendorCompatibilityPackKey(pack) == "" {
				return 0, fmt.Errorf("broadband.l2tp_wholesale.realms[%d].vendor_packs[%d] %q is unknown", i, packIndex, pack)
			}
		}
	}
	return enabled, nil
}

func validateBroadbandL2TPFailoverPolicies(l2tp BroadbandL2TPWholesaleConfig, tunnels map[string]struct{}) (int, error) {
	seen := map[string]struct{}{}
	enabled := 0
	for i, policy := range l2tp.FailoverPolicies {
		name := strings.TrimSpace(policy.Name)
		if !validBroadbandPPPoEText(name, 128) {
			return 0, fmt.Errorf("broadband.l2tp_wholesale.failover_policies[%d].name is invalid", i)
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			return 0, fmt.Errorf("broadband.l2tp_wholesale.failover_policies[%d].name %q duplicates an earlier failover policy", i, name)
		}
		seen[key] = struct{}{}
		if policy.Enabled {
			enabled++
		}
		if strings.TrimSpace(policy.Realm) != "" && !validRadiusRealmName(policy.Realm) {
			return 0, fmt.Errorf("broadband.l2tp_wholesale.failover_policies[%d].realm %q is invalid", i, policy.Realm)
		}
		if strings.TrimSpace(policy.PrimaryTunnel) == "" {
			return 0, fmt.Errorf("broadband.l2tp_wholesale.failover_policies[%d].primary_tunnel is required", i)
		}
		if _, ok := tunnels[strings.ToLower(strings.TrimSpace(policy.PrimaryTunnel))]; !ok {
			return 0, fmt.Errorf("broadband.l2tp_wholesale.failover_policies[%d].primary_tunnel %q does not match a tunnel profile", i, policy.PrimaryTunnel)
		}
		for backupIndex, backup := range policy.BackupTunnels {
			if _, ok := tunnels[strings.ToLower(strings.TrimSpace(backup))]; !ok {
				return 0, fmt.Errorf("broadband.l2tp_wholesale.failover_policies[%d].backup_tunnels[%d] %q does not match a tunnel profile", i, backupIndex, backup)
			}
		}
		switch strings.ToLower(strings.TrimSpace(policy.Action)) {
		case "", "standby", "reroute", "disconnect", "degrade":
		default:
			return 0, fmt.Errorf("broadband.l2tp_wholesale.failover_policies[%d].action %q is invalid", i, policy.Action)
		}
		if policy.HoldDownSeconds < 0 || policy.HoldDownSeconds > 86400 {
			return 0, fmt.Errorf("broadband.l2tp_wholesale.failover_policies[%d].hold_down_seconds must be between 0 and 86400", i)
		}
		if policy.MaxFailures < 0 || policy.MaxFailures > 1000 {
			return 0, fmt.Errorf("broadband.l2tp_wholesale.failover_policies[%d].max_failures must be between 0 and 1000", i)
		}
		switch strings.ToLower(strings.TrimSpace(policy.CoAAction)) {
		case "", "none", "reauth", "disconnect":
		default:
			return 0, fmt.Errorf("broadband.l2tp_wholesale.failover_policies[%d].coa_action %q is invalid", i, policy.CoAAction)
		}
	}
	return enabled, nil
}

func enabledBroadbandL2TPProxyRoutes(upstream RadiusUpstreamConfig) map[string]struct{} {
	out := map[string]struct{}{}
	for _, route := range upstream.Routes {
		if !route.Enabled {
			continue
		}
		if name := strings.TrimSpace(route.Name); name != "" {
			out[strings.ToLower(name)] = struct{}{}
		}
	}
	return out
}
