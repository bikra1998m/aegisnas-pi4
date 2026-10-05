package config

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
)

type BroadbandDHCPSecurityConfig struct {
	Enabled                  bool                                   `mapstructure:"enabled"`
	Mode                     string                                 `mapstructure:"mode"`
	FailClosed               bool                                   `mapstructure:"fail_closed"`
	RequireDHCP              bool                                   `mapstructure:"require_dhcp"`
	RequireSubscriberState   bool                                   `mapstructure:"require_subscriber_state"`
	RequireAddressLeases     bool                                   `mapstructure:"require_address_leases"`
	RequireAccounting        bool                                   `mapstructure:"require_accounting"`
	RequireDynamicAuth       bool                                   `mapstructure:"require_dynamic_auth"`
	RelayEnabled             bool                                   `mapstructure:"relay_enabled"`
	SnoopingEnabled          bool                                   `mapstructure:"snooping_enabled"`
	SourceGuardEnabled       bool                                   `mapstructure:"source_guard_enabled"`
	Option82Required         bool                                   `mapstructure:"option82_required"`
	DropUnknownBindings      bool                                   `mapstructure:"drop_unknown_bindings"`
	TrustedUplinkRequired    bool                                   `mapstructure:"trusted_uplink_required"`
	Option82Policy           string                                 `mapstructure:"option82_policy"`
	BindingRetentionSeconds  int                                    `mapstructure:"binding_retention_seconds"`
	ViolationHoldDownSeconds int                                    `mapstructure:"violation_hold_down_seconds"`
	EventRetentionLimit      int                                    `mapstructure:"event_retention_limit"`
	RelayAgents              []BroadbandDHCPRelayAgentConfig        `mapstructure:"relay_agents"`
	Ports                    []BroadbandDHCPSecurityPortConfig      `mapstructure:"ports"`
	Option82Rules            []BroadbandDHCPOption82RuleConfig      `mapstructure:"option82_rules"`
	SourceGuardPolicies      []BroadbandDHCPSourceGuardPolicyConfig `mapstructure:"source_guard_policies"`
	RADIUSCorrelation        []BroadbandDHCPRADIUSCorrelationConfig `mapstructure:"radius_correlation"`
}

type BroadbandDHCPRelayAgentConfig struct {
	Name              string   `mapstructure:"name"`
	Enabled           bool     `mapstructure:"enabled"`
	Interface         string   `mapstructure:"interface"`
	VLAN              int      `mapstructure:"vlan"`
	GatewayAddress    string   `mapstructure:"gateway_address"`
	ServerGroup       string   `mapstructure:"server_group"`
	VRF               string   `mapstructure:"vrf"`
	CircuitIDTemplate string   `mapstructure:"circuit_id_template"`
	RemoteIDTemplate  string   `mapstructure:"remote_id_template"`
	AppendOption82    bool     `mapstructure:"append_option82"`
	ReplaceOption82   bool     `mapstructure:"replace_option82"`
	Trusted           bool     `mapstructure:"trusted"`
	MaxClients        int      `mapstructure:"max_clients"`
	VendorPacks       []string `mapstructure:"vendor_packs"`
}

type BroadbandDHCPSecurityPortConfig struct {
	Name              string   `mapstructure:"name"`
	Enabled           bool     `mapstructure:"enabled"`
	Interface         string   `mapstructure:"interface"`
	VLAN              int      `mapstructure:"vlan"`
	Role              string   `mapstructure:"role"`
	Trusted           bool     `mapstructure:"trusted"`
	CircuitID         string   `mapstructure:"circuit_id"`
	RemoteID          string   `mapstructure:"remote_id"`
	SubscriberProduct string   `mapstructure:"subscriber_product"`
	Tenant            string   `mapstructure:"tenant"`
	MaxLeases         int      `mapstructure:"max_leases"`
	SourceGuardPolicy string   `mapstructure:"source_guard_policy"`
	VendorPacks       []string `mapstructure:"vendor_packs"`
}

type BroadbandDHCPOption82RuleConfig struct {
	Name              string   `mapstructure:"name"`
	Enabled           bool     `mapstructure:"enabled"`
	MatchInterface    string   `mapstructure:"match_interface"`
	MatchVLAN         int      `mapstructure:"match_vlan"`
	CircuitIDTemplate string   `mapstructure:"circuit_id_template"`
	RemoteIDTemplate  string   `mapstructure:"remote_id_template"`
	Action            string   `mapstructure:"action"`
	RequireRemoteID   bool     `mapstructure:"require_remote_id"`
	VendorPacks       []string `mapstructure:"vendor_packs"`
}

type BroadbandDHCPSourceGuardPolicyConfig struct {
	Name              string   `mapstructure:"name"`
	Enabled           bool     `mapstructure:"enabled"`
	Mode              string   `mapstructure:"mode"`
	Interfaces        []string `mapstructure:"interfaces"`
	VLANs             []int    `mapstructure:"vlans"`
	AllowUnknown      bool     `mapstructure:"allow_unknown"`
	MaxBindings       int      `mapstructure:"max_bindings"`
	IPv6Enabled       bool     `mapstructure:"ipv6_enabled"`
	ActionOnViolation string   `mapstructure:"action_on_violation"`
	CoAAction         string   `mapstructure:"coa_action"`
}

type BroadbandDHCPRADIUSCorrelationConfig struct {
	Name             string   `mapstructure:"name"`
	Enabled          bool     `mapstructure:"enabled"`
	Source           string   `mapstructure:"source"`
	Attributes       []string `mapstructure:"attributes"`
	AccountingStages []string `mapstructure:"accounting_stages"`
}

func EffectiveBroadbandDHCPSecurityConfig(raw BroadbandDHCPSecurityConfig) BroadbandDHCPSecurityConfig {
	security := raw
	security.Mode = EffectiveBroadbandDHCPSecurityMode(security.Mode)
	security.Option82Policy = EffectiveBroadbandDHCPOption82Policy(security.Option82Policy)
	if security.BindingRetentionSeconds == 0 {
		security.BindingRetentionSeconds = 86400
	}
	if security.ViolationHoldDownSeconds == 0 {
		security.ViolationHoldDownSeconds = 300
	}
	if security.EventRetentionLimit == 0 {
		security.EventRetentionLimit = 10000
	}
	if !raw.RequireDHCP && !raw.RequireSubscriberState && !raw.RequireAddressLeases &&
		!raw.RequireAccounting && !raw.RequireDynamicAuth && !raw.RelayEnabled &&
		!raw.SnoopingEnabled && !raw.SourceGuardEnabled && !raw.Option82Required &&
		!raw.DropUnknownBindings && !raw.TrustedUplinkRequired {
		security.RequireDHCP = true
		security.RequireSubscriberState = true
		security.RequireAddressLeases = true
		security.RequireAccounting = true
		security.RequireDynamicAuth = true
		security.RelayEnabled = true
		security.SnoopingEnabled = true
		security.SourceGuardEnabled = true
		security.Option82Required = true
		security.DropUnknownBindings = true
		security.TrustedUplinkRequired = true
	}
	return security
}

func EffectiveBroadbandDHCPSecurityMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "monitor", "enforce":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "monitor"
	}
}

func EffectiveBroadbandDHCPOption82Policy(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "append", "replace", "verify", "strip", "preserve":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "append"
	}
}

func validateBroadbandDHCPSecurityConfig(raw BroadbandDHCPSecurityConfig, dhcp DHCPConfig, subscriberRaw BroadbandSubscriberStateConfig, leasesRaw BroadbandAddressLeaseConfig, radius RadiusConfig, profile string) error {
	security := EffectiveBroadbandDHCPSecurityConfig(raw)
	if !security.Enabled && len(security.RelayAgents) == 0 && len(security.Ports) == 0 &&
		len(security.Option82Rules) == 0 && len(security.SourceGuardPolicies) == 0 && len(security.RADIUSCorrelation) == 0 {
		return nil
	}
	if profile == "lite" && security.Mode == "enforce" {
		return errors.New("broadband.dhcp_security cannot use enforce mode on lite deployment profile")
	}
	if security.EventRetentionLimit < 0 || security.EventRetentionLimit > 1000000 {
		return errors.New("broadband.dhcp_security.event_retention_limit must be between 0 and 1000000")
	}
	if security.BindingRetentionSeconds < 0 || security.BindingRetentionSeconds > 31536000 {
		return errors.New("broadband.dhcp_security.binding_retention_seconds must be between 0 and 31536000")
	}
	if security.ViolationHoldDownSeconds < 0 || security.ViolationHoldDownSeconds > 86400 {
		return errors.New("broadband.dhcp_security.violation_hold_down_seconds must be between 0 and 86400")
	}
	if EffectiveBroadbandDHCPOption82Policy(raw.Option82Policy) != security.Option82Policy {
		return fmt.Errorf("broadband.dhcp_security.option82_policy %q is invalid", raw.Option82Policy)
	}
	subscriber := EffectiveBroadbandSubscriberStateConfig(subscriberRaw)
	leases := EffectiveBroadbandAddressLeaseConfig(leasesRaw)
	if security.Enabled && security.RequireDHCP && !dhcp.Enabled {
		return errors.New("broadband.dhcp_security requires dhcp.enabled")
	}
	if security.Enabled && security.RequireSubscriberState && !subscriber.Enabled {
		return errors.New("broadband.dhcp_security requires broadband.subscriber_state.enabled")
	}
	if security.Enabled && security.RequireAddressLeases && !leases.Enabled {
		return errors.New("broadband.dhcp_security requires broadband.address_leases.enabled")
	}
	if security.Enabled && security.RequireAccounting && (!radius.SQLAccounting.Enabled || !radius.AccountingServices.Enabled) {
		return errors.New("broadband.dhcp_security accounting correlation requires radius.sql_accounting and radius.accounting_services")
	}
	if security.Enabled && security.RequireDynamicAuth && !radius.DynamicAuth.Enabled {
		return errors.New("broadband.dhcp_security source guard recovery requires radius.dynamic_auth.enabled")
	}
	relayCount, err := validateBroadbandDHCPRelayAgents(security)
	if err != nil {
		return err
	}
	policyNames, policyCount, err := validateBroadbandDHCPSourceGuardPolicies(security)
	if err != nil {
		return err
	}
	portCount, trustedCount, err := validateBroadbandDHCPSecurityPorts(security, policyNames, broadbandSubscriberProductNames(subscriber))
	if err != nil {
		return err
	}
	ruleCount, err := validateBroadbandDHCPOption82Rules(security)
	if err != nil {
		return err
	}
	if err := validateBroadbandDHCPRADIUSCorrelation(security); err != nil {
		return err
	}
	if security.Enabled && security.Mode == "enforce" {
		if security.RelayEnabled && relayCount == 0 {
			return errors.New("broadband.dhcp_security enforce mode requires at least one enabled relay agent")
		}
		if security.SnoopingEnabled && portCount == 0 {
			return errors.New("broadband.dhcp_security enforce mode requires at least one enabled DHCP snooping port")
		}
		if security.TrustedUplinkRequired && trustedCount == 0 {
			return errors.New("broadband.dhcp_security trusted uplink enforcement requires at least one trusted port")
		}
		if security.Option82Required && ruleCount == 0 {
			return errors.New("broadband.dhcp_security option82_required requires at least one enabled Option 82 rule")
		}
		if security.SourceGuardEnabled && policyCount == 0 {
			return errors.New("broadband.dhcp_security source_guard_enabled requires at least one enabled source guard policy")
		}
	}
	return nil
}

func validateBroadbandDHCPRelayAgents(security BroadbandDHCPSecurityConfig) (int, error) {
	seen := map[string]struct{}{}
	enabled := 0
	for i, relay := range security.RelayAgents {
		name := strings.TrimSpace(relay.Name)
		if !validBroadbandPPPoEText(name, 128) {
			return 0, fmt.Errorf("broadband.dhcp_security.relay_agents[%d].name is invalid", i)
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			return 0, fmt.Errorf("broadband.dhcp_security.relay_agents[%d].name %q duplicates an earlier relay agent", i, name)
		}
		seen[key] = struct{}{}
		if relay.Enabled {
			enabled++
		}
		if strings.TrimSpace(relay.Interface) == "" || !validBroadbandPPPoEText(relay.Interface, 64) {
			return 0, fmt.Errorf("broadband.dhcp_security.relay_agents[%d].interface is invalid", i)
		}
		if relay.VLAN < 0 || relay.VLAN > 4094 {
			return 0, fmt.Errorf("broadband.dhcp_security.relay_agents[%d].vlan must be between 0 and 4094", i)
		}
		if relay.GatewayAddress != "" {
			if _, err := netip.ParseAddr(strings.TrimSpace(relay.GatewayAddress)); err != nil {
				return 0, fmt.Errorf("broadband.dhcp_security.relay_agents[%d].gateway_address is invalid", i)
			}
		}
		if err := validateBroadbandDHCPTextFields("broadband.dhcp_security.relay_agents", i, map[string]string{
			"server_group":        relay.ServerGroup,
			"vrf":                 relay.VRF,
			"circuit_id_template": relay.CircuitIDTemplate,
			"remote_id_template":  relay.RemoteIDTemplate,
		}); err != nil {
			return 0, err
		}
		if relay.MaxClients < 0 || relay.MaxClients > 1000000 {
			return 0, fmt.Errorf("broadband.dhcp_security.relay_agents[%d].max_clients must be between 0 and 1000000", i)
		}
		if err := validateBroadbandDHCPVendorPacks(fmt.Sprintf("broadband.dhcp_security.relay_agents[%d].vendor_packs", i), relay.VendorPacks); err != nil {
			return 0, err
		}
	}
	return enabled, nil
}

func validateBroadbandDHCPSecurityPorts(security BroadbandDHCPSecurityConfig, policies, products map[string]struct{}) (int, int, error) {
	seen := map[string]struct{}{}
	enabled := 0
	trusted := 0
	for i, port := range security.Ports {
		name := strings.TrimSpace(port.Name)
		if !validBroadbandPPPoEText(name, 128) {
			return 0, 0, fmt.Errorf("broadband.dhcp_security.ports[%d].name is invalid", i)
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			return 0, 0, fmt.Errorf("broadband.dhcp_security.ports[%d].name %q duplicates an earlier port", i, name)
		}
		seen[key] = struct{}{}
		if port.Enabled {
			enabled++
		}
		if port.Enabled && port.Trusted {
			trusted++
		}
		if strings.TrimSpace(port.Interface) == "" || !validBroadbandPPPoEText(port.Interface, 64) {
			return 0, 0, fmt.Errorf("broadband.dhcp_security.ports[%d].interface is invalid", i)
		}
		if port.VLAN < 0 || port.VLAN > 4094 {
			return 0, 0, fmt.Errorf("broadband.dhcp_security.ports[%d].vlan must be between 0 and 4094", i)
		}
		switch strings.ToLower(strings.TrimSpace(port.Role)) {
		case "", "access", "uplink", "subscriber", "trusted", "relay", "mirror":
		default:
			return 0, 0, fmt.Errorf("broadband.dhcp_security.ports[%d].role %q is invalid", i, port.Role)
		}
		if port.MaxLeases < 0 || port.MaxLeases > 1000000 {
			return 0, 0, fmt.Errorf("broadband.dhcp_security.ports[%d].max_leases must be between 0 and 1000000", i)
		}
		if strings.TrimSpace(port.SourceGuardPolicy) != "" {
			if _, ok := policies[strings.ToLower(strings.TrimSpace(port.SourceGuardPolicy))]; !ok {
				return 0, 0, fmt.Errorf("broadband.dhcp_security.ports[%d].source_guard_policy %q is not configured", i, port.SourceGuardPolicy)
			}
		}
		if strings.TrimSpace(port.SubscriberProduct) != "" && len(products) > 0 {
			if _, ok := products[strings.ToLower(strings.TrimSpace(port.SubscriberProduct))]; !ok {
				return 0, 0, fmt.Errorf("broadband.dhcp_security.ports[%d].subscriber_product %q is not configured", i, port.SubscriberProduct)
			}
		}
		if err := validateBroadbandDHCPTextFields("broadband.dhcp_security.ports", i, map[string]string{
			"circuit_id":         port.CircuitID,
			"remote_id":          port.RemoteID,
			"subscriber_product": port.SubscriberProduct,
			"tenant":             port.Tenant,
		}); err != nil {
			return 0, 0, err
		}
		if err := validateBroadbandDHCPVendorPacks(fmt.Sprintf("broadband.dhcp_security.ports[%d].vendor_packs", i), port.VendorPacks); err != nil {
			return 0, 0, err
		}
	}
	return enabled, trusted, nil
}

func validateBroadbandDHCPOption82Rules(security BroadbandDHCPSecurityConfig) (int, error) {
	seen := map[string]struct{}{}
	enabled := 0
	for i, rule := range security.Option82Rules {
		name := strings.TrimSpace(rule.Name)
		if !validBroadbandPPPoEText(name, 128) {
			return 0, fmt.Errorf("broadband.dhcp_security.option82_rules[%d].name is invalid", i)
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			return 0, fmt.Errorf("broadband.dhcp_security.option82_rules[%d].name %q duplicates an earlier Option 82 rule", i, name)
		}
		seen[key] = struct{}{}
		if rule.Enabled {
			enabled++
		}
		if rule.MatchVLAN < 0 || rule.MatchVLAN > 4094 {
			return 0, fmt.Errorf("broadband.dhcp_security.option82_rules[%d].match_vlan must be between 0 and 4094", i)
		}
		switch strings.ToLower(strings.TrimSpace(rule.Action)) {
		case "", "append", "replace", "verify", "strip", "drop", "preserve":
		default:
			return 0, fmt.Errorf("broadband.dhcp_security.option82_rules[%d].action %q is invalid", i, rule.Action)
		}
		if err := validateBroadbandDHCPTextFields("broadband.dhcp_security.option82_rules", i, map[string]string{
			"match_interface":     rule.MatchInterface,
			"circuit_id_template": rule.CircuitIDTemplate,
			"remote_id_template":  rule.RemoteIDTemplate,
		}); err != nil {
			return 0, err
		}
		if err := validateBroadbandDHCPVendorPacks(fmt.Sprintf("broadband.dhcp_security.option82_rules[%d].vendor_packs", i), rule.VendorPacks); err != nil {
			return 0, err
		}
	}
	return enabled, nil
}

func validateBroadbandDHCPSourceGuardPolicies(security BroadbandDHCPSecurityConfig) (map[string]struct{}, int, error) {
	seen := map[string]struct{}{}
	enabled := 0
	for i, policy := range security.SourceGuardPolicies {
		name := strings.TrimSpace(policy.Name)
		if !validBroadbandPPPoEText(name, 128) {
			return nil, 0, fmt.Errorf("broadband.dhcp_security.source_guard_policies[%d].name is invalid", i)
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			return nil, 0, fmt.Errorf("broadband.dhcp_security.source_guard_policies[%d].name %q duplicates an earlier source guard policy", i, name)
		}
		seen[key] = struct{}{}
		if policy.Enabled {
			enabled++
		}
		switch strings.ToLower(strings.TrimSpace(policy.Mode)) {
		case "", "monitor", "enforce", "strict":
		default:
			return nil, 0, fmt.Errorf("broadband.dhcp_security.source_guard_policies[%d].mode %q is invalid", i, policy.Mode)
		}
		switch strings.ToLower(strings.TrimSpace(policy.ActionOnViolation)) {
		case "", "log", "drop", "quarantine", "disconnect", "coa":
		default:
			return nil, 0, fmt.Errorf("broadband.dhcp_security.source_guard_policies[%d].action_on_violation %q is invalid", i, policy.ActionOnViolation)
		}
		switch strings.ToLower(strings.TrimSpace(policy.CoAAction)) {
		case "", "none", "reauth", "disconnect", "quarantine":
		default:
			return nil, 0, fmt.Errorf("broadband.dhcp_security.source_guard_policies[%d].coa_action %q is invalid", i, policy.CoAAction)
		}
		if policy.MaxBindings < 0 || policy.MaxBindings > 1000000 {
			return nil, 0, fmt.Errorf("broadband.dhcp_security.source_guard_policies[%d].max_bindings must be between 0 and 1000000", i)
		}
		for interfaceIndex, iface := range policy.Interfaces {
			if strings.TrimSpace(iface) == "" || !validBroadbandPPPoEText(iface, 64) {
				return nil, 0, fmt.Errorf("broadband.dhcp_security.source_guard_policies[%d].interfaces[%d] is invalid", i, interfaceIndex)
			}
		}
		for vlanIndex, vlan := range policy.VLANs {
			if vlan < 1 || vlan > 4094 {
				return nil, 0, fmt.Errorf("broadband.dhcp_security.source_guard_policies[%d].vlans[%d] must be between 1 and 4094", i, vlanIndex)
			}
		}
	}
	return seen, enabled, nil
}

func validateBroadbandDHCPRADIUSCorrelation(security BroadbandDHCPSecurityConfig) error {
	seen := map[string]struct{}{}
	for i, correlation := range security.RADIUSCorrelation {
		name := strings.TrimSpace(correlation.Name)
		if !validBroadbandPPPoEText(name, 128) {
			return fmt.Errorf("broadband.dhcp_security.radius_correlation[%d].name is invalid", i)
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			return fmt.Errorf("broadband.dhcp_security.radius_correlation[%d].name %q duplicates an earlier correlation rule", i, name)
		}
		seen[key] = struct{}{}
		switch strings.ToLower(strings.TrimSpace(correlation.Source)) {
		case "", "option82", "lease", "accounting", "subscriber", "radius":
		default:
			return fmt.Errorf("broadband.dhcp_security.radius_correlation[%d].source %q is invalid", i, correlation.Source)
		}
		for attrIndex, attr := range correlation.Attributes {
			if !validRadiusDictionaryName(strings.TrimSpace(attr)) {
				return fmt.Errorf("broadband.dhcp_security.radius_correlation[%d].attributes[%d] %q is invalid", i, attrIndex, attr)
			}
		}
		for stageIndex, stage := range correlation.AccountingStages {
			switch strings.ToLower(strings.TrimSpace(stage)) {
			case "start", "interim", "stop", "coa", "disconnect":
			default:
				return fmt.Errorf("broadband.dhcp_security.radius_correlation[%d].accounting_stages[%d] %q is invalid", i, stageIndex, stage)
			}
		}
	}
	return nil
}

func validateBroadbandDHCPTextFields(prefix string, index int, fields map[string]string) error {
	for name, value := range fields {
		if strings.TrimSpace(value) != "" && !validBroadbandPPPoEText(value, 253) {
			return fmt.Errorf("%s[%d].%s is invalid", prefix, index, name)
		}
	}
	return nil
}

func validateBroadbandDHCPVendorPacks(field string, packs []string) error {
	for i, pack := range packs {
		if productconfigs.NormalizeVendorCompatibilityPackKey(pack) == "" {
			return fmt.Errorf("%s[%d] %q is unknown", field, i, pack)
		}
	}
	return nil
}
