package config

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
)

type BroadbandServiceActivationConfig struct {
	Enabled                  bool                                      `mapstructure:"enabled"`
	Mode                     string                                    `mapstructure:"mode"`
	FailClosed               bool                                      `mapstructure:"fail_closed"`
	RequireSubscriberState   bool                                      `mapstructure:"require_subscriber_state"`
	RequireCommercialCatalog bool                                      `mapstructure:"require_commercial_catalog"`
	RequireAddressLeases     bool                                      `mapstructure:"require_address_leases"`
	RequireQoSServiceFlows   bool                                      `mapstructure:"require_qos_service_flows"`
	RequireDHCPSecurity      bool                                      `mapstructure:"require_dhcp_security"`
	RequireRouteExport       bool                                      `mapstructure:"require_route_export"`
	RequireAccounting        bool                                      `mapstructure:"require_accounting"`
	RequireDynamicAuth       bool                                      `mapstructure:"require_dynamic_auth"`
	TransactionalApply       bool                                      `mapstructure:"transactional_apply"`
	RollbackOnFailure        bool                                      `mapstructure:"rollback_on_failure"`
	RoutePublishEnabled      bool                                      `mapstructure:"route_publish_enabled"`
	MulticastEnabled         bool                                      `mapstructure:"multicast_enabled"`
	ActivationTimeoutSeconds int                                       `mapstructure:"activation_timeout_seconds"`
	EventRetentionLimit      int                                       `mapstructure:"event_retention_limit"`
	Services                 []BroadbandServiceActivationServiceConfig `mapstructure:"services"`
	RoutePolicies            []BroadbandActivationRoutePolicyConfig    `mapstructure:"route_policies"`
	MulticastProfiles        []BroadbandMulticastProfileConfig         `mapstructure:"multicast_profiles"`
	ActivationPolicies       []BroadbandActivationPolicyConfig         `mapstructure:"activation_policies"`
}

type BroadbandServiceActivationServiceConfig struct {
	Name             string   `mapstructure:"name"`
	Enabled          bool     `mapstructure:"enabled"`
	Required         bool     `mapstructure:"required"`
	Product          string   `mapstructure:"product"`
	SubscriberID     string   `mapstructure:"subscriber_id"`
	Username         string   `mapstructure:"username"`
	Tenant           string   `mapstructure:"tenant"`
	ServiceChain     string   `mapstructure:"service_chain"`
	RoutePolicy      string   `mapstructure:"route_policy"`
	MulticastProfile string   `mapstructure:"multicast_profile"`
	AddressPool      string   `mapstructure:"address_pool"`
	QoSProfile       string   `mapstructure:"qos_profile"`
	AccountingClass  string   `mapstructure:"accounting_class"`
	VendorPacks      []string `mapstructure:"vendor_packs"`
}

type BroadbandActivationRoutePolicyConfig struct {
	Name                 string   `mapstructure:"name"`
	Enabled              bool     `mapstructure:"enabled"`
	VRF                  string   `mapstructure:"vrf"`
	Protocol             string   `mapstructure:"protocol"`
	IPv4Routes           []string `mapstructure:"ipv4_routes"`
	IPv6Routes           []string `mapstructure:"ipv6_routes"`
	NextHop              string   `mapstructure:"next_hop"`
	RouteTarget          string   `mapstructure:"route_target"`
	Metric               int      `mapstructure:"metric"`
	Preference           int      `mapstructure:"preference"`
	WithdrawOnDeactivate bool     `mapstructure:"withdraw_on_deactivate"`
	Aggregate            bool     `mapstructure:"aggregate"`
	VendorPacks          []string `mapstructure:"vendor_packs"`
}

type BroadbandMulticastProfileConfig struct {
	Name                string   `mapstructure:"name"`
	Enabled             bool     `mapstructure:"enabled"`
	Mode                string   `mapstructure:"mode"`
	Groups              []string `mapstructure:"groups"`
	SourceAddresses     []string `mapstructure:"source_addresses"`
	MaxGroups           int      `mapstructure:"max_groups"`
	QuerierInterface    string   `mapstructure:"querier_interface"`
	VLAN                int      `mapstructure:"vlan"`
	VRF                 string   `mapstructure:"vrf"`
	EntitlementRequired bool     `mapstructure:"entitlement_required"`
	VendorPacks         []string `mapstructure:"vendor_packs"`
}

type BroadbandActivationPolicyConfig struct {
	Name              string `mapstructure:"name"`
	Enabled           bool   `mapstructure:"enabled"`
	MatchProduct      string `mapstructure:"match_product"`
	MatchTenant       string `mapstructure:"match_tenant"`
	AllowRollback     bool   `mapstructure:"allow_rollback"`
	RequireRoutes     bool   `mapstructure:"require_routes"`
	RequireMulticast  bool   `mapstructure:"require_multicast"`
	RequireAccounting bool   `mapstructure:"require_accounting"`
	ChangeWindow      string `mapstructure:"change_window"`
	FailureAction     string `mapstructure:"failure_action"`
}

func EffectiveBroadbandServiceActivationConfig(raw BroadbandServiceActivationConfig) BroadbandServiceActivationConfig {
	activation := raw
	activation.Mode = EffectiveBroadbandServiceActivationMode(activation.Mode)
	if activation.ActivationTimeoutSeconds == 0 {
		activation.ActivationTimeoutSeconds = 60
	}
	if activation.EventRetentionLimit == 0 {
		activation.EventRetentionLimit = 10000
	}
	if !raw.RequireSubscriberState && !raw.RequireCommercialCatalog && !raw.RequireAddressLeases &&
		!raw.RequireQoSServiceFlows && !raw.RequireDHCPSecurity && !raw.RequireRouteExport &&
		!raw.RequireAccounting && !raw.RequireDynamicAuth && !raw.TransactionalApply &&
		!raw.RollbackOnFailure && !raw.RoutePublishEnabled && !raw.MulticastEnabled {
		activation.RequireSubscriberState = true
		activation.RequireCommercialCatalog = true
		activation.RequireAddressLeases = true
		activation.RequireQoSServiceFlows = true
		activation.RequireDHCPSecurity = true
		activation.RequireRouteExport = true
		activation.RequireAccounting = true
		activation.RequireDynamicAuth = true
		activation.TransactionalApply = true
		activation.RollbackOnFailure = true
		activation.RoutePublishEnabled = true
		activation.MulticastEnabled = true
	}
	return activation
}

func EffectiveBroadbandServiceActivationMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "monitor", "enforce":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "monitor"
	}
}

func validateBroadbandServiceActivationConfig(raw BroadbandServiceActivationConfig, subscriberRaw BroadbandSubscriberStateConfig, catalogRaw BroadbandCommercialCatalog, leasesRaw BroadbandAddressLeaseConfig, qosRaw BroadbandQoSServiceFlowConfig, dhcpRaw BroadbandDHCPSecurityConfig, radius RadiusConfig, profile string) error {
	activation := EffectiveBroadbandServiceActivationConfig(raw)
	if !activation.Enabled && len(activation.Services) == 0 && len(activation.RoutePolicies) == 0 &&
		len(activation.MulticastProfiles) == 0 && len(activation.ActivationPolicies) == 0 {
		return nil
	}
	if profile == "lite" && activation.Mode == "enforce" {
		return errors.New("broadband.service_activation cannot use enforce mode on lite deployment profile")
	}
	if activation.EventRetentionLimit < 0 || activation.EventRetentionLimit > 1000000 {
		return errors.New("broadband.service_activation.event_retention_limit must be between 0 and 1000000")
	}
	if activation.ActivationTimeoutSeconds < 0 || activation.ActivationTimeoutSeconds > 3600 {
		return errors.New("broadband.service_activation.activation_timeout_seconds must be between 0 and 3600")
	}
	subscriber := EffectiveBroadbandSubscriberStateConfig(subscriberRaw)
	catalog := EffectiveBroadbandCommercialCatalog(catalogRaw)
	leases := EffectiveBroadbandAddressLeaseConfig(leasesRaw)
	qos := EffectiveBroadbandQoSServiceFlowConfig(qosRaw)
	dhcp := EffectiveBroadbandDHCPSecurityConfig(dhcpRaw)
	if activation.Enabled && activation.RequireSubscriberState && !subscriber.Enabled {
		return errors.New("broadband.service_activation requires broadband.subscriber_state.enabled")
	}
	if activation.Enabled && activation.RequireCommercialCatalog && !catalog.Enabled {
		return errors.New("broadband.service_activation requires broadband.commercial_catalog.enabled")
	}
	if activation.Enabled && activation.RequireAddressLeases && !leases.Enabled {
		return errors.New("broadband.service_activation requires broadband.address_leases.enabled")
	}
	if activation.Enabled && activation.RequireQoSServiceFlows && !qos.Enabled {
		return errors.New("broadband.service_activation requires broadband.qos_service_flows.enabled")
	}
	if activation.Enabled && activation.RequireDHCPSecurity && !dhcp.Enabled {
		return errors.New("broadband.service_activation requires broadband.dhcp_security.enabled")
	}
	if activation.Enabled && activation.RequireRouteExport && (!radius.RoutePolicy.Enabled || !radius.RoutePolicy.DynamicRouting.Enabled) {
		return errors.New("broadband.service_activation route publish lifecycle requires radius.route_policy.dynamic_routing.enabled")
	}
	if activation.Enabled && activation.RequireAccounting && (!radius.SQLAccounting.Enabled || !radius.AccountingServices.Enabled) {
		return errors.New("broadband.service_activation requires radius.sql_accounting and radius.accounting_services")
	}
	if activation.Enabled && activation.RequireDynamicAuth && !radius.DynamicAuth.Enabled {
		return errors.New("broadband.service_activation requires radius.dynamic_auth.enabled")
	}
	routePolicies, enabledRoutes, err := validateBroadbandActivationRoutePolicies(activation)
	if err != nil {
		return err
	}
	multicastProfiles, enabledMulticast, err := validateBroadbandMulticastProfiles(activation)
	if err != nil {
		return err
	}
	enabledPolicies, err := validateBroadbandActivationPolicies(activation, broadbandSubscriberProductNames(subscriber))
	if err != nil {
		return err
	}
	enabledServices, err := validateBroadbandActivationServices(activation, broadbandSubscriberProductNames(subscriber), routePolicies, multicastProfiles)
	if err != nil {
		return err
	}
	if activation.Enabled && activation.Mode == "enforce" {
		if enabledServices == 0 {
			return errors.New("broadband.service_activation enforce mode requires at least one enabled service")
		}
		if activation.RoutePublishEnabled && enabledRoutes == 0 {
			return errors.New("broadband.service_activation route_publish_enabled requires at least one enabled route policy")
		}
		if activation.MulticastEnabled && enabledMulticast == 0 {
			return errors.New("broadband.service_activation multicast_enabled requires at least one enabled multicast profile")
		}
		if activation.TransactionalApply && !activation.RollbackOnFailure {
			return errors.New("broadband.service_activation transactional apply requires rollback_on_failure")
		}
		if enabledPolicies == 0 {
			return errors.New("broadband.service_activation enforce mode requires at least one activation policy")
		}
	}
	return nil
}

func validateBroadbandActivationServices(activation BroadbandServiceActivationConfig, productNames, routePolicies, multicastProfiles map[string]struct{}) (int, error) {
	seen := map[string]struct{}{}
	enabled := 0
	for i, service := range activation.Services {
		name := strings.TrimSpace(service.Name)
		if !validBroadbandPPPoEText(name, 128) {
			return 0, fmt.Errorf("broadband.service_activation.services[%d].name is invalid", i)
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			return 0, fmt.Errorf("broadband.service_activation.services[%d].name %q duplicates an earlier service", i, name)
		}
		seen[key] = struct{}{}
		if service.Enabled {
			enabled++
		}
		if product := strings.TrimSpace(service.Product); product != "" {
			if _, ok := productNames[strings.ToLower(product)]; !ok && len(productNames) > 0 {
				return 0, fmt.Errorf("broadband.service_activation.services[%d].product %q is not configured", i, product)
			}
		}
		if route := strings.TrimSpace(service.RoutePolicy); route != "" {
			if _, ok := routePolicies[strings.ToLower(route)]; !ok {
				return 0, fmt.Errorf("broadband.service_activation.services[%d].route_policy %q is not configured", i, route)
			}
		}
		if multicast := strings.TrimSpace(service.MulticastProfile); multicast != "" {
			if _, ok := multicastProfiles[strings.ToLower(multicast)]; !ok {
				return 0, fmt.Errorf("broadband.service_activation.services[%d].multicast_profile %q is not configured", i, multicast)
			}
		}
		for _, binding := range []struct {
			field string
			value string
			limit int
		}{
			{"subscriber_id", service.SubscriberID, 253},
			{"username", service.Username, 253},
			{"tenant", service.Tenant, 128},
			{"service_chain", service.ServiceChain, 128},
			{"address_pool", service.AddressPool, 128},
			{"qos_profile", service.QoSProfile, 128},
			{"accounting_class", service.AccountingClass, 128},
		} {
			if strings.TrimSpace(binding.value) != "" && !validBroadbandPPPoEText(binding.value, binding.limit) {
				return 0, fmt.Errorf("broadband.service_activation.services[%d].%s is invalid", i, binding.field)
			}
		}
		if err := validateBroadbandServiceVendorPacks(fmt.Sprintf("broadband.service_activation.services[%d].vendor_packs", i), service.VendorPacks); err != nil {
			return 0, err
		}
	}
	return enabled, nil
}

func validateBroadbandActivationRoutePolicies(activation BroadbandServiceActivationConfig) (map[string]struct{}, int, error) {
	seen := map[string]struct{}{}
	enabled := 0
	for i, policy := range activation.RoutePolicies {
		name := strings.TrimSpace(policy.Name)
		if !validBroadbandPPPoEText(name, 128) {
			return nil, 0, fmt.Errorf("broadband.service_activation.route_policies[%d].name is invalid", i)
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			return nil, 0, fmt.Errorf("broadband.service_activation.route_policies[%d].name %q duplicates an earlier route policy", i, name)
		}
		seen[key] = struct{}{}
		if policy.Enabled {
			enabled++
		}
		switch strings.ToLower(strings.TrimSpace(policy.Protocol)) {
		case "", "bgp", "ospf", "ospf3", "static", "isis":
		default:
			return nil, 0, fmt.Errorf("broadband.service_activation.route_policies[%d].protocol %q is invalid", i, policy.Protocol)
		}
		for routeIndex, route := range policy.IPv4Routes {
			prefix, err := netip.ParsePrefix(strings.TrimSpace(route))
			if err != nil || !prefix.Addr().Is4() {
				return nil, 0, fmt.Errorf("broadband.service_activation.route_policies[%d].ipv4_routes[%d] is invalid", i, routeIndex)
			}
		}
		for routeIndex, route := range policy.IPv6Routes {
			prefix, err := netip.ParsePrefix(strings.TrimSpace(route))
			if err != nil || !prefix.Addr().Is6() {
				return nil, 0, fmt.Errorf("broadband.service_activation.route_policies[%d].ipv6_routes[%d] is invalid", i, routeIndex)
			}
		}
		if strings.TrimSpace(policy.NextHop) != "" {
			if _, err := netip.ParseAddr(strings.TrimSpace(policy.NextHop)); err != nil {
				return nil, 0, fmt.Errorf("broadband.service_activation.route_policies[%d].next_hop is invalid", i)
			}
		}
		if policy.Metric < 0 || policy.Metric > 16777215 || policy.Preference < 0 || policy.Preference > 2147483647 {
			return nil, 0, fmt.Errorf("broadband.service_activation.route_policies[%d] metric and preference must be non-negative and within routing limits", i)
		}
		for _, binding := range []struct {
			field string
			value string
			limit int
		}{
			{"vrf", policy.VRF, 128},
			{"route_target", policy.RouteTarget, 128},
		} {
			if strings.TrimSpace(binding.value) != "" && !validBroadbandPPPoEText(binding.value, binding.limit) {
				return nil, 0, fmt.Errorf("broadband.service_activation.route_policies[%d].%s is invalid", i, binding.field)
			}
		}
		if err := validateBroadbandServiceVendorPacks(fmt.Sprintf("broadband.service_activation.route_policies[%d].vendor_packs", i), policy.VendorPacks); err != nil {
			return nil, 0, err
		}
	}
	return seen, enabled, nil
}

func validateBroadbandMulticastProfiles(activation BroadbandServiceActivationConfig) (map[string]struct{}, int, error) {
	seen := map[string]struct{}{}
	enabled := 0
	for i, profile := range activation.MulticastProfiles {
		name := strings.TrimSpace(profile.Name)
		if !validBroadbandPPPoEText(name, 128) {
			return nil, 0, fmt.Errorf("broadband.service_activation.multicast_profiles[%d].name is invalid", i)
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			return nil, 0, fmt.Errorf("broadband.service_activation.multicast_profiles[%d].name %q duplicates an earlier multicast profile", i, name)
		}
		seen[key] = struct{}{}
		if profile.Enabled {
			enabled++
		}
		switch strings.ToLower(strings.TrimSpace(profile.Mode)) {
		case "", "igmp", "mld", "igmp-mld", "igmp_mld":
		default:
			return nil, 0, fmt.Errorf("broadband.service_activation.multicast_profiles[%d].mode %q is invalid", i, profile.Mode)
		}
		if profile.VLAN < 0 || profile.VLAN > 4094 {
			return nil, 0, fmt.Errorf("broadband.service_activation.multicast_profiles[%d].vlan must be between 0 and 4094", i)
		}
		if profile.MaxGroups < 0 || profile.MaxGroups > 1000000 {
			return nil, 0, fmt.Errorf("broadband.service_activation.multicast_profiles[%d].max_groups must be between 0 and 1000000", i)
		}
		for groupIndex, group := range profile.Groups {
			addr, err := netip.ParseAddr(strings.TrimSpace(group))
			if err != nil || !addr.IsMulticast() {
				return nil, 0, fmt.Errorf("broadband.service_activation.multicast_profiles[%d].groups[%d] must be a multicast address", i, groupIndex)
			}
		}
		for sourceIndex, source := range profile.SourceAddresses {
			if _, err := netip.ParseAddr(strings.TrimSpace(source)); err != nil {
				return nil, 0, fmt.Errorf("broadband.service_activation.multicast_profiles[%d].source_addresses[%d] is invalid", i, sourceIndex)
			}
		}
		for _, binding := range []struct {
			field string
			value string
			limit int
		}{
			{"querier_interface", profile.QuerierInterface, 64},
			{"vrf", profile.VRF, 128},
		} {
			if strings.TrimSpace(binding.value) != "" && !validBroadbandPPPoEText(binding.value, binding.limit) {
				return nil, 0, fmt.Errorf("broadband.service_activation.multicast_profiles[%d].%s is invalid", i, binding.field)
			}
		}
		if err := validateBroadbandServiceVendorPacks(fmt.Sprintf("broadband.service_activation.multicast_profiles[%d].vendor_packs", i), profile.VendorPacks); err != nil {
			return nil, 0, err
		}
	}
	return seen, enabled, nil
}

func validateBroadbandActivationPolicies(activation BroadbandServiceActivationConfig, productNames map[string]struct{}) (int, error) {
	seen := map[string]struct{}{}
	enabled := 0
	for i, policy := range activation.ActivationPolicies {
		name := strings.TrimSpace(policy.Name)
		if !validBroadbandPPPoEText(name, 128) {
			return 0, fmt.Errorf("broadband.service_activation.activation_policies[%d].name is invalid", i)
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			return 0, fmt.Errorf("broadband.service_activation.activation_policies[%d].name %q duplicates an earlier activation policy", i, name)
		}
		seen[key] = struct{}{}
		if policy.Enabled {
			enabled++
		}
		if product := strings.TrimSpace(policy.MatchProduct); product != "" {
			if _, ok := productNames[strings.ToLower(product)]; !ok && len(productNames) > 0 {
				return 0, fmt.Errorf("broadband.service_activation.activation_policies[%d].match_product %q is not configured", i, product)
			}
		}
		switch strings.ToLower(strings.TrimSpace(policy.FailureAction)) {
		case "", "rollback", "block", "degrade", "disconnect", "monitor":
		default:
			return 0, fmt.Errorf("broadband.service_activation.activation_policies[%d].failure_action %q is invalid", i, policy.FailureAction)
		}
		for _, binding := range []struct {
			field string
			value string
			limit int
		}{
			{"match_tenant", policy.MatchTenant, 128},
			{"change_window", policy.ChangeWindow, 128},
		} {
			if strings.TrimSpace(binding.value) != "" && !validBroadbandPPPoEText(binding.value, binding.limit) {
				return 0, fmt.Errorf("broadband.service_activation.activation_policies[%d].%s is invalid", i, binding.field)
			}
		}
	}
	return enabled, nil
}

func validateBroadbandServiceVendorPacks(field string, values []string) error {
	for index, pack := range values {
		key := productconfigs.NormalizeVendorCompatibilityPackKey(pack)
		if key == "" || !productconfigs.ValidVendorCompatibilityPackKey(key) {
			return fmt.Errorf("%s[%d] %q is unknown", field, index, pack)
		}
	}
	return nil
}
