package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBroadbandServiceActivationValidation(t *testing.T) {
	cfg := testBroadbandServiceActivationConfig()
	require.NoError(t, validateBroadbandServiceActivationConfig(cfg.Broadband.ServiceActivation, cfg.Broadband.Subscriber, cfg.Broadband.CommercialCatalog, cfg.Broadband.AddressLeases, cfg.Broadband.QoSServiceFlows, cfg.Broadband.DHCPSecurity, cfg.Radius, "enterprise"))

	cfg.Broadband.ServiceActivation.Services[0].RoutePolicy = "missing"
	require.ErrorContains(t, validateBroadbandServiceActivationConfig(cfg.Broadband.ServiceActivation, cfg.Broadband.Subscriber, cfg.Broadband.CommercialCatalog, cfg.Broadband.AddressLeases, cfg.Broadband.QoSServiceFlows, cfg.Broadband.DHCPSecurity, cfg.Radius, "enterprise"), "route_policy")

	cfg = testBroadbandServiceActivationConfig()
	cfg.Radius.RoutePolicy.DynamicRouting.Enabled = false
	require.ErrorContains(t, validateBroadbandServiceActivationConfig(cfg.Broadband.ServiceActivation, cfg.Broadband.Subscriber, cfg.Broadband.CommercialCatalog, cfg.Broadband.AddressLeases, cfg.Broadband.QoSServiceFlows, cfg.Broadband.DHCPSecurity, cfg.Radius, "enterprise"), "dynamic_routing.enabled")

	cfg = testBroadbandServiceActivationConfig()
	cfg.Broadband.ServiceActivation.MulticastProfiles[0].Groups[0] = "192.0.2.10"
	require.ErrorContains(t, validateBroadbandServiceActivationConfig(cfg.Broadband.ServiceActivation, cfg.Broadband.Subscriber, cfg.Broadband.CommercialCatalog, cfg.Broadband.AddressLeases, cfg.Broadband.QoSServiceFlows, cfg.Broadband.DHCPSecurity, cfg.Radius, "enterprise"), "multicast address")

	cfg = testBroadbandServiceActivationConfig()
	cfg.Broadband.ServiceActivation.RollbackOnFailure = false
	require.ErrorContains(t, validateBroadbandServiceActivationConfig(cfg.Broadband.ServiceActivation, cfg.Broadband.Subscriber, cfg.Broadband.CommercialCatalog, cfg.Broadband.AddressLeases, cfg.Broadband.QoSServiceFlows, cfg.Broadband.DHCPSecurity, cfg.Radius, "enterprise"), "rollback_on_failure")

	cfg = testBroadbandServiceActivationConfig()
	require.ErrorContains(t, validateBroadbandServiceActivationConfig(cfg.Broadband.ServiceActivation, cfg.Broadband.Subscriber, cfg.Broadband.CommercialCatalog, cfg.Broadband.AddressLeases, cfg.Broadband.QoSServiceFlows, cfg.Broadband.DHCPSecurity, cfg.Radius, "lite"), "lite")
}

func testBroadbandServiceActivationConfig() *Config {
	return &Config{
		Radius: RadiusConfig{
			SQLAccounting:      RadiusSQLAccountingConfig{Enabled: true},
			AccountingServices: RadiusAccountingServicesConfig{Enabled: true},
			DynamicAuth:        DynamicAuthConfig{Enabled: true},
			RoutePolicy: RadiusRoutePolicyConfig{
				Enabled: true,
				DynamicRouting: RadiusDynamicRoutingConfig{
					Enabled: true,
				},
			},
		},
		Broadband: BroadbandConfig{
			Subscriber: BroadbandSubscriberStateConfig{
				Enabled:             true,
				DefaultAccessMethod: "pppoe",
				Products: []BroadbandSubscriberProductConfig{
					{Name: "residential-fiber", Enabled: true, Role: "subscriber", ServiceChain: "retail-internet", AddressPool: "pppoe-v4", QoSProfile: "silver", RoutePolicy: "retail-bgp"},
				},
			},
			CommercialCatalog: BroadbandCommercialCatalog{Enabled: true},
			AddressLeases:     BroadbandAddressLeaseConfig{Enabled: true},
			QoSServiceFlows:   BroadbandQoSServiceFlowConfig{Enabled: true},
			DHCPSecurity:      BroadbandDHCPSecurityConfig{Enabled: true},
			ServiceActivation: BroadbandServiceActivationConfig{
				Enabled:                  true,
				Mode:                     "enforce",
				FailClosed:               true,
				RequireSubscriberState:   true,
				RequireCommercialCatalog: true,
				RequireAddressLeases:     true,
				RequireQoSServiceFlows:   true,
				RequireDHCPSecurity:      true,
				RequireRouteExport:       true,
				RequireAccounting:        true,
				RequireDynamicAuth:       true,
				TransactionalApply:       true,
				RollbackOnFailure:        true,
				RoutePublishEnabled:      true,
				MulticastEnabled:         true,
				Services: []BroadbandServiceActivationServiceConfig{
					{Name: "fiber-internet-activation", Enabled: true, Required: true, Product: "residential-fiber", SubscriberID: "sub-lab-cpe-01", Username: "lab-cpe-01@example.net", Tenant: "retail", ServiceChain: "retail-internet", RoutePolicy: "retail-bgp", MulticastProfile: "iptv-basic", AddressPool: "pppoe-v4", QoSProfile: "silver", AccountingClass: "internet", VendorPacks: []string{"standard", "erx", "huawei", "h3c", "nokia", "zte"}},
				},
				RoutePolicies: []BroadbandActivationRoutePolicyConfig{
					{Name: "retail-bgp", Enabled: true, VRF: "retail", Protocol: "bgp", IPv4Routes: []string{"100.64.0.0/24"}, IPv6Routes: []string{"2001:db8:100::/48"}, NextHop: "192.0.2.1", RouteTarget: "65000:100", Metric: 100, Preference: 100, WithdrawOnDeactivate: true, VendorPacks: []string{"standard", "erx", "huawei", "nokia", "zte"}},
				},
				MulticastProfiles: []BroadbandMulticastProfileConfig{
					{Name: "iptv-basic", Enabled: true, Mode: "igmp-mld", Groups: []string{"239.1.1.1", "ff3e::1"}, SourceAddresses: []string{"198.51.100.10"}, MaxGroups: 64, QuerierInterface: "eth1.100", VLAN: 120, VRF: "retail", EntitlementRequired: true, VendorPacks: []string{"standard", "erx", "huawei", "h3c", "nokia", "zte"}},
				},
				ActivationPolicies: []BroadbandActivationPolicyConfig{
					{Name: "retail-transactional", Enabled: true, MatchProduct: "residential-fiber", MatchTenant: "retail", AllowRollback: true, RequireRoutes: true, RequireMulticast: true, RequireAccounting: true, ChangeWindow: "always", FailureAction: "rollback"},
				},
			},
		},
	}
}
