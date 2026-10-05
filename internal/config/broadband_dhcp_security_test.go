package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBroadbandDHCPSecurityValidation(t *testing.T) {
	cfg := testBroadbandDHCPSecurityConfig()
	require.NoError(t, validateBroadbandDHCPSecurityConfig(cfg.Broadband.DHCPSecurity, cfg.DHCP, cfg.Broadband.Subscriber, cfg.Broadband.AddressLeases, cfg.Radius, "enterprise"))

	cfg.Broadband.DHCPSecurity.Ports[0].SourceGuardPolicy = "missing"
	require.ErrorContains(t, validateBroadbandDHCPSecurityConfig(cfg.Broadband.DHCPSecurity, cfg.DHCP, cfg.Broadband.Subscriber, cfg.Broadband.AddressLeases, cfg.Radius, "enterprise"), "source_guard_policy")

	cfg = testBroadbandDHCPSecurityConfig()
	cfg.DHCP.Enabled = false
	require.ErrorContains(t, validateBroadbandDHCPSecurityConfig(cfg.Broadband.DHCPSecurity, cfg.DHCP, cfg.Broadband.Subscriber, cfg.Broadband.AddressLeases, cfg.Radius, "enterprise"), "dhcp.enabled")

	cfg = testBroadbandDHCPSecurityConfig()
	cfg.Radius.DynamicAuth.Enabled = false
	require.ErrorContains(t, validateBroadbandDHCPSecurityConfig(cfg.Broadband.DHCPSecurity, cfg.DHCP, cfg.Broadband.Subscriber, cfg.Broadband.AddressLeases, cfg.Radius, "enterprise"), "radius.dynamic_auth.enabled")

	cfg = testBroadbandDHCPSecurityConfig()
	cfg.Broadband.DHCPSecurity.Ports[1].Trusted = false
	require.ErrorContains(t, validateBroadbandDHCPSecurityConfig(cfg.Broadband.DHCPSecurity, cfg.DHCP, cfg.Broadband.Subscriber, cfg.Broadband.AddressLeases, cfg.Radius, "enterprise"), "trusted")

	cfg = testBroadbandDHCPSecurityConfig()
	require.ErrorContains(t, validateBroadbandDHCPSecurityConfig(cfg.Broadband.DHCPSecurity, cfg.DHCP, cfg.Broadband.Subscriber, cfg.Broadband.AddressLeases, cfg.Radius, "lite"), "lite")
}

func testBroadbandDHCPSecurityConfig() *Config {
	return &Config{
		DHCP: DHCPConfig{Enabled: true},
		Radius: RadiusConfig{
			SQLAccounting:      RadiusSQLAccountingConfig{Enabled: true},
			AccountingServices: RadiusAccountingServicesConfig{Enabled: true},
			DynamicAuth:        DynamicAuthConfig{Enabled: true},
		},
		Broadband: BroadbandConfig{
			Subscriber: BroadbandSubscriberStateConfig{
				Enabled:             true,
				DefaultAccessMethod: "dhcp",
				Products: []BroadbandSubscriberProductConfig{
					{Name: "residential-fiber", Enabled: true, Role: "subscriber"},
				},
			},
			AddressLeases: BroadbandAddressLeaseConfig{Enabled: true},
			DHCPSecurity: BroadbandDHCPSecurityConfig{
				Enabled:                  true,
				Mode:                     "enforce",
				FailClosed:               true,
				RequireDHCP:              true,
				RequireSubscriberState:   true,
				RequireAddressLeases:     true,
				RequireAccounting:        true,
				RequireDynamicAuth:       true,
				RelayEnabled:             true,
				SnoopingEnabled:          true,
				SourceGuardEnabled:       true,
				Option82Required:         true,
				DropUnknownBindings:      true,
				TrustedUplinkRequired:    true,
				Option82Policy:           "append",
				BindingRetentionSeconds:  86400,
				EventRetentionLimit:      10000,
				ViolationHoldDownSeconds: 300,
				RelayAgents: []BroadbandDHCPRelayAgentConfig{
					{Name: "relay-vlan100", Enabled: true, Interface: "eth1.100", VLAN: 100, GatewayAddress: "192.0.2.1", ServerGroup: "dhcp-core", VRF: "retail", CircuitIDTemplate: "{{interface}}:{{vlan}}", RemoteIDTemplate: "{{tenant}}", AppendOption82: true, Trusted: true, MaxClients: 4096, VendorPacks: []string{"standard", "cisco", "huawei"}},
				},
				Ports: []BroadbandDHCPSecurityPortConfig{
					{Name: "subscriber-port-1", Enabled: true, Interface: "eth1.100", VLAN: 100, Role: "access", CircuitID: "olt1/1/1", RemoteID: "retail", SubscriberProduct: "residential-fiber", Tenant: "retail", MaxLeases: 4, SourceGuardPolicy: "strict-access", VendorPacks: []string{"standard", "cisco"}},
					{Name: "uplink", Enabled: true, Interface: "eth1", VLAN: 0, Role: "uplink", Trusted: true, MaxLeases: 100000, VendorPacks: []string{"standard"}},
				},
				Option82Rules: []BroadbandDHCPOption82RuleConfig{
					{Name: "access-option82", Enabled: true, MatchInterface: "eth1.100", MatchVLAN: 100, CircuitIDTemplate: "{{port}}", RemoteIDTemplate: "{{tenant}}", Action: "append", RequireRemoteID: true, VendorPacks: []string{"standard", "cisco"}},
				},
				SourceGuardPolicies: []BroadbandDHCPSourceGuardPolicyConfig{
					{Name: "strict-access", Enabled: true, Mode: "enforce", Interfaces: []string{"eth1.100"}, VLANs: []int{100}, AllowUnknown: false, MaxBindings: 4096, IPv6Enabled: true, ActionOnViolation: "drop", CoAAction: "disconnect"},
				},
				RADIUSCorrelation: []BroadbandDHCPRADIUSCorrelationConfig{
					{Name: "option82-accounting", Enabled: true, Source: "option82", Attributes: []string{"Class", "NAS-Port-Id", "Calling-Station-Id"}, AccountingStages: []string{"start", "interim", "stop"}},
				},
			},
		},
	}
}
