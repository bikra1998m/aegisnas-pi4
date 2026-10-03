package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBroadbandL2TPWholesaleValidation(t *testing.T) {
	cfg := testBroadbandL2TPWholesaleConfig()
	require.NoError(t, validateBroadbandL2TPWholesaleConfig(cfg.Broadband.L2TPWholesale, cfg.Broadband.PPPoE, cfg.Broadband.Subscriber, cfg.Radius, "enterprise"))

	cfg.Broadband.L2TPWholesale.Realms[0].TunnelProfile = "missing"
	require.ErrorContains(t, validateBroadbandL2TPWholesaleConfig(cfg.Broadband.L2TPWholesale, cfg.Broadband.PPPoE, cfg.Broadband.Subscriber, cfg.Radius, "enterprise"), "tunnel_profile")

	cfg = testBroadbandL2TPWholesaleConfig()
	cfg.Radius.Upstream.Enabled = false
	require.ErrorContains(t, validateBroadbandL2TPWholesaleConfig(cfg.Broadband.L2TPWholesale, cfg.Broadband.PPPoE, cfg.Broadband.Subscriber, cfg.Radius, "enterprise"), "radius.upstream.enabled")

	cfg = testBroadbandL2TPWholesaleConfig()
	cfg.Broadband.Subscriber.WholesaleEnabled = false
	require.ErrorContains(t, validateBroadbandL2TPWholesaleConfig(cfg.Broadband.L2TPWholesale, cfg.Broadband.PPPoE, cfg.Broadband.Subscriber, cfg.Radius, "enterprise"), "wholesale_enabled")
}

func testBroadbandL2TPWholesaleConfig() *Config {
	return &Config{
		Radius: RadiusConfig{
			SQLAccounting:      RadiusSQLAccountingConfig{Enabled: true},
			AccountingServices: RadiusAccountingServicesConfig{Enabled: true},
			DynamicAuth:        DynamicAuthConfig{Enabled: true},
			Upstream: RadiusUpstreamConfig{
				Enabled: true,
				Routes: []RadiusProxyRouteConfig{
					{Name: "wholesale-retail-auth", Enabled: true, Realm: "retail.example.net"},
					{Name: "wholesale-retail-acct", Enabled: true, Realm: "acct.retail.example.net"},
				},
			},
		},
		Broadband: BroadbandConfig{
			PPPoE: BroadbandPPPoEConfig{Enabled: true},
			Subscriber: BroadbandSubscriberStateConfig{
				Enabled:             true,
				WholesaleEnabled:    true,
				DefaultAccessMethod: "pppoe",
				Products: []BroadbandSubscriberProductConfig{
					{Name: "residential-fiber", Enabled: true, Role: "subscriber"},
				},
			},
			L2TPWholesale: BroadbandL2TPWholesaleConfig{
				Enabled:                     true,
				Mode:                        "enforce",
				FailClosed:                  true,
				RequirePPPoE:                true,
				RequireSubscriberState:      true,
				RequireProxyRoutes:          true,
				RequireAccountingDelegation: true,
				RequireTunnelFailover:       true,
				RealmIsolationRequired:      true,
				StripCustomerRealm:          true,
				AccountingDelegationEnabled: true,
				CoAOnFailover:               true,
				SelectionPolicy:             "realm",
				DefaultTunnelProfile:        "lns-primary",
				Realms: []BroadbandWholesaleRealmConfig{
					{Name: "wholesale-retail", Enabled: true, Realm: "retail.example.net", Tenant: "retail", Partner: "partner-a", MatchRealms: []string{"retail.example.net"}, AccessMethod: "pppoe", TunnelProfile: "lns-primary", ProxyRoute: "wholesale-retail-auth", AccountingRoute: "wholesale-retail-acct", AddressPool: "wholesale-v4", QoSProfile: "silver", Product: "residential-fiber", StripRealm: true, RequireAccounting: true, VendorPacks: []string{"standard", "cisco", "juniper", "nokia"}},
				},
				TunnelProfiles: []BroadbandL2TPTunnelProfileConfig{
					{Name: "lns-primary", Enabled: true, Mode: "lns", LocalName: "aegisnas-lac", PeerName: "partner-lns-1", PeerAddress: "192.0.2.10", SecretRef: "env:L2TP_SECRET", TunnelGroup: "wholesale-retail", RequireEncryption: true, AllowedAuth: []string{"pap", "chap"}, VendorPacks: []string{"cisco", "juniper", "nokia"}},
					{Name: "lns-backup", Enabled: true, Mode: "lns", LocalName: "aegisnas-lac", PeerName: "partner-lns-2", PeerAddress: "192.0.2.11", SecretRef: "env:L2TP_SECRET", TunnelGroup: "wholesale-retail-backup", RequireEncryption: true, AllowedAuth: []string{"pap", "chap"}, VendorPacks: []string{"cisco"}},
				},
				FailoverPolicies: []BroadbandL2TPFailoverPolicyConfig{
					{Name: "retail-failover", Enabled: true, Realm: "retail.example.net", PrimaryTunnel: "lns-primary", BackupTunnels: []string{"lns-backup"}, Action: "standby", HoldDownSeconds: 30, MaxFailures: 3, AccountingReplay: true, CoAAction: "reauth"},
				},
			},
		},
	}
}
