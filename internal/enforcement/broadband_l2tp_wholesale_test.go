package enforcement

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestPreviewBroadbandL2TPWholesaleBuildsCompiledPlan(t *testing.T) {
	cfg := loadBroadbandL2TPWholesaleTestConfig(t)

	report, err := PreviewBroadbandL2TPWholesale(cfg)
	require.NoError(t, err)
	assert.Equal(t, BroadbandL2TPWholesaleFeatureID, report.FeatureID)
	assert.Equal(t, "ready", report.Status)
	assert.Equal(t, 100.0, report.SoftwareCompletionPercent)
	assert.True(t, report.ReadyForExternalValidation)
	assert.Equal(t, 1, report.Summary.RealmCount)
	assert.Equal(t, 2, report.Summary.TunnelProfileCount)
	assert.Equal(t, 1, report.Summary.FailoverPolicyCount)
	assert.GreaterOrEqual(t, report.Summary.CompiledAttributeCount, 8)
	assert.Equal(t, report.Summary.ComplianceCheckCount, report.Summary.PassedCheckCount)
	assert.Empty(t, report.Blockers)
	assert.NotEmpty(t, report.PlanFingerprint)
	require.NotEmpty(t, report.Realms)
	assert.Equal(t, "retail-failover", report.Realms[0].FailoverPolicy)
	assert.Contains(t, l2tpAttributeNames(report.Realms[0].CompiledAttributes), "Tunnel-Type")
	assert.Contains(t, l2tpAttributeNames(report.Realms[0].CompiledAttributes), "Proxy-State")
	assert.Contains(t, l2tpAttributeNames(report.Realms[0].CompiledAttributes), "Cisco-AVPair")
}

func TestPreviewBroadbandL2TPWholesaleBlocksMissingCoA(t *testing.T) {
	cfg := loadBroadbandL2TPWholesaleTestConfig(t)
	cfg.Radius.DynamicAuth.Enabled = false

	report, err := PreviewBroadbandL2TPWholesale(cfg)
	require.NoError(t, err)
	assert.Equal(t, "blocked", report.Status)
	assert.Contains(t, strings.Join(report.Blockers, "\n"), "CoA")
}

func TestApplyBroadbandL2TPWholesaleRecordsEvidenceAndRuntimeStatus(t *testing.T) {
	cfg := loadBroadbandL2TPWholesaleTestConfig(t)
	previousDB := db.DB
	require.NoError(t, db.Init(":memory:"))
	db.DB.SetMaxOpenConns(1)
	require.NoError(t, db.Migrate())
	t.Cleanup(func() {
		_ = db.Close()
		db.DB = previousDB
	})

	report, eventID, err := ApplyBroadbandL2TPWholesale(context.Background(), cfg, "ops@example.test")
	require.NoError(t, err)
	assert.Equal(t, "ready", report.Status)
	assert.NotEmpty(t, eventID)

	events, err := db.ListBroadbandL2TPWholesaleEvents(10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "applied", events[0].Status)
	assert.Equal(t, 1, events[0].RealmCount)

	bindings, err := db.ListBroadbandL2TPWholesaleBindings(10, "active")
	require.NoError(t, err)
	require.Len(t, bindings, 1)
	assert.Equal(t, "wholesale-retail", bindings[0].RealmName)
	assert.Equal(t, "lns-primary", bindings[0].TunnelProfile)

	runtime, err := db.GetRuntimeStatus(BroadbandL2TPWholesaleComponent())
	require.NoError(t, err)
	require.NotNil(t, runtime)
	assert.Equal(t, "ok", runtime.Status)
	assert.Contains(t, runtime.Message, "NAS-0088")
}

func loadBroadbandL2TPWholesaleTestConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		Radius: config.RadiusConfig{
			SQLAccounting:      config.RadiusSQLAccountingConfig{Enabled: true},
			AccountingServices: config.RadiusAccountingServicesConfig{Enabled: true},
			DynamicAuth:        config.DynamicAuthConfig{Enabled: true},
			Upstream: config.RadiusUpstreamConfig{
				Enabled: true,
				Routes: []config.RadiusProxyRouteConfig{
					{Name: "wholesale-retail-auth", Enabled: true, Realm: "retail.example.net"},
					{Name: "wholesale-retail-acct", Enabled: true, Realm: "acct.retail.example.net"},
				},
			},
		},
		Broadband: config.BroadbandConfig{
			PPPoE: config.BroadbandPPPoEConfig{Enabled: true},
			Subscriber: config.BroadbandSubscriberStateConfig{
				Enabled:             true,
				WholesaleEnabled:    true,
				DefaultAccessMethod: "pppoe",
				Products: []config.BroadbandSubscriberProductConfig{
					{Name: "residential-fiber", Enabled: true, Role: "subscriber"},
				},
			},
			L2TPWholesale: config.BroadbandL2TPWholesaleConfig{
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
				Realms: []config.BroadbandWholesaleRealmConfig{
					{Name: "wholesale-retail", Enabled: true, Realm: "retail.example.net", Tenant: "retail", Partner: "partner-a", MatchRealms: []string{"retail.example.net"}, AccessMethod: "pppoe", TunnelProfile: "lns-primary", ProxyRoute: "wholesale-retail-auth", AccountingRoute: "wholesale-retail-acct", AddressPool: "wholesale-v4", QoSProfile: "silver", Product: "residential-fiber", StripRealm: true, RequireAccounting: true, VendorPacks: []string{"standard", "cisco", "juniper", "nokia"}},
				},
				TunnelProfiles: []config.BroadbandL2TPTunnelProfileConfig{
					{Name: "lns-primary", Enabled: true, Mode: "lns", LocalName: "aegisnas-lac", PeerName: "partner-lns-1", LocalAddress: "198.51.100.1", PeerAddress: "192.0.2.10", SecretRef: "env:L2TP_SECRET", TunnelGroup: "wholesale-retail", WindowSize: 4, HelloIntervalSeconds: 60, SessionLimit: 4096, RequireEncryption: true, AllowedAuth: []string{"pap", "chap"}, VendorPacks: []string{"cisco", "juniper", "nokia"}},
					{Name: "lns-backup", Enabled: true, Mode: "lns", LocalName: "aegisnas-lac", PeerName: "partner-lns-2", LocalAddress: "198.51.100.2", PeerAddress: "192.0.2.11", SecretRef: "env:L2TP_SECRET", TunnelGroup: "wholesale-retail-backup", WindowSize: 4, HelloIntervalSeconds: 60, SessionLimit: 4096, RequireEncryption: true, AllowedAuth: []string{"pap", "chap"}, VendorPacks: []string{"cisco"}},
				},
				FailoverPolicies: []config.BroadbandL2TPFailoverPolicyConfig{
					{Name: "retail-failover", Enabled: true, Realm: "retail.example.net", PrimaryTunnel: "lns-primary", BackupTunnels: []string{"lns-backup"}, Action: "standby", HoldDownSeconds: 30, MaxFailures: 3, AccountingReplay: true, CoAAction: "reauth"},
				},
			},
		},
	}
}

func l2tpAttributeNames(attrs []BroadbandL2TPRadiusAttribute) []string {
	names := make([]string, 0, len(attrs))
	for _, attr := range attrs {
		names = append(names, attr.Name)
	}
	return names
}
