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

func TestPreviewBroadbandServiceActivationBuildsCompiledPlan(t *testing.T) {
	cfg := loadBroadbandServiceActivationTestConfig(t)

	report, err := PreviewBroadbandServiceActivation(cfg)
	require.NoError(t, err)
	assert.Equal(t, BroadbandServiceActivationFeatureID, report.FeatureID)
	assert.Equal(t, "ready", report.Status)
	assert.Equal(t, 100.0, report.SoftwareCompletionPercent)
	assert.True(t, report.ReadyForExternalValidation)
	assert.Equal(t, 1, report.Summary.ServiceCount)
	assert.Equal(t, 1, report.Summary.RoutePolicyCount)
	assert.Equal(t, 1, report.Summary.MulticastProfileCount)
	assert.Equal(t, 1, report.Summary.ActivationPolicyCount)
	assert.GreaterOrEqual(t, report.Summary.RouteAttributeCount, 8)
	assert.GreaterOrEqual(t, report.Summary.MulticastAttributeCount, 8)
	assert.GreaterOrEqual(t, report.Summary.RadiusAttributeCount, 10)
	assert.Equal(t, report.Summary.ComplianceCheckCount, report.Summary.PassedCheckCount)
	assert.Empty(t, report.Blockers)
	assert.NotEmpty(t, report.PlanFingerprint)
	require.NotEmpty(t, report.Services)
	assert.Contains(t, serviceActivationAttributeNames(report.Services[0].RouteAttributes), "Framed-Route")
	assert.Contains(t, serviceActivationAttributeNames(report.Services[0].RouteAttributes), "Framed-IPv6-Route")
	assert.Contains(t, serviceActivationAttributeNames(report.Services[0].MulticastAttributes), "AegisNAS-Multicast-Group")
	assert.Contains(t, serviceActivationAttributeNames(report.Services[0].RadiusAttributes), "ERX-Service-Activate")
	assert.Contains(t, serviceActivationAttributeNames(report.Services[0].RadiusAttributes), "ERX-Update-Service")
	assert.Contains(t, serviceActivationAttributeNames(report.Services[0].RadiusAttributes), "Nokia-Service-Name")
}

func TestPreviewBroadbandServiceActivationBlocksMissingRouteExport(t *testing.T) {
	cfg := loadBroadbandServiceActivationTestConfig(t)
	cfg.Radius.RoutePolicy.DynamicRouting.Enabled = false

	report, err := PreviewBroadbandServiceActivation(cfg)
	require.NoError(t, err)
	assert.Equal(t, "blocked", report.Status)
	assert.Contains(t, strings.Join(report.Blockers, "\n"), "radius.route_policy.dynamic_routing.enabled")
}

func TestApplyBroadbandServiceActivationRecordsEvidenceAndRuntimeStatus(t *testing.T) {
	cfg := loadBroadbandServiceActivationTestConfig(t)
	previousDB := db.DB
	require.NoError(t, db.Init(":memory:"))
	db.DB.SetMaxOpenConns(1)
	require.NoError(t, db.Migrate())
	t.Cleanup(func() {
		_ = db.Close()
		db.DB = previousDB
	})

	report, eventID, err := ApplyBroadbandServiceActivation(context.Background(), cfg, "ops@example.test")
	require.NoError(t, err)
	assert.Equal(t, "ready", report.Status)
	assert.NotEmpty(t, eventID)

	events, err := db.ListBroadbandServiceActivationEvents(10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "applied", events[0].Status)
	assert.Equal(t, 1, events[0].ServiceCount)
	assert.Equal(t, 1, events[0].RoutePolicyCount)
	assert.Equal(t, 1, events[0].MulticastProfileCount)

	transactions, err := db.ListBroadbandServiceActivationTransactions(10, "active")
	require.NoError(t, err)
	require.Len(t, transactions, 1)
	assert.Equal(t, "fiber-internet-activation", transactions[0].ServiceName)
	assert.Equal(t, "retail-bgp", transactions[0].RoutePolicy)
	assert.Equal(t, "iptv-basic", transactions[0].MulticastProfile)
	assert.True(t, transactions[0].RollbackRequired)

	runtime, err := db.GetRuntimeStatus(BroadbandServiceActivationComponent())
	require.NoError(t, err)
	require.NotNil(t, runtime)
	assert.Equal(t, "ok", runtime.Status)
	assert.Contains(t, runtime.Message, "NAS-0090")
}

func loadBroadbandServiceActivationTestConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		Radius: config.RadiusConfig{
			SQLAccounting:      config.RadiusSQLAccountingConfig{Enabled: true},
			AccountingServices: config.RadiusAccountingServicesConfig{Enabled: true},
			DynamicAuth:        config.DynamicAuthConfig{Enabled: true},
			RoutePolicy: config.RadiusRoutePolicyConfig{
				Enabled: true,
				DynamicRouting: config.RadiusDynamicRoutingConfig{
					Enabled: true,
				},
			},
		},
		Broadband: config.BroadbandConfig{
			Subscriber: config.BroadbandSubscriberStateConfig{
				Enabled:             true,
				DefaultAccessMethod: "pppoe",
				Products: []config.BroadbandSubscriberProductConfig{
					{Name: "residential-fiber", Enabled: true, Role: "subscriber", ServiceChain: "retail-internet", AddressPool: "pppoe-v4", QoSProfile: "silver", RoutePolicy: "retail-bgp", VendorPacks: []string{"standard", "erx", "huawei", "nokia"}},
				},
			},
			CommercialCatalog: config.BroadbandCommercialCatalog{Enabled: true},
			AddressLeases:     config.BroadbandAddressLeaseConfig{Enabled: true},
			QoSServiceFlows:   config.BroadbandQoSServiceFlowConfig{Enabled: true},
			DHCPSecurity:      config.BroadbandDHCPSecurityConfig{Enabled: true},
			ServiceActivation: config.BroadbandServiceActivationConfig{
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
				Services: []config.BroadbandServiceActivationServiceConfig{
					{Name: "fiber-internet-activation", Enabled: true, Required: true, Product: "residential-fiber", SubscriberID: "sub-lab-cpe-01", Username: "lab-cpe-01@example.net", Tenant: "retail", ServiceChain: "retail-internet", RoutePolicy: "retail-bgp", MulticastProfile: "iptv-basic", AddressPool: "pppoe-v4", QoSProfile: "silver", AccountingClass: "internet", VendorPacks: []string{"standard", "erx", "huawei", "h3c", "nokia", "zte"}},
				},
				RoutePolicies: []config.BroadbandActivationRoutePolicyConfig{
					{Name: "retail-bgp", Enabled: true, VRF: "retail", Protocol: "bgp", IPv4Routes: []string{"100.64.0.0/24"}, IPv6Routes: []string{"2001:db8:100::/48"}, NextHop: "192.0.2.1", RouteTarget: "65000:100", Metric: 100, Preference: 100, WithdrawOnDeactivate: true, VendorPacks: []string{"standard", "erx", "huawei", "h3c", "nokia", "zte"}},
				},
				MulticastProfiles: []config.BroadbandMulticastProfileConfig{
					{Name: "iptv-basic", Enabled: true, Mode: "igmp-mld", Groups: []string{"239.1.1.1", "ff3e::1"}, SourceAddresses: []string{"198.51.100.10"}, MaxGroups: 64, QuerierInterface: "eth1.100", VLAN: 120, VRF: "retail", EntitlementRequired: true, VendorPacks: []string{"standard", "erx", "huawei", "h3c", "nokia", "zte"}},
				},
				ActivationPolicies: []config.BroadbandActivationPolicyConfig{
					{Name: "retail-transactional", Enabled: true, MatchProduct: "residential-fiber", MatchTenant: "retail", AllowRollback: true, RequireRoutes: true, RequireMulticast: true, RequireAccounting: true, ChangeWindow: "always", FailureAction: "rollback"},
				},
			},
		},
	}
}

func serviceActivationAttributeNames(attributes []BroadbandServiceActivationAttribute) []string {
	names := make([]string, 0, len(attributes))
	for _, attribute := range attributes {
		names = append(names, attribute.Name)
	}
	return names
}
