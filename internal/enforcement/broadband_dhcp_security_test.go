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

func TestPreviewBroadbandDHCPSecurityBuildsCompiledPlan(t *testing.T) {
	cfg := loadBroadbandDHCPSecurityTestConfig(t)

	report, err := PreviewBroadbandDHCPSecurity(cfg)
	require.NoError(t, err)
	assert.Equal(t, BroadbandDHCPSecurityFeatureID, report.FeatureID)
	assert.Equal(t, "ready", report.Status)
	assert.Equal(t, 100.0, report.SoftwareCompletionPercent)
	assert.True(t, report.ReadyForExternalValidation)
	assert.Equal(t, 1, report.Summary.RelayAgentCount)
	assert.Equal(t, 2, report.Summary.PortCount)
	assert.Equal(t, 1, report.Summary.TrustedPortCount)
	assert.Equal(t, 1, report.Summary.Option82RuleCount)
	assert.Equal(t, 1, report.Summary.SourceGuardPolicyCount)
	assert.GreaterOrEqual(t, report.Summary.CompiledOptionCount, 7)
	assert.Equal(t, report.Summary.ComplianceCheckCount, report.Summary.PassedCheckCount)
	assert.Empty(t, report.Blockers)
	assert.NotEmpty(t, report.PlanFingerprint)
	require.NotEmpty(t, report.Ports)
	assert.Contains(t, dhcpSecurityOptionNames(report.Ports[0].CompiledOptions), "DHCP-Relay-Agent-Information")
	assert.Contains(t, dhcpSecurityOptionNames(report.Ports[0].CompiledOptions), "Agent-Circuit-Id")
	assert.Contains(t, dhcpSecurityOptionNames(report.Ports[0].CompiledOptions), "Agent-Remote-Id")
	assert.Contains(t, dhcpSecurityOptionNames(report.Ports[0].CompiledOptions), "Cisco-AVPair")
	assert.Contains(t, dhcpSecurityOptionNames(report.Ports[0].CompiledOptions), "Source-Guard")
}

func TestPreviewBroadbandDHCPSecurityBlocksMissingDHCP(t *testing.T) {
	cfg := loadBroadbandDHCPSecurityTestConfig(t)
	cfg.DHCP.Enabled = false

	report, err := PreviewBroadbandDHCPSecurity(cfg)
	require.NoError(t, err)
	assert.Equal(t, "blocked", report.Status)
	assert.Contains(t, strings.Join(report.Blockers, "\n"), "dhcp.enabled")
}

func TestApplyBroadbandDHCPSecurityRecordsEvidenceAndRuntimeStatus(t *testing.T) {
	cfg := loadBroadbandDHCPSecurityTestConfig(t)
	previousDB := db.DB
	require.NoError(t, db.Init(":memory:"))
	db.DB.SetMaxOpenConns(1)
	require.NoError(t, db.Migrate())
	t.Cleanup(func() {
		_ = db.Close()
		db.DB = previousDB
	})

	report, eventID, err := ApplyBroadbandDHCPSecurity(context.Background(), cfg, "ops@example.test")
	require.NoError(t, err)
	assert.Equal(t, "ready", report.Status)
	assert.NotEmpty(t, eventID)

	events, err := db.ListBroadbandDHCPSecurityEvents(10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "applied", events[0].Status)
	assert.Equal(t, 2, events[0].PortCount)

	bindings, err := db.ListBroadbandDHCPSecurityBindings(10, "active")
	require.NoError(t, err)
	require.Len(t, bindings, 2)
	var subscriberBinding db.BroadbandDHCPSecurityBindingRecord
	for _, binding := range bindings {
		if binding.PortName == "subscriber-port-1" {
			subscriberBinding = binding
		}
	}
	require.Equal(t, "subscriber-port-1", subscriberBinding.PortName)
	assert.Equal(t, "strict-access", subscriberBinding.SourceGuardPolicy)

	runtime, err := db.GetRuntimeStatus(BroadbandDHCPSecurityComponent())
	require.NoError(t, err)
	require.NotNil(t, runtime)
	assert.Equal(t, "ok", runtime.Status)
	assert.Contains(t, runtime.Message, "NAS-0089")
}

func loadBroadbandDHCPSecurityTestConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		DHCP: config.DHCPConfig{Enabled: true},
		Radius: config.RadiusConfig{
			SQLAccounting:      config.RadiusSQLAccountingConfig{Enabled: true},
			AccountingServices: config.RadiusAccountingServicesConfig{Enabled: true},
			DynamicAuth:        config.DynamicAuthConfig{Enabled: true},
		},
		Broadband: config.BroadbandConfig{
			Subscriber: config.BroadbandSubscriberStateConfig{
				Enabled:             true,
				DefaultAccessMethod: "dhcp",
				Products: []config.BroadbandSubscriberProductConfig{
					{Name: "residential-fiber", Enabled: true, Role: "subscriber"},
				},
			},
			AddressLeases: config.BroadbandAddressLeaseConfig{Enabled: true},
			DHCPSecurity: config.BroadbandDHCPSecurityConfig{
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
				RelayAgents: []config.BroadbandDHCPRelayAgentConfig{
					{Name: "relay-vlan100", Enabled: true, Interface: "eth1.100", VLAN: 100, GatewayAddress: "192.0.2.1", ServerGroup: "dhcp-core", VRF: "retail", CircuitIDTemplate: "{{interface}}:{{vlan}}", RemoteIDTemplate: "{{tenant}}", AppendOption82: true, Trusted: true, MaxClients: 4096, VendorPacks: []string{"standard", "cisco", "huawei"}},
				},
				Ports: []config.BroadbandDHCPSecurityPortConfig{
					{Name: "subscriber-port-1", Enabled: true, Interface: "eth1.100", VLAN: 100, Role: "access", CircuitID: "olt1/1/1", RemoteID: "retail", SubscriberProduct: "residential-fiber", Tenant: "retail", MaxLeases: 4, SourceGuardPolicy: "strict-access", VendorPacks: []string{"standard", "cisco"}},
					{Name: "uplink", Enabled: true, Interface: "eth1", VLAN: 0, Role: "uplink", Trusted: true, MaxLeases: 100000, VendorPacks: []string{"standard"}},
				},
				Option82Rules: []config.BroadbandDHCPOption82RuleConfig{
					{Name: "access-option82", Enabled: true, MatchInterface: "eth1.100", MatchVLAN: 100, CircuitIDTemplate: "{{port}}", RemoteIDTemplate: "{{tenant}}", Action: "append", RequireRemoteID: true, VendorPacks: []string{"standard", "cisco"}},
				},
				SourceGuardPolicies: []config.BroadbandDHCPSourceGuardPolicyConfig{
					{Name: "strict-access", Enabled: true, Mode: "enforce", Interfaces: []string{"eth1.100"}, VLANs: []int{100}, AllowUnknown: false, MaxBindings: 4096, IPv6Enabled: true, ActionOnViolation: "drop", CoAAction: "disconnect"},
				},
				RADIUSCorrelation: []config.BroadbandDHCPRADIUSCorrelationConfig{
					{Name: "option82-accounting", Enabled: true, Source: "option82", Attributes: []string{"Class", "NAS-Port-Id", "Calling-Station-Id"}, AccountingStages: []string{"start", "interim", "stop"}},
				},
			},
		},
	}
}

func dhcpSecurityOptionNames(options []BroadbandDHCPOption) []string {
	names := make([]string, 0, len(options))
	for _, option := range options {
		names = append(names, option.Name)
	}
	return names
}
