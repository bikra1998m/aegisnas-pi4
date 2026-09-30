package enforcement

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestPreviewPPPoEAccessLifecycleBuildsFullPlan(t *testing.T) {
	cfg := loadPPPoEAccessLifecycleTestConfig(t, "")

	report, err := PreviewPPPoEAccessLifecycle(cfg)
	require.NoError(t, err)

	assert.Equal(t, PPPoEAccessLifecycleFeatureID, report.FeatureID)
	assert.Equal(t, "ready", report.Status, "blockers: %v warnings: %v", report.Blockers, report.Warnings)
	assert.True(t, report.ReadyForExternalValidation)
	assert.Equal(t, float64(100), report.SoftwareCompletionPercent)
	assert.Equal(t, "enforce", report.Summary.Mode)
	assert.Equal(t, "aegisnas-bng-01", report.Summary.AccessConcentratorName)
	assert.Equal(t, "internet", report.Summary.ServiceName)
	assert.Equal(t, 1, report.Summary.EnabledInterfaceCount)
	assert.Equal(t, 1, report.Summary.EnabledProfileCount)
	assert.GreaterOrEqual(t, report.Summary.PacketStageCount, 10)
	assert.GreaterOrEqual(t, report.Summary.RadiusAttributeCount, 16)
	assert.Equal(t, report.Summary.ComplianceCheckCount, report.Summary.PassedCheckCount)
	assert.Zero(t, report.Summary.BlockerCount)
	assert.NotEmpty(t, report.PlanFingerprint)
	assert.Equal(t, "docs/nas-0082-release-certification-checklist.md", report.ReleaseCertificationChecklist)
	assert.Contains(t, fmt.Sprint(report.PacketStages), "PADI")
	assert.Contains(t, fmt.Sprint(report.RadiusAttributes), "NAS-Port-Type = PPPoE")
}

func TestPreviewPPPoEAccessLifecycleBlocksUnsafeEnforceConfig(t *testing.T) {
	cfg := loadPPPoEAccessLifecycleTestConfig(t, `
  pppoe:
    enabled: true
    mode: enforce
    fail_closed: true
    access_concentrator_name: aegisnas-bng-01
    service_name: internet
    interfaces: []
    profiles: []
`)

	report, err := PreviewPPPoEAccessLifecycle(cfg)
	require.NoError(t, err)

	assert.Equal(t, "blocked", report.Status)
	assert.False(t, report.ReadyForExternalValidation)
	assert.Equal(t, float64(100), report.SoftwareCompletionPercent)
	assert.Contains(t, fmt.Sprint(report.Blockers), "at least one enabled interface")
}

func TestPreviewPPPoEAccessLifecycleSkippedWhenDisabled(t *testing.T) {
	cfg := loadPPPoEAccessLifecycleTestConfig(t, "disabled")

	report, err := PreviewPPPoEAccessLifecycle(cfg)
	require.NoError(t, err)

	assert.Equal(t, "skipped", report.Status)
	assert.True(t, report.ReadyForExternalValidation)
	assert.Equal(t, float64(100), report.SoftwareCompletionPercent)
	assert.False(t, report.Summary.Enabled)
	assert.Empty(t, report.Interfaces)
	assert.NotEmpty(t, report.PlanFingerprint)
}

func TestApplyPPPoEAccessLifecycleRecordsEvidenceAndRuntimeStatus(t *testing.T) {
	cfg := loadPPPoEAccessLifecycleTestConfig(t, "")
	previousDB := db.DB
	require.NoError(t, db.Init(":memory:"))
	db.DB.SetMaxOpenConns(1)
	require.NoError(t, db.Migrate())
	t.Cleanup(func() {
		_ = db.Close()
		db.DB = previousDB
	})

	report, eventID, err := ApplyPPPoEAccessLifecycle(context.Background(), cfg, "ops@example.test")
	require.NoError(t, err)

	assert.Equal(t, "applied", report.Status)
	assert.NotEmpty(t, eventID)

	events, err := db.ListPPPoEAccessLifecycleEvents(10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "apply", events[0].Operation)
	assert.Equal(t, "applied", events[0].Status)
	assert.Equal(t, "ops@example.test", events[0].Actor)
	assert.Equal(t, 1, events[0].InterfaceCount)
	assert.Equal(t, 1, events[0].ProfileCount)

	runtime, err := db.GetRuntimeStatus(PPPoEAccessLifecycleComponent())
	require.NoError(t, err)
	require.NotNil(t, runtime)
	assert.Equal(t, "ok", runtime.Status)
	assert.Contains(t, runtime.Message, "NAS-0082")
}

func loadPPPoEAccessLifecycleTestConfig(t *testing.T, override string) *config.Config {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	pppoeBlock := `
  pppoe:
    enabled: true
    mode: enforce
    fail_closed: true
    access_concentrator_name: aegisnas-bng-01
    service_name: internet
    max_sessions: 4096
    max_sessions_per_mac: 4
    mtu: 1492
    mru: 1492
    require_chap: true
    accounting_required: true
    session_ownership_required: true
    ipv6cp_enabled: true
    prefix_delegation_enabled: true
    route_injection_enabled: true
    qos_enabled: true
    nat_translation_enabled: true
    coa_enabled: true
    interfaces:
      - name: eth1.100
        enabled: true
        vlan: 100
        max_sessions: 2048
        pado_delay_ms: 10
    profiles:
      - name: residential
        enabled: true
        role: residential
        address_pool: pppoe-v4
        ipv6_pool: pppoe-v6
        delegated_ipv6_pool: pppoe-pd
        route_policy: residential
        qos_profile: silver
        translation_pool: cgnat-pool
        service_chain: retail-internet
        rate_limit: 100m
        vendor_packs: [mikrotik, alcatel-lucent-service-router, huawei]
`
	if override == "disabled" {
		pppoeBlock = strings.Replace(pppoeBlock, "    enabled: true\n", "    enabled: false\n", 1)
	} else if strings.TrimSpace(override) != "" {
		pppoeBlock = override
	}
	content := `
mode: two-nic
deployment:
  profile: enterprise
  form: physical
database:
  path: ":memory:"
wan:
  name: ens33
  dhcp: true
lan:
  name: ens37
  address: 192.168.50.1/24
high_availability:
  enabled: true
  role: active
  peer_api_url: "https://192.0.2.20:8083"
  virtual_ip: "192.0.2.10"
radius:
  secret: radius-secret
  dynamic_auth:
    enabled: true
    outbound_enabled: true
    outbound_require_known_client: true
  accounting_services:
    enabled: true
    correlate_subscriber_chains: true
    retention_days: 365
    max_recent_services: 100
  address_policy:
    enabled: true
    pools:
      - name: pppoe-v4
        family: ipv4
        cidr: 100.64.0.0/24
        start: 100.64.0.10
        end: 100.64.0.250
        gateway: 100.64.0.1
        mode: address
      - name: pppoe-v6
        family: ipv6
        cidr: 2001:db8:100::/48
        prefix_length: 64
        mode: prefix
      - name: pppoe-pd
        family: ipv6
        cidr: 2001:db8:200::/40
        delegated_prefix_length: 56
        mode: delegated-prefix
    role_policies:
      - role: residential
        owner: broadband-team
        ipv4_pool: pppoe-v4
        ipv6_pool: pppoe-v6
        delegated_ipv6_pool: pppoe-pd
        dhcpv6_mode: stateful-pd
        vendor_packs: [standard, aegisnas, mikrotik, huawei]
  route_policy:
    enabled: true
    default_vrf: internet
    vrfs:
      - name: internet
    role_policies:
      - role: residential
        vrf: internet
        owner: aegisnas
        ipv4_routes:
          - destination: 100.64.0.0/24
            gateway: 192.0.2.1
            install: true
  translation_policy:
    enabled: true
    pools:
      - name: cgnat-pool
        family: ipv4
        cidr: 198.51.100.0/24
        port_start: 1024
        port_end: 65535
        port_block_size: 512
    role_policies:
      - role: residential
        translation_mode: cgnat
        public_pool: cgnat-pool
broadband:
` + pppoeBlock + `
policy:
  default_role: residential
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	cfg, err := config.Load(path)
	require.NoError(t, err)
	return cfg
}
