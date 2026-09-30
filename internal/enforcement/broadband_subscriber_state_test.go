package enforcement

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestPreviewBroadbandSubscriberStateBuildsFullPlan(t *testing.T) {
	cfg := loadBroadbandSubscriberStateTestConfig(t, "")

	report, err := PreviewBroadbandSubscriberState(cfg)
	require.NoError(t, err)

	assert.Equal(t, BroadbandSubscriberStateFeatureID, report.FeatureID)
	assert.Equal(t, "ready", report.Status, "blockers: %v warnings: %v", report.Blockers, report.Warnings)
	assert.True(t, report.ReadyForExternalValidation)
	assert.Equal(t, float64(100), report.SoftwareCompletionPercent)
	assert.Equal(t, "enforce", report.Summary.Mode)
	assert.Equal(t, "pppoe", report.Summary.DefaultAccessMethod)
	assert.GreaterOrEqual(t, report.Summary.StateCount, 15)
	assert.GreaterOrEqual(t, report.Summary.TransitionCount, 20)
	assert.Equal(t, 1, report.Summary.EnabledProductCount)
	assert.Equal(t, 2, report.Summary.EnabledServicePolicyCount)
	assert.Equal(t, report.Summary.ComplianceCheckCount, report.Summary.PassedCheckCount)
	assert.NotEmpty(t, report.PlanFingerprint)
	assert.Contains(t, report.ReleaseCertificationChecklist, "nas-0083")
}

func TestPreviewBroadbandSubscriberStateBlocksUnsafeEnforceConfig(t *testing.T) {
	cfg := loadBroadbandSubscriberStateTestConfig(t, `
  subscriber_state:
    enabled: true
    mode: enforce
    fail_closed: true
    default_access_method: pppoe
    products: []
    service_policies: []
`)

	report, err := PreviewBroadbandSubscriberState(cfg)
	require.NoError(t, err)

	assert.Equal(t, "blocked", report.Status)
	assert.False(t, report.ReadyForExternalValidation)
	assert.Contains(t, strings.Join(report.Blockers, " "), "enabled product")
}

func TestPreviewBroadbandSubscriberStateSkippedWhenDisabled(t *testing.T) {
	cfg := loadBroadbandSubscriberStateTestConfig(t, "disabled")

	report, err := PreviewBroadbandSubscriberState(cfg)
	require.NoError(t, err)

	assert.Equal(t, "skipped", report.Status)
	assert.True(t, report.ReadyForExternalValidation)
	assert.False(t, report.Summary.Enabled)
	assert.NotEmpty(t, report.Transitions)
	assert.NotEmpty(t, report.PlanFingerprint)
}

func TestApplyBroadbandSubscriberStateRecordsEvidenceAndRuntimeStatus(t *testing.T) {
	cfg := loadBroadbandSubscriberStateTestConfig(t, "")
	previousDB := db.DB
	require.NoError(t, db.Init(":memory:"))
	db.DB.SetMaxOpenConns(1)
	require.NoError(t, db.Migrate())
	t.Cleanup(func() {
		_ = db.Close()
		db.DB = previousDB
	})

	report, eventID, err := ApplyBroadbandSubscriberState(context.Background(), cfg, "ops@example.test")
	require.NoError(t, err)

	assert.Equal(t, "applied", report.Status)
	assert.NotEmpty(t, eventID)

	events, err := db.ListBroadbandSubscriberStateEvents(10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "apply", events[0].Operation)
	assert.Equal(t, "applied", events[0].Status)
	assert.Equal(t, 1, events[0].ProductCount)

	runtime, err := db.GetRuntimeStatus(BroadbandSubscriberStateComponent())
	require.NoError(t, err)
	require.NotNil(t, runtime)
	assert.Equal(t, "ok", runtime.Status)
	assert.Contains(t, runtime.Message, "NAS-0083")
}

func loadBroadbandSubscriberStateTestConfig(t *testing.T, override string) *config.Config {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	subscriberBlock := `
  subscriber_state:
    enabled: true
    mode: enforce
    fail_closed: true
    default_access_method: pppoe
    max_sessions: 4096
    max_sessions_per_subscriber: 4
    max_reconnects: 3
    reconnect_window_seconds: 300
    accounting_grace_seconds: 90
    recovery_scan_seconds: 60
    require_accounting_start: true
    require_accounting_stop: true
    require_session_ownership: true
    service_legs_enabled: true
    policy_transitions_enabled: true
    reconnect_recovery_enabled: true
    quota_hooks_enabled: true
    charging_hooks_enabled: true
    dual_stack_required: true
    route_policy_required: true
    qos_required: true
    nat_required: true
    coa_required: true
    products:
      - name: residential-fiber
        enabled: true
        role: residential
        service_chain: retail-internet
        address_pool: pppoe-v4
        ipv6_pool: pppoe-v6
        delegated_ipv6_pool: pppoe-pd
        route_policy: residential
        qos_profile: silver
        translation_pool: cgnat-pool
        quota_profile: unlimited
        max_sessions: 4
        vendor_packs: [standard, aegisnas, mikrotik, huawei]
    service_policies:
      - name: base-internet-start
        enabled: true
        product: residential-fiber
        leg: internet
        trigger: accounting-start
        required_state: service_active
        next_state: accounting_started
        accounting_class: internet
        route_policy: residential
        qos_profile: silver
        translation_pool: cgnat-pool
        vendor_packs: [standard, aegisnas, mikrotik]
      - name: quota-policy-update
        enabled: true
        product: residential-fiber
        leg: quota
        trigger: quota-threshold
        required_state: interim_seen
        next_state: policy_update_pending
        coa_action: rate-limit
        qos_profile: silver
        vendor_packs: [standard, aegisnas]
    failure_policies:
      - name: accounting-gap-recovery
        enabled: true
        failure: accounting-gap
        action: recover
        target_state: recovered
        recovery_after_seconds: 120
`
	if override == "disabled" {
		subscriberBlock = strings.Replace(subscriberBlock, "    enabled: true\n", "    enabled: false\n", 1)
	} else if strings.TrimSpace(override) != "" {
		subscriberBlock = override
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
  sql_accounting:
    enabled: true
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
  pppoe:
    enabled: true
    mode: enforce
    fail_closed: true
    access_concentrator_name: aegisnas-bng-01
    service_name: internet
    max_sessions: 4096
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
        vendor_packs: [mikrotik, alcatel-lucent-service-router, huawei]
` + subscriberBlock + `
policy:
  default_role: residential
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	cfg, err := config.Load(path)
	require.NoError(t, err)
	return cfg
}
