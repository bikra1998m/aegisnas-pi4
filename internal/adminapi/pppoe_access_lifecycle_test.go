package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestPPPoEAccessLifecycleAPIPreviewApplyStatusHistoryReadinessAndSupportBundle(t *testing.T) {
	preparePPPoEAccessLifecycleAPITestRuntime(t)

	previewRec := httptest.NewRecorder()
	HandlePreviewPPPoEAccessLifecycle(previewRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/pppoe-access-lifecycle/preview", nil))
	require.Equal(t, http.StatusOK, previewRec.Code, previewRec.Body.String())
	var previewPayload struct {
		EventID string `json:"event_id"`
		Report  struct {
			FeatureID       string `json:"feature_id"`
			Status          string `json:"status"`
			PlanFingerprint string `json:"plan_fingerprint"`
			Summary         struct {
				EnabledInterfaceCount    int `json:"enabled_interface_count"`
				EnabledProfileCount      int `json:"enabled_profile_count"`
				PacketStageCount         int `json:"packet_stage_count"`
				RadiusAttributeCount     int `json:"radius_attribute_count"`
				EnforcementActionCount   int `json:"enforcement_action_count"`
				ComplianceCheckCount     int `json:"compliance_check_count"`
				PassedCheckCount         int `json:"passed_check_count"`
				BlockerCount             int `json:"blocker_count"`
				ExternalRequirementCount int `json:"external_requirement_count"`
			} `json:"summary"`
		} `json:"report"`
	}
	require.NoError(t, json.Unmarshal(previewRec.Body.Bytes(), &previewPayload))
	assert.NotEmpty(t, previewPayload.EventID)
	assert.Equal(t, "NAS-0082", previewPayload.Report.FeatureID)
	assert.Equal(t, "ready", previewPayload.Report.Status)
	assert.Equal(t, 1, previewPayload.Report.Summary.EnabledInterfaceCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.EnabledProfileCount)
	assert.GreaterOrEqual(t, previewPayload.Report.Summary.PacketStageCount, 10)
	assert.GreaterOrEqual(t, previewPayload.Report.Summary.RadiusAttributeCount, 16)
	assert.Equal(t, previewPayload.Report.Summary.ComplianceCheckCount, previewPayload.Report.Summary.PassedCheckCount)
	assert.Zero(t, previewPayload.Report.Summary.BlockerCount)
	assert.Greater(t, previewPayload.Report.Summary.ExternalRequirementCount, 0)
	assert.NotEmpty(t, previewPayload.Report.PlanFingerprint)

	applyRec := httptest.NewRecorder()
	HandleApplyPPPoEAccessLifecycle(applyRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/pppoe-access-lifecycle/apply", nil))
	require.Equal(t, http.StatusOK, applyRec.Code, applyRec.Body.String())
	assert.Contains(t, applyRec.Body.String(), `"status":"applied"`)

	statusRec := httptest.NewRecorder()
	HandleGetPPPoEAccessLifecycle(statusRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/pppoe-access-lifecycle", nil))
	require.Equal(t, http.StatusOK, statusRec.Code, statusRec.Body.String())
	assert.Contains(t, statusRec.Body.String(), `"ready_for_external_validation":true`)
	assert.Contains(t, statusRec.Body.String(), `"recent_events"`)

	historyRec := httptest.NewRecorder()
	HandleListPPPoEAccessLifecycleHistory(historyRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/pppoe-access-lifecycle/history?limit=5", nil))
	require.Equal(t, http.StatusOK, historyRec.Code, historyRec.Body.String())
	assert.Contains(t, historyRec.Body.String(), `"feature_id":"NAS-0082"`)
	assert.Contains(t, historyRec.Body.String(), `"preview_events":1`)
	assert.Contains(t, historyRec.Body.String(), `"applied_count":1`)

	readiness := buildProductionReadinessReport(config.Get())
	assert.Equal(t, "passed", productionReadinessCheckStatus(readiness.Checks, "pppoe_access_lifecycle"))

	systemRec := httptest.NewRecorder()
	HandleGetSystemStatus(systemRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/status", nil))
	require.Equal(t, http.StatusOK, systemRec.Code, systemRec.Body.String())
	assert.Contains(t, systemRec.Body.String(), `"pppoe_access_lifecycle"`)

	spec := buildOpenAPISpec(httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil), config.Get())
	paths := spec["paths"].(map[string]any)
	for _, path := range []string{
		"/api/v1/system/pppoe-access-lifecycle",
		"/api/v1/system/pppoe-access-lifecycle/preview",
		"/api/v1/system/pppoe-access-lifecycle/apply",
		"/api/v1/system/pppoe-access-lifecycle/history",
	} {
		_, ok := paths[path]
		assert.True(t, ok, "OpenAPI path %s should exist", path)
	}

	foundStatusCapture := false
	foundHistoryCapture := false
	for _, capture := range supportBundleAPICaptures() {
		if capture.archivePath == "api/pppoe-access-lifecycle.json" {
			foundStatusCapture = true
		}
		if capture.archivePath == "api/pppoe-access-lifecycle-history.json" {
			foundHistoryCapture = true
		}
	}
	assert.True(t, foundStatusCapture)
	assert.True(t, foundHistoryCapture)
}

func TestPPPoEAccessLifecycleRBAC(t *testing.T) {
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/pppoe-access-lifecycle"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/pppoe-access-lifecycle/preview"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/pppoe-access-lifecycle/history"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/pppoe-access-lifecycle/apply"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/pppoe-access-lifecycle/apply"))
}

func preparePPPoEAccessLifecycleAPITestRuntime(t *testing.T) {
	t.Helper()
	previousDB := db.DB
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
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
policy:
  default_role: residential
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(content), 0o600))
	_, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.NoError(t, db.Init(":memory:"))
	db.DB.SetMaxOpenConns(1)
	require.NoError(t, db.Migrate())
	t.Cleanup(func() {
		_ = db.Close()
		db.DB = previousDB
	})
}
