package adminapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestHandleGetProductionReadinessReportsVendorBlockers(t *testing.T) {
	dbPath := prepareProductionReadinessDB(t)
	_, err := db.DB.Exec(`INSERT INTO radius_clients (shortname, ipaddr, secret, nas_type, enabled) VALUES (?, ?, ?, ?, ?)`,
		"mystery-ap", "192.0.2.10", "secret", "mystery-vendor", true)
	require.NoError(t, err)

	cfgPath := writeProductionReadinessConfig(t, dbPath, productconfigs.AegisNASPlaceholderVendorID)
	_, err = config.Load(cfgPath)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/production-readiness", nil)
	rec := httptest.NewRecorder()
	HandleGetProductionReadiness(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var payload productionReadinessReport
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, "blocked", payload.Status)
	assert.False(t, payload.Ready)
	assert.True(t, payload.VendorIdentity.ConfiguredIDPlaceholder)
	assert.Equal(t, "blocked", productionReadinessCheckStatus(payload.Checks, "vendor_identity"))
	assert.Equal(t, "passed", productionReadinessCheckStatus(payload.Checks, "attribute_registry"))
	assert.Equal(t, "passed", productionReadinessCheckStatus(payload.Checks, "vsa_codec"))
	assert.Equal(t, "passed", productionReadinessCheckStatus(payload.Checks, "opaque_passthrough"))
	assert.Equal(t, "passed", productionReadinessCheckStatus(payload.Checks, "radius_packet_hardening"))
	assert.Equal(t, "passed", productionReadinessCheckStatus(payload.Checks, "radius_proxy_routes"))
	assert.Equal(t, "passed", productionReadinessCheckStatus(payload.Checks, "radius_proxy_policy"))
	assert.Equal(t, "passed", productionReadinessCheckStatus(payload.Checks, "radius_fallback_policy"))
	assert.Equal(t, "passed", productionReadinessCheckStatus(payload.Checks, "radius_outbound_dac_client"))
	assert.Equal(t, "degraded", productionReadinessCheckStatus(payload.Checks, "typed_policy_engine"))
	assert.Equal(t, "degraded", productionReadinessCheckStatus(payload.Checks, "policy_set_governance"))
	assert.Equal(t, "degraded", productionReadinessCheckStatus(payload.Checks, "policy_simulation_analysis"))
	assert.Equal(t, "blocked", productionReadinessCheckStatus(payload.Checks, "secret_providers"))
	assert.Equal(t, "degraded", productionReadinessCheckStatus(payload.Checks, "database_data_plane"))
	assert.Equal(t, "passed", productionReadinessCheckStatus(payload.Checks, "dictionary_release_profile"))
	assert.Equal(t, "degraded", productionReadinessCheckStatus(payload.Checks, "compatibility_evidence"))
	assert.Equal(t, "blocked", productionReadinessCheckStatus(payload.Checks, "nas_profile_coverage"))
	assert.GreaterOrEqual(t, payload.BlockingCount, 2)
}

func prepareProductionReadinessDB(t *testing.T) string {
	t.Helper()
	tmpfile, err := os.CreateTemp("", "production-readiness-*.db")
	require.NoError(t, err)
	dbPath := tmpfile.Name()
	require.NoError(t, tmpfile.Close())

	require.NoError(t, db.Init(dbPath))
	require.NoError(t, db.Migrate())
	t.Cleanup(func() {
		db.Close()
		_ = os.Remove(dbPath)
	})
	return dbPath
}

func writeProductionReadinessConfig(t *testing.T, dbPath string, vendorID int) string {
	t.Helper()
	tmpfile, err := os.CreateTemp("", "production-readiness-config-*.yaml")
	require.NoError(t, err)
	cfgPath := tmpfile.Name()
	require.NoError(t, tmpfile.Close())

	content := fmt.Sprintf(`
mode: two-nic
deployment:
  profile: enterprise
  form: physical
  hardware:
    memory_mb: 8192
    cpu_cores: 4
    storage_gb: 64
wan:
  name: eth0
  dhcp: true
lan:
  name: eth1
  address: 192.168.1.1/24
database:
  path: %s
ailite:
  enabled: false
radius:
  secret: secret
  dynamic_auth:
    enabled: true
    port: 3799
    outbound_enabled: true
    outbound_default_port: 3799
    outbound_timeout_seconds: 5
    outbound_require_known_client: true
    outbound_history_limit: 10000
    outbound_max_attributes: 32
    outbound_allow_coa: true
    outbound_allow_disconnect: true
    outbound_require_confirmation: true
    outbound_queue_enabled: true
    outbound_replay_enabled: true
    outbound_max_queue_records: 10000
    outbound_max_attempts: 6
    outbound_initial_retry_seconds: 5
    outbound_max_retry_seconds: 300
    outbound_record_ttl_seconds: 3600
    outbound_replay_interval_seconds: 15
    outbound_batch_size: 50
    outbound_lock_seconds: 60
    outbound_ack_retention_seconds: 86400
    outbound_dead_letter_retention_seconds: 2592000
    outbound_idempotency_window_seconds: 3600
    outbound_proxy_enabled: true
    outbound_proxy_allow_udp: true
    outbound_proxy_allow_radsec: true
    outbound_proxy_max_hops: 8
    outbound_proxy_loop_marker: aegisnas
    outbound_proxy_add_loop_marker: true
    outbound_proxy_reject_loop_marker: true
  upstream:
    enabled: true
    realm: corp.example.test
    pool_strategy: fail-over
    status_check: status-server
    transport_policy:
      enabled: true
      mode: enforce
      fail_closed: true
      default_required_transport: any
      allow_mixed_transports: false
    servers:
      - name: upstream-1
        address: 203.0.113.20
        auth_port: 1812
        acct_port: 1813
        dynamic_auth_port: 3799
        secret: upstream-secret
        transport: udp
    routes:
      - name: corp
        enabled: true
        realm: corp.example.test
        match_realms: [corp.example.test]
        default: true
        pool_strategy: fail-over
        status_check: status-server
        servers: [upstream-1]
  vendor:
    enabled: true
    name: AegisNAS
    id: %d
    compatibility_packs: ["standard", "aegisnas", "aruba"]
`, strconv.Quote(dbPath), vendorID)
	require.NoError(t, os.WriteFile(cfgPath, []byte(content), 0644))
	t.Cleanup(func() { _ = os.Remove(cfgPath) })
	return cfgPath
}

func productionReadinessCheckStatus(checks []productionReadinessCheck, key string) string {
	for _, check := range checks {
		if check.Key == key {
			return check.Status
		}
	}
	return ""
}
