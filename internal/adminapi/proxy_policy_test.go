package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/radius"
)

func TestHandleGetProxyPolicy(t *testing.T) {
	cfgPath := writeProxyPolicyConfig(t)
	_, err := config.Load(cfgPath)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/proxy-policy", nil)
	HandleGetProxyPolicy(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var payload radius.ProxyPolicyReport
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, "ready", payload.Status)
	assert.Equal(t, radius.ProxyPolicySchemaVersion, payload.SchemaVersion)
	assert.True(t, payload.FreeRADIUS.LoopMarkerEnforced)
	assert.GreaterOrEqual(t, payload.Summary.RoutePolicyCount, 2)
}

func writeProxyPolicyConfig(t *testing.T) string {
	t.Helper()
	tmpfile, err := os.CreateTemp("", "proxy-policy-config-*.yaml")
	require.NoError(t, err)
	cfgPath := tmpfile.Name()
	require.NoError(t, tmpfile.Close())

	content := `
mode: two-nic
wan:
  name: eth0
  dhcp: true
lan:
  name: eth1
  address: 192.168.50.1/24
database:
  path: ` + strconv.Quote("/tmp/aegisnas-proxy-policy-api.db") + `
health:
  port: 8080
telemetry:
  enabled: false
  prometheus_port: 9090
radius:
  secret: testing123
  auth_port: 1812
  acct_port: 1813
  request_timeout_seconds: 5
  upstream:
    enabled: true
    realm: legacy.example.com
    pool_strategy: fail-over
    status_check: status-server
    response_window: 20
    zombie_period: 40
    revive_interval: 120
    check_interval: 30
    num_answers_to_alive: 3
    servers:
      - name: primary
        address: 10.0.0.10
        secret: secret-one
    routes:
      - name: corp
        enabled: true
        realm: corp.example.com
        match_realms: [employees.example.com]
        default: true
        servers: [primary]
    proxy_policy:
      enabled: true
      fail_closed: true
      default_action: drop
      loop_marker: aegisnas
      add_loop_marker: true
      reject_loop_marker: true
      max_hops: 8
      route_policies:
        - route: corp
          direction: any
          trusted_source_realms: [corp.example.com, employees.example.com]
          allow_vendor_ids: [9]
          deny_standard: [Filter-Id]
          rewrite_rules:
            - attribute: User-Name
              action: replace_realm
              match_realm: employees.example.com
              replacement: corp.example.com
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(content), 0644))
	t.Cleanup(func() { _ = os.Remove(cfgPath) })
	return cfgPath
}
