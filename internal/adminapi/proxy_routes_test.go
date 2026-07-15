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

func TestHandleGetProxyRoutes(t *testing.T) {
	cfgPath := writeProxyRoutesConfig(t)
	_, err := config.Load(cfgPath)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/proxy-routes", nil)
	HandleGetProxyRoutes(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var payload radius.ProxyRoutingReport
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, "ready", payload.Status)
	assert.Equal(t, 2, payload.Summary.RouteCount)
	assert.Equal(t, "corp.example.com", payload.Summary.DefaultRealm)
	require.Len(t, payload.Routes, 2)
	assert.Equal(t, "corp", payload.Routes[0].Name)
	assert.NotContains(t, rec.Body.String(), "secret-one")
}

func TestHandleGetTransportPolicy(t *testing.T) {
	cfgPath := writeProxyRoutesConfig(t)
	_, err := config.Load(cfgPath)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/transport-policy", nil)
	HandleGetTransportPolicy(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var payload radius.TransportPolicyReport
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, "ready", payload.Status)
	assert.Equal(t, "enforce", payload.Policy.Mode)
	assert.Equal(t, 2, payload.Summary.RouteCount)
	assert.Equal(t, 0, payload.Summary.MixedTransportRoutes)
}

func writeProxyRoutesConfig(t *testing.T) string {
	t.Helper()
	tmpfile, err := os.CreateTemp("", "proxy-routes-config-*.yaml")
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
  path: ` + strconv.Quote("/tmp/aegisnas-proxy-routes-api.db") + `
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
      - name: secondary
        address: 10.0.0.11
        secret: secret-two
    routes:
      - name: corp
        description: Corporate 802.1X users
        enabled: true
        realm: corp.example.com
        match_realms: [employees.example.com]
        default: true
        servers: [primary, secondary]
      - name: guest
        enabled: true
        realm: guest.example.com
        pool_strategy: load-balance
        status_check: none
        servers: [secondary]
    transport_policy:
      enabled: true
      mode: enforce
      fail_closed: true
      default_required_transport: any
      allow_mixed_transports: false
      route_policies:
        - route: corp
          required_transport: any
          allow_mixed_transports: false
        - route: guest
          required_transport: udp
          allow_mixed_transports: false
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(content), 0644))
	t.Cleanup(func() { _ = os.Remove(cfgPath) })
	return cfgPath
}
