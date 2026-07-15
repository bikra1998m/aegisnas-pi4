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
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestHandleGetFallbackPolicy(t *testing.T) {
	cfgPath := prepareFallbackPolicyAPIConfig(t)
	_, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.NoError(t, db.RecordRadiusFallbackEvent(db.RadiusFallbackEvent{
		ObservedAt:     "2026-06-01T10:00:00Z",
		Source:         "portal",
		UsernameHash:   "hash-a",
		Decision:       "allowed",
		Reason:         "fallback policy permits this identity",
		UpstreamStatus: "down",
		PolicyMode:     "enforce",
		FailClosed:     true,
	}, nil, 6000))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/fallback-policy?decision=allowed&limit=10", nil)
	HandleGetFallbackPolicy(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var payload map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	report, ok := payload["report"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "ready", report["status"])
	assert.Equal(t, true, report["enabled"])
	events, ok := payload["events"].([]any)
	require.True(t, ok)
	require.Len(t, events, 1)
}

func prepareFallbackPolicyAPIConfig(t *testing.T) string {
	t.Helper()
	tmpdb, err := os.CreateTemp("", "fallback-policy-api-*.db")
	require.NoError(t, err)
	dbPath := tmpdb.Name()
	require.NoError(t, tmpdb.Close())
	require.NoError(t, db.Init(dbPath))
	require.NoError(t, db.Migrate())

	tmpcfg, err := os.CreateTemp("", "fallback-policy-api-*.yaml")
	require.NoError(t, err)
	cfgPath := tmpcfg.Name()
	require.NoError(t, tmpcfg.Close())
	content := fmt.Sprintf(`
mode: two-nic
wan:
  name: eth0
lan:
  name: eth1
  address: 192.168.1.1/24
database:
  path: %s
portal:
  radius_auth: true
  local_fallback: true
radius:
  secret: secret
  upstream:
    enabled: true
    realm: corp.example.com
    pool_strategy: fail-over
    status_check: status-server
    response_window: 20
    zombie_period: 40
    revive_interval: 120
    check_interval: 30
    num_answers_to_alive: 3
    fallback_policy:
      enabled: true
      mode: enforce
      fail_closed: true
      allow_portal_local: true
      allow_ldap: false
      require_identity_allowlist: true
      max_outage_seconds: 900
      stale_policy_seconds: 3600
      recovery_successes: 2
      allowed_roles: [guest-basic]
      audit_enabled: true
      retention_limit: 6000
    servers:
      - name: primary
        address: 10.0.0.10
        secret: secret
    routes:
      - name: corp
        enabled: true
        realm: corp.example.com
        default: true
        servers: [primary]
`, strconv.Quote(dbPath))
	require.NoError(t, os.WriteFile(cfgPath, []byte(content), 0644))
	t.Cleanup(func() {
		_ = db.Close()
		_ = os.Remove(dbPath)
		_ = os.Remove(cfgPath)
	})
	return cfgPath
}
