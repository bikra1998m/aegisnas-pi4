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

func TestHandleGetIdentityFailover(t *testing.T) {
	cfgPath := prepareIdentityFailoverAPIConfig(t)
	_, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.NoError(t, db.RecordIdentitySourceEvent(db.IdentitySourceEvent{
		ObservedAt:   "2026-07-01T10:00:00Z",
		SourceName:   "local",
		SourceType:   "local",
		UsernameHash: db.HashIdentityUsername("alice@example.com"),
		Decision:     "accepted",
		Reason:       "credentials accepted",
		CircuitState: "closed",
	}, nil, 6000))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/identity-failover?source=local&decision=accepted&limit=10", nil)
	HandleGetIdentityFailover(rec, req)

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

func TestProductionReadinessIncludesIdentityFailoverCheck(t *testing.T) {
	cfgPath := prepareIdentityFailoverAPIConfig(t)
	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)

	report := buildProductionReadinessReport(cfg)

	var found bool
	for _, check := range report.Checks {
		if check.Key == "identity_source_failover" {
			found = true
			assert.Equal(t, "passed", check.Status)
			assert.Contains(t, check.Dependencies, "/api/v1/system/identity-failover")
		}
	}
	assert.True(t, found)
}

func TestSupportBundleIncludesIdentityFailoverCapture(t *testing.T) {
	var found bool
	for _, capture := range supportBundleAPICaptures() {
		if capture.archivePath == "api/identity-failover.json" {
			found = true
			assert.Equal(t, "/api/v1/system/identity-failover", capture.requestPath)
			assert.Equal(t, "Identity source failover", capture.label)
		}
	}
	assert.True(t, found)
}

func prepareIdentityFailoverAPIConfig(t *testing.T) string {
	t.Helper()
	tmpdb, err := os.CreateTemp("", "identity-failover-api-*.db")
	require.NoError(t, err)
	dbPath := tmpdb.Name()
	require.NoError(t, tmpdb.Close())
	require.NoError(t, db.Init(dbPath))
	require.NoError(t, db.Migrate())

	tmpcfg, err := os.CreateTemp("", "identity-failover-api-*.yaml")
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
  enabled: true
  radius_auth: false
  local_fallback: true
identity:
  failover:
    enabled: true
    mode: enforce
    fail_closed: true
    source_order: [local]
    max_failures: 3
    circuit_open_seconds: 300
    stale_cache_seconds: 3600
    cache_credentials: false
    split_result_policy: deny
    health_check_interval_seconds: 60
    audit_enabled: true
    retention_limit: 6000
radius:
  secret: secret
`, strconv.Quote(dbPath))
	require.NoError(t, os.WriteFile(cfgPath, []byte(content), 0644))
	t.Cleanup(func() {
		_ = db.Close()
		_ = os.Remove(dbPath)
		_ = os.Remove(cfgPath)
	})
	return cfgPath
}
