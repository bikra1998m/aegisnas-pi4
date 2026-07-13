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

func TestHandleGetAccountingSpool(t *testing.T) {
	cfgPath := prepareAccountingSpoolAPIConfig(t)
	_, err := config.Load(cfgPath)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/accounting-spool", nil)
	HandleGetAccountingSpool(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var payload map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	report, ok := payload["report"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "ready", report["status"])
	assert.Equal(t, true, report["enabled"])
}

func TestHandleReplayAccountingSpool(t *testing.T) {
	cfgPath := prepareAccountingSpoolAPIConfig(t)
	_, err := config.Load(cfgPath)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/accounting-spool/replay", nil)
	HandleReplayAccountingSpool(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var payload map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, "ok", payload["status"])
	assert.Equal(t, float64(0), payload["claimed"])
}

func prepareAccountingSpoolAPIConfig(t *testing.T) string {
	t.Helper()
	tmpdb, err := os.CreateTemp("", "accounting-spool-api-*.db")
	require.NoError(t, err)
	dbPath := tmpdb.Name()
	require.NoError(t, tmpdb.Close())
	require.NoError(t, db.Init(dbPath))
	require.NoError(t, db.Migrate())

	tmpcfg, err := os.CreateTemp("", "accounting-spool-api-*.yaml")
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
    accounting_spool:
      enabled: true
      max_queue_records: 10
      max_attempts: 3
      initial_retry_seconds: 1
      max_retry_seconds: 4
      record_ttl_seconds: 3600
      replay_interval_seconds: 1
      batch_size: 10
      lock_seconds: 30
      sent_retention_seconds: 3600
      poison_retention_seconds: 3600
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
