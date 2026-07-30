package adminapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestHandleGetSQLAccounting(t *testing.T) {
	prepareSQLAccountingAPIConfig(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/sql-accounting", nil)
	HandleGetSQLAccounting(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var payload map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	report, ok := payload["report"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "ready", report["status"])
	assert.Equal(t, true, report["enabled"])
}

func TestHandleReconcileSQLAccounting(t *testing.T) {
	prepareSQLAccountingAPIConfig(t)
	_, err := db.UpsertFreeRADIUSAccountingRecord(t.Context(), db.FreeRADIUSAccountingRecord{
		AcctSessionID:  "api-sess-1",
		AcctUniqueID:   db.FreeRADIUSAcctUniqueID("api-sess-1", "erin", "10.0.0.11", "3"),
		Username:       "erin",
		NASIPAddress:   "10.0.0.11",
		NASPortID:      "3",
		AcctStartTime:  time.Now().UTC().Format(time.RFC3339Nano),
		AcctUpdateTime: time.Now().UTC().Format(time.RFC3339Nano),
	})
	require.NoError(t, err)

	body := bytes.NewBufferString(`{"batch_size":5}`)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/sql-accounting/reconcile", body)
	HandleReconcileSQLAccounting(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var payload map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, "ok", payload["status"])
	result := payload["result"].(map[string]any)
	assert.Equal(t, float64(1), result["reconciled"])
}

func TestProductionReadinessIncludesSQLAccounting(t *testing.T) {
	cfg := prepareSQLAccountingAPIConfig(t)

	report := buildProductionReadinessReport(cfg)

	assert.Equal(t, "passed", productionReadinessCheckStatus(report.Checks, "radius_sql_accounting"))
	assert.Equal(t, "passed", productionReadinessCheckStatus(report.Checks, "radius_accounting_ordering"))
}

func TestOpenAPIAndSupportBundleIncludeSQLAccountingAndOrdering(t *testing.T) {
	spec := buildOpenAPISpec(httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil), nil)
	paths := spec["paths"].(map[string]any)
	assert.Contains(t, paths, "/api/v1/system/sql-accounting")
	assert.Contains(t, paths, "/api/v1/system/sql-accounting/reconcile")
	assert.Contains(t, paths, "/api/v1/system/accounting-ordering")
	assert.Contains(t, paths, "/api/v1/system/accounting-ordering/replay")

	var foundSQL, foundOrdering bool
	for _, capture := range supportBundleAPICaptures() {
		if capture.archivePath == "api/sql-accounting.json" {
			foundSQL = true
			assert.Equal(t, "/api/v1/system/sql-accounting", capture.requestPath)
		}
		if capture.archivePath == "api/accounting-ordering.json" {
			foundOrdering = true
			assert.Equal(t, "/api/v1/system/accounting-ordering", capture.requestPath)
		}
	}
	assert.True(t, foundSQL)
	assert.True(t, foundOrdering)
}

func TestAuthorizeSQLAccounting(t *testing.T) {
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/sql-accounting"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/sql-accounting/reconcile"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/sql-accounting/reconcile"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/accounting-ordering"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/accounting-ordering/replay"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/accounting-ordering/replay"))
}

func TestHandleAccountingOrderingReportAndReplay(t *testing.T) {
	prepareSQLAccountingAPIConfig(t)
	ingested, err := db.IngestAccountingEvent(t.Context(), db.AccountingEventRecord{
		AcctUniqueID:     "api-ordering-1",
		AcctSessionID:    "api-ordering-1",
		SessionKey:       "api-ordering-1",
		StatusType:       "Start",
		EventTime:        time.Now().UTC().Format(time.RFC3339Nano),
		Username:         "finn",
		NASIPAddress:     "10.0.0.12",
		NASPortID:        "8",
		CallingStationID: "00-11-22-33-44-66",
		Source:           "api-test",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, ingested.Event.EventID)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/accounting-ordering", nil)
	HandleGetAccountingOrdering(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var payload map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	report := payload["report"].(map[string]any)
	assert.Equal(t, "ready", report["status"])

	body := bytes.NewBufferString(`{"limit":5,"session_key":"api-ordering-1"}`)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/system/accounting-ordering/replay", body)
	HandleReplayAccountingOrdering(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, "ok", payload["status"])
}

func prepareSQLAccountingAPIConfig(t *testing.T) *config.Config {
	t.Helper()
	require.NoError(t, db.Init(":memory:"))
	db.DB.SetMaxOpenConns(1)
	require.NoError(t, db.Migrate())

	tmpcfg, err := os.CreateTemp("", "sql-accounting-api-*.yaml")
	require.NoError(t, err)
	cfgPath := tmpcfg.Name()
	require.NoError(t, tmpcfg.Close())
	content := `
mode: two-nic
wan:
  name: eth0
lan:
  name: eth1
  address: 192.168.1.1/24
database:
  path: ":memory:"
radius:
  secret: secret
  sql_accounting:
    enabled: true
    reconcile_enabled: true
    reconcile_interval_seconds: 30
    batch_size: 25
    stale_after_seconds: 300
    accounting_retention_days: 365
    postauth_retention_days: 30
  accounting_ordering:
    enabled: true
    replay_enabled: true
    sequence_window_seconds: 300
    late_stop_window_seconds: 86400
    max_replay_batch: 1000
    duplicate_retention_days: 365
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(content), 0644))
	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = db.Close()
		_ = os.Remove(cfgPath)
	})
	return cfg
}
