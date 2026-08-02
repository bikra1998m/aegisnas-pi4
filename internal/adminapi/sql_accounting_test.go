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

func TestHandleAccountingIngestSpoolReportAndReplay(t *testing.T) {
	prepareSQLAccountingAPIConfig(t)
	now := time.Now().UTC()
	_, _, err := db.EnqueueAccountingIngestSpool(db.AccountingIngestSpoolCreate{
		Event: db.AccountingEventRecord{
			AcctUniqueID:     "api-ingest-1",
			AcctSessionID:    "api-ingest-1",
			SessionKey:       "api-ingest-1",
			StatusType:       "Start",
			EventTime:        now.Format(time.RFC3339Nano),
			Username:         "piper",
			NASIPAddress:     "10.0.0.16",
			NASPortID:        "16",
			CallingStationID: "00-11-22-33-44-16",
			Source:           "api-test",
		},
		MaxAttempts:   3,
		NextAttemptAt: now.Add(-time.Second),
		ExpiresAt:     now.Add(time.Hour),
		OwnerNode:     "node-a",
	}, 10)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/accounting-ingest-spool?status=queued&limit=5", nil)
	HandleGetAccountingIngestSpool(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var payload map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	report := payload["report"].(map[string]any)
	assert.Equal(t, "ready", report["status"])
	records := payload["records"].([]any)
	require.Len(t, records, 1)
	record := records[0].(map[string]any)
	assert.NotContains(t, record, "payload_json")

	body := bytes.NewBufferString(`{"batch_size":5}`)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/system/accounting-ingest-spool/replay", body)
	HandleReplayAccountingIngestSpool(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, "ok", payload["status"])
	assert.Equal(t, float64(1), payload["applied"])
}

func TestHandleAccountingChargingReportReconcileExportAndDownload(t *testing.T) {
	prepareSQLAccountingAPIConfig(t)
	now := time.Now().UTC().Truncate(time.Second)
	_, err := db.IngestAccountingEvent(t.Context(), db.AccountingEventRecord{
		AcctUniqueID:     "api-charge-1",
		AcctSessionID:    "api-charge-1",
		SessionKey:       "api-charge-1",
		StatusType:       "Stop",
		EventTime:        now.Format(time.RFC3339Nano),
		Username:         "charge-api@example.com",
		NASIPAddress:     "10.0.0.17",
		NASPortID:        "17",
		CallingStationID: "00-11-22-33-44-17",
		AcctInputOctets:  1 << 30,
		AcctOutputOctets: 1 << 30,
		AcctSessionTime:  3600,
		Class:            "service_key=internet;service_category=data;service_leg_id=api-ppp",
		Source:           "api-test",
	})
	require.NoError(t, err)
	_, err = db.ApplyPendingAccountingEvents(t.Context(), 10)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/accounting-charging?limit=5", nil)
	HandleGetAccountingCharging(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var payload map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	report := payload["report"].(map[string]any)
	assert.Equal(t, "ready", report["status"])
	records := payload["records"].([]any)
	require.Len(t, records, 1)
	record := records[0].(map[string]any)
	assert.NotContains(t, record["username_hash"], "charge-api")
	cdrID := record["cdr_id"].(string)

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/v1/system/accounting-charging?cdr_id="+cdrID, nil)
	HandleGetAccountingCharging(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	records = payload["records"].([]any)
	require.Len(t, records, 1)
	assert.Equal(t, cdrID, records[0].(map[string]any)["cdr_id"])

	body := bytes.NewBufferString(`{"batch_size":5}`)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/system/accounting-charging/reconcile", body)
	HandleReconcileAccountingCharging(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, "ok", payload["status"])

	body = bytes.NewBufferString(`{"format":"jsonl","limit":5}`)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/system/accounting-charging/export", body)
	HandleExportAccountingCharging(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, "complete", payload["status"])
	exportID := payload["export_id"].(string)
	assert.NotEmpty(t, payload["payload_sha256"])
	assert.NotEmpty(t, payload["manifest_sha256"])

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/v1/system/accounting-charging/export/download?export_id="+exportID, nil)
	HandleDownloadAccountingChargingExport(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/x-ndjson", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Body.String(), "api-charge-1")
}

func TestProductionReadinessIncludesSQLAccounting(t *testing.T) {
	cfg := prepareSQLAccountingAPIConfig(t)

	report := buildProductionReadinessReport(cfg)

	assert.Equal(t, "passed", productionReadinessCheckStatus(report.Checks, "radius_accounting_ingest_spool"))
	assert.Equal(t, "passed", productionReadinessCheckStatus(report.Checks, "radius_accounting_charging"))
	assert.Equal(t, "passed", productionReadinessCheckStatus(report.Checks, "radius_sql_accounting"))
	assert.Equal(t, "passed", productionReadinessCheckStatus(report.Checks, "radius_accounting_ordering"))
	assert.Equal(t, "passed", productionReadinessCheckStatus(report.Checks, "radius_accounting_counters"))
	assert.Equal(t, "passed", productionReadinessCheckStatus(report.Checks, "radius_accounting_ip"))
	assert.Equal(t, "passed", productionReadinessCheckStatus(report.Checks, "radius_accounting_services"))
}

func TestOpenAPIAndSupportBundleIncludeSQLAccountingOrderingCountersIPAndServices(t *testing.T) {
	spec := buildOpenAPISpec(httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil), nil)
	paths := spec["paths"].(map[string]any)
	assert.Contains(t, paths, "/api/v1/system/accounting-ingest-spool")
	assert.Contains(t, paths, "/api/v1/system/accounting-ingest-spool/replay")
	assert.Contains(t, paths, "/api/v1/system/accounting-charging")
	assert.Contains(t, paths, "/api/v1/system/accounting-charging/reconcile")
	assert.Contains(t, paths, "/api/v1/system/accounting-charging/export")
	assert.Contains(t, paths, "/api/v1/system/accounting-charging/export/download")
	assert.Contains(t, paths, "/api/v1/system/sql-accounting")
	assert.Contains(t, paths, "/api/v1/system/sql-accounting/reconcile")
	assert.Contains(t, paths, "/api/v1/system/accounting-ordering")
	assert.Contains(t, paths, "/api/v1/system/accounting-ordering/replay")
	assert.Contains(t, paths, "/api/v1/system/accounting-counters")
	assert.Contains(t, paths, "/api/v1/system/accounting-ip")
	assert.Contains(t, paths, "/api/v1/system/accounting-services")

	var foundIngestSpool, foundCharging, foundSQL, foundOrdering, foundCounters, foundIP, foundServices bool
	for _, capture := range supportBundleAPICaptures() {
		if capture.archivePath == "api/accounting-ingest-spool.json" {
			foundIngestSpool = true
			assert.Equal(t, "/api/v1/system/accounting-ingest-spool", capture.requestPath)
		}
		if capture.archivePath == "api/accounting-charging.json" {
			foundCharging = true
			assert.Equal(t, "/api/v1/system/accounting-charging", capture.requestPath)
		}
		if capture.archivePath == "api/sql-accounting.json" {
			foundSQL = true
			assert.Equal(t, "/api/v1/system/sql-accounting", capture.requestPath)
		}
		if capture.archivePath == "api/accounting-ordering.json" {
			foundOrdering = true
			assert.Equal(t, "/api/v1/system/accounting-ordering", capture.requestPath)
		}
		if capture.archivePath == "api/accounting-counters.json" {
			foundCounters = true
			assert.Equal(t, "/api/v1/system/accounting-counters", capture.requestPath)
		}
		if capture.archivePath == "api/accounting-ip.json" {
			foundIP = true
			assert.Equal(t, "/api/v1/system/accounting-ip", capture.requestPath)
		}
		if capture.archivePath == "api/accounting-services.json" {
			foundServices = true
			assert.Equal(t, "/api/v1/system/accounting-services", capture.requestPath)
		}
	}
	assert.True(t, foundIngestSpool)
	assert.True(t, foundCharging)
	assert.True(t, foundSQL)
	assert.True(t, foundOrdering)
	assert.True(t, foundCounters)
	assert.True(t, foundIP)
	assert.True(t, foundServices)
}

func TestAuthorizeSQLAccounting(t *testing.T) {
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/accounting-ingest-spool"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/accounting-ingest-spool/replay"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/accounting-ingest-spool/replay"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/accounting-charging"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/accounting-charging/reconcile"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/accounting-charging/reconcile"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/accounting-charging/export"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/accounting-charging/export"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/accounting-charging/export/download?export_id=cdr-export-1"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/sql-accounting"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/sql-accounting/reconcile"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/sql-accounting/reconcile"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/accounting-ordering"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/accounting-ordering/replay"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/accounting-ordering/replay"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/accounting-counters"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/accounting-ip"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/accounting-services"))
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

func TestHandleAccountingCountersReport(t *testing.T) {
	prepareSQLAccountingAPIConfig(t)
	_, err := db.IngestAccountingEvent(t.Context(), db.AccountingEventRecord{
		AcctUniqueID:     "api-counter-1",
		AcctSessionID:    "api-counter-1",
		SessionKey:       "api-counter-1",
		StatusType:       "Interim-Update",
		EventTime:        time.Now().UTC().Format(time.RFC3339Nano),
		Username:         "gale",
		NASIPAddress:     "10.0.0.13",
		NASPortID:        "9",
		AcctInputOctets:  uint64(1<<32) + 44,
		AcctOutputOctets: uint64(1<<32) + 55,
		CallingStationID: "00-11-22-33-44-88",
		Source:           "api-test",
	})
	require.NoError(t, err)
	_, err = db.ApplyPendingAccountingEvents(t.Context(), 10)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/accounting-counters", nil)
	HandleGetAccountingCounters(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var payload map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	report := payload["report"].(map[string]any)
	assert.Equal(t, "ready", report["status"])
	summary := report["summary"].(map[string]any)
	assert.Equal(t, float64(1), summary["rollover_events"])
}

func TestHandleAccountingIPReport(t *testing.T) {
	prepareSQLAccountingAPIConfig(t)
	_, err := db.IngestAccountingEvent(t.Context(), db.AccountingEventRecord{
		AcctUniqueID:        "api-ip-1",
		AcctSessionID:       "api-ip-1",
		SessionKey:          "api-ip-1",
		StatusType:          "Interim-Update",
		EventTime:           time.Now().UTC().Format(time.RFC3339Nano),
		Username:            "helen",
		NASIPAddress:        "10.0.0.14",
		NASPortID:           "14",
		FramedIPv6Address:   "2001:db8::14",
		DelegatedIPv6Prefix: "2001:db8:1400::/56",
		FramedIPv6Route:     "2001:db8:1401::/64 fe80::1",
		Source:              "api-test",
	})
	require.NoError(t, err)
	_, err = db.ApplyPendingAccountingEvents(t.Context(), 10)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/accounting-ip?limit=5", nil)
	HandleGetAccountingIP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var payload map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	report := payload["report"].(map[string]any)
	assert.Equal(t, "ready", report["status"])
	summary := report["summary"].(map[string]any)
	assert.Equal(t, float64(1), summary["assignment_rows"])
	assert.Equal(t, float64(1), summary["ipv6_route_rows"])
	records := payload["records"].([]any)
	assert.Len(t, records, 1)
}

func TestHandleAccountingServicesReport(t *testing.T) {
	prepareSQLAccountingAPIConfig(t)
	_, err := db.IngestAccountingEvent(t.Context(), db.AccountingEventRecord{
		AcctUniqueID:       "api-service-1",
		AcctSessionID:      "api-service-child",
		SessionKey:         "api-service-child",
		StatusType:         "Interim-Update",
		AcctMultiSessionID: "api-service-parent",
		AcctLinkCount:      2,
		EventTime:          time.Now().UTC().Format(time.RFC3339Nano),
		Username:           "irene",
		NASIPAddress:       "10.0.0.15",
		NASPortID:          "15",
		ServiceType:        "Framed-User",
		FramedProtocol:     "PPP",
		Class:              "service_key=data;service_leg_id=api-ppp",
		Source:             "api-test",
	})
	require.NoError(t, err)
	_, err = db.ApplyPendingAccountingEvents(t.Context(), 10)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/accounting-services?parent_session_key=api-service-parent&limit=5", nil)
	HandleGetAccountingServices(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var payload map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	report := payload["report"].(map[string]any)
	assert.Equal(t, "ready", report["status"])
	summary := report["summary"].(map[string]any)
	assert.Equal(t, float64(1), summary["correlation_rows"])
	assert.Equal(t, float64(1), summary["acct_multi_session_rows"])
	records := payload["records"].([]any)
	require.Len(t, records, 1)
	record := records[0].(map[string]any)
	assert.Equal(t, "api-service-parent", record["parent_session_key"])
	assert.Equal(t, "data", record["service_key"])
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
  accounting_ingest_spool:
    enabled: true
    replay_enabled: true
    max_queue_records: 10000
    max_attempts: 10
    initial_retry_seconds: 5
    max_retry_seconds: 300
    record_ttl_seconds: 604800
    replay_interval_seconds: 30
    batch_size: 500
    lock_seconds: 120
    applied_retention_seconds: 86400
    poison_retention_seconds: 2592000
    loss_slo_seconds: 300
  accounting_ordering:
    enabled: true
    replay_enabled: true
    sequence_window_seconds: 300
    late_stop_window_seconds: 86400
    max_replay_batch: 1000
    duplicate_retention_days: 365
  accounting_counters:
    enabled: true
    gigawords_enabled: true
    reset_detection_enabled: true
    max_counter_bits: 64
    overflow_policy: saturate
    retention_days: 365
  accounting_ip:
    enabled: true
    ipv6_enabled: true
    route_accounting_enabled: true
    delegated_prefix_enabled: true
    reject_invalid: false
    retention_days: 365
  accounting_services:
    enabled: true
    correlate_subscriber_chains: true
    derive_from_class: true
    derive_from_acct_multi_session_id: true
    retain_unmatched: true
    retention_days: 365
    max_recent_services: 25
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
