package adminapi

import (
	"bytes"
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

func TestOutboundDACClientHandlersPreviewSendAndHistory(t *testing.T) {
	prepareOutboundDACAPITestRuntime(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/dac-client", nil)
	rec := httptest.NewRecorder()
	HandleGetOutboundDACClient(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var reportPayload map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &reportPayload))
	report := reportPayload["report"].(map[string]any)
	assert.Equal(t, "ready", report["status"])
	proxyRouting := report["proxy_routing"].(map[string]any)
	assert.Equal(t, "ready", proxyRouting["status"])
	proxySummary := proxyRouting["summary"].(map[string]any)
	assert.Equal(t, float64(1), proxySummary["route_count"])

	previewBody := bytes.NewBufferString(`{
		"action":"coa",
		"target_address":"192.0.2.10",
		"acct_session_id":"acct-123",
		"filter_id":"employee"
	}`)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/system/dac-client/preview", previewBody)
	rec = httptest.NewRecorder()
	HandlePreviewOutboundDAC(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var preview map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &preview))
	assert.Equal(t, "ready", preview["status"])
	assert.Equal(t, float64(43), preview["request_code"])

	sendBody := bytes.NewBufferString(`{
		"action":"disconnect",
		"target_address":"192.0.2.10",
		"acct_session_id":"acct-123"
	}`)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/system/dac-client/send", sendBody)
	rec = httptest.NewRecorder()
	HandleSendOutboundDAC(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var sendResult map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &sendResult))
	assert.Equal(t, "blocked", sendResult["status"])

	enqueueBody := bytes.NewBufferString(`{
		"action":"coa",
		"target_address":"192.0.2.10",
		"acct_session_id":"acct-queued",
		"filter_id":"employee",
		"idempotency_key":"ticket-queued",
		"confirm":true
	}`)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/system/dac-client/enqueue", enqueueBody)
	rec = httptest.NewRecorder()
	HandleEnqueueOutboundDAC(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var enqueueResult map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &enqueueResult))
	assert.Equal(t, "queued", enqueueResult["status"])
	queue := enqueueResult["queue"].(map[string]any)
	queueID := queue["queue_id"].(string)
	assert.NotEmpty(t, queueID)
	assert.Nil(t, queue["payload_json"])

	cancelBody, err := json.Marshal(map[string]any{"queue_id": queueID, "reason": "operator changed policy"})
	require.NoError(t, err)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/system/dac-client/cancel", bytes.NewReader(cancelBody))
	rec = httptest.NewRecorder()
	HandleCancelOutboundDACQueue(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var cancelResult map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &cancelResult))
	assert.Equal(t, "canceled", cancelResult["status"])

	retryBody, err := json.Marshal(map[string]any{"queue_id": queueID})
	require.NoError(t, err)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/system/dac-client/retry", bytes.NewReader(retryBody))
	rec = httptest.NewRecorder()
	HandleRetryOutboundDACQueue(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var retryResult map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &retryResult))
	assert.Equal(t, "queued", retryResult["status"])

	req = httptest.NewRequest(http.MethodGet, "/api/v1/system/dac-client/history?limit=5", nil)
	rec = httptest.NewRecorder()
	HandleListOutboundDACHistory(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var history map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &history))
	records := history["records"].([]any)
	require.Len(t, records, 1)
	assert.Equal(t, "blocked", records[0].(map[string]any)["status"])
	queueRecords := history["queue_records"].([]any)
	require.Len(t, queueRecords, 1)
	assert.Equal(t, queueID, queueRecords[0].(map[string]any)["queue_id"])
	queueSummary := history["queue_summary"].(map[string]any)
	assert.Equal(t, float64(1), queueSummary["queued_count"])
}

func TestOutboundDACClientOpenAPIRBACReadinessAndSupportBundle(t *testing.T) {
	prepareOutboundDACAPITestRuntime(t)

	paths := openAPIPathsForTest(t)
	assert.Contains(t, paths, "/api/v1/system/dac-client")
	assert.Contains(t, paths, "/api/v1/system/dac-client/preview")
	assert.Contains(t, paths, "/api/v1/system/dac-client/send")
	assert.Contains(t, paths, "/api/v1/system/dac-client/enqueue")
	assert.Contains(t, paths, "/api/v1/system/dac-client/replay")
	assert.Contains(t, paths, "/api/v1/system/dac-client/cancel")
	assert.Contains(t, paths, "/api/v1/system/dac-client/retry")
	assert.Contains(t, paths, "/api/v1/system/dac-client/history")

	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/dac-client"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/dac-client/preview"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/dac-client/preview"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/dac-client/send"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/dac-client/send"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/dac-client/enqueue"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/dac-client/enqueue"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/dac-client/replay"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/dac-client/cancel"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/dac-client/retry"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/dac-client/history"))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/production-readiness", nil)
	rec := httptest.NewRecorder()
	HandleGetProductionReadiness(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var readiness productionReadinessReport
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &readiness))
	assert.Equal(t, "passed", productionReadinessCheckStatus(readiness.Checks, "radius_outbound_dac_client"))

	foundClientCapture := false
	foundHistoryCapture := false
	for _, capture := range supportBundleAPICaptures() {
		if capture.archivePath == "api/dac-client.json" {
			foundClientCapture = true
			assert.Equal(t, "/api/v1/system/dac-client", capture.requestPath)
		}
		if capture.archivePath == "api/dac-client-history.json" {
			foundHistoryCapture = true
			assert.Equal(t, "/api/v1/system/dac-client/history", capture.requestPath)
		}
	}
	assert.True(t, foundClientCapture)
	assert.True(t, foundHistoryCapture)
}

func prepareOutboundDACAPITestRuntime(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	dbPath := ":memory:"
	cfgPath := filepath.Join(dir, "config.yaml")
	content := `
mode: two-nic
wan:
  name: eth0
  dhcp: true
lan:
  name: eth1
  address: 192.168.1.1/24
database:
  path: "` + dbPath + `"
health:
  port: 8080
telemetry:
  prometheus_port: 9090
radius:
  secret: global-secret
  dynamic_auth:
    enabled: true
    port: 3799
    outbound_enabled: true
    outbound_default_port: 3799
    outbound_timeout_seconds: 5
    outbound_require_known_client: true
    outbound_history_limit: 1000
    outbound_max_attributes: 32
    outbound_allow_coa: true
    outbound_allow_disconnect: true
    outbound_require_confirmation: true
    outbound_queue_enabled: true
    outbound_replay_enabled: true
    outbound_max_queue_records: 100
    outbound_max_attempts: 6
    outbound_initial_retry_seconds: 5
    outbound_max_retry_seconds: 300
    outbound_record_ttl_seconds: 3600
    outbound_replay_interval_seconds: 15
    outbound_batch_size: 10
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
  clients:
    - ip: 192.0.2.10
      secret: shared-secret
      shortname: branch-ap
      nas_type: cisco
      transport: udp
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(content), 0644))
	_, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.NoError(t, db.Init(dbPath))
	db.DB.SetMaxOpenConns(1)
	require.NoError(t, db.Migrate())
	_, err = db.DB.Exec(`INSERT INTO radius_clients (shortname, ipaddr, secret, nas_type, enabled, transport)
		VALUES (?, ?, ?, ?, ?, ?)`, "branch-ap", "192.0.2.10", "shared-secret", "cisco", true, "udp")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
}

func openAPIPathsForTest(t *testing.T) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "https://appliance.example.test/api/v1/openapi.json", nil)
	rec := httptest.NewRecorder()
	HandleGetOpenAPI(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var payload map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	paths, ok := payload["paths"].(map[string]any)
	require.True(t, ok)
	return paths
}
