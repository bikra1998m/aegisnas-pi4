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

	req = httptest.NewRequest(http.MethodGet, "/api/v1/system/dac-client/history?limit=5", nil)
	rec = httptest.NewRecorder()
	HandleListOutboundDACHistory(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var history map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &history))
	records := history["records"].([]any)
	require.Len(t, records, 1)
	assert.Equal(t, "blocked", records[0].(map[string]any)["status"])
}

func TestOutboundDACClientOpenAPIRBACReadinessAndSupportBundle(t *testing.T) {
	prepareOutboundDACAPITestRuntime(t)

	paths := openAPIPathsForTest(t)
	assert.Contains(t, paths, "/api/v1/system/dac-client")
	assert.Contains(t, paths, "/api/v1/system/dac-client/preview")
	assert.Contains(t, paths, "/api/v1/system/dac-client/send")
	assert.Contains(t, paths, "/api/v1/system/dac-client/history")

	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/dac-client"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/dac-client/preview"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/dac-client/preview"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/dac-client/send"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/dac-client/send"))
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
