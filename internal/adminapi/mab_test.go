package adminapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestMABEndpointAPIAndEvaluate(t *testing.T) {
	_ = prepareMABAPIConfig(t)

	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/system/mab/endpoints", bytes.NewBufferString(`{
		"mac":"aa-bb-cc-dd-ee-ff",
		"status":"approved",
		"role":"printer",
		"vlan":30,
		"tenant":"tenant-a",
		"device_group":"printers",
		"posture":"trusted",
		"source":"api-test"
	}`))
	createRec := httptest.NewRecorder()
	HandleUpsertMABEndpoint(createRec, createReq)
	require.Equal(t, http.StatusCreated, createRec.Code)

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/system/mab/endpoints?status=approved&limit=10", nil)
	listRec := httptest.NewRecorder()
	HandleListMABEndpoints(listRec, listReq)
	require.Equal(t, http.StatusOK, listRec.Code)
	var listPayload map[string]any
	require.NoError(t, json.Unmarshal(listRec.Body.Bytes(), &listPayload))
	require.Len(t, listPayload["endpoints"].([]any), 1)

	evaluateReq := httptest.NewRequest(http.MethodPost, "/api/v1/system/mab/evaluate", bytes.NewBufferString(`{
		"calling_station_id":"AA:BB:CC:DD:EE:FF",
		"username":"aabb.ccdd.eeff",
		"nas_identifier":"switch-1",
		"nas_port_type":"Ethernet",
		"record_audit":true
	}`))
	evaluateRec := httptest.NewRecorder()
	HandleEvaluateMAB(evaluateRec, evaluateReq)
	require.Equal(t, http.StatusOK, evaluateRec.Code)
	var evaluatePayload map[string]any
	require.NoError(t, json.Unmarshal(evaluateRec.Body.Bytes(), &evaluatePayload))
	result := evaluatePayload["result"].(map[string]any)
	assert.Equal(t, true, result["accepted"])
	assert.Equal(t, "accepted", result["decision"])

	statusReq := httptest.NewRequest(http.MethodGet, "/api/v1/system/mab?decision=accepted&limit=10", nil)
	statusRec := httptest.NewRecorder()
	HandleGetMAB(statusRec, statusReq)
	require.Equal(t, http.StatusOK, statusRec.Code)
	var statusPayload map[string]any
	require.NoError(t, json.Unmarshal(statusRec.Body.Bytes(), &statusPayload))
	report := statusPayload["report"].(map[string]any)
	assert.Equal(t, "ready", report["status"])
	assert.Len(t, statusPayload["events"].([]any), 1)
}

func TestProductionReadinessIncludesMABCheck(t *testing.T) {
	cfg := prepareMABAPIConfig(t)
	_, err := db.UpsertMABEndpoint(db.MABEndpoint{MAC: "aa:bb:cc:dd:ee:ff", Status: "approved", Role: "printer", Source: "test"}, nowForTest())
	require.NoError(t, err)
	report := buildProductionReadinessReport(cfg)
	var found bool
	for _, check := range report.Checks {
		if check.Key == "mac_authentication_bypass" {
			found = true
			assert.Equal(t, "passed", check.Status)
			assert.Contains(t, check.Dependencies, "/api/v1/system/mab")
		}
	}
	assert.True(t, found)
}

func TestOpenAPIAndSupportBundleIncludeMAB(t *testing.T) {
	spec := buildOpenAPISpec(httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil), nil)
	paths := spec["paths"].(map[string]any)
	assert.Contains(t, paths, "/api/v1/system/mab")
	assert.Contains(t, paths, "/api/v1/system/mab/endpoints")
	assert.Contains(t, paths, "/api/v1/system/mab/evaluate")

	var found bool
	for _, capture := range supportBundleAPICaptures() {
		if capture.archivePath == "api/mab.json" {
			found = true
			assert.Equal(t, "/api/v1/system/mab", capture.requestPath)
		}
	}
	assert.True(t, found)
}

func TestAuthorizeMABRequestsByRole(t *testing.T) {
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/mab"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/mab/endpoints"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/mab/endpoints"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/mab/endpoints"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/mab/evaluate"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleGuestAdmin}, "POST", "/api/v1/system/mab/evaluate"))
}

func prepareMABAPIConfig(t *testing.T) *config.Config {
	t.Helper()
	tmpdb, err := os.CreateTemp("", "mab-api-*.db")
	require.NoError(t, err)
	dbPath := tmpdb.Name()
	require.NoError(t, tmpdb.Close())
	require.NoError(t, db.Init(dbPath))
	require.NoError(t, db.Migrate())

	tmpcfg, err := os.CreateTemp("", "mab-api-*.yaml")
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
mab:
  enabled: true
  mode: enforce
  fail_closed: true
  unknown_endpoint_policy: deny
  default_role: employee
  guest_role: guest
  quarantine_role: quarantine
  allowed_nas_port_types: [ethernet, wireless-802.11, wireless80211]
  mac_formats: [colon, hyphen, plain, cisco-dot]
  password_policy: accept_known_mac
  profiling_link_enabled: true
  endpoint_inventory_fallback: true
  revalidate_interval_seconds: 300
  cache_ttl_seconds: 300
  audit_enabled: true
  retention_limit: 6000
radius:
  secret: secret
`, strconv.Quote(dbPath))
	require.NoError(t, os.WriteFile(cfgPath, []byte(content), 0644))
	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = db.Close()
		_ = os.Remove(dbPath)
		_ = os.Remove(cfgPath)
	})
	return cfg
}

func nowForTest() time.Time {
	return time.Now().UTC()
}
