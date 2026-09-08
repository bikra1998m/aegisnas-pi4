package adminapi

import (
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

func TestHostapdVLANLifecycleAPIPreviewStatusHistoryReadinessAndSupportBundle(t *testing.T) {
	prepareHostapdVLANLifecycleAPITestRuntime(t)

	previewRec := httptest.NewRecorder()
	HandlePreviewHostapdVLANLifecycle(previewRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/hostapd-vlan-lifecycle/preview", nil))
	require.Equal(t, http.StatusOK, previewRec.Code, previewRec.Body.String())
	var previewPayload struct {
		EventID string `json:"event_id"`
		Report  struct {
			FeatureID string `json:"feature_id"`
			Status    string `json:"status"`
			Summary   struct {
				DynamicSSIDCount      int `json:"dynamic_ssid_count"`
				FallbackSSIDCount     int `json:"fallback_ssid_count"`
				FailClosedSSIDCount   int `json:"fail_closed_ssid_count"`
				HostapdVLANEntryCount int `json:"hostapd_vlan_entry_count"`
			} `json:"summary"`
			Plan struct {
				HostapdBindings []struct {
					SSID                string `json:"ssid"`
					DynamicVLANMode     int    `json:"dynamic_vlan_mode"`
					DynamicVLANModeName string `json:"dynamic_vlan_mode_name"`
					Status              string `json:"status"`
				} `json:"hostapd_bindings"`
			} `json:"plan"`
		} `json:"report"`
	}
	require.NoError(t, json.Unmarshal(previewRec.Body.Bytes(), &previewPayload))
	assert.NotEmpty(t, previewPayload.EventID)
	assert.Equal(t, "NAS-0074", previewPayload.Report.FeatureID)
	assert.Equal(t, "ready", previewPayload.Report.Status)
	assert.Equal(t, 2, previewPayload.Report.Summary.DynamicSSIDCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.FallbackSSIDCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.FailClosedSSIDCount)
	assert.Equal(t, 2, previewPayload.Report.Summary.HostapdVLANEntryCount)
	require.Len(t, previewPayload.Report.Plan.HostapdBindings, 2)

	statusRec := httptest.NewRecorder()
	HandleGetHostapdVLANLifecycle(statusRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/hostapd-vlan-lifecycle", nil))
	require.Equal(t, http.StatusOK, statusRec.Code, statusRec.Body.String())
	assert.Contains(t, statusRec.Body.String(), `"ready_for_external_validation":true`)
	assert.Contains(t, statusRec.Body.String(), `"recent_events"`)

	historyRec := httptest.NewRecorder()
	HandleListHostapdVLANLifecycleHistory(historyRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/hostapd-vlan-lifecycle/history?limit=5", nil))
	require.Equal(t, http.StatusOK, historyRec.Code, historyRec.Body.String())
	assert.Contains(t, historyRec.Body.String(), `"feature_id":"NAS-0074"`)
	assert.Contains(t, historyRec.Body.String(), `"preview_events":1`)

	readiness := buildProductionReadinessReport(config.Get())
	assert.Equal(t, "passed", productionReadinessCheckStatus(readiness.Checks, "hostapd_dynamic_vlan_lifecycle"))

	spec := buildOpenAPISpec(httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil), config.Get())
	paths := spec["paths"].(map[string]any)
	for _, path := range []string{
		"/api/v1/system/hostapd-vlan-lifecycle",
		"/api/v1/system/hostapd-vlan-lifecycle/preview",
		"/api/v1/system/hostapd-vlan-lifecycle/apply",
		"/api/v1/system/hostapd-vlan-lifecycle/rollback",
		"/api/v1/system/hostapd-vlan-lifecycle/history",
	} {
		_, ok := paths[path]
		assert.True(t, ok, "OpenAPI path %s should exist", path)
	}

	foundStatusCapture := false
	foundHistoryCapture := false
	for _, capture := range supportBundleAPICaptures() {
		if capture.archivePath == "api/hostapd-vlan-lifecycle.json" {
			foundStatusCapture = true
		}
		if capture.archivePath == "api/hostapd-vlan-lifecycle-history.json" {
			foundHistoryCapture = true
		}
	}
	assert.True(t, foundStatusCapture)
	assert.True(t, foundHistoryCapture)
}

func TestHostapdVLANLifecycleRBAC(t *testing.T) {
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/hostapd-vlan-lifecycle"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/hostapd-vlan-lifecycle/preview"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/hostapd-vlan-lifecycle/history"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/hostapd-vlan-lifecycle/apply"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/hostapd-vlan-lifecycle/rollback"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/hostapd-vlan-lifecycle/apply"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/hostapd-vlan-lifecycle/rollback"))
}

func prepareHostapdVLANLifecycleAPITestRuntime(t *testing.T) {
	t.Helper()
	previousDB := db.DB
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	content := `
mode: two-nic
deployment:
  profile: enterprise
  form: virtual
  hardware:
    memory_mb: 8192
    cpu_cores: 4
    storage_gb: 64
    wireless_passthrough: true
wan:
  name: ens33
  dhcp: true
lan:
  name: ens37
  address: 192.168.50.1/24
policy:
  runtime_vlan_lifecycle_enabled: true
database:
  path: ":memory:"
radius:
  secret: radius-shared-secret
  auth_port: 1812
  acct_port: 1813
  request_timeout_seconds: 5
wireless:
  enabled: true
  interface: wlan0
  country_code: US
  driver: nl80211
  hw_mode: g
  channel: 6
  beacon_interval: 100
  wmm_enabled: true
  ht_enabled: true
  hostapd_config_path: /etc/hostapd/hostapd.conf
  hostapd_vlan_file_path: /etc/hostapd/aegisnas-vlans.conf
  ssids:
    - name: Corp
      auth_mode: wpa2-enterprise
      vlan: 30
      bridge: br-corp
      dynamic_vlan: true
    - name: Research
      auth_mode: wpa3-enterprise
      dynamic_vlan: true
vlans:
  - id: 30
    name: corp
    purpose: employee
  - id: 40
    name: research
    purpose: lab
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(content), 0o600))
	_, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.NoError(t, db.Init(":memory:"))
	db.DB.SetMaxOpenConns(1)
	require.NoError(t, db.Migrate())
	t.Cleanup(func() {
		_ = db.Close()
		db.DB = previousDB
	})
}
