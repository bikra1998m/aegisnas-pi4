package adminapi

import (
	"encoding/json"
	"fmt"
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

func TestWirelessRoamingLifecycleAPIPreviewApplyStatusHistoryReadinessAndSupportBundle(t *testing.T) {
	hostapdPath := prepareWirelessRoamingLifecycleAPITestRuntime(t)

	previewRec := httptest.NewRecorder()
	HandlePreviewWirelessRoamingLifecycle(previewRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/wireless-roaming-lifecycle/preview", nil))
	require.Equal(t, http.StatusOK, previewRec.Code, previewRec.Body.String())
	var previewPayload struct {
		EventID string `json:"event_id"`
		Report  struct {
			FeatureID            string `json:"feature_id"`
			Status               string `json:"status"`
			HostapdConfigPreview string `json:"hostapd_config_preview"`
			Summary              struct {
				RoamingSSIDCount      int `json:"roaming_ssid_count"`
				FTSSIDCount           int `json:"ft_ssid_count"`
				KSSIDCount            int `json:"k_ssid_count"`
				VSSIDCount            int `json:"v_ssid_count"`
				ResolvableKeyRefCount int `json:"resolvable_key_ref_count"`
			} `json:"summary"`
		} `json:"report"`
	}
	require.NoError(t, json.Unmarshal(previewRec.Body.Bytes(), &previewPayload))
	assert.NotEmpty(t, previewPayload.EventID)
	assert.Equal(t, "NAS-0075", previewPayload.Report.FeatureID)
	assert.Equal(t, "ready", previewPayload.Report.Status)
	assert.Equal(t, 1, previewPayload.Report.Summary.RoamingSSIDCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.FTSSIDCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.KSSIDCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.VSSIDCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.ResolvableKeyRefCount)
	assert.Contains(t, previewPayload.Report.HostapdConfigPreview, "r0kh=<redacted>")
	assert.NotContains(t, previewPayload.Report.HostapdConfigPreview, "test-ft-seed-that-is-long-enough")

	applyRec := httptest.NewRecorder()
	HandleApplyWirelessRoamingLifecycle(applyRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/wireless-roaming-lifecycle/apply", nil))
	require.Equal(t, http.StatusOK, applyRec.Code, applyRec.Body.String())
	assert.Contains(t, applyRec.Body.String(), `"status":"applied"`)
	raw, err := os.ReadFile(hostapdPath)
	require.NoError(t, err)
	assert.Contains(t, string(raw), "wpa_key_mgmt=WPA-EAP FT-EAP")
	assert.NotContains(t, string(raw), "test-ft-seed-that-is-long-enough")

	statusRec := httptest.NewRecorder()
	HandleGetWirelessRoamingLifecycle(statusRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/wireless-roaming-lifecycle", nil))
	require.Equal(t, http.StatusOK, statusRec.Code, statusRec.Body.String())
	assert.Contains(t, statusRec.Body.String(), `"ready_for_external_validation":true`)
	assert.Contains(t, statusRec.Body.String(), `"recent_events"`)

	historyRec := httptest.NewRecorder()
	HandleListWirelessRoamingLifecycleHistory(historyRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/wireless-roaming-lifecycle/history?limit=5", nil))
	require.Equal(t, http.StatusOK, historyRec.Code, historyRec.Body.String())
	assert.Contains(t, historyRec.Body.String(), `"feature_id":"NAS-0075"`)
	assert.Contains(t, historyRec.Body.String(), `"preview_events":1`)
	assert.Contains(t, historyRec.Body.String(), `"applied_count":1`)

	readiness := buildProductionReadinessReport(config.Get())
	assert.Equal(t, "passed", productionReadinessCheckStatus(readiness.Checks, "wireless_roaming_lifecycle"))

	systemRec := httptest.NewRecorder()
	HandleGetSystemStatus(systemRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/status", nil))
	require.Equal(t, http.StatusOK, systemRec.Code, systemRec.Body.String())
	assert.Contains(t, systemRec.Body.String(), `"roaming_lifecycle"`)

	spec := buildOpenAPISpec(httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil), config.Get())
	paths := spec["paths"].(map[string]any)
	for _, path := range []string{
		"/api/v1/system/wireless-roaming-lifecycle",
		"/api/v1/system/wireless-roaming-lifecycle/preview",
		"/api/v1/system/wireless-roaming-lifecycle/apply",
		"/api/v1/system/wireless-roaming-lifecycle/history",
	} {
		_, ok := paths[path]
		assert.True(t, ok, "OpenAPI path %s should exist", path)
	}

	foundStatusCapture := false
	foundHistoryCapture := false
	for _, capture := range supportBundleAPICaptures() {
		if capture.archivePath == "api/wireless-roaming-lifecycle.json" {
			foundStatusCapture = true
		}
		if capture.archivePath == "api/wireless-roaming-lifecycle-history.json" {
			foundHistoryCapture = true
		}
	}
	assert.True(t, foundStatusCapture)
	assert.True(t, foundHistoryCapture)
}

func TestWirelessRoamingLifecycleRBAC(t *testing.T) {
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/wireless-roaming-lifecycle"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/wireless-roaming-lifecycle/preview"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/wireless-roaming-lifecycle/history"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/wireless-roaming-lifecycle/apply"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/wireless-roaming-lifecycle/apply"))
}

func prepareWirelessRoamingLifecycleAPITestRuntime(t *testing.T) string {
	t.Helper()
	t.Setenv("AEGIS_FT_KEY_SEED", "test-ft-seed-that-is-long-enough")
	previousDB := db.DB
	dir := t.TempDir()
	hostapdPath := filepath.ToSlash(filepath.Join(dir, "hostapd.conf"))
	cfgPath := filepath.Join(dir, "config.yaml")
	content := fmt.Sprintf(`
mode: two-nic
deployment:
  profile: enterprise
  form: physical
wan:
  name: ens33
  dhcp: true
lan:
  name: ens37
  address: 192.168.50.1/24
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
  hostapd_config_path: %q
  roaming:
    enabled: true
    mode: enforce
    fail_closed: true
    ieee80211r: true
    ieee80211k: true
    ieee80211v: true
    mobility_domain: 4f57
    pmf_required: true
    r0_key_lifetime_seconds: 7200
    reassociation_deadline: 1200
    nas_identifier: aegis-ap-1
    r1_key_holder: "001122334455"
    key_seed_ref: "env:AEGIS_FT_KEY_SEED"
    key_rotation_mode: active
    rrm_neighbor_report: true
    rrm_beacon_report: true
    bss_transition: true
    neighbor_aps:
      - name: ap-2
        bssid: "02:11:22:33:44:55"
        nas_identifier: aegis-ap-2
        r1_key_holder: "021122334455"
        ssids: ["Corp"]
        channel: 6
        op_class: 81
        preference: 255
    profiles:
      - name: corp-fast-roam
        enabled: true
        ieee80211r: true
        ieee80211k: true
        ieee80211v: true
        pmf_required: true
        neighbor_aps: ["ap-2"]
  ssids:
    - name: Corp
      auth_mode: wpa2-enterprise
      roaming_profile: corp-fast-roam
`, hostapdPath)
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
	return filepath.FromSlash(hostapdPath)
}
