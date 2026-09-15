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

func TestPPSKLifecycleAPIPreviewApplyStatusHistoryReadinessAndSupportBundle(t *testing.T) {
	hostapdPath, pskPath := preparePPSKLifecycleAPITestRuntime(t)

	previewRec := httptest.NewRecorder()
	HandlePreviewPPSKLifecycle(previewRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/ppsk-lifecycle/preview", nil))
	require.Equal(t, http.StatusOK, previewRec.Code, previewRec.Body.String())
	var previewPayload struct {
		EventID string `json:"event_id"`
		Report  struct {
			FeatureID            string `json:"feature_id"`
			Status               string `json:"status"`
			HostapdConfigPreview string `json:"hostapd_config_preview"`
			PSKFilePreview       string `json:"psk_file_preview"`
			Summary              struct {
				PPSKSSIDCount          int `json:"ppsk_ssid_count"`
				ProfileCount           int `json:"profile_count"`
				GroupCount             int `json:"group_count"`
				CredentialCount        int `json:"credential_count"`
				ActiveCredentialCount  int `json:"active_credential_count"`
				StagedCredentialCount  int `json:"staged_credential_count"`
				RevokedCredentialCount int `json:"revoked_credential_count"`
			} `json:"summary"`
		} `json:"report"`
	}
	require.NoError(t, json.Unmarshal(previewRec.Body.Bytes(), &previewPayload))
	assert.NotEmpty(t, previewPayload.EventID)
	assert.Equal(t, "NAS-0077", previewPayload.Report.FeatureID)
	assert.Equal(t, "ready", previewPayload.Report.Status)
	assert.Equal(t, 1, previewPayload.Report.Summary.PPSKSSIDCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.ProfileCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.GroupCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.CredentialCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.ActiveCredentialCount)
	assert.Contains(t, previewPayload.Report.HostapdConfigPreview, "wpa_psk_file=")
	assert.Contains(t, previewPayload.Report.PSKFilePreview, "02:11:22:33:44:55 <redacted>")
	assert.NotContains(t, previewPayload.Report.PSKFilePreview, "camera-secret-123")

	applyRec := httptest.NewRecorder()
	HandleApplyPPSKLifecycle(applyRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/ppsk-lifecycle/apply", nil))
	require.Equal(t, http.StatusOK, applyRec.Code, applyRec.Body.String())
	assert.Contains(t, applyRec.Body.String(), `"status":"applied"`)
	hostapdRaw, err := os.ReadFile(hostapdPath)
	require.NoError(t, err)
	assert.Contains(t, string(hostapdRaw), "wpa_psk_file=")
	pskRaw, err := os.ReadFile(pskPath)
	require.NoError(t, err)
	assert.Contains(t, string(pskRaw), "02:11:22:33:44:55 camera-secret-123")

	statusRec := httptest.NewRecorder()
	HandleGetPPSKLifecycle(statusRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/ppsk-lifecycle", nil))
	require.Equal(t, http.StatusOK, statusRec.Code, statusRec.Body.String())
	assert.Contains(t, statusRec.Body.String(), `"ready_for_external_validation":true`)
	assert.Contains(t, statusRec.Body.String(), `"recent_events"`)

	historyRec := httptest.NewRecorder()
	HandleListPPSKLifecycleHistory(historyRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/ppsk-lifecycle/history?limit=5", nil))
	require.Equal(t, http.StatusOK, historyRec.Code, historyRec.Body.String())
	assert.Contains(t, historyRec.Body.String(), `"feature_id":"NAS-0077"`)
	assert.Contains(t, historyRec.Body.String(), `"preview_events":1`)
	assert.Contains(t, historyRec.Body.String(), `"applied_count":1`)

	readiness := buildProductionReadinessReport(config.Get())
	assert.Equal(t, "passed", productionReadinessCheckStatus(readiness.Checks, "ppsk_lifecycle"))

	systemRec := httptest.NewRecorder()
	HandleGetSystemStatus(systemRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/status", nil))
	require.Equal(t, http.StatusOK, systemRec.Code, systemRec.Body.String())
	assert.Contains(t, systemRec.Body.String(), `"ppsk_lifecycle"`)

	spec := buildOpenAPISpec(httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil), config.Get())
	paths := spec["paths"].(map[string]any)
	for _, path := range []string{
		"/api/v1/system/ppsk-lifecycle",
		"/api/v1/system/ppsk-lifecycle/preview",
		"/api/v1/system/ppsk-lifecycle/apply",
		"/api/v1/system/ppsk-lifecycle/history",
	} {
		_, ok := paths[path]
		assert.True(t, ok, "OpenAPI path %s should exist", path)
	}

	foundStatusCapture := false
	foundHistoryCapture := false
	for _, capture := range supportBundleAPICaptures() {
		if capture.archivePath == "api/ppsk-lifecycle.json" {
			foundStatusCapture = true
		}
		if capture.archivePath == "api/ppsk-lifecycle-history.json" {
			foundHistoryCapture = true
		}
	}
	assert.True(t, foundStatusCapture)
	assert.True(t, foundHistoryCapture)
}

func TestPPSKLifecycleRBAC(t *testing.T) {
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/ppsk-lifecycle"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/ppsk-lifecycle/preview"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/ppsk-lifecycle/history"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/ppsk-lifecycle/apply"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/ppsk-lifecycle/apply"))
}

func preparePPSKLifecycleAPITestRuntime(t *testing.T) (string, string) {
	t.Helper()
	t.Setenv("AEGIS_TEST_PPSK", "camera-secret-123")
	previousDB := db.DB
	dir := t.TempDir()
	hostapdPath := filepath.ToSlash(filepath.Join(dir, "hostapd.conf"))
	pskPath := filepath.ToSlash(filepath.Join(dir, "aegisnas-ppsk.psk"))
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
  ppsk:
    enabled: true
    mode: enforce
    fail_closed: true
    psk_file_path: %q
    rotation_mode: active
    min_passphrase_length: 8
    profiles:
      - name: iot-ppsk
        enabled: true
        mode: enforce
        fail_closed: true
        groups: ["cameras"]
        default_vlan: 30
        role: iot
        bandwidth_profile: iot-basic
        controller_sync: false
    groups:
      - name: cameras
        enabled: true
        vlan: 30
        role: iot
        bandwidth_profile: iot-basic
        max_devices: 100
        session_limit: 1
    credentials:
      - id: camera-1
        enabled: true
        mac: "02:11:22:33:44:55"
        device_id: cam-1
        owner: facilities
        profile: iot-ppsk
        group: cameras
        secret_ref: env:AEGIS_TEST_PPSK
  ssids:
    - name: IoT
      auth_mode: wpa2-personal
      ppsk_profile: iot-ppsk
`, hostapdPath, pskPath)
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
	return filepath.FromSlash(hostapdPath), filepath.FromSlash(pskPath)
}
