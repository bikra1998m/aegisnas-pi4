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

func TestWirelessSecurityLifecycleAPIPreviewApplyStatusHistoryReadinessAndSupportBundle(t *testing.T) {
	prepareWirelessSecurityLifecycleAPITestRuntime(t)

	previewRec := httptest.NewRecorder()
	HandlePreviewWirelessSecurityLifecycle(previewRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/wireless-security-lifecycle/preview", nil))
	require.Equal(t, http.StatusOK, previewRec.Code, previewRec.Body.String())
	var previewPayload struct {
		EventID string `json:"event_id"`
		Report  struct {
			FeatureID       string `json:"feature_id"`
			Status          string `json:"status"`
			PlanFingerprint string `json:"plan_fingerprint"`
			Summary         struct {
				SensorCount              int `json:"sensor_count"`
				RoguePolicyCount         int `json:"rogue_policy_count"`
				WIPSDetectionCount       int `json:"wips_detection_count"`
				SpectrumChannelCount     int `json:"spectrum_channel_count"`
				LocationZoneCount        int `json:"location_zone_count"`
				MulticastPolicyCount     int `json:"multicast_policy_count"`
				ComplianceCheckCount     int `json:"compliance_check_count"`
				PassedCheckCount         int `json:"passed_check_count"`
				BlockerCount             int `json:"blocker_count"`
				ExternalRequirementCount int `json:"external_requirement_count"`
			} `json:"summary"`
		} `json:"report"`
	}
	require.NoError(t, json.Unmarshal(previewRec.Body.Bytes(), &previewPayload))
	assert.NotEmpty(t, previewPayload.EventID)
	assert.Equal(t, "NAS-0080", previewPayload.Report.FeatureID)
	assert.Equal(t, "ready", previewPayload.Report.Status)
	assert.Equal(t, 2, previewPayload.Report.Summary.SensorCount)
	assert.Equal(t, 3, previewPayload.Report.Summary.RoguePolicyCount)
	assert.Equal(t, 8, previewPayload.Report.Summary.WIPSDetectionCount)
	assert.Equal(t, 2, previewPayload.Report.Summary.SpectrumChannelCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.LocationZoneCount)
	assert.Equal(t, 7, previewPayload.Report.Summary.MulticastPolicyCount)
	assert.Equal(t, previewPayload.Report.Summary.ComplianceCheckCount, previewPayload.Report.Summary.PassedCheckCount)
	assert.Zero(t, previewPayload.Report.Summary.BlockerCount)
	assert.Greater(t, previewPayload.Report.Summary.ExternalRequirementCount, 0)
	assert.NotEmpty(t, previewPayload.Report.PlanFingerprint)

	applyRec := httptest.NewRecorder()
	HandleApplyWirelessSecurityLifecycle(applyRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/wireless-security-lifecycle/apply", nil))
	require.Equal(t, http.StatusOK, applyRec.Code, applyRec.Body.String())
	assert.Contains(t, applyRec.Body.String(), `"status":"applied"`)

	statusRec := httptest.NewRecorder()
	HandleGetWirelessSecurityLifecycle(statusRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/wireless-security-lifecycle", nil))
	require.Equal(t, http.StatusOK, statusRec.Code, statusRec.Body.String())
	assert.Contains(t, statusRec.Body.String(), `"ready_for_external_validation":true`)
	assert.Contains(t, statusRec.Body.String(), `"recent_events"`)

	historyRec := httptest.NewRecorder()
	HandleListWirelessSecurityLifecycleHistory(historyRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/wireless-security-lifecycle/history?limit=5", nil))
	require.Equal(t, http.StatusOK, historyRec.Code, historyRec.Body.String())
	assert.Contains(t, historyRec.Body.String(), `"feature_id":"NAS-0080"`)
	assert.Contains(t, historyRec.Body.String(), `"preview_events":1`)
	assert.Contains(t, historyRec.Body.String(), `"applied_count":1`)

	readiness := buildProductionReadinessReport(config.Get())
	assert.Equal(t, "passed", productionReadinessCheckStatus(readiness.Checks, "wireless_security_lifecycle"))

	systemRec := httptest.NewRecorder()
	HandleGetSystemStatus(systemRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/status", nil))
	require.Equal(t, http.StatusOK, systemRec.Code, systemRec.Body.String())
	assert.Contains(t, systemRec.Body.String(), `"security_lifecycle"`)

	spec := buildOpenAPISpec(httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil), config.Get())
	paths := spec["paths"].(map[string]any)
	for _, path := range []string{
		"/api/v1/system/wireless-security-lifecycle",
		"/api/v1/system/wireless-security-lifecycle/preview",
		"/api/v1/system/wireless-security-lifecycle/apply",
		"/api/v1/system/wireless-security-lifecycle/history",
	} {
		_, ok := paths[path]
		assert.True(t, ok, "OpenAPI path %s should exist", path)
	}

	foundStatusCapture := false
	foundHistoryCapture := false
	for _, capture := range supportBundleAPICaptures() {
		if capture.archivePath == "api/wireless-security-lifecycle.json" {
			foundStatusCapture = true
		}
		if capture.archivePath == "api/wireless-security-lifecycle-history.json" {
			foundHistoryCapture = true
		}
	}
	assert.True(t, foundStatusCapture)
	assert.True(t, foundHistoryCapture)
}

func TestWirelessSecurityLifecycleRBAC(t *testing.T) {
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/wireless-security-lifecycle"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/wireless-security-lifecycle/preview"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/wireless-security-lifecycle/history"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/wireless-security-lifecycle/apply"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/wireless-security-lifecycle/apply"))
}

func prepareWirelessSecurityLifecycleAPITestRuntime(t *testing.T) {
	t.Helper()
	previousDB := db.DB
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	content := `
mode: two-nic
deployment:
  profile: enterprise
  form: virtual
database:
  path: ":memory:"
wan:
  name: ens33
  dhcp: true
lan:
  name: ens37
  address: 192.168.50.1/24
radius:
  secret: radius-secret
  dynamic_auth:
    enabled: true
wireless:
  enabled: false
  country_code: US
  ssids:
    - name: Corp
      auth_mode: wpa2-enterprise
      vlan: 20
  rf:
    enabled: true
    mode: monitor
    channel_plan_mode: auto
    bands:
      - name: 5ghz
        enabled: true
        channels: [36, 44]
    aps:
      - name: ap-lobby
        enabled: true
        location: Lobby
        zone: HQ
        floor: "1"
        radios:
          - name: radio-5g
            enabled: true
            interface: wlan0
            bssid: "02:11:22:33:44:55"
            band: 5ghz
            channel: 36
            channel_width_mhz: 40
            tx_power_dbm: 18
            ssids: [Corp]
      - name: ap-hallway
        enabled: true
        location: Hallway
        zone: HQ
        floor: "1"
        radios:
          - name: radio-5g
            enabled: true
            interface: wlan1
            bssid: "02:11:22:33:44:66"
            band: 5ghz
            channel: 44
            channel_width_mhz: 40
            tx_power_dbm: 16
            ssids: [Corp]
  security:
    enabled: true
    mode: monitor
    fail_closed: true
    rogue:
      enabled: true
      containment_enabled: true
      allow_containment: true
      allowed_ouis: ["001122"]
      trusted_bssids: ["02:11:22:33:44:55"]
      trusted_ssids: [Corp]
      watch_ssids: [Corp]
      min_rssi: -80
      classification_policy: balanced
      quarantine_role: quarantine
    wips:
      enabled: true
      deauth_detection: true
      evil_twin_detection: true
      honeypot_detection: true
      adhoc_detection: true
      spoofing_detection: true
      flood_detection: true
      eapol_attack_detection: true
      pmf_required: true
      alert_threshold: 1
    spectrum:
      enabled: true
      noise_floor_dbm: -95
      channel_utilization_warn_percent: 70
      interference_warn_percent: 35
      duty_cycle_warn_percent: 80
      sample_interval_seconds: 30
    location:
      enabled: true
      mode: coordinate
      privacy_mode: hashed
      export_client_coordinates: false
      min_aps_for_triangulation: 2
      retention_hours: 720
      hash_client_identifiers: true
      zones:
        - name: HQ
          floor: "1"
          building: HQ
    multicast:
      enabled: true
      mode: optimize
      igmp_snooping: true
      mld_snooping: true
      multicast_to_unicast: true
      broadcast_filter: true
      mdns_gateway: true
      ssdp_filter: true
      ipv6_multicast: true
      max_groups: 128
      allowed_groups: ["239.255.255.250"]
    sensors:
      - name: sensor-lobby
        enabled: true
        location: Lobby
        zone: HQ
        floor: "1"
        bssid: "02:11:22:33:44:55"
        channels: [36]
        bands: [5ghz]
        controller: generic
      - name: sensor-hallway
        enabled: true
        location: Hallway
        zone: HQ
        floor: "1"
        bssid: "02:11:22:33:44:66"
        channels: [44]
        bands: [5ghz]
        controller: generic
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
