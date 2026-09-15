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

func TestRFPlanningLifecycleAPIPreviewApplyStatusHistoryReadinessAndSupportBundle(t *testing.T) {
	prepareRFPlanningLifecycleAPITestRuntime(t)

	previewRec := httptest.NewRecorder()
	HandlePreviewRFPlanningLifecycle(previewRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/rf-planning-lifecycle/preview", nil))
	require.Equal(t, http.StatusOK, previewRec.Code, previewRec.Body.String())
	var previewPayload struct {
		EventID string `json:"event_id"`
		Report  struct {
			FeatureID       string `json:"feature_id"`
			Status          string `json:"status"`
			PlanFingerprint string `json:"plan_fingerprint"`
			Summary         struct {
				APCount                  int `json:"ap_count"`
				RadioCount               int `json:"radio_count"`
				ChannelPlanCount         int `json:"channel_plan_count"`
				PowerPlanCount           int `json:"power_plan_count"`
				MeshLinkCount            int `json:"mesh_link_count"`
				SteeringPolicyCount      int `json:"steering_policy_count"`
				ComplianceCheckCount     int `json:"compliance_check_count"`
				PassedCheckCount         int `json:"passed_check_count"`
				BlockerCount             int `json:"blocker_count"`
				ExternalRequirementCount int `json:"external_requirement_count"`
			} `json:"summary"`
		} `json:"report"`
	}
	require.NoError(t, json.Unmarshal(previewRec.Body.Bytes(), &previewPayload))
	assert.NotEmpty(t, previewPayload.EventID)
	assert.Equal(t, "NAS-0079", previewPayload.Report.FeatureID)
	assert.Equal(t, "ready", previewPayload.Report.Status)
	assert.Equal(t, 2, previewPayload.Report.Summary.APCount)
	assert.Equal(t, 2, previewPayload.Report.Summary.RadioCount)
	assert.Equal(t, 2, previewPayload.Report.Summary.ChannelPlanCount)
	assert.Equal(t, 2, previewPayload.Report.Summary.PowerPlanCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.MeshLinkCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.SteeringPolicyCount)
	assert.Equal(t, previewPayload.Report.Summary.ComplianceCheckCount, previewPayload.Report.Summary.PassedCheckCount)
	assert.Zero(t, previewPayload.Report.Summary.BlockerCount)
	assert.Greater(t, previewPayload.Report.Summary.ExternalRequirementCount, 0)
	assert.NotEmpty(t, previewPayload.Report.PlanFingerprint)

	applyRec := httptest.NewRecorder()
	HandleApplyRFPlanningLifecycle(applyRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/rf-planning-lifecycle/apply", nil))
	require.Equal(t, http.StatusOK, applyRec.Code, applyRec.Body.String())
	assert.Contains(t, applyRec.Body.String(), `"status":"applied"`)

	statusRec := httptest.NewRecorder()
	HandleGetRFPlanningLifecycle(statusRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/rf-planning-lifecycle", nil))
	require.Equal(t, http.StatusOK, statusRec.Code, statusRec.Body.String())
	assert.Contains(t, statusRec.Body.String(), `"ready_for_external_validation":true`)
	assert.Contains(t, statusRec.Body.String(), `"recent_events"`)

	historyRec := httptest.NewRecorder()
	HandleListRFPlanningLifecycleHistory(historyRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/rf-planning-lifecycle/history?limit=5", nil))
	require.Equal(t, http.StatusOK, historyRec.Code, historyRec.Body.String())
	assert.Contains(t, historyRec.Body.String(), `"feature_id":"NAS-0079"`)
	assert.Contains(t, historyRec.Body.String(), `"preview_events":1`)
	assert.Contains(t, historyRec.Body.String(), `"applied_count":1`)

	readiness := buildProductionReadinessReport(config.Get())
	assert.Equal(t, "passed", productionReadinessCheckStatus(readiness.Checks, "rf_planning_lifecycle"))

	systemRec := httptest.NewRecorder()
	HandleGetSystemStatus(systemRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/status", nil))
	require.Equal(t, http.StatusOK, systemRec.Code, systemRec.Body.String())
	assert.Contains(t, systemRec.Body.String(), `"rf_planning_lifecycle"`)

	spec := buildOpenAPISpec(httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil), config.Get())
	paths := spec["paths"].(map[string]any)
	for _, path := range []string{
		"/api/v1/system/rf-planning-lifecycle",
		"/api/v1/system/rf-planning-lifecycle/preview",
		"/api/v1/system/rf-planning-lifecycle/apply",
		"/api/v1/system/rf-planning-lifecycle/history",
	} {
		_, ok := paths[path]
		assert.True(t, ok, "OpenAPI path %s should exist", path)
	}

	foundStatusCapture := false
	foundHistoryCapture := false
	for _, capture := range supportBundleAPICaptures() {
		if capture.archivePath == "api/rf-planning-lifecycle.json" {
			foundStatusCapture = true
		}
		if capture.archivePath == "api/rf-planning-lifecycle-history.json" {
			foundHistoryCapture = true
		}
	}
	assert.True(t, foundStatusCapture)
	assert.True(t, foundHistoryCapture)
}

func TestRFPlanningLifecycleRBAC(t *testing.T) {
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/rf-planning-lifecycle"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/rf-planning-lifecycle/preview"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/rf-planning-lifecycle/history"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/rf-planning-lifecycle/apply"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/rf-planning-lifecycle/apply"))
}

func prepareRFPlanningLifecycleAPITestRuntime(t *testing.T) {
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
wireless:
  enabled: false
  country_code: US
  roaming:
    enabled: true
    ieee80211k: true
    ieee80211v: true
  ssids:
    - name: Corp
      auth_mode: wpa2-enterprise
      vlan: 20
  rf:
    enabled: true
    mode: monitor
    channel_plan_mode: auto
    default_channel_width_mhz: 40
    min_power_dbm: 8
    max_power_dbm: 23
    target_cell_rssi: -67
    max_channel_reuse: 2
    max_clients_per_radio: 80
    bands:
      - name: 5ghz
        enabled: true
        channels: [36, 44, 149]
        channel_width_mhz: 40
        min_power_dbm: 8
        max_power_dbm: 23
        dfs_allowed: true
        max_clients_per_radio: 80
    mesh:
      enabled: true
      mode: monitor
      root_aps: [ap-lobby]
      backhaul_ssid: AegisMesh
      bridge_vlan: 30
      max_hops: 2
      min_backhaul_rssi: -67
      prefer_5ghz: true
    client_steering:
      enabled: true
      mode: monitor
      min_rssi: -72
      sticky_client_rssi: -78
      band_preference: 5ghz
      load_balance: true
      max_clients_per_radio: 80
      reject_below_min_rssi: true
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
            max_clients: 80
            ssids: [Corp]
            mesh_enabled: true
            mesh_role: root
            client_steering: true
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
            max_clients: 80
            ssids: [Corp]
            mesh_enabled: true
            mesh_role: mesh
            client_steering: true
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
