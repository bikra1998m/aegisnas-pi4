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

func TestPasspointLifecycleAPIPreviewApplyStatusHistoryReadinessAndSupportBundle(t *testing.T) {
	hostapdPath := preparePasspointLifecycleAPITestRuntime(t)

	previewRec := httptest.NewRecorder()
	HandlePreviewPasspointLifecycle(previewRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/passpoint-lifecycle/preview", nil))
	require.Equal(t, http.StatusOK, previewRec.Code, previewRec.Body.String())
	var previewPayload struct {
		EventID string `json:"event_id"`
		Report  struct {
			FeatureID            string `json:"feature_id"`
			Status               string `json:"status"`
			HostapdConfigPreview string `json:"hostapd_config_preview"`
			Summary              struct {
				PasspointSSIDCount        int `json:"passpoint_ssid_count"`
				InterworkingSSIDCount     int `json:"interworking_ssid_count"`
				HS20SSIDCount             int `json:"hs20_ssid_count"`
				OSUProviderCount          int `json:"osu_provider_count"`
				DomainNameCount           int `json:"domain_name_count"`
				RoamingConsortiumCount    int `json:"roaming_consortium_count"`
				NAIRealmCount             int `json:"nai_realm_count"`
				CellularNetworkCount      int `json:"cellular_network_count"`
				ConnectionCapabilityCount int `json:"connection_capability_count"`
			} `json:"summary"`
		} `json:"report"`
	}
	require.NoError(t, json.Unmarshal(previewRec.Body.Bytes(), &previewPayload))
	assert.NotEmpty(t, previewPayload.EventID)
	assert.Equal(t, "NAS-0076", previewPayload.Report.FeatureID)
	assert.Equal(t, "ready", previewPayload.Report.Status)
	assert.Equal(t, 1, previewPayload.Report.Summary.PasspointSSIDCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.InterworkingSSIDCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.HS20SSIDCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.OSUProviderCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.DomainNameCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.RoamingConsortiumCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.NAIRealmCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.CellularNetworkCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.ConnectionCapabilityCount)
	assert.Contains(t, previewPayload.Report.HostapdConfigPreview, "interworking=1")
	assert.Contains(t, previewPayload.Report.HostapdConfigPreview, "hs20=1")
	assert.Contains(t, previewPayload.Report.HostapdConfigPreview, "osu_server_uri=https://osu.example.com/signup")

	applyRec := httptest.NewRecorder()
	HandleApplyPasspointLifecycle(applyRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/passpoint-lifecycle/apply", nil))
	require.Equal(t, http.StatusOK, applyRec.Code, applyRec.Body.String())
	assert.Contains(t, applyRec.Body.String(), `"status":"applied"`)
	raw, err := os.ReadFile(hostapdPath)
	require.NoError(t, err)
	assert.Contains(t, string(raw), "interworking=1")
	assert.Contains(t, string(raw), "hs20_oper_friendly_name=eng:AegisNAS")

	statusRec := httptest.NewRecorder()
	HandleGetPasspointLifecycle(statusRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/passpoint-lifecycle", nil))
	require.Equal(t, http.StatusOK, statusRec.Code, statusRec.Body.String())
	assert.Contains(t, statusRec.Body.String(), `"ready_for_external_validation":true`)
	assert.Contains(t, statusRec.Body.String(), `"recent_events"`)

	historyRec := httptest.NewRecorder()
	HandleListPasspointLifecycleHistory(historyRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/passpoint-lifecycle/history?limit=5", nil))
	require.Equal(t, http.StatusOK, historyRec.Code, historyRec.Body.String())
	assert.Contains(t, historyRec.Body.String(), `"feature_id":"NAS-0076"`)
	assert.Contains(t, historyRec.Body.String(), `"preview_events":1`)
	assert.Contains(t, historyRec.Body.String(), `"applied_count":1`)

	readiness := buildProductionReadinessReport(config.Get())
	assert.Equal(t, "passed", productionReadinessCheckStatus(readiness.Checks, "passpoint_lifecycle"))

	systemRec := httptest.NewRecorder()
	HandleGetSystemStatus(systemRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/status", nil))
	require.Equal(t, http.StatusOK, systemRec.Code, systemRec.Body.String())
	assert.Contains(t, systemRec.Body.String(), `"passpoint_lifecycle"`)

	spec := buildOpenAPISpec(httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil), config.Get())
	paths := spec["paths"].(map[string]any)
	for _, path := range []string{
		"/api/v1/system/passpoint-lifecycle",
		"/api/v1/system/passpoint-lifecycle/preview",
		"/api/v1/system/passpoint-lifecycle/apply",
		"/api/v1/system/passpoint-lifecycle/history",
	} {
		_, ok := paths[path]
		assert.True(t, ok, "OpenAPI path %s should exist", path)
	}

	foundStatusCapture := false
	foundHistoryCapture := false
	for _, capture := range supportBundleAPICaptures() {
		if capture.archivePath == "api/passpoint-lifecycle.json" {
			foundStatusCapture = true
		}
		if capture.archivePath == "api/passpoint-lifecycle-history.json" {
			foundHistoryCapture = true
		}
	}
	assert.True(t, foundStatusCapture)
	assert.True(t, foundHistoryCapture)
}

func TestPasspointLifecycleRBAC(t *testing.T) {
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/passpoint-lifecycle"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/passpoint-lifecycle/preview"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/passpoint-lifecycle/history"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/passpoint-lifecycle/apply"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/passpoint-lifecycle/apply"))
}

func preparePasspointLifecycleAPITestRuntime(t *testing.T) string {
	t.Helper()
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
  passpoint:
    enabled: true
    mode: enforce
    fail_closed: true
    interworking: true
    hs20: true
    access_network_type: 2
    internet: true
    profiles:
      - name: corp-passpoint
        enabled: true
        interworking: true
        hs20: true
        hessid: "02:11:22:33:44:55"
        disable_dgaf: true
        proxy_arp: true
        domain_names: ["corp.example.com"]
        roaming_consortium_ois: ["112233"]
        operator_friendly_names:
          - language: eng
            text: AegisNAS
        venue_names:
          - language: eng
            text: AegisNAS Lab
        nai_realms:
          - realm: corp.example.com
            encoding: 0
            eap_methods: ["tls", "ttls"]
            auth_params: ["5:6"]
        cellular_networks:
          - mcc: "310"
            mnc: "260"
        wan_metrics:
          enabled: true
          wan_info: "01"
          downlink_kbps: 100000
          uplink_kbps: 50000
          downlink_load: 1
          uplink_load: 1
        connection_capabilities:
          - protocol: 6
            port: 443
            status: 1
        osu:
          enabled: true
          ssid: Aegis OSU
          server_uri: https://osu.example.com/signup
          friendly_names:
            - language: eng
              text: AegisNAS Signup
          nai: anonymous@corp.example.com
          method_list: [1]
          service_descriptions:
            - language: eng
              text: Corporate onboarding
  ssids:
    - name: Corp
      auth_mode: wpa2-enterprise
      passpoint_profile: corp-passpoint
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
