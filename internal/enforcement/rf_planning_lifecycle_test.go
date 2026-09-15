package enforcement

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestPreviewRFPlanningLifecycleBuildsChannelPowerMeshAndSteeringPlan(t *testing.T) {
	cfg := loadRFPlanningLifecycleTestConfig(t, "")

	report, err := PreviewRFPlanningLifecycle(cfg)
	require.NoError(t, err)

	assert.Equal(t, RFPlanningLifecycleFeatureID, report.FeatureID)
	assert.Equal(t, "ready", report.Status)
	assert.True(t, report.ReadyForExternalValidation)
	assert.Equal(t, float64(100), report.SoftwareCompletionPercent)
	assert.Equal(t, "US", report.Summary.CountryCode)
	assert.Equal(t, "auto", report.Summary.ChannelPlanMode)
	assert.Equal(t, 2, report.Summary.APCount)
	assert.Equal(t, 2, report.Summary.RadioCount)
	assert.Equal(t, 1, report.Summary.BandCount)
	assert.Equal(t, 2, report.Summary.ChannelPlanCount)
	assert.Equal(t, 2, report.Summary.PowerPlanCount)
	assert.Equal(t, 1, report.Summary.MeshRootCount)
	assert.Equal(t, 1, report.Summary.MeshLinkCount)
	assert.Equal(t, 1, report.Summary.SteeringPolicyCount)
	assert.Zero(t, report.Summary.BlockerCount)
	assert.Zero(t, report.Summary.WarningCount)
	assert.NotEmpty(t, report.PlanFingerprint)
	assert.Equal(t, "docs/nas-0079-release-certification-checklist.md", report.ReleaseCertificationChecklist)
	require.Len(t, report.MeshPlan, 1)
	assert.Equal(t, "ap-lobby", report.MeshPlan[0].RootAP)
	assert.Equal(t, "ap-hallway", report.MeshPlan[0].MeshAP)
	require.Len(t, report.SteeringPolicies, 1)
	assert.Equal(t, "Corp", report.SteeringPolicies[0].SSID)
	assert.Len(t, report.SteeringPolicies[0].TargetRadios, 2)
	require.NotEmpty(t, report.ControllerActions)
	assert.Equal(t, "preview", report.ControllerActions[0].Operation)
}

func TestPreviewRFPlanningLifecycleBlocksMissingMeshRoot(t *testing.T) {
	cfg := loadRFPlanningLifecycleTestConfig(t, `
wireless:
  rf:
    mesh:
      root_aps: []
`)

	report, err := PreviewRFPlanningLifecycle(cfg)
	require.NoError(t, err)

	assert.Equal(t, "blocked", report.Status)
	assert.False(t, report.ReadyForExternalValidation)
	assert.Equal(t, float64(0), report.SoftwareCompletionPercent)
	assert.NotEmpty(t, report.Blockers)
	assert.Contains(t, fmt.Sprint(report.Blockers), "root")
}

func TestPreviewRFPlanningLifecycleSkippedWhenDisabled(t *testing.T) {
	cfg := loadRFPlanningLifecycleTestConfig(t, `
wireless:
  rf:
    enabled: false
`)

	report, err := PreviewRFPlanningLifecycle(cfg)
	require.NoError(t, err)

	assert.Equal(t, "skipped", report.Status)
	assert.True(t, report.ReadyForExternalValidation)
	assert.Equal(t, float64(100), report.SoftwareCompletionPercent)
	assert.False(t, report.Summary.RFEnabled)
	assert.Empty(t, report.ChannelPlan)
	assert.NotEmpty(t, report.PlanFingerprint)
}

func TestApplyRFPlanningLifecycleRecordsEvidenceAndRuntimeStatus(t *testing.T) {
	cfg := loadRFPlanningLifecycleTestConfig(t, "")
	previousDB := db.DB
	require.NoError(t, db.Init(":memory:"))
	db.DB.SetMaxOpenConns(1)
	require.NoError(t, db.Migrate())
	t.Cleanup(func() {
		_ = db.Close()
		db.DB = previousDB
	})

	report, eventID, err := ApplyRFPlanningLifecycle(context.Background(), cfg, "ops@example.test")
	require.NoError(t, err)

	assert.Equal(t, "applied", report.Status)
	assert.NotEmpty(t, eventID)

	events, err := db.ListRFPlanningLifecycleEvents(10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "apply", events[0].Operation)
	assert.Equal(t, "applied", events[0].Status)
	assert.Equal(t, "ops@example.test", events[0].Actor)
	assert.Equal(t, 2, events[0].RadioCount)
	assert.Equal(t, 1, events[0].MeshLinkCount)

	runtime, err := db.GetRuntimeStatus(RFPlanningLifecycleComponent())
	require.NoError(t, err)
	require.NotNil(t, runtime)
	assert.Equal(t, "ok", runtime.Status)
	assert.Contains(t, runtime.Message, "NAS-0079")
}

func loadRFPlanningLifecycleTestConfig(t *testing.T, override string) *config.Config {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
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
	if override != "" {
		content = mergeRFPlanningLifecycleOverride(content, override)
	}
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	cfg, err := config.LoadCandidate(path)
	require.NoError(t, err)
	return cfg
}

func mergeRFPlanningLifecycleOverride(base, override string) string {
	switch {
	case strings.Contains(override, "enabled: false"):
		return strings.Replace(base, "    enabled: true\n    mode: monitor\n", "    enabled: false\n    mode: monitor\n", 1)
	case strings.Contains(override, "root_aps: []"):
		updated := strings.Replace(base, "      root_aps: [ap-lobby]\n", "      root_aps: []\n", 1)
		return strings.Replace(updated, "            mesh_role: root\n", "            mesh_role: mesh\n", 1)
	default:
		return base + "\n" + override
	}
}
