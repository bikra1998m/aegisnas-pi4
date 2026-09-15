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

func TestPreviewWirelessSecurityLifecycleBuildsFullPlan(t *testing.T) {
	cfg := loadWirelessSecurityLifecycleTestConfig(t, "")

	report, err := PreviewWirelessSecurityLifecycle(cfg)
	require.NoError(t, err)

	assert.Equal(t, WirelessSecurityLifecycleFeatureID, report.FeatureID)
	assert.Equal(t, "ready", report.Status)
	assert.True(t, report.ReadyForExternalValidation)
	assert.Equal(t, float64(100), report.SoftwareCompletionPercent)
	assert.Equal(t, "monitor", report.Summary.Mode)
	assert.Equal(t, 2, report.Summary.SensorCount)
	assert.Equal(t, 3, report.Summary.RoguePolicyCount)
	assert.Equal(t, 8, report.Summary.WIPSDetectionCount)
	assert.Equal(t, 2, report.Summary.SpectrumChannelCount)
	assert.Equal(t, 1, report.Summary.LocationZoneCount)
	assert.Equal(t, 7, report.Summary.MulticastPolicyCount)
	assert.Zero(t, report.Summary.BlockerCount)
	assert.Zero(t, report.Summary.WarningCount)
	assert.NotEmpty(t, report.PlanFingerprint)
	assert.Equal(t, "docs/nas-0080-release-certification-checklist.md", report.ReleaseCertificationChecklist)
	require.Len(t, report.Sensors, 2)
	require.NotEmpty(t, report.ControllerActions)
	assert.Equal(t, "preview", report.ControllerActions[0].Operation)
	assert.Contains(t, fmt.Sprint(report.Compliance), "Location Privacy")
}

func TestPreviewWirelessSecurityLifecycleBlocksUnsafeLocationPrivacy(t *testing.T) {
	cfg := loadWirelessSecurityLifecycleTestConfig(t, `
    enabled: true
    mode: enforce
    fail_closed: true
    location:
      enabled: true
      mode: coordinate
      privacy_mode: raw
      export_client_coordinates: true
      min_aps_for_triangulation: 4
      retention_hours: 720
      hash_client_identifiers: false
      zones:
        - name: HQ
          floor: "1"
          building: HQ
`)

	report, err := PreviewWirelessSecurityLifecycle(cfg)
	require.NoError(t, err)

	assert.Equal(t, "blocked", report.Status)
	assert.False(t, report.ReadyForExternalValidation)
	assert.Equal(t, float64(0), report.SoftwareCompletionPercent)
	assert.NotEmpty(t, report.Blockers)
	assert.Contains(t, fmt.Sprint(report.Blockers), "Raw client coordinate export")
}

func TestPreviewWirelessSecurityLifecycleSkippedWhenDisabled(t *testing.T) {
	cfg := loadWirelessSecurityLifecycleTestConfig(t, "disabled")

	report, err := PreviewWirelessSecurityLifecycle(cfg)
	require.NoError(t, err)

	assert.Equal(t, "skipped", report.Status)
	assert.True(t, report.ReadyForExternalValidation)
	assert.Equal(t, float64(100), report.SoftwareCompletionPercent)
	assert.False(t, report.Summary.SecurityEnabled)
	assert.Empty(t, report.Sensors)
	assert.NotEmpty(t, report.PlanFingerprint)
}

func TestApplyWirelessSecurityLifecycleRecordsEvidenceAndRuntimeStatus(t *testing.T) {
	cfg := loadWirelessSecurityLifecycleTestConfig(t, "")
	previousDB := db.DB
	require.NoError(t, db.Init(":memory:"))
	db.DB.SetMaxOpenConns(1)
	require.NoError(t, db.Migrate())
	t.Cleanup(func() {
		_ = db.Close()
		db.DB = previousDB
	})

	report, eventID, err := ApplyWirelessSecurityLifecycle(context.Background(), cfg, "ops@example.test")
	require.NoError(t, err)

	assert.Equal(t, "applied", report.Status)
	assert.NotEmpty(t, eventID)

	events, err := db.ListWirelessSecurityLifecycleEvents(10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "apply", events[0].Operation)
	assert.Equal(t, "applied", events[0].Status)
	assert.Equal(t, "ops@example.test", events[0].Actor)
	assert.Equal(t, 2, events[0].SensorCount)
	assert.Equal(t, 8, events[0].WIPSDetectionCount)

	runtime, err := db.GetRuntimeStatus(WirelessSecurityLifecycleComponent())
	require.NoError(t, err)
	require.NotNil(t, runtime)
	assert.Equal(t, "ok", runtime.Status)
	assert.Contains(t, runtime.Message, "NAS-0080")
}

func loadWirelessSecurityLifecycleTestConfig(t *testing.T, override string) *config.Config {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	securityBlock := `
    enabled: true
    mode: monitor
    fail_closed: true
    rogue:
      enabled: true
      containment_enabled: true
      allow_containment: true
      auto_containment: false
      quarantine_role: quarantine
      allowed_ouis: ["001122"]
      trusted_bssids: ["02:11:22:33:44:55"]
      trusted_ssids: [Corp]
      watch_ssids: [Corp]
      min_rssi: -80
      classification_policy: balanced
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
	if override == "disabled" {
		securityBlock = strings.Replace(securityBlock, "    enabled: true\n", "    enabled: false\n", 1)
	} else if strings.TrimSpace(override) != "" {
		securityBlock = override
	}
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
` + securityBlock
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	cfg, err := config.LoadCandidate(path)
	require.NoError(t, err)
	return cfg
}
