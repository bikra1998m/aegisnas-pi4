package enforcement

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

func TestPreviewHostapdVLANLifecycleReadyWithFallbackAndFailClosedSSIDs(t *testing.T) {
	cfg := hostapdLifecycleTestConfig()

	report, err := PreviewHostapdVLANLifecycle(cfg)
	require.NoError(t, err)

	assert.Equal(t, HostapdVLANLifecycleFeatureID, report.FeatureID)
	assert.Equal(t, "ready", report.Status)
	assert.True(t, report.ReadyForExternalValidation)
	assert.Equal(t, float64(100), report.SoftwareCompletionPercent)
	assert.Equal(t, 2, report.Summary.DynamicSSIDCount)
	assert.Equal(t, 1, report.Summary.FallbackSSIDCount)
	assert.Equal(t, 1, report.Summary.FailClosedSSIDCount)
	assert.Equal(t, 2, report.Summary.HostapdVLANEntryCount)
	assert.NotEmpty(t, report.Plan.PlanFingerprint)
	assert.Contains(t, report.HostapdConfigPreview, "ssid=Corp")
	assert.Contains(t, report.HostapdConfigPreview, "dynamic_vlan=1")
	assert.Contains(t, report.HostapdConfigPreview, "ssid=Research")
	assert.Contains(t, report.HostapdConfigPreview, "dynamic_vlan=2")
	assert.Contains(t, report.HostapdConfigPreview, "auth_server_shared_secret=<redacted>")
	assert.NotContains(t, report.HostapdConfigPreview, "radius-secret")
	assert.Contains(t, report.Plan.HostapdVLANFileText, "30 br-corp wlan0.30")
	assert.Contains(t, report.Plan.HostapdVLANFileText, "40 br-vlan40 wlan0.40")
	assert.Contains(t, report.Requirements, "dynamic SSIDs without fallback VLAN use fail-closed dynamic_vlan=2")
	assert.Equal(t, "docs/nas-0074-release-certification-checklist.md", report.ReleaseCertificationChecklist)
}

func TestPreviewHostapdVLANLifecycleBlocksEmptyVLANFile(t *testing.T) {
	cfg := hostapdLifecycleTestConfig()
	cfg.VLANs = nil
	cfg.Wireless.SSIDs = []config.SSIDConfig{
		{Name: "Research", AuthMode: "wpa2-enterprise", DynamicVLAN: true},
	}

	report, err := PreviewHostapdVLANLifecycle(cfg)
	require.NoError(t, err)

	assert.Equal(t, "blocked", report.Status)
	assert.False(t, report.ReadyForExternalValidation)
	assert.Equal(t, float64(0), report.SoftwareCompletionPercent)
	assert.Equal(t, 1, report.Summary.DynamicSSIDCount)
	assert.Equal(t, 0, report.Summary.HostapdVLANEntryCount)
	assert.Contains(t, report.Blockers, "dynamic VLAN SSID needs at least one configured VLAN intent before hostapd can accept VLAN assignments")
	assert.True(t, containsLifecycleDiagnostic(report.Plan.Diagnostics, "hostapd_vlan_file_empty"))
}

func TestPreviewHostapdVLANLifecycleBlocksDisabledLifecycleWithDynamicSSID(t *testing.T) {
	cfg := hostapdLifecycleTestConfig()
	cfg.Policy.RuntimeVLANLifecycleEnabled = false

	report, err := PreviewHostapdVLANLifecycle(cfg)
	require.NoError(t, err)

	assert.Equal(t, "blocked", report.Status)
	assert.Equal(t, 2, report.Summary.DynamicSSIDCount)
	assert.Equal(t, float64(0), report.SoftwareCompletionPercent)
	assert.Contains(t, report.Blockers, "wireless dynamic VLAN SSIDs require policy.runtime_vlan_lifecycle_enabled before local hostapd rollout")
	assert.True(t, containsLifecycleDiagnostic(report.Plan.Diagnostics, "hostapd_vlan_lifecycle_disabled"))
}

func hostapdLifecycleTestConfig() *config.Config {
	return &config.Config{
		Mode: "two-nic",
		WAN:  config.InterfaceConfig{Name: "eth0", DHCP: true},
		LAN:  config.InterfaceConfig{Name: "eth1", Address: "192.168.50.1/24"},
		Database: config.DatabaseConfig{
			Path: "/tmp/aegisnas-test.db",
		},
		Health: config.HealthConfig{
			Port: 8080,
		},
		Telemetry: config.TelemetryConfig{
			Enabled:        true,
			PrometheusPort: 9090,
		},
		Policy: config.PolicyConfig{
			RuntimeVLANLifecycleEnabled: true,
		},
		Radius: config.RadiusConfig{
			Secret:                "radius-secret",
			AuthPort:              1812,
			AcctPort:              1813,
			RequestTimeoutSeconds: 5,
		},
		Wireless: config.WirelessConfig{
			Enabled:             true,
			Interface:           "wlan0",
			CountryCode:         "US",
			Driver:              "nl80211",
			HWMode:              "g",
			Channel:             6,
			BeaconInterval:      100,
			WMMEnabled:          true,
			HTEnabled:           true,
			HostapdConfigPath:   "/etc/hostapd/hostapd.conf",
			HostapdVLANFilePath: "/etc/hostapd/aegisnas-vlans.conf",
			SSIDs: []config.SSIDConfig{
				{Name: "Corp", AuthMode: "wpa2-enterprise", VLAN: 30, Bridge: "br-corp", DynamicVLAN: true},
				{Name: "Research", AuthMode: "wpa3-enterprise", DynamicVLAN: true},
			},
		},
		VLANs: []config.VLANConfig{
			{ID: 30, Name: "corp", Purpose: "employee"},
			{ID: 40, Name: "research", Purpose: "lab"},
		},
	}
}
