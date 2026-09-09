package enforcement

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestPreviewWirelessRoamingLifecycleReadyRedactsFTKeys(t *testing.T) {
	t.Setenv("AEGIS_FT_KEY_SEED", "test-ft-seed-that-is-long-enough")
	cfg := wirelessRoamingLifecycleTestConfig(t)

	report, err := PreviewWirelessRoamingLifecycle(cfg)
	require.NoError(t, err)

	assert.Equal(t, WirelessRoamingLifecycleFeatureID, report.FeatureID)
	assert.Equal(t, "ready", report.Status)
	assert.True(t, report.ReadyForExternalValidation)
	assert.Equal(t, float64(100), report.SoftwareCompletionPercent)
	assert.Equal(t, 1, report.Summary.RoamingSSIDCount)
	assert.Equal(t, 1, report.Summary.FTSSIDCount)
	assert.Equal(t, 1, report.Summary.KSSIDCount)
	assert.Equal(t, 1, report.Summary.VSSIDCount)
	assert.Equal(t, 1, report.Summary.NeighborCount)
	assert.Equal(t, 1, report.Summary.KeyRefCount)
	assert.Equal(t, 1, report.Summary.ResolvableKeyRefCount)
	assert.Contains(t, report.HostapdConfigPreview, "wpa_key_mgmt=WPA-EAP FT-EAP")
	assert.Contains(t, report.HostapdConfigPreview, "r0kh=<redacted>")
	assert.Contains(t, report.HostapdConfigPreview, "r1kh=<redacted>")
	assert.NotContains(t, report.HostapdConfigPreview, "test-ft-seed-that-is-long-enough")
	assert.Contains(t, report.Attributes, "EAP-Message")
	assert.Equal(t, "docs/nas-0075-release-certification-checklist.md", report.ReleaseCertificationChecklist)
}

func TestPreviewWirelessRoamingLifecycleBlocksUnresolvedKeyRef(t *testing.T) {
	cfg := wirelessRoamingLifecycleTestConfig(t)
	cfg.Wireless.Roaming.KeySeedRef = "env:AEGIS_MISSING_FT_KEY_SEED"

	report, err := PreviewWirelessRoamingLifecycle(cfg)
	require.NoError(t, err)

	assert.Equal(t, "blocked", report.Status)
	assert.False(t, report.ReadyForExternalValidation)
	assert.Equal(t, float64(0), report.SoftwareCompletionPercent)
	assert.NotEmpty(t, report.Blockers)
	assert.Contains(t, report.Blockers[0], "key_seed_ref does not resolve")
}

func TestPreviewWirelessRoamingLifecycleSkippedWhenDisabled(t *testing.T) {
	cfg := wirelessRoamingLifecycleTestConfig(t)
	cfg.Wireless.Roaming.Enabled = false

	report, err := PreviewWirelessRoamingLifecycle(cfg)
	require.NoError(t, err)

	assert.Equal(t, "skipped", report.Status)
	assert.True(t, report.ReadyForExternalValidation)
	assert.Equal(t, float64(100), report.SoftwareCompletionPercent)
	assert.Empty(t, report.HostapdConfigPreview)
}

func TestApplyWirelessRoamingLifecycleWritesConfigAndRecordsEvent(t *testing.T) {
	t.Setenv("AEGIS_FT_KEY_SEED", "test-ft-seed-that-is-long-enough")
	previousDB := db.DB
	require.NoError(t, db.Init(":memory:"))
	db.DB.SetMaxOpenConns(1)
	require.NoError(t, db.Migrate())
	t.Cleanup(func() {
		_ = db.Close()
		db.DB = previousDB
	})
	cfg := wirelessRoamingLifecycleTestConfig(t)

	report, eventID, err := ApplyWirelessRoamingLifecycle(cfg, "ops")
	require.NoError(t, err)

	assert.NotEmpty(t, eventID)
	assert.Equal(t, "applied", report.Status)
	raw, err := os.ReadFile(cfg.Wireless.HostapdConfigPath)
	require.NoError(t, err)
	assert.Contains(t, string(raw), "mobility_domain=4f57")
	assert.Contains(t, string(raw), "r0kh=02:11:22:33:44:55")

	events, err := db.ListWirelessRoamingLifecycleEvents(5)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "apply", events[0].Operation)
	assert.Equal(t, "applied", events[0].Status)
	assert.Equal(t, "ops", events[0].Actor)

	summary, err := db.GetWirelessRoamingLifecycleSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TotalEvents)
	assert.Equal(t, 1, summary.AppliedCount)
	assert.Equal(t, 1, summary.LastRoamingSSIDCount)
}

func wirelessRoamingLifecycleTestConfig(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	return &config.Config{
		Mode: "two-nic",
		WAN:  config.InterfaceConfig{Name: "eth0"},
		LAN:  config.InterfaceConfig{Name: "eth1"},
		Database: config.DatabaseConfig{
			Path: filepath.Join(dir, "aegis.db"),
		},
		Health: config.HealthConfig{
			Port: 8080,
		},
		Telemetry: config.TelemetryConfig{
			Enabled:        true,
			PrometheusPort: 9090,
		},
		Radius: config.RadiusConfig{
			Secret:                "radius-secret",
			AuthPort:              1812,
			AcctPort:              1813,
			RequestTimeoutSeconds: 5,
		},
		Wireless: config.WirelessConfig{
			Enabled:           true,
			Interface:         "wlan0",
			CountryCode:       "US",
			Driver:            "nl80211",
			HWMode:            "g",
			Channel:           6,
			BeaconInterval:    100,
			WMMEnabled:        true,
			HTEnabled:         true,
			HostapdConfigPath: filepath.Join(dir, "hostapd.conf"),
			Roaming: config.WirelessRoamingConfig{
				Enabled:               true,
				Mode:                  "enforce",
				FailClosed:            true,
				IEEE80211R:            true,
				IEEE80211K:            true,
				IEEE80211V:            true,
				MobilityDomain:        "4f57",
				PMFRequired:           true,
				R0KeyLifetimeSeconds:  7200,
				ReassociationDeadline: 1200,
				NASIdentifier:         "aegis-ap-1",
				R1KeyHolder:           "00:11:22:33:44:55",
				KeySeedRef:            "env:AEGIS_FT_KEY_SEED",
				KeyRotationMode:       "active",
				RRMNeighborReport:     true,
				RRMBeaconReport:       true,
				BSSTransition:         true,
				NeighborAPs: []config.WirelessNeighborAPConfig{
					{
						Name:          "ap-2",
						BSSID:         "02:11:22:33:44:55",
						NASIdentifier: "aegis-ap-2",
						R1KeyHolder:   "02:11:22:33:44:55",
						SSIDs:         []string{"Corp"},
						Channel:       6,
						OpClass:       81,
						Preference:    255,
					},
				},
				Profiles: []config.WirelessRoamingProfileConfig{
					{
						Name:        "corp-fast-roam",
						Enabled:     true,
						IEEE80211R:  true,
						IEEE80211K:  true,
						IEEE80211V:  true,
						PMFRequired: true,
						NeighborAPs: []string{"ap-2"},
					},
				},
			},
			SSIDs: []config.SSIDConfig{
				{Name: "Corp", AuthMode: "wpa2-enterprise", RoamingProfile: "corp-fast-roam"},
			},
		},
	}
}
