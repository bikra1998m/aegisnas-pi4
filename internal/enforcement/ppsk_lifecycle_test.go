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

func TestPreviewPPSKLifecycleReady(t *testing.T) {
	cfg := ppskLifecycleTestConfig(t)

	report, err := PreviewPPSKLifecycle(cfg)
	require.NoError(t, err)

	assert.Equal(t, PPSKLifecycleFeatureID, report.FeatureID)
	assert.Equal(t, "degraded", report.Status)
	assert.True(t, report.ReadyForExternalValidation)
	assert.Equal(t, float64(100), report.SoftwareCompletionPercent)
	assert.Equal(t, 1, report.Summary.PPSKSSIDCount)
	assert.Equal(t, 1, report.Summary.ProfileCount)
	assert.Equal(t, 1, report.Summary.GroupCount)
	assert.Equal(t, 2, report.Summary.CredentialCount)
	assert.Equal(t, 1, report.Summary.ActiveCredentialCount)
	assert.Equal(t, 1, report.Summary.StagedCredentialCount)
	assert.Equal(t, 1, report.Summary.RevokedCredentialCount)
	assert.Equal(t, 1, report.Summary.ControllerSyncCount)
	assert.Contains(t, report.HostapdConfigPreview, "wpa_psk_file=")
	assert.Contains(t, report.PSKFilePreview, "02:11:22:33:44:55 <redacted>")
	assert.NotContains(t, report.PSKFilePreview, "camera-secret-123")
	assert.Contains(t, report.Attributes, "Calling-Station-Id")
	assert.Equal(t, "docs/nas-0077-release-certification-checklist.md", report.ReleaseCertificationChecklist)
}

func TestPreviewPPSKLifecycleBlocksMissingSecret(t *testing.T) {
	cfg := ppskLifecycleTestConfig(t)
	cfg.Wireless.PPSK.Credentials[0].SecretRef = "env:AEGIS_MISSING_PPSK"

	report, err := PreviewPPSKLifecycle(cfg)
	require.NoError(t, err)

	assert.Equal(t, "blocked", report.Status)
	assert.False(t, report.ReadyForExternalValidation)
	assert.Equal(t, float64(0), report.SoftwareCompletionPercent)
	require.NotEmpty(t, report.Blockers)
	assert.Contains(t, report.Blockers[0], "does not resolve")
}

func TestPreviewPPSKLifecycleSkippedWhenDisabled(t *testing.T) {
	cfg := ppskLifecycleTestConfig(t)
	cfg.Wireless.PPSK.Enabled = false
	cfg.Wireless.SSIDs[0].PPSKProfile = ""
	cfg.Wireless.SSIDs[0].Passphrase = "fallback-secret"

	report, err := PreviewPPSKLifecycle(cfg)
	require.NoError(t, err)

	assert.Equal(t, "skipped", report.Status)
	assert.True(t, report.ReadyForExternalValidation)
	assert.Equal(t, float64(100), report.SoftwareCompletionPercent)
	assert.Empty(t, report.PSKFilePreview)
}

func TestApplyPPSKLifecycleWritesFilesAndRecordsEvent(t *testing.T) {
	previousDB := db.DB
	require.NoError(t, db.Init(":memory:"))
	db.DB.SetMaxOpenConns(1)
	require.NoError(t, db.Migrate())
	t.Cleanup(func() {
		_ = db.Close()
		db.DB = previousDB
	})
	cfg := ppskLifecycleTestConfig(t)
	cfg.Wireless.PPSK.Profiles[0].ControllerSync = false

	report, eventID, err := ApplyPPSKLifecycle(cfg, "ops")
	require.NoError(t, err)

	assert.NotEmpty(t, eventID)
	assert.Equal(t, "applied", report.Status)
	hostapdRaw, err := os.ReadFile(cfg.Wireless.HostapdConfigPath)
	require.NoError(t, err)
	assert.Contains(t, string(hostapdRaw), "wpa_psk_file=")
	pskRaw, err := os.ReadFile(cfg.Wireless.PPSK.PSKFilePath)
	require.NoError(t, err)
	assert.Contains(t, string(pskRaw), "02:11:22:33:44:55 camera-secret-123")

	events, err := db.ListPPSKLifecycleEvents(5)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "apply", events[0].Operation)
	assert.Equal(t, "applied", events[0].Status)
	assert.Equal(t, "ops", events[0].Actor)

	summary, err := db.GetPPSKLifecycleSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TotalEvents)
	assert.Equal(t, 1, summary.AppliedCount)
	assert.Equal(t, 1, summary.LastPPSKSSIDCount)
	assert.Equal(t, 1, summary.LastActiveCredentialCount)
}

func ppskLifecycleTestConfig(t *testing.T) *config.Config {
	t.Helper()
	t.Setenv("AEGIS_TEST_PPSK", "camera-secret-123")
	t.Setenv("AEGIS_TEST_PPSK_NEXT", "camera-secret-next")
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
			Secret:                "testing-secret",
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
			PPSK: config.WirelessPPSKConfig{
				Enabled:             true,
				Mode:                "enforce",
				FailClosed:          true,
				PSKFilePath:         filepath.Join(dir, "aegisnas-ppsk.psk"),
				RotationMode:        "overlap",
				MinPassphraseLength: 8,
				Profiles: []config.WirelessPPSKProfileConfig{
					{
						Name:             "iot-ppsk",
						Enabled:          true,
						Mode:             "enforce",
						FailClosed:       true,
						Groups:           []string{"cameras"},
						DefaultVLAN:      30,
						Role:             "iot",
						BandwidthProfile: "iot-basic",
						ControllerSync:   true,
					},
				},
				Groups: []config.WirelessPPSKGroupConfig{
					{Name: "cameras", Enabled: true, VLAN: 30, Role: "iot", BandwidthProfile: "iot-basic", MaxDevices: 100, SessionLimit: 1},
				},
				Credentials: []config.WirelessPPSKCredentialConfig{
					{
						ID:            "camera-1",
						Enabled:       true,
						MAC:           "02:11:22:33:44:55",
						DeviceID:      "cam-1",
						Owner:         "facilities",
						Profile:       "iot-ppsk",
						Group:         "cameras",
						SecretRef:     "env:AEGIS_TEST_PPSK",
						NextSecretRef: "env:AEGIS_TEST_PPSK_NEXT",
						NextNotBefore: "2026-01-01T00:00:00Z",
						NextNotAfter:  "2026-01-08T00:00:00Z",
					},
					{
						ID:        "camera-old",
						Enabled:   true,
						Revoked:   true,
						MAC:       "02:11:22:33:44:66",
						Profile:   "iot-ppsk",
						Group:     "cameras",
						SecretRef: "env:AEGIS_TEST_PPSK",
					},
				},
				EventRetentionLimit: 6000,
			},
			SSIDs: []config.SSIDConfig{
				{Name: "IoT", AuthMode: "wpa2-personal", PPSKProfile: "iot-ppsk"},
			},
		},
	}
}
