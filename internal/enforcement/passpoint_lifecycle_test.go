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

func TestPreviewPasspointLifecycleReady(t *testing.T) {
	cfg := passpointLifecycleTestConfig(t)

	report, err := PreviewPasspointLifecycle(cfg)
	require.NoError(t, err)

	assert.Equal(t, PasspointLifecycleFeatureID, report.FeatureID)
	assert.Equal(t, "ready", report.Status)
	assert.True(t, report.ReadyForExternalValidation)
	assert.Equal(t, float64(100), report.SoftwareCompletionPercent)
	assert.Equal(t, 1, report.Summary.PasspointSSIDCount)
	assert.Equal(t, 1, report.Summary.InterworkingSSIDCount)
	assert.Equal(t, 1, report.Summary.HS20SSIDCount)
	assert.Equal(t, 1, report.Summary.OSUProviderCount)
	assert.Equal(t, 1, report.Summary.DomainNameCount)
	assert.Equal(t, 1, report.Summary.RoamingConsortiumCount)
	assert.Equal(t, 1, report.Summary.NAIRealmCount)
	assert.Equal(t, 1, report.Summary.CellularNetworkCount)
	assert.Equal(t, 1, report.Summary.ConnectionCapabilityCount)
	assert.Contains(t, report.HostapdConfigPreview, "interworking=1")
	assert.Contains(t, report.HostapdConfigPreview, "hs20=1")
	assert.Contains(t, report.HostapdConfigPreview, "nai_realm=0,corp.example.com")
	assert.Contains(t, report.HostapdConfigPreview, "osu_server_uri=https://osu.example.com/signup")
	assert.Contains(t, report.Attributes, "Chargeable-User-Identity")
	assert.Equal(t, "docs/nas-0076-release-certification-checklist.md", report.ReleaseCertificationChecklist)
}

func TestPreviewPasspointLifecycleBlocksInvalidConfig(t *testing.T) {
	cfg := passpointLifecycleTestConfig(t)
	cfg.Wireless.Passpoint.Profiles[0].DomainNames = nil

	report, err := PreviewPasspointLifecycle(cfg)
	require.NoError(t, err)

	assert.Equal(t, "blocked", report.Status)
	assert.False(t, report.ReadyForExternalValidation)
	assert.Equal(t, float64(0), report.SoftwareCompletionPercent)
	require.NotEmpty(t, report.Blockers)
	assert.Contains(t, report.Blockers[0], "domain_name")
}

func TestPreviewPasspointLifecycleSkippedWhenDisabled(t *testing.T) {
	cfg := passpointLifecycleTestConfig(t)
	cfg.Wireless.Passpoint.Enabled = false

	report, err := PreviewPasspointLifecycle(cfg)
	require.NoError(t, err)

	assert.Equal(t, "skipped", report.Status)
	assert.True(t, report.ReadyForExternalValidation)
	assert.Equal(t, float64(100), report.SoftwareCompletionPercent)
	assert.Empty(t, report.HostapdConfigPreview)
}

func TestApplyPasspointLifecycleWritesConfigAndRecordsEvent(t *testing.T) {
	previousDB := db.DB
	require.NoError(t, db.Init(":memory:"))
	db.DB.SetMaxOpenConns(1)
	require.NoError(t, db.Migrate())
	t.Cleanup(func() {
		_ = db.Close()
		db.DB = previousDB
	})
	cfg := passpointLifecycleTestConfig(t)

	report, eventID, err := ApplyPasspointLifecycle(cfg, "ops")
	require.NoError(t, err)

	assert.NotEmpty(t, eventID)
	assert.Equal(t, "applied", report.Status)
	raw, err := os.ReadFile(cfg.Wireless.HostapdConfigPath)
	require.NoError(t, err)
	assert.Contains(t, string(raw), "interworking=1")
	assert.Contains(t, string(raw), "hs20_oper_friendly_name=eng:AegisNAS")

	events, err := db.ListPasspointLifecycleEvents(5)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "apply", events[0].Operation)
	assert.Equal(t, "applied", events[0].Status)
	assert.Equal(t, "ops", events[0].Actor)

	summary, err := db.GetPasspointLifecycleSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TotalEvents)
	assert.Equal(t, 1, summary.AppliedCount)
	assert.Equal(t, 1, summary.LastPasspointSSIDCount)
	assert.Equal(t, 1, summary.LastHS20SSIDCount)
}

func passpointLifecycleTestConfig(t *testing.T) *config.Config {
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
			Passpoint: config.WirelessPasspointConfig{
				Enabled:           true,
				Mode:              "enforce",
				FailClosed:        true,
				Interworking:      true,
				HS20:              true,
				AccessNetworkType: 2,
				Internet:          true,
				Profiles: []config.WirelessPasspointProfileConfig{
					{
						Name:                 "corp-passpoint",
						Enabled:              true,
						Description:          "Corporate Passpoint",
						Interworking:         true,
						HS20:                 true,
						AccessNetworkType:    2,
						Internet:             true,
						HESSID:               "02:11:22:33:44:55",
						DisableDGAF:          true,
						ProxyARP:             true,
						DomainNames:          []string{"corp.example.com"},
						RoamingConsortiumOIs: []string{"112233"},
						OperatorFriendlyNames: []config.WirelessLocalizedTextConfig{
							{Language: "eng", Text: "AegisNAS"},
						},
						VenueNames: []config.WirelessLocalizedTextConfig{
							{Language: "eng", Text: "AegisNAS Lab"},
						},
						NAIRealms: []config.WirelessPasspointNAIRealmConfig{
							{Realm: "corp.example.com", Encoding: 0, EAPMethods: []string{"tls", "ttls"}, AuthParams: []string{"5:6"}},
						},
						CellularNetworks: []config.WirelessPasspointCellularNetworkConfig{
							{MCC: "310", MNC: "260"},
						},
						WANMetrics: config.WirelessPasspointWANMetricsConfig{
							Enabled:      true,
							WANInfo:      "01",
							DownlinkKbps: 100000,
							UplinkKbps:   50000,
							DownlinkLoad: 1,
							UplinkLoad:   1,
						},
						ConnectionCapabilities: []config.WirelessPasspointConnectionCapabilityConfig{
							{Protocol: 6, Port: 443, Status: 1},
						},
						OSU: config.WirelessPasspointOSUConfig{
							Enabled:   true,
							SSID:      "Aegis OSU",
							ServerURI: "https://osu.example.com/signup",
							FriendlyNames: []config.WirelessLocalizedTextConfig{
								{Language: "eng", Text: "AegisNAS Signup"},
							},
							NAI:        "anonymous@corp.example.com",
							MethodList: []int{1},
							ServiceDescriptions: []config.WirelessLocalizedTextConfig{
								{Language: "eng", Text: "Corporate onboarding"},
							},
						},
					},
				},
				EventRetentionLimit: 6000,
			},
			SSIDs: []config.SSIDConfig{
				{Name: "Corp", AuthMode: "wpa2-enterprise", PasspointProfile: "corp-passpoint"},
			},
		},
	}
}
