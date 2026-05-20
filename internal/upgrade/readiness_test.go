package upgrade

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestAssessReadiness(t *testing.T) {
	cfg, configPath := prepareUpgradeTestConfig(t)

	report, err := AssessReadiness(cfg, configPath)
	require.NoError(t, err)

	assert.True(t, report.DatabaseExists)
	assert.Equal(t, db.LatestSchemaVersion(), report.TargetSchemaVersion)
	assert.Equal(t, db.LatestSchemaVersion(), report.CurrentSchemaVersion)
	assert.True(t, report.Rehearsal.Ran)
	assert.True(t, report.Rehearsal.Succeeded)
	assert.Equal(t, report.CurrentSchemaVersion, report.Rehearsal.StartedSchemaVersion)
	assert.Equal(t, db.LatestSchemaVersion(), report.Rehearsal.ResultSchemaVersion)
	assert.NotEmpty(t, report.Recommendations)
}

func TestAssessReadinessMissingDatabase(t *testing.T) {
	cfg, configPath := prepareUpgradeTestConfig(t)
	require.NoError(t, db.Close())
	cfg.Database.Path = filepath.Join(t.TempDir(), "missing.db")

	report, err := AssessReadiness(cfg, configPath)
	require.NoError(t, err)

	assert.False(t, report.DatabaseExists)
	assert.False(t, report.Rehearsal.Ran)
	assert.NotEmpty(t, report.Recommendations)
}

func prepareUpgradeTestConfig(t *testing.T) (*config.Config, string) {
	t.Helper()

	dir := t.TempDir()
	cfg := &config.Config{
		Mode: "two-nic",
		Deployment: config.DeploymentConfig{
			Profile: "enterprise",
			Form:    "virtual",
		},
		WAN:       config.InterfaceConfig{Name: "ens33", DHCP: true},
		LAN:       config.InterfaceConfig{Name: "ens37", DHCP: false, Address: "192.168.50.1/24", DHCPRange: "192.168.50.100,192.168.50.200,12h"},
		Database:  config.DatabaseConfig{Path: filepath.Join(dir, "data.db")},
		Logging:   config.LoggingConfig{Level: "info", Output: "stdout"},
		Health:    config.HealthConfig{Port: 8080},
		AdminPort: 8083,
		Telemetry: config.TelemetryConfig{
			Enabled:                 true,
			PrometheusPort:          9090,
			LeaseHistoryPollSeconds: 300,
		},
		Radius: config.RadiusConfig{
			Secret:                "radius-shared-secret",
			AuthPort:              1812,
			AcctPort:              1813,
			MaxSessions:           1024,
			CertDir:               "/etc/freeradius/3.0/certs",
			NASIdentifier:         "aegisnas",
			RequestTimeoutSeconds: 5,
			InterimUpdateSeconds:  300,
			DynamicAuth: config.DynamicAuthConfig{
				Enabled: true,
				Port:    3799,
			},
		},
		Portal: config.PortalConfig{
			Enabled:       true,
			Port:          8081,
			LocalFallback: true,
			Branding:      "AegisNAS",
		},
		HighAvailability: config.HighAvailabilityConfig{
			Enabled:                     true,
			Role:                        "standby",
			PeerAPIURL:                  "https://active.example.test:8083",
			VirtualIP:                   "192.168.50.2",
			HeartbeatIntervalSeconds:    5,
			FailoverTimeoutSeconds:      20,
			SharedStateDir:              filepath.Join(dir, "ha"),
			SplitBrainProtectionEnabled: true,
			WitnessAPIURL:               "https://witness.example.test/promote",
		},
		DHCP: config.DHCPConfig{
			Enabled:       true,
			LeaseTime:     "12h",
			Authoritative: true,
		},
	}

	configPath := filepath.Join(dir, "config.yaml")
	require.NoError(t, config.WriteFile(configPath, cfg))
	loadedCfg, err := config.Load(configPath)
	require.NoError(t, err)
	require.NoError(t, db.Init(cfg.Database.Path))
	require.NoError(t, db.Migrate())
	t.Cleanup(func() {
		_ = db.Close()
	})
	return loadedCfg, configPath
}
