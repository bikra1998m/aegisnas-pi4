package upgrade

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestCreateRollbackPackage(t *testing.T) {
	cfg, configPath := prepareRollbackPackageTestConfig(t)

	payload, filename, manifest, err := CreateRollbackPackage(cfg, configPath)
	require.NoError(t, err)

	assert.Contains(t, filename, "aegisnas-upgrade-rollback-")
	assert.Equal(t, rollbackPackageVersion, manifest.PackageVersion)
	assert.Equal(t, db.LatestSchemaVersion(), manifest.TargetSchemaVersion)
	assert.Equal(t, db.LatestSchemaVersion(), manifest.CurrentSchemaVersion)
	assert.Equal(t, "vacuum_into", manifest.DatabaseCopyMode)
	assert.True(t, manifest.ContainsSecrets)

	inspected, err := InspectRollbackPackage(bytes.NewReader(payload), int64(len(payload)))
	require.NoError(t, err)
	assert.Equal(t, manifest.CurrentSchemaVersion, inspected.CurrentSchemaVersion)
	assert.Equal(t, manifest.DatabasePath, inspected.DatabasePath)
}

func TestReadRollbackConfigBytesFallsBackToSettingsSnapshot(t *testing.T) {
	cfg, _ := prepareRollbackPackageTestConfig(t)
	bytes, err := readRollbackConfigBytes(cfg, filepath.Join(t.TempDir(), "missing-config.yaml"))
	require.NoError(t, err)
	assert.Contains(t, string(bytes), "admin_port:")
	assert.Contains(t, string(bytes), "database:")
}

func TestInspectRollbackPackageBytes(t *testing.T) {
	cfg, configPath := prepareRollbackPackageTestConfig(t)
	payload, _, _, err := CreateRollbackPackage(cfg, configPath)
	require.NoError(t, err)

	inspection, err := InspectRollbackPackageBytes(payload, cfg, configPath)
	require.NoError(t, err)

	assert.True(t, inspection.OnlineRestoreSupported)
	assert.Equal(t, "online_supported", inspection.CompatibilityStatus)
	assert.True(t, inspection.HasConfigYAML)
	assert.True(t, inspection.HasSystemSettings)
	assert.True(t, inspection.HasDatabase)
	assert.Equal(t, rollbackRestoreConfirmationText, inspection.RequiredConfirmationText)
}

func TestRestoreRollbackPackage(t *testing.T) {
	cfg, configPath := prepareRollbackPackageTestConfig(t)
	payload, _, _, err := CreateRollbackPackage(cfg, configPath)
	require.NoError(t, err)

	originalConfigBytes, err := os.ReadFile(configPath)
	require.NoError(t, err)

	result, err := RestoreRollbackPackage(cfg, configPath, payload, rollbackRestoreConfirmationText)
	require.NoError(t, err)

	assert.True(t, result.RestartRequired)
	assert.NotEmpty(t, result.SafetyPackagePath)
	assert.True(t, result.Inspection.OnlineRestoreSupported)

	restoredConfigBytes, err := os.ReadFile(configPath)
	require.NoError(t, err)
	assert.Equal(t, string(originalConfigBytes), string(restoredConfigBytes))

	safetyBytes, err := os.ReadFile(result.SafetyPackagePath)
	require.NoError(t, err)
	manifest, err := InspectRollbackPackage(bytes.NewReader(safetyBytes), int64(len(safetyBytes)))
	require.NoError(t, err)
	assert.Equal(t, db.LatestSchemaVersion(), manifest.TargetSchemaVersion)
}

func TestInspectRollbackPackageBytesOfflineRequiredOnSchemaMismatch(t *testing.T) {
	cfg, configPath := prepareRollbackPackageTestConfig(t)
	payload, _, _, err := CreateRollbackPackage(cfg, configPath)
	require.NoError(t, err)

	contents, err := ReadRollbackPackage(bytes.NewReader(payload), int64(len(payload)))
	require.NoError(t, err)
	contents.Manifest.TargetSchemaVersion = db.LatestSchemaVersion() - 1
	manifestJSON, err := json.Marshal(contents.Manifest)
	require.NoError(t, err)

	mutated := bytes.NewBuffer(nil)
	archive := zip.NewWriter(mutated)
	entry, err := archive.Create("manifest.json")
	require.NoError(t, err)
	_, err = entry.Write(manifestJSON)
	require.NoError(t, err)
	entry, err = archive.Create("config/config.yaml")
	require.NoError(t, err)
	_, err = entry.Write(contents.ConfigYAML)
	require.NoError(t, err)
	entry, err = archive.Create("config/system-settings.json")
	require.NoError(t, err)
	_, err = entry.Write(contents.SystemSettings)
	require.NoError(t, err)
	entry, err = archive.Create("database/data.db")
	require.NoError(t, err)
	_, err = entry.Write(contents.Database)
	require.NoError(t, err)
	require.NoError(t, archive.Close())

	inspection, err := InspectRollbackPackageBytes(mutated.Bytes(), cfg, configPath)
	require.NoError(t, err)
	assert.False(t, inspection.OnlineRestoreSupported)
	assert.Equal(t, "offline_required", inspection.CompatibilityStatus)
	assert.NotEmpty(t, inspection.Warnings)
}

func TestExtractRollbackPackageBytes(t *testing.T) {
	cfg, configPath := prepareRollbackPackageTestConfig(t)
	payload, _, manifest, err := CreateRollbackPackage(cfg, configPath)
	require.NoError(t, err)

	outputDir := filepath.Join(t.TempDir(), "rollback-extracted")
	extraction, err := ExtractRollbackPackageBytes(payload, outputDir)
	require.NoError(t, err)

	assert.Equal(t, outputDir, extraction.OutputDir)
	assert.Equal(t, manifest, extraction.Manifest)
	assert.FileExists(t, extraction.ManifestPath)
	assert.FileExists(t, extraction.ConfigPath)
	assert.FileExists(t, extraction.SystemSettingsPath)
	assert.FileExists(t, extraction.DatabasePath)

	configBytes, err := os.ReadFile(extraction.ConfigPath)
	require.NoError(t, err)
	assert.NotEmpty(t, configBytes)

	settingsBytes, err := os.ReadFile(extraction.SystemSettingsPath)
	require.NoError(t, err)
	assert.NotEmpty(t, settingsBytes)

	dbBytes, err := os.ReadFile(extraction.DatabasePath)
	require.NoError(t, err)
	assert.NotEmpty(t, dbBytes)
}

func prepareRollbackPackageTestConfig(t *testing.T) (*config.Config, string) {
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
