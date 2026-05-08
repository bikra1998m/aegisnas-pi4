package ha

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/network"
	"go.uber.org/zap"
	_ "modernc.org/sqlite"
)

func TestReplicationPackageRoundTripAndStandbyActivation(t *testing.T) {
	activeDir := t.TempDir()
	activeCfgPath := filepath.Join(activeDir, "config.yaml")
	activeDBPath := filepath.Join(activeDir, "data.db")
	activeCfg := testHAConfig(activeDBPath, "active", "https://standby.example.test:8083", "Active Branding")
	writeTestConfig(t, activeCfgPath, activeCfg)

	require.NoError(t, db.Init(activeDBPath))
	require.NoError(t, db.Migrate())
	_, err := db.DB.Exec(`INSERT INTO local_users (username, password_hash, role) VALUES ('alice', 'hash', 'guest-basic')`)
	require.NoError(t, err)
	require.NoError(t, network.SaveState(network.StatePath(activeCfg), network.AppliedState{
		Interfaces: []network.ManagedInterfaceState{{Name: "ens37", Address: "192.168.50.1/24"}},
	}))
	require.NoError(t, db.Close())

	_, err = config.Load(activeCfgPath)
	require.NoError(t, err)
	packageBytes, manifest, err := CreateReplicationPackage(activeCfg)
	require.NoError(t, err)
	assert.Equal(t, "active", manifest.SourceRole)
	assert.NotEmpty(t, manifest.Files["config.yaml"])
	assert.NotEmpty(t, manifest.Files["data.db"])

	standbyDir := t.TempDir()
	standbyCfgPath := filepath.Join(standbyDir, "config.yaml")
	standbyDBPath := filepath.Join(standbyDir, "data.db")
	standbyCfg := testHAConfig(standbyDBPath, "standby", "https://active.example.test:8083", "Standby Branding")
	writeTestConfig(t, standbyCfgPath, standbyCfg)

	require.NoError(t, db.Init(standbyDBPath))
	defer db.Close()
	require.NoError(t, db.Migrate())
	_, err = config.Load(standbyCfgPath)
	require.NoError(t, err)

	stage, err := ImportReplicationPackage(standbyCfg, packageBytes, "ops-admin")
	require.NoError(t, err)
	assert.True(t, stage.Ready)
	assert.True(t, stage.ConfigValid)
	assert.True(t, stage.DatabaseValid)
	assert.True(t, stage.NetworkStatePresent)
	assert.Equal(t, "unsigned", stage.SignatureStatus)

	stagedPackages, err := ListStagedReplicationPackages(standbyCfg)
	require.NoError(t, err)
	require.Len(t, stagedPackages, 1)
	assert.Equal(t, stage.ID, stagedPackages[0].ID)

	result, err := ActivateStagedReplicationPackage(standbyCfg, stage.ID, "ops-admin")
	require.NoError(t, err)
	assert.True(t, result.RestartScheduled)
	assert.Contains(t, result.BackupPath, "replication-rollback-")

	mergedCfg, err := config.LoadCandidate(standbyCfgPath)
	require.NoError(t, err)
	assert.Equal(t, "standby", mergedCfg.HighAvailability.Role)
	assert.Equal(t, "https://active.example.test:8083", mergedCfg.HighAvailability.PeerAPIURL)
	assert.Equal(t, standbyDBPath, mergedCfg.Database.Path)
	assert.Equal(t, "Active Branding", mergedCfg.Portal.Branding)

	userCount := countUsers(t, standbyDBPath)
	assert.Equal(t, 1, userCount)
}

func TestSignedReplicationPackageVerifiesOnStandby(t *testing.T) {
	tokenEnv := "AEGIS_HA_REPLICATION_SIGNING_KEY"
	t.Setenv(tokenEnv, "shared-secret-value")

	activeDir := t.TempDir()
	activeCfgPath := filepath.Join(activeDir, "config.yaml")
	activeDBPath := filepath.Join(activeDir, "data.db")
	activeCfg := testHAConfig(activeDBPath, "active", "https://standby.example.test:8083", "Active Branding")
	activeCfg.HighAvailability.ReplicationSigningKeyEnv = tokenEnv
	writeTestConfig(t, activeCfgPath, activeCfg)

	require.NoError(t, db.Init(activeDBPath))
	require.NoError(t, db.Migrate())
	require.NoError(t, db.Close())

	_, err := config.Load(activeCfgPath)
	require.NoError(t, err)
	packageBytes, manifest, err := CreateReplicationPackage(activeCfg)
	require.NoError(t, err)
	assert.Equal(t, replicationSignatureAlgorithm, manifest.SignatureAlgorithm)
	assert.NotEmpty(t, manifest.Signature)

	standbyDir := t.TempDir()
	standbyCfgPath := filepath.Join(standbyDir, "config.yaml")
	standbyDBPath := filepath.Join(standbyDir, "data.db")
	standbyCfg := testHAConfig(standbyDBPath, "standby", "https://active.example.test:8083", "Standby Branding")
	standbyCfg.HighAvailability.ReplicationSigningKeyEnv = tokenEnv
	writeTestConfig(t, standbyCfgPath, standbyCfg)

	require.NoError(t, db.Init(standbyDBPath))
	defer db.Close()
	require.NoError(t, db.Migrate())
	_, err = config.Load(standbyCfgPath)
	require.NoError(t, err)

	stage, err := ImportReplicationPackage(standbyCfg, packageBytes, "ops-admin")
	require.NoError(t, err)
	assert.Equal(t, "verified", stage.SignatureStatus)
	assert.NotEmpty(t, stage.Signature)
	assert.Equal(t, replicationSignatureAlgorithm, stage.SignatureAlgorithm)
}

func TestEncryptedReplicationPackageDecryptsOnStandby(t *testing.T) {
	encryptionEnv := "AEGIS_HA_REPLICATION_ENCRYPTION_KEY"
	t.Setenv(encryptionEnv, "shared-encryption-secret")

	activeDir := t.TempDir()
	activeCfgPath := filepath.Join(activeDir, "config.yaml")
	activeDBPath := filepath.Join(activeDir, "data.db")
	activeCfg := testHAConfig(activeDBPath, "active", "https://standby.example.test:8083", "Active Branding")
	activeCfg.HighAvailability.ReplicationEncryptionKeyEnv = encryptionEnv
	writeTestConfig(t, activeCfgPath, activeCfg)

	require.NoError(t, db.Init(activeDBPath))
	require.NoError(t, db.Migrate())
	require.NoError(t, db.Close())

	_, err := config.Load(activeCfgPath)
	require.NoError(t, err)
	packageBytes, manifest, err := CreateReplicationPackage(activeCfg)
	require.NoError(t, err)
	assert.NotEmpty(t, manifest.ContentFingerprint)
	assert.NotContains(t, string(packageBytes), "config.yaml")

	standbyDir := t.TempDir()
	standbyCfgPath := filepath.Join(standbyDir, "config.yaml")
	standbyDBPath := filepath.Join(standbyDir, "data.db")
	standbyCfg := testHAConfig(standbyDBPath, "standby", "https://active.example.test:8083", "Standby Branding")
	standbyCfg.HighAvailability.ReplicationEncryptionKeyEnv = encryptionEnv
	writeTestConfig(t, standbyCfgPath, standbyCfg)

	require.NoError(t, db.Init(standbyDBPath))
	defer db.Close()
	require.NoError(t, db.Migrate())
	_, err = config.Load(standbyCfgPath)
	require.NoError(t, err)

	stage, err := ImportReplicationPackage(standbyCfg, packageBytes, "ops-admin")
	require.NoError(t, err)
	assert.Equal(t, "decrypted", stage.EncryptionStatus)
	assert.Equal(t, replicationEncryptionAlgorithm, stage.EncryptionAlgorithm)
	assert.True(t, stage.Ready)
}

func TestEncryptedReplicationPackageIsRequiredWhenStandbyHasEncryptionKey(t *testing.T) {
	encryptionEnv := "AEGIS_HA_REPLICATION_ENCRYPTION_KEY"
	t.Setenv(encryptionEnv, "shared-encryption-secret")

	activeDir := t.TempDir()
	activeCfgPath := filepath.Join(activeDir, "config.yaml")
	activeDBPath := filepath.Join(activeDir, "data.db")
	activeCfg := testHAConfig(activeDBPath, "active", "https://standby.example.test:8083", "Active Branding")
	writeTestConfig(t, activeCfgPath, activeCfg)

	require.NoError(t, db.Init(activeDBPath))
	require.NoError(t, db.Migrate())
	require.NoError(t, db.Close())

	_, err := config.Load(activeCfgPath)
	require.NoError(t, err)
	packageBytes, _, err := CreateReplicationPackage(activeCfg)
	require.NoError(t, err)

	standbyDir := t.TempDir()
	standbyCfgPath := filepath.Join(standbyDir, "config.yaml")
	standbyDBPath := filepath.Join(standbyDir, "data.db")
	standbyCfg := testHAConfig(standbyDBPath, "standby", "https://active.example.test:8083", "Standby Branding")
	standbyCfg.HighAvailability.ReplicationEncryptionKeyEnv = encryptionEnv
	writeTestConfig(t, standbyCfgPath, standbyCfg)

	require.NoError(t, db.Init(standbyDBPath))
	defer db.Close()
	require.NoError(t, db.Migrate())
	_, err = config.Load(standbyCfgPath)
	require.NoError(t, err)

	_, err = ImportReplicationPackage(standbyCfg, packageBytes, "ops-admin")
	require.ErrorContains(t, err, "encrypted HA replication packages are required")
}

func TestEncryptedReplicationPackageFailsWithWrongKey(t *testing.T) {
	activeEnv := "AEGIS_HA_REPLICATION_ENCRYPTION_KEY_ACTIVE"
	standbyEnv := "AEGIS_HA_REPLICATION_ENCRYPTION_KEY_STANDBY"
	t.Setenv(activeEnv, "active-secret")
	t.Setenv(standbyEnv, "standby-secret")

	activeDir := t.TempDir()
	activeCfgPath := filepath.Join(activeDir, "config.yaml")
	activeDBPath := filepath.Join(activeDir, "data.db")
	activeCfg := testHAConfig(activeDBPath, "active", "https://standby.example.test:8083", "Active Branding")
	activeCfg.HighAvailability.ReplicationEncryptionKeyEnv = activeEnv
	writeTestConfig(t, activeCfgPath, activeCfg)

	require.NoError(t, db.Init(activeDBPath))
	require.NoError(t, db.Migrate())
	require.NoError(t, db.Close())

	_, err := config.Load(activeCfgPath)
	require.NoError(t, err)
	packageBytes, _, err := CreateReplicationPackage(activeCfg)
	require.NoError(t, err)

	standbyDir := t.TempDir()
	standbyCfgPath := filepath.Join(standbyDir, "config.yaml")
	standbyDBPath := filepath.Join(standbyDir, "data.db")
	standbyCfg := testHAConfig(standbyDBPath, "standby", "https://active.example.test:8083", "Standby Branding")
	standbyCfg.HighAvailability.ReplicationEncryptionKeyEnv = standbyEnv
	writeTestConfig(t, standbyCfgPath, standbyCfg)

	require.NoError(t, db.Init(standbyDBPath))
	defer db.Close()
	require.NoError(t, db.Migrate())
	_, err = config.Load(standbyCfgPath)
	require.NoError(t, err)

	_, err = ImportReplicationPackage(standbyCfg, packageBytes, "ops-admin")
	require.ErrorContains(t, err, "decryption failed")
}

func TestSignedReplicationPackageIsRequiredWhenStandbyHasSigningKey(t *testing.T) {
	tokenEnv := "AEGIS_HA_REPLICATION_SIGNING_KEY"
	t.Setenv(tokenEnv, "shared-secret-value")

	activeDir := t.TempDir()
	activeCfgPath := filepath.Join(activeDir, "config.yaml")
	activeDBPath := filepath.Join(activeDir, "data.db")
	activeCfg := testHAConfig(activeDBPath, "active", "https://standby.example.test:8083", "Active Branding")
	writeTestConfig(t, activeCfgPath, activeCfg)

	require.NoError(t, db.Init(activeDBPath))
	require.NoError(t, db.Migrate())
	require.NoError(t, db.Close())

	_, err := config.Load(activeCfgPath)
	require.NoError(t, err)
	packageBytes, _, err := CreateReplicationPackage(activeCfg)
	require.NoError(t, err)

	standbyDir := t.TempDir()
	standbyCfgPath := filepath.Join(standbyDir, "config.yaml")
	standbyDBPath := filepath.Join(standbyDir, "data.db")
	standbyCfg := testHAConfig(standbyDBPath, "standby", "https://active.example.test:8083", "Standby Branding")
	standbyCfg.HighAvailability.ReplicationSigningKeyEnv = tokenEnv
	writeTestConfig(t, standbyCfgPath, standbyCfg)

	require.NoError(t, db.Init(standbyDBPath))
	defer db.Close()
	require.NoError(t, db.Migrate())
	_, err = config.Load(standbyCfgPath)
	require.NoError(t, err)

	_, err = ImportReplicationPackage(standbyCfg, packageBytes, "ops-admin")
	require.ErrorContains(t, err, "signed HA replication packages are required")
}

func TestImportReplicationPackageRejectsUnsupportedSchema(t *testing.T) {
	dbFile, err := os.CreateTemp("", "ha-unsupported-*.db")
	require.NoError(t, err)
	dbPath := dbFile.Name()
	require.NoError(t, dbFile.Close())
	defer os.Remove(dbPath)

	cfg := testHAConfig(dbPath, "standby", "https://active.example.test:8083", "Standby")
	writeTestConfig(t, filepath.Join(t.TempDir(), "config.yaml"), cfg)

	require.NoError(t, db.Init(cfg.Database.Path))
	require.NoError(t, db.Migrate())

	packageBytes := buildTestPackage(t, ReplicationManifest{
		PackageType:   "aegisnas-ha-replication",
		GeneratedAt:   "2026-05-05T00:00:00Z",
		SourceNode:    "active-node",
		SourceRole:    "active",
		SchemaVersion: db.LatestSchemaVersion() + 1,
		Files:         map[string]string{},
	})

	_, err = ImportReplicationPackage(cfg, packageBytes, "ops-admin")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "newer than this node supports")
	require.NoError(t, db.Close())
}

func TestPublishSharedReplicationPackageAndLoadStatus(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	dbPath := filepath.Join(dir, "data.db")
	cfg := testHAConfig(dbPath, "active", "https://standby.example.test:8083", "Active Branding")
	writeTestConfig(t, cfgPath, cfg)

	require.NoError(t, db.Init(dbPath))
	require.NoError(t, db.Migrate())
	require.NoError(t, db.Close())

	_, err := config.Load(cfgPath)
	require.NoError(t, err)

	shared, err := PublishSharedReplicationPackage(cfg)
	require.NoError(t, err)
	assert.True(t, shared.Present)
	assert.Equal(t, "active", shared.SourceRole)
	assert.FileExists(t, shared.PackagePath)
	assert.FileExists(t, shared.MetadataPath)
	assert.NotEmpty(t, shared.ContentFingerprint)

	loaded, err := LoadSharedReplicationStatus(cfg)
	require.NoError(t, err)
	assert.True(t, loaded.Present)
	assert.Equal(t, shared.SourceNode, loaded.SourceNode)
	assert.Equal(t, shared.PackageChecksum, loaded.PackageChecksum)
	assert.Equal(t, shared.ContentFingerprint, loaded.ContentFingerprint)
}

func TestStageLatestSharedReplicationPackageUsesPublishedBundle(t *testing.T) {
	activeDir := t.TempDir()
	activeCfgPath := filepath.Join(activeDir, "config.yaml")
	activeDBPath := filepath.Join(activeDir, "data.db")
	activeCfg := testHAConfig(activeDBPath, "active", "https://standby.example.test:8083", "Active Branding")
	writeTestConfig(t, activeCfgPath, activeCfg)

	require.NoError(t, db.Init(activeDBPath))
	require.NoError(t, db.Migrate())
	_, err := db.DB.Exec(`INSERT INTO local_users (username, password_hash, role) VALUES ('fresh-sync-user', 'hash', 'guest-basic')`)
	require.NoError(t, err)
	require.NoError(t, db.Close())

	_, err = config.Load(activeCfgPath)
	require.NoError(t, err)
	_, err = PublishSharedReplicationPackage(activeCfg)
	require.NoError(t, err)

	standbyDir := t.TempDir()
	standbyCfgPath := filepath.Join(standbyDir, "config.yaml")
	standbyDBPath := filepath.Join(standbyDir, "data.db")
	standbyCfg := testHAConfig(standbyDBPath, "standby", "https://active.example.test:8083", "Standby Branding")
	standbyCfg.HighAvailability.SharedStateDir = activeCfg.HighAvailability.SharedStateDir
	writeTestConfig(t, standbyCfgPath, standbyCfg)

	require.NoError(t, db.Init(standbyDBPath))
	defer db.Close()
	require.NoError(t, db.Migrate())
	_, err = config.Load(standbyCfgPath)
	require.NoError(t, err)

	stage, err := StageLatestSharedReplicationPackage(standbyCfg, "ops-admin")
	require.NoError(t, err)
	assert.True(t, stage.Ready)
	assert.Equal(t, "active", stage.Manifest.SourceRole)
	assert.Equal(t, "shared-live", stage.ImportedSource)
	assert.NotEmpty(t, stage.PackageChecksum)
	assert.NotEmpty(t, stage.ContentFingerprint)
	assert.Equal(t, "fresh-sync-user", lookupFirstUsername(t, filepath.Join(standbyCfg.HighAvailability.SharedStateDir, "replication", "staged", stage.ID, "content", "data.db")))
}

func TestReplicationMonitorAutoStagesFreshSharedPackage(t *testing.T) {
	activeDir := t.TempDir()
	activeCfgPath := filepath.Join(activeDir, "config.yaml")
	activeDBPath := filepath.Join(activeDir, "data.db")
	activeCfg := testHAConfig(activeDBPath, "active", "https://standby.example.test:8083", "Active Branding")
	writeTestConfig(t, activeCfgPath, activeCfg)

	require.NoError(t, db.Init(activeDBPath))
	require.NoError(t, db.Migrate())
	require.NoError(t, db.Close())

	_, err := config.Load(activeCfgPath)
	require.NoError(t, err)
	shared, err := PublishSharedReplicationPackage(activeCfg)
	require.NoError(t, err)

	standbyDir := t.TempDir()
	standbyCfgPath := filepath.Join(standbyDir, "config.yaml")
	standbyDBPath := filepath.Join(standbyDir, "data.db")
	standbyCfg := testHAConfig(standbyDBPath, "standby", "https://active.example.test:8083", "Standby Branding")
	standbyCfg.HighAvailability.SharedStateDir = activeCfg.HighAvailability.SharedStateDir
	standbyCfg.HighAvailability.AutoStageSharedPackage = true
	writeTestConfig(t, standbyCfgPath, standbyCfg)

	require.NoError(t, db.Init(standbyDBPath))
	defer db.Close()
	require.NoError(t, db.Migrate())
	_, err = config.Load(standbyCfgPath)
	require.NoError(t, err)

	monitor := newReplicationMonitor(standbyCfg, zap.NewNop())
	status, message, details := monitor.probe()
	require.Equal(t, "ok", status)
	assert.Contains(t, message, "auto-staged")
	assert.Equal(t, "staged", details["auto_stage_status"])

	packages, err := ListStagedReplicationPackages(standbyCfg)
	require.NoError(t, err)
	require.Len(t, packages, 1)
	assert.Equal(t, "shared-auto", packages[0].ImportedSource)
	assert.Equal(t, shared.ContentFingerprint, packages[0].ContentFingerprint)

	time.Sleep(1100 * time.Millisecond)
	_, err = config.Load(activeCfgPath)
	require.NoError(t, err)
	republished, err := PublishSharedReplicationPackage(activeCfg)
	require.NoError(t, err)
	assert.NotEqual(t, shared.PackageChecksum, republished.PackageChecksum)
	assert.Equal(t, shared.ContentFingerprint, republished.ContentFingerprint)

	status, message, details = monitor.probe()
	require.Equal(t, "ok", status)
	assert.Contains(t, message, "auto-stage is ready")
	assert.Equal(t, "ready", details["auto_stage_status"])
	assert.Equal(t, republished.ContentFingerprint, details["auto_stage_content_fingerprint"])

	packages, err = ListStagedReplicationPackages(standbyCfg)
	require.NoError(t, err)
	assert.Len(t, packages, 1)
}

func TestReplicationMonitorMarksStaleSharedPackage(t *testing.T) {
	cfg := testHAConfig(filepath.Join(t.TempDir(), "data.db"), "standby", "https://active.example.test:8083", "Standby")
	cfg.HighAvailability.ReplicationIntervalSeconds = 60
	cfg.HighAvailability.ReplicationStaleAfterSeconds = 120

	shared := SharedReplicationStatus{
		Present:          true,
		SourceNode:       "active-node",
		SourceRole:       "active",
		PublishedAt:      time.Now().UTC().Add(-10 * time.Minute).Format(time.RFC3339),
		SchemaVersion:    7,
		PackagePath:      "/var/lib/aegisnas/ha/replication/live/latest.tar.gz",
		MetadataPath:     "/var/lib/aegisnas/ha/replication/live/latest.json",
		PackageSizeBytes: 2048,
	}

	details := map[string]any{}
	mergeSharedReplicationDetails(details, shared, cfg, time.Now().UTC())
	assert.Equal(t, true, details["stale"])
	assert.Greater(t, details["latest_age_seconds"].(int), 120)
}

func testHAConfig(dbPath, role, peerURL, branding string) *config.Config {
	return &config.Config{
		Mode:      "two-nic",
		AdminPort: 8083,
		Deployment: config.DeploymentConfig{
			Profile: "enterprise",
			Form:    "virtual",
			Hardware: config.DeploymentHardwareConfig{
				MemoryMB: 8192,
				CPUCores: 4,
			},
		},
		WAN:      config.InterfaceConfig{Name: "ens33", DHCP: true},
		LAN:      config.InterfaceConfig{Name: "ens37", DHCP: false, Address: "192.168.50.1/24", DHCPRange: "192.168.50.100,192.168.50.200,12h"},
		Database: config.DatabaseConfig{Path: dbPath},
		Logging:  config.LoggingConfig{Level: "info", Output: "stdout"},
		Health:   config.HealthConfig{Port: 8080},
		Portal: config.PortalConfig{
			Enabled:       true,
			Port:          8081,
			LocalFallback: true,
			Branding:      branding,
		},
		Radius: config.RadiusConfig{
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
		DHCP: config.DHCPConfig{
			Enabled:       true,
			LeaseTime:     "12h",
			Authoritative: true,
		},
		Telemetry: config.TelemetryConfig{
			Enabled:                 true,
			PrometheusPort:          9090,
			LeaseHistoryPollSeconds: 300,
		},
		HighAvailability: config.HighAvailabilityConfig{
			Enabled:                  true,
			Role:                     role,
			PeerAPIURL:               peerURL,
			VirtualIP:                "192.168.50.2",
			HeartbeatIntervalSeconds: 5,
			FailoverTimeoutSeconds:   20,
			SharedStateDir:           filepath.Join(filepath.Dir(dbPath), "ha"),
		},
	}
}

func writeTestConfig(t *testing.T, path string, cfg *config.Config) {
	t.Helper()
	require.NoError(t, config.WriteFile(path, cfg))
}

func countUsers(t *testing.T, dbPath string) int {
	t.Helper()
	sqlDB, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	defer sqlDB.Close()
	var count int
	require.NoError(t, sqlDB.QueryRow(`SELECT COUNT(*) FROM local_users`).Scan(&count))
	return count
}

func lookupFirstUsername(t *testing.T, dbPath string) string {
	t.Helper()
	sqlDB, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	defer sqlDB.Close()
	var username string
	require.NoError(t, sqlDB.QueryRow(`SELECT username FROM local_users ORDER BY id LIMIT 1`).Scan(&username))
	return username
}

func buildTestPackage(t *testing.T, manifest ReplicationManifest) []byte {
	t.Helper()
	configContent := []byte(`
mode: two-nic
admin_port: 8083
deployment:
  profile: enterprise
  form: virtual
wan:
  name: ens33
  dhcp: true
lan:
  name: ens37
  dhcp: false
  address: 192.168.50.1/24
  dhcp_range: 192.168.50.100,192.168.50.200,12h
database:
  path: /var/lib/aegisnas/data.db
logging:
  level: info
  output: stdout
health:
  port: 8080
telemetry:
  enabled: true
  prometheus_port: 9090
  lease_history_poll_seconds: 300
portal:
  enabled: true
  port: 8081
  local_fallback: true
radius:
  auth_port: 1812
  acct_port: 1813
  max_sessions: 1024
  cert_dir: /etc/freeradius/3.0/certs
  nas_identifier: aegisnas
  request_timeout_seconds: 5
  interim_update_seconds: 300
  dynamic_auth:
    enabled: true
    port: 3799
high_availability:
  enabled: true
  role: active
  peer_api_url: https://standby.example.test:8083
  virtual_ip: 192.168.50.2
  heartbeat_interval_seconds: 5
  failover_timeout_seconds: 20
`)
	dbBytes := createDatabaseBytes(t)
	manifest.Files = map[string]string{
		"config.yaml": checksumString(configContent),
		"data.db":     checksumString(dbBytes),
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	require.NoError(t, err)

	var buffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&buffer)
	tarWriter := tar.NewWriter(gzipWriter)
	require.NoError(t, addBytesToArchive(tarWriter, configContent, "config.yaml", 0640))
	require.NoError(t, addBytesToArchive(tarWriter, dbBytes, "data.db", 0640))
	require.NoError(t, addBytesToArchive(tarWriter, manifestBytes, "manifest.json", 0644))
	require.NoError(t, tarWriter.Close())
	require.NoError(t, gzipWriter.Close())
	return buffer.Bytes()
}

func createDatabaseBytes(t *testing.T) []byte {
	t.Helper()
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "data.db")
	require.NoError(t, db.Init(dbPath))
	require.NoError(t, db.Migrate())
	require.NoError(t, db.Close())
	data, err := os.ReadFile(dbPath)
	require.NoError(t, err)
	return data
}

func checksumString(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
