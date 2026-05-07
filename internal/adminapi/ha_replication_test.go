package adminapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/ha"
)

func TestHandleDownloadHAReplicationPackage(t *testing.T) {
	prepareReplicationConfig(t)

	original := createReplicationPackageFn
	defer func() { createReplicationPackageFn = original }()
	createReplicationPackageFn = func(cfg *config.Config) ([]byte, ha.ReplicationManifest, error) {
		return []byte("package-bytes"), ha.ReplicationManifest{
			SourceNode: "active-node",
			SourceRole: "active",
		}, nil
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/ha/replication-package", nil)
	rec := httptest.NewRecorder()
	HandleDownloadHAReplicationPackage(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/gzip", rec.Header().Get("Content-Type"))
	assert.Equal(t, "active-node", rec.Header().Get("X-Aegis-Source-Node"))
	assert.Equal(t, "active", rec.Header().Get("X-Aegis-Source-Role"))
	assert.Equal(t, "package-bytes", rec.Body.String())
}

func TestHandleActivateHAReplicationPackageSchedulesRestart(t *testing.T) {
	prepareReplicationConfig(t)

	originalActivate := activateStagedReplicationFn
	originalSchedule := scheduleReplicationRestartFn
	defer func() {
		activateStagedReplicationFn = originalActivate
		scheduleReplicationRestartFn = originalSchedule
	}()

	activateStagedReplicationFn = func(cfg *config.Config, id, activatedBy string) (ha.ActivationResult, error) {
		return ha.ActivationResult{
			ID:               id,
			BackupPath:       "/var/lib/aegisnas/ha/replication/backups/rollback.tar.gz",
			RestartScheduled: true,
			RestartServices:  []string{"aegis-admin-api", "aegis-gateway"},
			Summary:          "Activated",
		}, nil
	}
	scheduled := []string{}
	scheduleReplicationRestartFn = func(services []string) {
		scheduled = append([]string(nil), services...)
	}

	body, err := json.Marshal(map[string]any{"id": "stage-123"})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/ha/replication-activate", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	HandleActivateHAReplicationPackage(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, []string{"aegis-admin-api", "aegis-gateway"}, scheduled)
	assert.Contains(t, rec.Body.String(), "stage-123")
}

func TestHandleGetSharedHAReplicationStatus(t *testing.T) {
	prepareReplicationConfig(t)

	original := loadSharedReplicationStatusFn
	defer func() { loadSharedReplicationStatusFn = original }()
	loadSharedReplicationStatusFn = func(cfg *config.Config) (ha.SharedReplicationStatus, error) {
		return ha.SharedReplicationStatus{
			Present:          true,
			SourceNode:       "active-node",
			SourceRole:       "active",
			PublishedAt:      "2026-05-06T10:00:00Z",
			SchemaVersion:    7,
			PackagePath:      "/var/lib/aegisnas/ha/replication/live/latest.tar.gz",
			MetadataPath:     "/var/lib/aegisnas/ha/replication/live/latest.json",
			PackageSizeBytes: 1024,
		}, nil
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/ha/replication-shared", nil)
	rec := httptest.NewRecorder()
	HandleGetSharedHAReplicationStatus(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "active-node")
	assert.Contains(t, rec.Body.String(), "\"present\":true")
}

func TestHandleStageLatestSharedHAReplicationPackage(t *testing.T) {
	prepareReplicationConfig(t)

	original := stageLatestSharedReplicationFn
	defer func() { stageLatestSharedReplicationFn = original }()
	stageLatestSharedReplicationFn = func(cfg *config.Config, importedBy string) (ha.StagedReplicationPackage, error) {
		return ha.StagedReplicationPackage{
			ID:         "shared-stage-1",
			ImportedAt: "2026-05-06T10:05:00Z",
			ImportedBy: importedBy,
			Ready:      true,
			Status:     "ready",
			Summary:    "Shared package staged",
			Manifest: ha.ReplicationManifest{
				SourceNode: "active-node",
				SourceRole: "active",
			},
		}, nil
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/ha/replication-stage-shared", bytes.NewReader([]byte(`{}`)))
	req = req.WithContext(withAdminIdentity(req.Context(), AdminIdentity{Subject: "ops-admin", Role: adminRoleOpsAdmin}))
	rec := httptest.NewRecorder()
	HandleStageLatestSharedHAReplicationPackage(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "shared-stage-1")
	assert.Contains(t, rec.Body.String(), "Latest shared HA replication package is staged")
}

func prepareReplicationConfig(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{
		Mode:      "two-nic",
		AdminPort: 8083,
		Deployment: config.DeploymentConfig{
			Profile: "enterprise",
			Form:    "virtual",
		},
		WAN:      config.InterfaceConfig{Name: "ens33", DHCP: true},
		LAN:      config.InterfaceConfig{Name: "ens37", DHCP: false, Address: "192.168.50.1/24", DHCPRange: "192.168.50.100,192.168.50.200,12h"},
		Database: config.DatabaseConfig{Path: filepath.Join(dir, "data.db")},
		Logging:  config.LoggingConfig{Level: "info", Output: "stdout"},
		Health:   config.HealthConfig{Port: 8080},
		Telemetry: config.TelemetryConfig{
			PrometheusPort:          9090,
			LeaseHistoryPollSeconds: 300,
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
		Portal: config.PortalConfig{
			Enabled:       true,
			Port:          8081,
			LocalFallback: true,
			Branding:      "AegisNAS",
		},
		HighAvailability: config.HighAvailabilityConfig{
			Enabled:                  true,
			Role:                     "standby",
			PeerAPIURL:               "https://active.example.test:8083",
			VirtualIP:                "192.168.50.2",
			HeartbeatIntervalSeconds: 5,
			FailoverTimeoutSeconds:   20,
			SharedStateDir:           filepath.Join(dir, "ha"),
		},
		DHCP: config.DHCPConfig{
			Enabled:       true,
			LeaseTime:     "12h",
			Authoritative: true,
		},
	}
	configPath := filepath.Join(dir, "config.yaml")
	require.NoError(t, config.WriteFile(configPath, cfg))
	_, err := config.Load(configPath)
	require.NoError(t, err)
}
