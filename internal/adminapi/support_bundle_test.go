package adminapi

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	upgradepkg "github.com/yourorg/aegisnas-pi4/internal/upgrade"
)

func TestHandleDownloadSupportBundle(t *testing.T) {
	cfg := prepareSupportBundleTestConfig(t)
	now := time.Date(2026, 5, 19, 8, 45, 0, 0, time.UTC)
	observedAt := now.Add(-15 * time.Minute)

	require.NoError(t, db.RecordNetworkApplyHistory("apply", "success", "all validation checks passed", "backup-7", "", "tester", map[string]any{
		"validated": true,
	}))
	_, err := db.DB.Exec(`INSERT INTO audit_logs (timestamp, user, action, details, result, ip_address) VALUES (?, ?, ?, ?, ?, ?)`,
		now, "ops-admin", "download_support_bundle", "bundle-1", "downloaded", "192.168.50.10")
	require.NoError(t, err)
	require.NoError(t, db.StoreDHCPLeaseObservations(observedAt, []db.DHCPLeaseObservation{{
		MAC:              "aa:bb:cc:dd:ee:ff",
		IP:               "192.168.50.10",
		Hostname:         "lab-client",
		Reservation:      true,
		Expired:          false,
		ExpiresAt:        observedAt.Add(time.Hour).Format(time.RFC3339),
		RemainingSeconds: 3600,
	}}))
	require.NoError(t, db.RecordHAHistory("failover", "promoted", "Standby promoted cleanly.", "standby", "", map[string]any{
		"vip": "192.168.50.2",
	}))
	_, err = db.DB.Exec(`INSERT INTO guest_registrations (
		id, status, tenant, full_name, email, sponsor_name, sponsor_email, role,
		guest_token_hash, approval_delivery_status, invite_delivery_status,
		created_at, approved_at, expires_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"guest-1", "approved", "tenant-a", "Alice Guest", "alice@example.test", "Sam Sponsor", "sam@example.test", "guest-basic",
		"hash-1", "sent", "sent", observedAt.Add(-20*time.Minute), observedAt.Add(-10*time.Minute), observedAt.Add(24*time.Hour),
	)
	require.NoError(t, err)
	_, err = db.DB.Exec(`INSERT INTO sessions (
		id, username, mac, ip, auth_method, identity_source, vlan, role, bandwidth_profile, start_time, last_activity, end_time, stop_reason, radius_session_id, bytes_in, bytes_out, acct_session_time
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"session-1", "alice", "aa:bb:cc:dd:ee:ff", "192.168.50.10", "dot1x", "ldap", 20, "employee", "gold",
		observedAt.Add(-30*time.Minute), observedAt.Add(-5*time.Minute), observedAt.Add(-1*time.Minute), "User-Request", "radius-1", 1024, 2048, 1800,
	)
	require.NoError(t, err)
	require.NoError(t, db.UpsertRuntimeStatus("controller_automation", "ok", "Controller sync healthy.", map[string]any{
		"sync_count": 2,
	}))

	origNow := supportBundleNow
	origHostname := supportBundleHostname
	origRunCommand := supportBundleRunCommand
	origAssessUpgradeReadiness := assessUpgradeReadinessFn
	supportBundleNow = func() time.Time { return now }
	supportBundleHostname = func() (string, error) { return "support-node", nil }
	supportBundleRunCommand = func(name string, args ...string) (string, error) {
		switch name {
		case "journalctl":
			return "journal output ok", nil
		case "ip":
			return "ip output ok", nil
		case "df":
			return "df output ok", nil
		case "nft":
			return "table inet filter", nil
		case "systemctl":
			return "service status ok", nil
		default:
			return "", nil
		}
	}
	assessUpgradeReadinessFn = func(cfg *config.Config, configPath string) (upgradepkg.ReadinessReport, error) {
		return upgradepkg.ReadinessReport{
			ConfigPath:           configPath,
			DatabasePath:         cfg.Database.Path,
			CurrentSchemaVersion: db.LatestSchemaVersion(),
			TargetSchemaVersion:  db.LatestSchemaVersion(),
			ConfigValid:          true,
			Rehearsal: upgradepkg.MigrationRehearsal{
				Ran:       true,
				Succeeded: true,
			},
		}, nil
	}
	t.Cleanup(func() {
		supportBundleNow = origNow
		supportBundleHostname = origHostname
		supportBundleRunCommand = origRunCommand
		assessUpgradeReadinessFn = origAssessUpgradeReadiness
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/support-bundle", nil)
	rec := httptest.NewRecorder()
	HandleDownloadSupportBundle(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/zip", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Header().Get("Content-Disposition"), "aegisnas-support-bundle-20260519-084500Z.zip")

	entries := readSupportBundleZip(t, rec.Body.Bytes())
	require.Contains(t, entries, "manifest.json")
	require.Contains(t, entries, "api/support-bundle-summary.json")
	require.Contains(t, entries, "api/system-settings-redacted.json")
	require.Contains(t, entries, "api/network-preview.json")
	require.Contains(t, entries, "api/session-history.json")
	require.Contains(t, entries, "api/session-analytics.json")
	require.Contains(t, entries, "api/voucher-aging-analytics.json")
	require.Contains(t, entries, "api/voucher-expiry-analytics.json")
	require.Contains(t, entries, "api/voucher-redemption-analytics.json")
	require.Contains(t, entries, "api/guest-lifecycle.json")
	require.Contains(t, entries, "api/guest-conversion-analytics.json")
	require.Contains(t, entries, "api/guest-invite-analytics.json")
	require.Contains(t, entries, "api/guest-delivery-analytics.json")
	require.Contains(t, entries, "api/guest-delivery-failures.json")
	require.Contains(t, entries, "api/guest-sponsor-analytics.json")
	require.Contains(t, entries, "api/network-apply-history.json")
	require.Contains(t, entries, "api/dhcp-lease-history.json")
	require.Contains(t, entries, "api/upstream-aaa-history.json")
	require.Contains(t, entries, "api/fallback-policy.json")
	require.Contains(t, entries, "api/audit-history.json")
	require.Contains(t, entries, "api/integration-history.json")
	require.Contains(t, entries, "api/ha-history.json")
	require.Contains(t, entries, "api/upgrade-readiness.json")
	require.Contains(t, entries, "api/secret-providers.json")
	require.Contains(t, entries, "api/database.json")
	require.Contains(t, entries, "api/openapi.json")
	require.Contains(t, entries, "runtime/runtime-statuses.json")
	require.Contains(t, entries, "system/database-backend.txt")
	require.Contains(t, entries, "system/ip-addr.txt")
	require.Contains(t, entries, "logs/aegis-admin-api.log")

	var settings map[string]any
	require.NoError(t, json.Unmarshal(entries["api/system-settings-redacted.json"], &settings))
	radius := settings["radius"].(map[string]any)
	assert.Equal(t, "<redacted>", radius["secret"])
	ldap := settings["ldap"].(map[string]any)
	assert.Equal(t, "<redacted>", ldap["bind_password"])
	activeDirectory := settings["active_directory"].(map[string]any)
	assert.Equal(t, "<redacted>", activeDirectory["bind_password"])
	ha := settings["high_availability"].(map[string]any)
	assert.Equal(t, "AEGIS_WITNESS_SIGNING_KEY", ha["witness_signing_key_env"])

	var manifest supportBundleManifest
	require.NoError(t, json.Unmarshal(entries["manifest.json"], &manifest))
	assert.Equal(t, "support-node", manifest.Hostname)
	assert.Equal(t, cfg.Database.Path, manifest.DatabasePath)
	assert.Equal(t, db.LatestSchemaVersion(), manifest.SchemaVersion)
	assert.Empty(t, manifest.Warnings)

	assert.Contains(t, string(entries["system/ip-addr.txt"]), "ip output ok")
	assert.Contains(t, string(entries["logs/aegis-admin-api.log"]), "journal output ok")
	assert.Contains(t, string(entries["api/audit-history.json"]), "download_support_bundle")
	assert.Contains(t, string(entries["api/session-history.json"]), "\"history\"")
	assert.Contains(t, string(entries["api/session-analytics.json"]), "\"summary\"")
	assert.Contains(t, string(entries["api/voucher-aging-analytics.json"]), "\"summary\"")
	assert.Contains(t, string(entries["api/voucher-expiry-analytics.json"]), "\"summary\"")
	assert.Contains(t, string(entries["api/voucher-redemption-analytics.json"]), "\"summary\"")
	assert.Contains(t, string(entries["api/guest-lifecycle.json"]), "\"summary\"")
	assert.Contains(t, string(entries["api/guest-conversion-analytics.json"]), "\"summary\"")
	assert.Contains(t, string(entries["api/guest-invite-analytics.json"]), "\"summary\"")
	assert.Contains(t, string(entries["api/guest-delivery-analytics.json"]), "\"summary\"")
	assert.Contains(t, string(entries["api/guest-delivery-failures.json"]), "\"summary\"")
	assert.Contains(t, string(entries["api/guest-sponsor-analytics.json"]), "\"summary\"")
	assert.Contains(t, string(entries["api/upstream-aaa-history.json"]), "\"history\"")
	assert.Contains(t, string(entries["api/ha-history.json"]), "Standby promoted cleanly.")
	assert.Contains(t, string(entries["api/integration-history.json"]), "\"history\"")
	assert.Contains(t, string(entries["api/upgrade-readiness.json"]), "\"config_valid\": true")
	assert.Contains(t, string(entries["api/database.json"]), "\"schema_version\"")
	assert.Contains(t, string(entries["api/openapi.json"]), "\"openapi\": \"3.1.0\"")
}

func TestSupportBundleKeepsSecretReferencesVisible(t *testing.T) {
	assert.False(t, shouldRedactSupportBundleKey("secret_ref"))
	assert.False(t, shouldRedactSupportBundleKey("bind_password_ref"))
	assert.False(t, shouldRedactSupportBundleKey("dsn_ref"))
	assert.True(t, shouldRedactSupportBundleKey("secret"))
	assert.True(t, shouldRedactSupportBundleKey("bind_password"))
	assert.True(t, shouldRedactSupportBundleKey("dsn"))
}

func TestBuildSupportBundleCapturesCommandWarnings(t *testing.T) {
	prepareSupportBundleTestConfig(t)

	origRunCommand := supportBundleRunCommand
	origHostname := supportBundleHostname
	origAssessUpgradeReadiness := assessUpgradeReadinessFn
	supportBundleRunCommand = func(name string, args ...string) (string, error) {
		if name == "ip" {
			return "", errors.New("ip unavailable")
		}
		return "ok", nil
	}
	supportBundleHostname = func() (string, error) { return "warning-node", nil }
	assessUpgradeReadinessFn = func(cfg *config.Config, configPath string) (upgradepkg.ReadinessReport, error) {
		return upgradepkg.ReadinessReport{
			ConfigPath:           configPath,
			DatabasePath:         cfg.Database.Path,
			CurrentSchemaVersion: db.LatestSchemaVersion(),
			TargetSchemaVersion:  db.LatestSchemaVersion(),
			ConfigValid:          true,
		}, nil
	}
	t.Cleanup(func() {
		supportBundleRunCommand = origRunCommand
		supportBundleHostname = origHostname
		assessUpgradeReadinessFn = origAssessUpgradeReadiness
	})

	payload, _, err := buildSupportBundle(config.Get())
	require.NoError(t, err)

	entries := readSupportBundleZip(t, payload)
	var manifest supportBundleManifest
	require.NoError(t, json.Unmarshal(entries["manifest.json"], &manifest))
	require.NotEmpty(t, manifest.Warnings)
	assert.Contains(t, string(entries["system/ip-addr.txt"]), "command failed: ip unavailable")
}

func TestHandleGetSupportBundleSummary(t *testing.T) {
	_ = prepareSupportBundleTestConfig(t)
	now := time.Date(2026, 5, 19, 8, 45, 0, 0, time.UTC)

	origNow := supportBundleNow
	supportBundleNow = func() time.Time { return now }
	t.Cleanup(func() {
		supportBundleNow = origNow
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/support-bundle/summary", nil)
	rec := httptest.NewRecorder()
	HandleGetSupportBundleSummary(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var payload supportBundleSummary
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, supportBundleVersion, payload.BundleVersion)
	assert.True(t, payload.ContainsSecrets)
	assert.Contains(t, payload.ArchiveEntries, "api/upgrade-readiness.json")
	assert.Contains(t, payload.ArchiveEntries, "api/openapi.json")
	assert.Contains(t, payload.ArchiveEntries, "api/upstream-aaa-history.json")
	assert.Contains(t, payload.ArchiveEntries, "api/audit-history.json")
	assert.Contains(t, payload.ArchiveEntries, "api/session-history.json")
	assert.Contains(t, payload.ArchiveEntries, "api/session-analytics.json")
	assert.Contains(t, payload.ArchiveEntries, "api/guest-lifecycle.json")
	assert.Contains(t, payload.ArchiveEntries, "api/guest-conversion-analytics.json")
	assert.Contains(t, payload.ArchiveEntries, "api/guest-invite-analytics.json")
	assert.Contains(t, payload.ArchiveEntries, "api/guest-delivery-analytics.json")
	assert.Contains(t, payload.ArchiveEntries, "api/guest-delivery-failures.json")
	assert.Contains(t, payload.ArchiveEntries, "api/guest-sponsor-analytics.json")
	assert.Contains(t, payload.ArchiveEntries, "api/integration-history.json")
	assert.Contains(t, payload.APICaptures, "Upgrade readiness")
	assert.Contains(t, payload.APICaptures, "OpenAPI schema")
	assert.Contains(t, payload.APICaptures, "Upstream AAA history")
	assert.Contains(t, payload.APICaptures, "Upstream fallback policy")
	assert.Contains(t, payload.APICaptures, "Audit history")
	assert.Contains(t, payload.APICaptures, "Session and accounting history")
	assert.Contains(t, payload.APICaptures, "Session activity analytics")
	assert.Contains(t, payload.APICaptures, "Guest lifecycle report")
	assert.Contains(t, payload.APICaptures, "Guest invite analytics")
	assert.Contains(t, payload.APICaptures, "Guest delivery analytics")
	assert.Contains(t, payload.APICaptures, "Guest delivery failures")
	assert.Contains(t, payload.APICaptures, "Guest sponsor analytics")
	assert.Contains(t, payload.APICaptures, "Integration history")
	assert.Contains(t, payload.SystemCaptures, "system/ip-addr.txt")
	assert.Contains(t, payload.LogCaptures, "logs/aegis-admin-api.log")
}

func prepareSupportBundleTestConfig(t *testing.T) *config.Config {
	t.Helper()

	dir := t.TempDir()
	cfg := &config.Config{
		Mode: "two-nic",
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
		LDAP: config.LDAPConfig{
			BindPassword: "directory-password",
		},
		ActiveDirectory: config.ActiveDirectoryConfig{
			BindPassword: "ad-directory-password",
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
			WitnessSigningKeyEnv:        "AEGIS_WITNESS_SIGNING_KEY",
		},
		DHCP: config.DHCPConfig{
			Enabled:       true,
			LeaseTime:     "12h",
			Authoritative: true,
		},
		AdminPort: 8083,
	}

	configPath := filepath.Join(dir, "config.yaml")
	require.NoError(t, config.WriteFile(configPath, cfg))
	_, err := config.Load(configPath)
	require.NoError(t, err)
	require.NoError(t, db.Init(cfg.Database.Path))
	require.NoError(t, db.Migrate())
	t.Cleanup(func() {
		db.Close()
	})
	return cfg
}

func readSupportBundleZip(t *testing.T, payload []byte) map[string][]byte {
	t.Helper()

	reader, err := zip.NewReader(bytes.NewReader(payload), int64(len(payload)))
	require.NoError(t, err)

	entries := make(map[string][]byte, len(reader.File))
	for _, file := range reader.File {
		handle, openErr := file.Open()
		require.NoError(t, openErr)
		data, readErr := io.ReadAll(handle)
		_ = handle.Close()
		require.NoError(t, readErr)
		entries[file.Name] = data
	}
	return entries
}
