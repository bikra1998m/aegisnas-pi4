package adminapi

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/radius"
	upgradepkg "github.com/yourorg/aegisnas-pi4/internal/upgrade"
)

func TestHandleGetDiagnosticsReport(t *testing.T) {
	cfg := prepareSupportBundleTestConfig(t)
	observedAt := time.Date(2026, 5, 20, 9, 0, 0, 0, time.UTC)

	require.NoError(t, db.RecordNetworkApplyHistory("apply", "success", "apply ok", "backup-1", "", "tester", map[string]any{"validated": true}))
	_, err := db.DB.Exec(`INSERT INTO audit_logs (timestamp, user, action, details, result, ip_address) VALUES (?, ?, ?, ?, ?, ?)`,
		observedAt, "ops-admin", "download_support_bundle", "bundle-1", "downloaded", "192.168.50.10")
	require.NoError(t, err)
	_, err = db.DB.Exec(`INSERT INTO guest_registrations (
		id, status, tenant, full_name, email, sponsor_name, sponsor_email, role,
		guest_token_hash, approval_delivery_status, invite_delivery_status,
		created_at, approved_at, expires_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"guest-1", "approved", "tenant-a", "Alice Guest", "alice@example.test", "Sam Sponsor", "sam@example.test", "guest-basic",
		"hash-1", "sent", "sent", observedAt.Add(-20*time.Minute), observedAt.Add(-10*time.Minute), observedAt.Add(24*time.Hour),
	)
	require.NoError(t, err)
	require.NoError(t, db.StoreDHCPLeaseObservations(observedAt, []db.DHCPLeaseObservation{{
		MAC:              "aa:bb:cc:dd:ee:ff",
		IP:               "192.168.50.10",
		Hostname:         "client-1",
		Reservation:      false,
		Expired:          false,
		ExpiresAt:        observedAt.Add(time.Hour).Format(time.RFC3339),
		RemainingSeconds: 3600,
	}}))
	require.NoError(t, db.RecordHAHistory("failover", "promoted", "Standby promoted cleanly.", "standby", "", map[string]any{"vip": "192.168.50.2"}))
	require.NoError(t, db.RecordIntegrationHistory("controller_automation", "ok", "Controller sync completed.", map[string]any{"adapter": "cisco-ise"}))
	require.NoError(t, db.RecordIntegrationHistory("mdm_sync", "degraded", "MDM sync failed.", map[string]any{"provider": "intune"}))
	_, err = db.DB.Exec(`INSERT INTO sessions (
		id, username, mac, ip, auth_method, identity_source, vlan, role, bandwidth_profile, start_time, last_activity, end_time, stop_reason, radius_session_id, bytes_in, bytes_out, acct_session_time
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"session-1", "alice", "aa:bb:cc:dd:ee:ff", "192.168.50.10", "dot1x", "ldap", 20, "employee", "gold",
		observedAt.Add(-35*time.Minute), observedAt.Add(-5*time.Minute), observedAt.Add(-1*time.Minute), "User-Request", "radius-1", 1024, 2048, 1800,
	)
	require.NoError(t, err)
	require.NoError(t, db.UpsertRuntimeStatus("controller_automation", "ok", "Controller sync healthy.", map[string]any{"sync_count": 2}))
	require.NoError(t, db.UpsertRuntimeStatus("siem_export", "ok", "SIEM export healthy.", map[string]any{"delivered": 4}))
	require.NoError(t, db.UpsertRuntimeStatus("admin_sso", "ok", "SSO healthy.", map[string]any{"provider": "oidc"}))
	require.NoError(t, db.UpsertRuntimeStatus("mdm_sync", "ok", "MDM sync healthy.", map[string]any{"managed": 5}))
	require.NoError(t, db.UpsertRuntimeStatus("posture_checks", "ok", "Posture checks healthy.", map[string]any{"compliant": 4}))

	origAssess := assessDiagnosticsUpgradeReadinessFn
	origProbe := probeDiagnosticsUpstreamServersFn
	assessDiagnosticsUpgradeReadinessFn = func(cfgArg *config.Config, configPath string) (upgradepkg.ReadinessReport, error) {
		return upgradepkg.ReadinessReport{
			ConfigPath:           configPath,
			DatabasePath:         cfgArg.Database.Path,
			CurrentSchemaVersion: db.LatestSchemaVersion(),
			TargetSchemaVersion:  db.LatestSchemaVersion(),
			ConfigValid:          true,
			Rehearsal: upgradepkg.MigrationRehearsal{
				Ran:       true,
				Succeeded: true,
			},
		}, nil
	}
	probeDiagnosticsUpstreamServersFn = func(ctx context.Context, cfgArg *config.Config) ([]radius.UpstreamServerHealth, error) {
		return []radius.UpstreamServerHealth{{
			Name:      "primary",
			Address:   "10.0.0.2",
			AuthPort:  1812,
			AcctPort:  1813,
			Status:    "ok",
			Message:   "reachable",
			CheckedAt: observedAt.Format(time.RFC3339),
		}}, nil
	}
	t.Cleanup(func() {
		assessDiagnosticsUpgradeReadinessFn = origAssess
		probeDiagnosticsUpstreamServersFn = origProbe
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/diagnostics-report", nil)
	rec := httptest.NewRecorder()
	HandleGetDiagnosticsReport(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var payload DiagnosticsReport
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, cfg.Database.Path, payload.DatabasePath)
	assert.Equal(t, "enterprise", payload.DeploymentProfile)
	assert.Equal(t, "standby", payload.HARole)
	assert.Equal(t, 1, payload.Audit.TotalRecords)
	assert.Equal(t, 1, payload.Sessions.TotalRecords)
	assert.Equal(t, 1, payload.Guest.Summary.TotalRecords)
	assert.Equal(t, 1, payload.Guest.Summary.ApprovedCount)
	assert.Equal(t, 1, payload.Guest.InviteAnalytics.TrackedInviteRecordsCount)
	assert.Equal(t, 0, payload.Guest.DeliveryFailures.TotalFailureCount)
	assert.Equal(t, int64(3072), payload.Sessions.TrafficTotal)
	assert.Equal(t, 1, payload.Network.ApplyStats.ApplySuccessCount)
	assert.Equal(t, 1, payload.HighAvailability.Stats.FailoverPromotions)
	require.NotNil(t, payload.Integrations.Controller)
	assert.Equal(t, "ok", payload.Integrations.Controller.Status)
	require.NotNil(t, payload.Integrations.HistoryStats)
	assert.Equal(t, 2, payload.Integrations.HistoryStats.TotalRecords)
	require.Len(t, payload.Integrations.UpstreamAAA, 1)
	assert.Equal(t, "primary", payload.Integrations.UpstreamAAA[0].Name)
	assert.True(t, payload.Upgrade.ConfigValid)
}

func TestHandleExportDiagnosticsReportCSV(t *testing.T) {
	_ = prepareSupportBundleTestConfig(t)

	origAssess := assessDiagnosticsUpgradeReadinessFn
	origProbe := probeDiagnosticsUpstreamServersFn
	assessDiagnosticsUpgradeReadinessFn = func(cfgArg *config.Config, configPath string) (upgradepkg.ReadinessReport, error) {
		return upgradepkg.ReadinessReport{
			ConfigPath:           configPath,
			DatabasePath:         cfgArg.Database.Path,
			CurrentSchemaVersion: db.LatestSchemaVersion(),
			TargetSchemaVersion:  db.LatestSchemaVersion(),
			ConfigValid:          true,
		}, nil
	}
	probeDiagnosticsUpstreamServersFn = func(ctx context.Context, cfgArg *config.Config) ([]radius.UpstreamServerHealth, error) {
		return []radius.UpstreamServerHealth{{Name: "primary", Address: "10.0.0.2", Status: "ok"}}, nil
	}
	t.Cleanup(func() {
		assessDiagnosticsUpgradeReadinessFn = origAssess
		probeDiagnosticsUpstreamServersFn = origProbe
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/diagnostics-report/export?format=csv", nil)
	rec := httptest.NewRecorder()
	HandleExportDiagnosticsReport(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/csv", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Header().Get("Content-Disposition"), "aegisnas-diagnostics-report-")

	reader := csv.NewReader(strings.NewReader(rec.Body.String()))
	rows, err := reader.ReadAll()
	require.NoError(t, err)
	require.NotEmpty(t, rows)
	assert.Contains(t, rec.Body.String(), "audit_total_records")
	assert.Contains(t, rec.Body.String(), "session_history_total_records")
	assert.Contains(t, rec.Body.String(), "guest_total_records")
	assert.Contains(t, rec.Body.String(), "guest_approved_count")
	assert.Contains(t, rec.Body.String(), "guest_invite_tracked_records_count")
	assert.Contains(t, rec.Body.String(), "guest_delivery_failure_total_count")
	assert.Contains(t, rec.Body.String(), "upgrade_target_schema")
	assert.Contains(t, rec.Body.String(), "upstream_aaa_primary")
	assert.Contains(t, rec.Body.String(), "upstream_aaa_history_total_records")
	assert.Contains(t, rec.Body.String(), "integration_history_total_records")
}

func TestHandleExportDiagnosticsReportRejectsUnsupportedFormat(t *testing.T) {
	_ = prepareSupportBundleTestConfig(t)

	origAssess := assessDiagnosticsUpgradeReadinessFn
	origProbe := probeDiagnosticsUpstreamServersFn
	assessDiagnosticsUpgradeReadinessFn = func(cfgArg *config.Config, configPath string) (upgradepkg.ReadinessReport, error) {
		return upgradepkg.ReadinessReport{
			ConfigPath:           configPath,
			DatabasePath:         cfgArg.Database.Path,
			CurrentSchemaVersion: db.LatestSchemaVersion(),
			TargetSchemaVersion:  db.LatestSchemaVersion(),
			ConfigValid:          true,
		}, nil
	}
	probeDiagnosticsUpstreamServersFn = func(ctx context.Context, cfgArg *config.Config) ([]radius.UpstreamServerHealth, error) {
		return nil, nil
	}
	t.Cleanup(func() {
		assessDiagnosticsUpgradeReadinessFn = origAssess
		probeDiagnosticsUpstreamServersFn = origProbe
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/diagnostics-report/export?format=xml", nil)
	rec := httptest.NewRecorder()
	HandleExportDiagnosticsReport(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "unsupported format")
}
