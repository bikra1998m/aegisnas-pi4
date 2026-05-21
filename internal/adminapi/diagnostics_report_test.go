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
	assert.Equal(t, 1, payload.Network.ApplyStats.ApplySuccessCount)
	assert.Equal(t, 1, payload.HighAvailability.Stats.FailoverPromotions)
	require.NotNil(t, payload.Integrations.Controller)
	assert.Equal(t, "ok", payload.Integrations.Controller.Status)
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
	assert.Contains(t, rec.Body.String(), "upgrade_target_schema")
	assert.Contains(t, rec.Body.String(), "upstream_aaa_primary")
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
