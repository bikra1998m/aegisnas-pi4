package adminapi

import (
	"context"
	"encoding/json"
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

func TestRunUpgradeReadinessExportCycleAndListUpgradeReadinessExports(t *testing.T) {
	prepareSupportBundleTestConfig(t)
	cfg := config.Get()
	require.NotNil(t, cfg)
	exportDir := filepath.Join(t.TempDir(), "upgrade-readiness-exports")
	cfg.Telemetry.UpgradeReadinessExports = config.DiagnosticsExportConfig{
		Enabled:         true,
		Directory:       exportDir,
		Format:          "both",
		IntervalMinutes: 60,
		RetentionCount:  2,
	}

	origAssess := upgradeReadinessExportAssessFn
	upgradeReadinessExportAssessFn = func(cfgArg *config.Config, configPath string) (upgradepkg.ReadinessReport, error) {
		return upgradepkg.ReadinessReport{
			GeneratedAt:          "2026-05-25T10:30:00Z",
			ConfigPath:           configPath,
			DatabasePath:         cfgArg.Database.Path,
			DatabaseExists:       true,
			DatabaseSizeBytes:    4096,
			CurrentSchemaVersion: 10,
			TargetSchemaVersion:  10,
			ConfigValid:          true,
			DeploymentProfile:    "branch",
			DeploymentForm:       "virtual",
			Rehearsal: upgradepkg.MigrationRehearsal{
				Ran:                  true,
				Succeeded:            true,
				StartedSchemaVersion: 10,
				ResultSchemaVersion:  10,
				DurationMilliseconds: 42,
			},
			Recommendations: []string{"Upgrade rehearsal passed."},
		}, nil
	}
	t.Cleanup(func() {
		upgradeReadinessExportAssessFn = origAssess
	})

	now := time.Date(2026, 5, 25, 10, 45, 0, 0, time.UTC)
	origNow := upgradeReadinessExportNow
	upgradeReadinessExportNow = func() time.Time { return now }
	t.Cleanup(func() {
		upgradeReadinessExportNow = origNow
	})

	runUpgradeReadinessExportCycle(context.Background(), cfg)

	runtimeStatus, err := db.GetRuntimeStatus(upgradeReadinessExportsComponent)
	require.NoError(t, err)
	require.NotNil(t, runtimeStatus)
	assert.Equal(t, "ok", runtimeStatus.Status)
	assert.Equal(t, now.Format(time.RFC3339), runtimeStatus.Details["last_export_at"])

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/upgrade-readiness-exports", nil)
	rec := httptest.NewRecorder()
	HandleListUpgradeReadinessExports(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var payload struct {
		Runtime *db.RuntimeStatus                `json:"runtime"`
		Exports []UpgradeReadinessExportArtifact `json:"exports"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	require.NotNil(t, payload.Runtime)
	require.Len(t, payload.Exports, 2)
	assert.Equal(t, "ok", payload.Runtime.Status)
}

func TestHandleDownloadUpgradeReadinessExport(t *testing.T) {
	prepareSupportBundleTestConfig(t)
	cfg := config.Get()
	require.NotNil(t, cfg)
	exportDir := filepath.Join(t.TempDir(), "upgrade-readiness-export-downloads")
	cfg.Telemetry.UpgradeReadinessExports = config.DiagnosticsExportConfig{
		Enabled:         true,
		Directory:       exportDir,
		Format:          "json",
		IntervalMinutes: 60,
		RetentionCount:  2,
	}

	origAssess := upgradeReadinessExportAssessFn
	upgradeReadinessExportAssessFn = func(cfgArg *config.Config, configPath string) (upgradepkg.ReadinessReport, error) {
		return upgradepkg.ReadinessReport{
			GeneratedAt:           "2026-05-25T11:00:00Z",
			ConfigPath:            configPath,
			DatabasePath:          cfgArg.Database.Path,
			CurrentSchemaVersion:  9,
			TargetSchemaVersion:   10,
			ConfigValid:           false,
			ConfigValidationError: "missing cert path",
			Rehearsal: upgradepkg.MigrationRehearsal{
				Ran:                  true,
				Succeeded:            false,
				StartedSchemaVersion: 9,
				ResultSchemaVersion:  0,
				DurationMilliseconds: 13,
				Error:                "migration failed",
			},
		}, nil
	}
	t.Cleanup(func() {
		upgradeReadinessExportAssessFn = origAssess
	})

	now := time.Date(2026, 5, 25, 11, 5, 0, 0, time.UTC)
	origNow := upgradeReadinessExportNow
	upgradeReadinessExportNow = func() time.Time { return now }
	t.Cleanup(func() {
		upgradeReadinessExportNow = origNow
	})

	runUpgradeReadinessExportCycle(context.Background(), cfg)

	artifacts, err := listUpgradeReadinessExportArtifacts(cfg)
	require.NoError(t, err)
	require.Len(t, artifacts, 1)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/upgrade-readiness-exports/download?name="+artifacts[0].Name, nil)
	rec := httptest.NewRecorder()
	HandleDownloadUpgradeReadinessExport(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Header().Get("Content-Disposition"), artifacts[0].Name)
	assert.Contains(t, rec.Body.String(), `"migration failed"`)
}
