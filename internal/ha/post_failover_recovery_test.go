package ha

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"go.uber.org/zap"
)

func TestResumePendingPostFailoverRecoveryMarksHealthyActivationValidated(t *testing.T) {
	cfg := testHAConfig(filepath.Join(t.TempDir(), "data.db"), "standby", "https://active.example.test:8083", "Standby")
	require.NoError(t, db.Init(cfg.Database.Path))
	require.NoError(t, db.Migrate())
	defer db.Close()

	originalValidate := postFailoverValidateServicesFn
	originalRestore := postFailoverRestoreBackupFn
	originalRestart := postFailoverScheduleRestartFn
	defer func() {
		postFailoverValidateServicesFn = originalValidate
		postFailoverRestoreBackupFn = originalRestore
		postFailoverScheduleRestartFn = originalRestart
	}()

	postFailoverValidateServicesFn = func(cfg *config.Config, services []string) PostFailoverValidationReport {
		return PostFailoverValidationReport{
			Healthy:    true,
			Summary:    "All standby services are healthy.",
			ObservedAt: time.Now().UTC().Format(time.RFC3339),
		}
	}
	postFailoverRestoreBackupFn = func(cfg *config.Config, backupPath, activatedBy string) (ActivationResult, error) {
		t.Fatalf("rollback restore should not run on healthy validation")
		return ActivationResult{}, nil
	}
	postFailoverScheduleRestartFn = func(services []string) error {
		t.Fatalf("restart handoff should not run on healthy validation")
		return nil
	}

	err := BeginPostFailoverHealthRecovery(cfg, ActivationResult{
		ID:              "stage-healthy",
		BackupPath:      "/var/lib/aegisnas/ha/replication/backups/healthy.tar.gz",
		RestartServices: []string{"aegis-gateway", "aegis-admin-api"},
	}, "ha-auto-activate")
	require.NoError(t, err)

	restartScheduled, err := ResumePendingPostFailoverRecovery(context.Background(), cfg, zap.NewNop())
	require.NoError(t, err)
	assert.False(t, restartScheduled)

	state, err := currentPostFailoverRecoveryState()
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.False(t, state.Pending)
	assert.Equal(t, "ok", state.Status)
	assert.Equal(t, "validated", state.LastValidationStatus)
	assert.NotEmpty(t, state.ValidatedAt)

	history, err := db.ListHAHistory(10)
	require.NoError(t, err)
	require.NotEmpty(t, history)
	assert.Equal(t, "post_failover_validation", history[0].EventType)
	assert.Equal(t, "validated", history[0].Status)
}

func TestResumePendingPostFailoverRecoveryRollsBackUnhealthyActivation(t *testing.T) {
	cfg := testHAConfig(filepath.Join(t.TempDir(), "data.db"), "standby", "https://active.example.test:8083", "Standby")
	require.NoError(t, db.Init(cfg.Database.Path))
	require.NoError(t, db.Migrate())
	defer db.Close()

	originalValidate := postFailoverValidateServicesFn
	originalRestore := postFailoverRestoreBackupFn
	originalRestart := postFailoverScheduleRestartFn
	originalWindow := postFailoverValidationWindow
	originalRetry := postFailoverRetryInterval
	defer func() {
		postFailoverValidateServicesFn = originalValidate
		postFailoverRestoreBackupFn = originalRestore
		postFailoverScheduleRestartFn = originalRestart
		postFailoverValidationWindow = originalWindow
		postFailoverRetryInterval = originalRetry
	}()

	postFailoverValidationWindow = 5 * time.Millisecond
	postFailoverRetryInterval = time.Millisecond
	postFailoverValidateServicesFn = func(cfg *config.Config, services []string) PostFailoverValidationReport {
		return PostFailoverValidationReport{
			Healthy: false,
			Summary: "aegis-admin-api health endpoint is still down",
			Checks: []PostFailoverCheck{
				{Name: "aegis-admin-api", Kind: "http", Status: "down", Message: "connection refused"},
			},
		}
	}

	restored := ""
	postFailoverRestoreBackupFn = func(cfg *config.Config, backupPath, activatedBy string) (ActivationResult, error) {
		restored = backupPath
		return ActivationResult{
			ID:              "rollback-stage",
			BackupPath:      "/var/lib/aegisnas/ha/replication/backups/failed-state.tar.gz",
			RestartServices: []string{"aegis-gateway", "aegis-admin-api"},
			Summary:         "Rollback bundle restored.",
		}, nil
	}

	var restarted []string
	postFailoverScheduleRestartFn = func(services []string) error {
		restarted = append([]string(nil), services...)
		return nil
	}

	err := BeginPostFailoverHealthRecovery(cfg, ActivationResult{
		ID:              "stage-unhealthy",
		BackupPath:      "/var/lib/aegisnas/ha/replication/backups/unhealthy.tar.gz",
		RestartServices: []string{"aegis-gateway", "aegis-admin-api"},
	}, "ha-auto-activate")
	require.NoError(t, err)

	restartScheduled, err := ResumePendingPostFailoverRecovery(context.Background(), cfg, zap.NewNop())
	require.NoError(t, err)
	assert.True(t, restartScheduled)
	assert.Equal(t, "/var/lib/aegisnas/ha/replication/backups/unhealthy.tar.gz", restored)
	assert.Equal(t, []string{"aegis-gateway", "aegis-admin-api"}, restarted)

	state, err := currentPostFailoverRecoveryState()
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.False(t, state.Pending)
	assert.Equal(t, "degraded", state.Status)
	assert.Equal(t, "rolled_back", state.LastValidationStatus)
	assert.NotEmpty(t, state.RolledBackAt)
	assert.Contains(t, state.LastValidationError, "aegis-admin-api")

	history, err := db.ListHAHistory(10)
	require.NoError(t, err)
	require.NotEmpty(t, history)
	assert.Equal(t, "post_failover_validation", history[0].EventType)
	assert.Equal(t, "rolled_back", history[0].Status)
}
