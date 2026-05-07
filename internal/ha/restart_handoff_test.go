package ha

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestScheduleServiceRestartDedupesServices(t *testing.T) {
	original := restartCommandFn
	defer func() { restartCommandFn = original }()

	called := []string{}
	restartCommandFn = func(services []string) error {
		called = append([]string(nil), services...)
		return nil
	}

	err := ScheduleServiceRestart([]string{"aegis-admin-api", "aegis-gateway", "aegis-admin-api", ""})
	require.NoError(t, err)
	assert.Equal(t, []string{"aegis-admin-api", "aegis-gateway"}, called)
}

func TestBuildRestartHandoffScriptQuotesServices(t *testing.T) {
	script := buildRestartHandoffScript([]string{"aegis-admin-api", "svc'quote"})
	assert.Contains(t, script, "sleep 2; exec")
	assert.Contains(t, script, "'systemctl' 'restart' 'aegis-admin-api' 'svc'\"'\"'quote'")
}

func TestScheduleActivationRestartRecordsWarning(t *testing.T) {
	cfg := testHAConfig(filepath.Join(t.TempDir(), "data.db"), "standby", "https://active.example.test:8083", "Standby")
	require.NoError(t, db.Init(cfg.Database.Path))
	require.NoError(t, db.Migrate())
	defer db.Close()

	original := restartCommandFn
	defer func() { restartCommandFn = original }()
	restartCommandFn = func(services []string) error {
		return errors.New("handoff failed")
	}

	err := ScheduleActivationRestart(cfg, ActivationResult{
		ID:              "stage-001",
		BackupPath:      "/var/lib/aegisnas/ha/replication/backups/rollback.tar.gz",
		RestartServices: []string{"aegis-admin-api"},
	}, "ops-admin")
	require.ErrorContains(t, err, "handoff failed")

	runtimeStatus, err := db.GetRuntimeStatus(ReplicationRuntimeComponent)
	require.NoError(t, err)
	require.NotNil(t, runtimeStatus)
	assert.Equal(t, "degraded", runtimeStatus.Status)
	assert.Contains(t, runtimeStatus.Message, "automatic restart handoff failed")
}

func TestScheduleActivationRestartRecordsPendingState(t *testing.T) {
	cfg := testHAConfig(filepath.Join(t.TempDir(), "data.db"), "standby", "https://active.example.test:8083", "Standby")
	require.NoError(t, db.Init(cfg.Database.Path))
	require.NoError(t, db.Migrate())
	defer db.Close()

	original := restartCommandFn
	defer func() { restartCommandFn = original }()
	restartCommandFn = func(services []string) error {
		return nil
	}

	err := ScheduleActivationRestart(cfg, ActivationResult{
		ID:              "stage-002",
		BackupPath:      "/var/lib/aegisnas/ha/replication/backups/rollback.tar.gz",
		RestartServices: []string{"aegis-admin-api", "aegis-gateway"},
	}, "ops-admin")
	require.NoError(t, err)

	runtimeStatus, err := db.GetRuntimeStatus(ReplicationRuntimeComponent)
	require.NoError(t, err)
	require.NotNil(t, runtimeStatus)
	assert.Equal(t, "pending", runtimeStatus.Status)
	assert.Contains(t, runtimeStatus.Message, "restart handoff queued")
}
