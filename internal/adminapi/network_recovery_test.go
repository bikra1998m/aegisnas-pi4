package adminapi

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/network"
	"go.uber.org/zap"
)

func TestStartPendingNetworkRecoveryAndConfirm(t *testing.T) {
	cfg := testNetworkRecoveryConfig(t)

	originalNow := networkRecoveryNowFn
	originalGrace := networkRecoveryGracePeriod
	originalLoadSnapshot := loadRecoverySnapshotFn
	originalRecordHistory := recordNetworkApplyHistoryFn
	defer func() {
		networkRecoveryNowFn = originalNow
		networkRecoveryGracePeriod = originalGrace
		loadRecoverySnapshotFn = originalLoadSnapshot
		recordNetworkApplyHistoryFn = originalRecordHistory
		resetNetworkRecoveryRuntime()
	}()

	baseTime := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	networkRecoveryNowFn = func() time.Time { return baseTime }
	networkRecoveryGracePeriod = 2 * time.Minute
	loadRecoverySnapshotFn = func(cfg *config.Config, id string) (network.Snapshot, error) {
		return network.Snapshot{ID: id}, nil
	}

	require.NoError(t, StartNetworkRecoveryMonitor(cfg, zap.NewNop()))

	state, err := StartPendingNetworkRecovery(cfg, "backup-123", network.ApplyRiskAssessment{
		RequiresConfirmation: true,
		Summary:              "WAN address change",
	}, network.ValidationReport{Healthy: true}, "tester")
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.True(t, state.Pending)
	assert.Equal(t, "backup-123", state.BackupID)
	assert.Equal(t, "pending", state.Status)

	pending, err := CurrentNetworkRecoveryState()
	require.NoError(t, err)
	require.NotNil(t, pending)
	assert.True(t, pending.Pending)
	assert.Equal(t, "backup-123", pending.BackupID)
	assert.Equal(t, int((2 * time.Minute).Seconds()), pending.GracePeriodSeconds)

	confirmed, err := ConfirmPendingNetworkRecovery("backup-123", "ops-admin")
	require.NoError(t, err)
	require.NotNil(t, confirmed)
	assert.False(t, confirmed.Pending)
	assert.Equal(t, "ok", confirmed.Status)
	assert.Equal(t, "ops-admin", confirmed.ConfirmedBy)
	assert.NotEmpty(t, confirmed.ConfirmedAt)
}

func TestStartNetworkRecoveryMonitorResumesAndAutoRollsBackPendingState(t *testing.T) {
	cfg := testNetworkRecoveryConfig(t)

	originalNow := networkRecoveryNowFn
	originalGrace := networkRecoveryGracePeriod
	originalLoadSnapshot := loadRecoverySnapshotFn
	originalRestoreSnapshot := restoreNetworkSnapshotFn
	defer func() {
		networkRecoveryNowFn = originalNow
		networkRecoveryGracePeriod = originalGrace
		loadRecoverySnapshotFn = originalLoadSnapshot
		restoreNetworkSnapshotFn = originalRestoreSnapshot
		resetNetworkRecoveryRuntime()
	}()

	networkRecoveryNowFn = time.Now
	networkRecoveryGracePeriod = 50 * time.Millisecond

	restoreCalled := make(chan string, 1)
	loadRecoverySnapshotFn = func(cfg *config.Config, id string) (network.Snapshot, error) {
		return network.Snapshot{ID: id}, nil
	}
	restoreNetworkSnapshotFn = func(cfg *config.Config, snapshot network.Snapshot) error {
		restoreCalled <- snapshot.ID
		return nil
	}

	details := map[string]any{
		"pending":              true,
		"backup_id":            "backup-auto",
		"deadline":             time.Now().Add(50 * time.Millisecond).UTC().Format(time.RFC3339),
		"grace_period_seconds": 1,
		"risk_summary":         "LAN address change",
		"validation_summary":   "all validation checks passed",
		"requested_by":         "tester",
	}
	require.NoError(t, db.UpsertRuntimeStatus(networkRecoveryComponent, "pending", "Awaiting management confirmation.", details))

	require.NoError(t, StartNetworkRecoveryMonitor(cfg, zap.NewNop()))

	select {
	case backupID := <-restoreCalled:
		assert.Equal(t, "backup-auto", backupID)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for auto rollback")
	}

	state, err := CurrentNetworkRecoveryState()
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.False(t, state.Pending)
	assert.Equal(t, "degraded", state.Status)
	assert.Contains(t, state.Message, "rolled back automatically")
}

func testNetworkRecoveryConfig(t *testing.T) *config.Config {
	t.Helper()

	tmpfile, err := os.CreateTemp("", "network-recovery-*.db")
	require.NoError(t, err)
	require.NoError(t, tmpfile.Close())
	t.Cleanup(func() {
		_ = os.Remove(tmpfile.Name())
	})

	require.NoError(t, db.Init(tmpfile.Name()))
	t.Cleanup(func() {
		db.Close()
	})
	require.NoError(t, db.Migrate())

	cfg := &config.Config{}
	cfg.Database.Path = tmpfile.Name()
	return cfg
}

func resetNetworkRecoveryRuntime() {
	networkRecoveryMu.Lock()
	defer networkRecoveryMu.Unlock()
	if networkRecoveryTimer != nil {
		networkRecoveryTimer.Stop()
		networkRecoveryTimer = nil
	}
	networkRecoveryCfg = nil
	networkRecoveryLogger = zap.NewNop()
}
