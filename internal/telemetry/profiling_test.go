package telemetry

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/onboarding"
	"go.uber.org/zap"
)

type fakeProfilingRuntimeService struct {
	mdmStats     *onboarding.ComplianceSyncStats
	mdmErr       error
	postureStats *onboarding.ComplianceSyncStats
	postureErr   error
}

func (f *fakeProfilingRuntimeService) SyncFromMDM(ctx context.Context) (*onboarding.ComplianceSyncStats, error) {
	return f.mdmStats, f.mdmErr
}

func (f *fakeProfilingRuntimeService) SyncFromComplianceWebhook(ctx context.Context) (*onboarding.ComplianceSyncStats, error) {
	return f.postureStats, f.postureErr
}

func TestRunProfilingRuntimeCycleRecordsIntegrationHistory(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "profiling-runtime-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	require.NoError(t, tmpfile.Close())

	require.NoError(t, db.Init(tmpfile.Name()))
	defer db.Close()
	require.NoError(t, db.Migrate())

	origFactory := newProfilingRuntimeService
	newProfilingRuntimeService = func(cfg *config.Config, logger *zap.Logger) profilingRuntimeService {
		return &fakeProfilingRuntimeService{
			mdmStats: &onboarding.ComplianceSyncStats{
				Source:              "mdm",
				Provider:            "intune",
				TotalRecords:        5,
				ManagedRecords:      4,
				CompliantRecords:    3,
				NonCompliantRecords: 1,
				UnknownRecords:      1,
				RemediationRecords:  1,
			},
			postureStats: &onboarding.ComplianceSyncStats{
				Source:              "compliance-webhook",
				Provider:            "workspace-one",
				TotalRecords:        2,
				ManagedRecords:      2,
				CompliantRecords:    2,
				NonCompliantRecords: 0,
				UnknownRecords:      0,
				RemediationRecords:  0,
			},
		}
	}
	t.Cleanup(func() {
		newProfilingRuntimeService = origFactory
	})

	cfg := &config.Config{}
	cfg.Telemetry.Enabled = true
	cfg.Profiling.PassiveEnabled = true
	cfg.Profiling.MDMSyncEnabled = true
	cfg.Profiling.PostureEnabled = true
	cfg.Profiling.MDMProvider = "intune"
	cfg.Profiling.ComplianceWebhook = "https://compliance.example.test/hook"

	runProfilingRuntimeCycle(context.Background(), cfg, zap.NewNop(), newProfilingRuntimeService(cfg, zap.NewNop()))

	mdmHistory, err := db.ListIntegrationHistory("mdm_sync", 10)
	require.NoError(t, err)
	require.NotEmpty(t, mdmHistory)
	assert.Equal(t, "ok", mdmHistory[0].Status)
	assert.Contains(t, mdmHistory[0].Summary, "MDM sync completed successfully")

	postureHistory, err := db.ListIntegrationHistory("posture_checks", 10)
	require.NoError(t, err)
	require.NotEmpty(t, postureHistory)
	assert.Equal(t, "ok", postureHistory[0].Status)
}
