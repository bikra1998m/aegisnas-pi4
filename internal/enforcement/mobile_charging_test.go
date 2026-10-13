package enforcement

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestPreviewMobileChargingBuildsCorrelationPlan(t *testing.T) {
	cfg, cleanup := loadMobileChargingTestConfig(t)
	defer cleanup()

	report, err := PreviewMobileCharging(cfg)
	require.NoError(t, err)
	assert.Equal(t, MobileChargingFeatureID, report.FeatureID)
	assert.Equal(t, "ready", report.Status)
	assert.Equal(t, 100.0, report.SoftwareCompletionPercent)
	assert.True(t, report.ReadyForExternalValidation)
	assert.GreaterOrEqual(t, report.Summary.StreamCount, 3)
	assert.GreaterOrEqual(t, report.Summary.RatingGroupCount, 2)
	assert.GreaterOrEqual(t, report.Summary.QuotaPolicyCount, 2)
	assert.Greater(t, report.Summary.CorrelationAttributeCount, 0)
	assert.GreaterOrEqual(t, report.Summary.MediationReferenceCount, 4)
	assert.GreaterOrEqual(t, report.Summary.CorrelationStepCount, 5)
	assert.Equal(t, report.Summary.ComplianceCheckCount, report.Summary.PassedCheckCount)
	assert.Empty(t, report.Blockers)
	assert.NotEmpty(t, report.PlanFingerprint)
	assert.Contains(t, report.RadiusAttributes, "3GPP-Charging-ID")
	assert.Contains(t, report.RadiusAttributes, "Acct-Input-Gigawords")
	assert.Contains(t, report.RadiusAttributes, "3GPP2-Prepaid-Quota-Identifier")
	assert.Equal(t, report.RadiusAttributes, sortedCopy(report.RadiusAttributes))
}

func TestPreviewMobileChargingBlocksUnsafeSubscriberPrivacy(t *testing.T) {
	cfg, cleanup := loadMobileChargingTestConfig(t)
	defer cleanup()
	cfg.Mobile.Charging.HashSubscriberIDs = false

	report, err := PreviewMobileCharging(cfg)
	require.NoError(t, err)
	assert.Equal(t, "blocked", report.Status)
	assert.Contains(t, strings.Join(report.Blockers, "\n"), "Subscriber redaction")
}

func TestApplyMobileChargingRecordsEvidenceAndRuntimeStatus(t *testing.T) {
	cfg, cleanup := loadMobileChargingTestConfig(t)
	defer cleanup()

	report, eventID, err := ApplyMobileCharging(context.Background(), cfg, "ops@example.test")
	require.NoError(t, err)
	assert.Equal(t, "ready", report.Status)
	assert.NotEmpty(t, eventID)

	events, err := db.ListMobileChargingEvents(10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "applied", events[0].Status)
	assert.GreaterOrEqual(t, events[0].StreamCount, 3)
	assert.GreaterOrEqual(t, events[0].RatingGroupCount, 2)
	assert.GreaterOrEqual(t, events[0].QuotaPolicyCount, 2)
	assert.Greater(t, events[0].CorrelationAttributeCount, 0)
	assert.GreaterOrEqual(t, events[0].MediationReferenceCount, 4)

	profiles, err := db.ListMobileChargingProfiles(10, "")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(profiles), 7)

	summary, err := db.GetMobileChargingSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.ApplyEvents)
	assert.GreaterOrEqual(t, summary.ReadyProfileCount, 7)
	assert.Equal(t, events[0].PlanFingerprint, summary.LastFingerprint)

	runtime, err := db.GetRuntimeStatus(MobileChargingComponent())
	require.NoError(t, err)
	require.NotNil(t, runtime)
	assert.Equal(t, "ok", runtime.Status)
	assert.Contains(t, strings.ToLower(runtime.Message), "online quota")
	assert.Contains(t, strings.ToLower(runtime.Message), "cdr")
}

func loadMobileChargingTestConfig(t *testing.T) (*config.Config, func()) {
	t.Helper()
	previousDB := db.DB
	require.NoError(t, db.Init(":memory:"))
	db.DB.SetMaxOpenConns(1)
	require.NoError(t, db.Migrate())
	cleanup := func() {
		_ = db.Close()
		db.DB = previousDB
	}
	cfg := &config.Config{
		Deployment: config.DeploymentConfig{Profile: "enterprise"},
		Radius: config.RadiusConfig{AccountingCharging: config.RadiusAccountingChargingConfig{
			Enabled:       true,
			RatingEnabled: true,
			ExportEnabled: true,
		}},
		Mobile: config.MobileConfig{
			GroupedAVPs: config.MobileGroupedAVPConfig{
				Enabled:         true,
				Mode:            "enforce",
				FailClosed:      true,
				SafeRawEvidence: true,
				HashRawValues:   true,
			},
			Sessions: config.MobileSessionConfig{
				Enabled:             true,
				Mode:                "enforce",
				FailClosed:          true,
				StateReconciliation: true,
				HandoverTracking:    true,
				RoamingTracking:     true,
				RedactSubscriberIDs: true,
				HashSubscriberIDs:   true,
			},
			Charging: config.MobileChargingConfig{
				Enabled:                   true,
				Mode:                      "enforce",
				FailClosed:                true,
				RequireDatabase:           true,
				RequireMobileSessions:     true,
				RequireAccountingCharging: true,
				RequireOnlineCharging:     true,
				RequireOfflineCharging:    true,
				RequireMediation:          true,
				QuotaCorrelation:          true,
				RedactSubscriberIDs:       true,
				HashSubscriberIDs:         true,
			},
		},
	}
	return cfg, cleanup
}
