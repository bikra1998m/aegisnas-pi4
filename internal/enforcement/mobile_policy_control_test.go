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

func TestPreviewMobilePolicyControlBuildsPolicyPlan(t *testing.T) {
	cfg, cleanup := loadMobilePolicyControlTestConfig(t)
	defer cleanup()

	report, err := PreviewMobilePolicyControl(cfg)
	require.NoError(t, err)
	assert.Equal(t, MobilePolicyControlFeatureID, report.FeatureID)
	assert.Equal(t, "ready", report.Status)
	assert.Equal(t, 100.0, report.SoftwareCompletionPercent)
	assert.True(t, report.ReadyForExternalValidation)
	assert.GreaterOrEqual(t, report.Summary.PolicyProfileCount, 3)
	assert.GreaterOrEqual(t, report.Summary.QoSClassCount, 3)
	assert.GreaterOrEqual(t, report.Summary.RoamingPolicyCount, 2)
	assert.GreaterOrEqual(t, report.Summary.FeedbackRuleCount, 2)
	assert.Greater(t, report.Summary.PolicyAttributeCount, 0)
	assert.GreaterOrEqual(t, report.Summary.ControlStepCount, 6)
	assert.Equal(t, report.Summary.ComplianceCheckCount, report.Summary.PassedCheckCount)
	assert.Empty(t, report.Blockers)
	assert.NotEmpty(t, report.PlanFingerprint)
	assert.Contains(t, report.RadiusAttributes, "3GPP-Negotiated-DSCP")
	assert.Contains(t, report.RadiusAttributes, "WiMAX-QoS-Descriptor")
	assert.Contains(t, report.RadiusAttributes, "Ericsson-QoS-Profile")
	assert.Equal(t, report.RadiusAttributes, sortedCopy(report.RadiusAttributes))
}

func TestPreviewMobilePolicyControlBlocksUnsafeSubscriberPrivacy(t *testing.T) {
	cfg, cleanup := loadMobilePolicyControlTestConfig(t)
	defer cleanup()
	cfg.Mobile.PolicyControl.HashSubscriberIDs = false

	report, err := PreviewMobilePolicyControl(cfg)
	require.NoError(t, err)
	assert.Equal(t, "blocked", report.Status)
	assert.Contains(t, strings.Join(report.Blockers, "\n"), "Subscriber redaction")
}

func TestApplyMobilePolicyControlRecordsEvidenceAndRuntimeStatus(t *testing.T) {
	cfg, cleanup := loadMobilePolicyControlTestConfig(t)
	defer cleanup()

	report, eventID, err := ApplyMobilePolicyControl(context.Background(), cfg, "ops@example.test")
	require.NoError(t, err)
	assert.Equal(t, "ready", report.Status)
	assert.NotEmpty(t, eventID)

	events, err := db.ListMobilePolicyControlEvents(10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "applied", events[0].Status)
	assert.GreaterOrEqual(t, events[0].PolicyProfileCount, 3)
	assert.GreaterOrEqual(t, events[0].QoSClassCount, 3)
	assert.GreaterOrEqual(t, events[0].RoamingPolicyCount, 2)
	assert.GreaterOrEqual(t, events[0].FeedbackRuleCount, 2)
	assert.Greater(t, events[0].PolicyAttributeCount, 0)

	profiles, err := db.ListMobilePolicyControlProfiles(20, "")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(profiles), 10)

	summary, err := db.GetMobilePolicyControlSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.ApplyEvents)
	assert.GreaterOrEqual(t, summary.ReadyProfileCount, 10)
	assert.Equal(t, events[0].PlanFingerprint, summary.LastFingerprint)

	runtime, err := db.GetRuntimeStatus(MobilePolicyControlComponent())
	require.NoError(t, err)
	require.NotNil(t, runtime)
	assert.Equal(t, "ok", runtime.Status)
	assert.Contains(t, strings.ToLower(runtime.Message), "policy")
	assert.Contains(t, strings.ToLower(runtime.Message), "roaming")
}

func loadMobilePolicyControlTestConfig(t *testing.T) (*config.Config, func()) {
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
		Policy: config.PolicyConfig{
			TypedEngineEnabled:    true,
			RuntimeShapingEnabled: true,
		},
		Radius: config.RadiusConfig{
			AccountingCharging: config.RadiusAccountingChargingConfig{
				Enabled:       true,
				RatingEnabled: true,
				ExportEnabled: true,
			},
			DynamicAuth: config.DynamicAuthConfig{
				Enabled:         true,
				OutboundEnabled: true,
			},
		},
		Broadband: config.BroadbandConfig{
			QoSServiceFlows: config.BroadbandQoSServiceFlowConfig{Enabled: true},
		},
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
			PolicyControl: config.MobilePolicyControlConfig{
				Enabled:             true,
				Mode:                "enforce",
				FailClosed:          true,
				RedactSubscriberIDs: true,
				HashSubscriberIDs:   true,
			},
		},
	}
	return cfg, cleanup
}
