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

func TestPreviewWiMAXServiceFlowsBuildsServiceFlowPlan(t *testing.T) {
	cfg, cleanup := loadWiMAXServiceFlowTestConfig(t)
	defer cleanup()

	report, err := PreviewWiMAXServiceFlows(cfg)
	require.NoError(t, err)
	assert.Equal(t, WiMAXServiceFlowFeatureID, report.FeatureID)
	assert.Equal(t, "ready", report.Status)
	assert.Equal(t, 100.0, report.SoftwareCompletionPercent)
	assert.True(t, report.ReadyForExternalValidation)
	assert.GreaterOrEqual(t, report.Summary.SubscriberProfileCount, 2)
	assert.GreaterOrEqual(t, report.Summary.ServiceFlowCount, 3)
	assert.GreaterOrEqual(t, report.Summary.ASNProfileCount, 2)
	assert.GreaterOrEqual(t, report.Summary.MobilityPolicyCount, 2)
	assert.Greater(t, report.Summary.RadiusAttributeCount, 0)
	assert.GreaterOrEqual(t, report.Summary.ProcessingStepCount, 6)
	assert.Equal(t, report.Summary.ComplianceCheckCount, report.Summary.PassedCheckCount)
	assert.Empty(t, report.Blockers)
	assert.NotEmpty(t, report.PlanFingerprint)
	assert.Contains(t, report.RadiusAttributes, "WiMAX-QoS-Descriptor")
	assert.Contains(t, report.RadiusAttributes, "WiMAX-Service-Flow-ID")
	assert.Contains(t, report.RadiusAttributes, "WiMAX-Packet-Flow-Descriptor")
	assert.Equal(t, report.RadiusAttributes, sortedCopy(report.RadiusAttributes))
}

func TestPreviewWiMAXServiceFlowsBlocksUnsafeSubscriberPrivacy(t *testing.T) {
	cfg, cleanup := loadWiMAXServiceFlowTestConfig(t)
	defer cleanup()
	cfg.Mobile.WiMAX.HashSubscriberIDs = false

	report, err := PreviewWiMAXServiceFlows(cfg)
	require.NoError(t, err)
	assert.Equal(t, "blocked", report.Status)
	assert.Contains(t, strings.Join(report.Blockers, "\n"), "Subscriber redaction")
}

func TestApplyWiMAXServiceFlowsRecordsEvidenceAndRuntimeStatus(t *testing.T) {
	cfg, cleanup := loadWiMAXServiceFlowTestConfig(t)
	defer cleanup()

	report, eventID, err := ApplyWiMAXServiceFlows(context.Background(), cfg, "ops@example.test")
	require.NoError(t, err)
	assert.Equal(t, "ready", report.Status)
	assert.NotEmpty(t, eventID)

	events, err := db.ListWiMAXServiceFlowEvents(10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "applied", events[0].Status)
	assert.GreaterOrEqual(t, events[0].SubscriberProfileCount, 2)
	assert.GreaterOrEqual(t, events[0].ServiceFlowCount, 3)
	assert.GreaterOrEqual(t, events[0].ASNProfileCount, 2)
	assert.GreaterOrEqual(t, events[0].MobilityPolicyCount, 2)
	assert.Greater(t, events[0].RadiusAttributeCount, 0)

	profiles, err := db.ListWiMAXServiceFlowProfiles(20, "")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(profiles), 9)

	summary, err := db.GetWiMAXServiceFlowSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.ApplyEvents)
	assert.GreaterOrEqual(t, summary.ReadyProfileCount, 9)
	assert.Equal(t, events[0].PlanFingerprint, summary.LastFingerprint)

	runtime, err := db.GetRuntimeStatus(WiMAXServiceFlowComponent())
	require.NoError(t, err)
	require.NotNil(t, runtime)
	assert.Equal(t, "ok", runtime.Status)
	assert.Contains(t, strings.ToLower(runtime.Message), "wimax")
	assert.Contains(t, strings.ToLower(runtime.Message), "service-flow")
}

func loadWiMAXServiceFlowTestConfig(t *testing.T) (*config.Config, func()) {
	t.Helper()
	cfg, cleanup := loadMobilePolicyControlTestConfig(t)
	cfg.Mobile.WiMAX = config.MobileWiMAXConfig{
		Enabled:             true,
		Mode:                "enforce",
		FailClosed:          true,
		RedactSubscriberIDs: true,
		HashSubscriberIDs:   true,
	}
	return cfg, cleanup
}
