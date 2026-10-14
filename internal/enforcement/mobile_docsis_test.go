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

func TestPreviewDOCSISPolicyBuildsCablePlan(t *testing.T) {
	cfg, cleanup := loadDOCSISPolicyTestConfig(t)
	defer cleanup()

	report, err := PreviewDOCSISPolicy(cfg)
	require.NoError(t, err)
	assert.Equal(t, DOCSISPolicyFeatureID, report.FeatureID)
	assert.Equal(t, "ready", report.Status)
	assert.Equal(t, 100.0, report.SoftwareCompletionPercent)
	assert.True(t, report.ReadyForExternalValidation)
	assert.GreaterOrEqual(t, report.Summary.ModemProfileCount, 2)
	assert.GreaterOrEqual(t, report.Summary.ServiceFlowCount, 3)
	assert.GreaterOrEqual(t, report.Summary.CMTSProfileCount, 2)
	assert.GreaterOrEqual(t, report.Summary.ChargingPolicyCount, 2)
	assert.True(t, report.Summary.QoSServiceFlowEnabled)
	assert.Greater(t, report.Summary.RadiusAttributeCount, 0)
	assert.GreaterOrEqual(t, report.Summary.ProcessingStepCount, 6)
	assert.Equal(t, report.Summary.ComplianceCheckCount, report.Summary.PassedCheckCount)
	assert.Empty(t, report.Blockers)
	assert.NotEmpty(t, report.PlanFingerprint)
	assert.Contains(t, report.RadiusAttributes, "CableLabs-QoS-Descriptor")
	assert.Contains(t, report.RadiusAttributes, "CableLabs-SF-ID")
	assert.Contains(t, report.RadiusAttributes, "CableLabs-Policy-Decision-Status")
	assert.Equal(t, report.RadiusAttributes, sortedCopy(report.RadiusAttributes))
}

func TestPreviewDOCSISPolicyBlocksUnsafeDevicePrivacy(t *testing.T) {
	cfg, cleanup := loadDOCSISPolicyTestConfig(t)
	defer cleanup()
	cfg.Mobile.DOCSIS.HashDeviceIDs = false

	report, err := PreviewDOCSISPolicy(cfg)
	require.NoError(t, err)
	assert.Equal(t, "blocked", report.Status)
	assert.Contains(t, strings.Join(report.Blockers, "\n"), "Device redaction")
}

func TestApplyDOCSISPolicyRecordsEvidenceAndRuntimeStatus(t *testing.T) {
	cfg, cleanup := loadDOCSISPolicyTestConfig(t)
	defer cleanup()

	report, eventID, err := ApplyDOCSISPolicy(context.Background(), cfg, "ops@example.test")
	require.NoError(t, err)
	assert.Equal(t, "ready", report.Status)
	assert.NotEmpty(t, eventID)

	events, err := db.ListDOCSISPolicyEvents(10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "applied", events[0].Status)
	assert.GreaterOrEqual(t, events[0].ModemProfileCount, 2)
	assert.GreaterOrEqual(t, events[0].ServiceFlowCount, 3)
	assert.GreaterOrEqual(t, events[0].CMTSProfileCount, 2)
	assert.GreaterOrEqual(t, events[0].ChargingPolicyCount, 2)
	assert.Greater(t, events[0].RadiusAttributeCount, 0)

	profiles, err := db.ListDOCSISPolicyProfiles(20, "")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(profiles), 9)

	summary, err := db.GetDOCSISPolicySummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.ApplyEvents)
	assert.GreaterOrEqual(t, summary.ReadyProfileCount, 9)
	assert.Equal(t, events[0].PlanFingerprint, summary.LastFingerprint)

	runtime, err := db.GetRuntimeStatus(DOCSISPolicyComponent())
	require.NoError(t, err)
	require.NotNil(t, runtime)
	assert.Equal(t, "ok", runtime.Status)
	assert.Contains(t, strings.ToLower(runtime.Message), "docsis")
}

func loadDOCSISPolicyTestConfig(t *testing.T) (*config.Config, func()) {
	t.Helper()
	cfg, cleanup := loadWiMAXServiceFlowTestConfig(t)
	cfg.Broadband.QoSServiceFlows.Enabled = true
	cfg.Mobile.DOCSIS = config.MobileDOCSISConfig{
		Enabled:         true,
		Mode:            "enforce",
		FailClosed:      true,
		RedactDeviceIDs: true,
		HashDeviceIDs:   true,
	}
	return cfg, cleanup
}
