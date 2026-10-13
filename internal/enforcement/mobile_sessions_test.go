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

func TestPreviewMobileSessionsBuildsTelecomStatePlan(t *testing.T) {
	cfg := loadMobileSessionTestConfig()

	report, err := PreviewMobileSessions(cfg)
	require.NoError(t, err)
	assert.Equal(t, MobileSessionFeatureID, report.FeatureID)
	assert.Equal(t, "ready", report.Status)
	assert.Equal(t, 100.0, report.SoftwareCompletionPercent)
	assert.True(t, report.ReadyForExternalValidation)
	assert.GreaterOrEqual(t, report.Summary.APNProfileCount, 2)
	assert.GreaterOrEqual(t, report.Summary.BearerTemplateCount, 2)
	assert.GreaterOrEqual(t, report.Summary.RoamingPartnerCount, 2)
	assert.GreaterOrEqual(t, report.Summary.StateStepCount, 6)
	assert.Greater(t, report.Summary.RadiusAttributeCount, 0)
	assert.Equal(t, report.Summary.ComplianceCheckCount, report.Summary.PassedCheckCount)
	assert.Empty(t, report.Blockers)
	assert.NotEmpty(t, report.PlanFingerprint)
	assert.Contains(t, report.RadiusAttributes, "3GPP-IMSI")
	assert.Contains(t, report.RadiusAttributes, "Framed-IPv6-Prefix")
	assert.Equal(t, report.RadiusAttributes, sortedCopy(report.RadiusAttributes))
}

func TestPreviewMobileSessionsBlocksUnsafeSubscriberPrivacy(t *testing.T) {
	cfg := loadMobileSessionTestConfig()
	cfg.Mobile.Sessions.HashSubscriberIDs = false

	report, err := PreviewMobileSessions(cfg)
	require.NoError(t, err)
	assert.Equal(t, "blocked", report.Status)
	assert.Contains(t, strings.Join(report.Blockers, "\n"), "Subscriber redaction")
}

func TestApplyMobileSessionsRecordsEvidenceAndRuntimeStatus(t *testing.T) {
	cfg := loadMobileSessionTestConfig()
	previousDB := db.DB
	require.NoError(t, db.Init(":memory:"))
	db.DB.SetMaxOpenConns(1)
	require.NoError(t, db.Migrate())
	t.Cleanup(func() {
		_ = db.Close()
		db.DB = previousDB
	})

	report, eventID, err := ApplyMobileSessions(context.Background(), cfg, "ops@example.test")
	require.NoError(t, err)
	assert.Equal(t, "ready", report.Status)
	assert.NotEmpty(t, eventID)

	events, err := db.ListMobileSessionEvents(10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "applied", events[0].Status)
	assert.GreaterOrEqual(t, events[0].APNProfileCount, 2)
	assert.GreaterOrEqual(t, events[0].BearerTemplateCount, 2)
	assert.GreaterOrEqual(t, events[0].RoamingPartnerCount, 2)
	assert.Greater(t, events[0].RadiusAttributeCount, 0)

	profiles, err := db.ListMobileSessionProfiles(10, "apn")
	require.NoError(t, err)
	require.NotEmpty(t, profiles)

	summary, err := db.GetMobileSessionSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.ApplyEvents)
	assert.GreaterOrEqual(t, summary.ReadyProfileCount, 6)

	runtime, err := db.GetRuntimeStatus(MobileSessionComponent())
	require.NoError(t, err)
	require.NotNil(t, runtime)
	assert.Equal(t, "ok", runtime.Status)
	assert.Contains(t, strings.ToLower(runtime.Message), "mobile")
}

func loadMobileSessionTestConfig() *config.Config {
	return &config.Config{
		Deployment: config.DeploymentConfig{Profile: "enterprise"},
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
		},
	}
}

func sortedCopy(values []string) []string {
	out := append([]string(nil), values...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
