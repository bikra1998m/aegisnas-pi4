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

func TestPreviewMobileGroupedAVPsBuildsTelecomPlan(t *testing.T) {
	cfg := loadMobileGroupedAVPTestConfig()

	report, err := PreviewMobileGroupedAVPs(cfg)
	require.NoError(t, err)
	assert.Equal(t, MobileGroupedAVPFeatureID, report.FeatureID)
	assert.Equal(t, "ready", report.Status)
	assert.Equal(t, 100.0, report.SoftwareCompletionPercent)
	assert.True(t, report.ReadyForExternalValidation)
	assert.GreaterOrEqual(t, report.Summary.VendorScopeCount, 5)
	assert.Greater(t, report.Summary.GroupedAttributeCount, 0)
	assert.Greater(t, report.Summary.CompiledAttributeCount, 0)
	assert.Equal(t, report.Summary.ComplianceCheckCount, report.Summary.PassedCheckCount)
	assert.Empty(t, report.Blockers)
	assert.NotEmpty(t, report.PlanFingerprint)
	assert.Contains(t, mobileGroupedAVPScopeVendors(report.VendorScopes), "3GPP")
	assert.Contains(t, mobileGroupedAVPScopeVendors(report.VendorScopes), "WiMAX")
}

func TestPreviewMobileGroupedAVPsBlocksUnsafeRawEvidence(t *testing.T) {
	cfg := loadMobileGroupedAVPTestConfig()
	cfg.Mobile.GroupedAVPs.HashRawValues = false

	report, err := PreviewMobileGroupedAVPs(cfg)
	require.NoError(t, err)
	assert.Equal(t, "blocked", report.Status)
	assert.Contains(t, strings.Join(report.Blockers, "\n"), "hash_raw_values")
}

func TestApplyMobileGroupedAVPsRecordsEvidenceAndRuntimeStatus(t *testing.T) {
	cfg := loadMobileGroupedAVPTestConfig()
	previousDB := db.DB
	require.NoError(t, db.Init(":memory:"))
	db.DB.SetMaxOpenConns(1)
	require.NoError(t, db.Migrate())
	t.Cleanup(func() {
		_ = db.Close()
		db.DB = previousDB
	})

	report, eventID, err := ApplyMobileGroupedAVPs(context.Background(), cfg, "ops@example.test")
	require.NoError(t, err)
	assert.Equal(t, "ready", report.Status)
	assert.NotEmpty(t, eventID)

	events, err := db.ListMobileGroupedAVPEvents(10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "applied", events[0].Status)
	assert.GreaterOrEqual(t, events[0].VendorScopeCount, 5)
	assert.Greater(t, events[0].GroupedAttributeCount, 0)

	scopes, err := db.ListMobileGroupedAVPScopes(10, "ready")
	require.NoError(t, err)
	require.NotEmpty(t, scopes)

	runtime, err := db.GetRuntimeStatus(MobileGroupedAVPComponent())
	require.NoError(t, err)
	require.NotNil(t, runtime)
	assert.Equal(t, "ok", runtime.Status)
	assert.Contains(t, strings.ToLower(runtime.Message), "telecom")
}

func loadMobileGroupedAVPTestConfig() *config.Config {
	return &config.Config{
		Deployment: config.DeploymentConfig{Profile: "enterprise"},
		Mobile: config.MobileConfig{GroupedAVPs: config.MobileGroupedAVPConfig{
			Enabled:         true,
			Mode:            "enforce",
			FailClosed:      true,
			SafeRawEvidence: true,
			HashRawValues:   true,
		}},
	}
}

func mobileGroupedAVPScopeVendors(scopes []MobileGroupedAVPScope) []string {
	values := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		values = append(values, scope.Vendor)
	}
	return values
}
