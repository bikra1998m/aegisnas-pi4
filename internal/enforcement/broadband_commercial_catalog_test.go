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

func TestPreviewBroadbandCommercialCatalogBuildsFullPlan(t *testing.T) {
	cfg := loadBroadbandCommercialCatalogTestConfig(t)

	report, err := PreviewBroadbandCommercialCatalog(cfg)
	require.NoError(t, err)

	assert.Equal(t, BroadbandCommercialCatalogFeatureID, report.FeatureID)
	assert.Equal(t, "ready", report.Status, "blockers: %v warnings: %v", report.Blockers, report.Warnings)
	assert.True(t, report.ReadyForExternalValidation)
	assert.Equal(t, float64(100), report.SoftwareCompletionPercent)
	assert.Equal(t, "enforce", report.Summary.Mode)
	assert.Equal(t, 1, report.Summary.AccountCount)
	assert.Equal(t, 1, report.Summary.EnabledPlanCount)
	assert.Equal(t, 1, report.Summary.EnabledBundleCount)
	assert.Equal(t, 1, report.Summary.ActiveSubscriptionCount)
	assert.Equal(t, 1, report.Summary.EnabledConcurrencyPolicyCount)
	assert.Equal(t, report.Summary.ComplianceCheckCount, report.Summary.PassedCheckCount)
	assert.NotEmpty(t, report.PlanFingerprint)
	assert.Contains(t, report.ReleaseCertificationChecklist, "nas-0084")
	require.NotEmpty(t, report.AuthorizationBindings)
	assert.Contains(t, strings.Join(report.AuthorizationBindings[1].Attributes, " "), "Cisco-AVPair")
}

func TestPreviewBroadbandCommercialCatalogBlocksUnsafeConfig(t *testing.T) {
	cfg := loadBroadbandCommercialCatalogTestConfig(t)
	cfg.Radius.DynamicAuth.Enabled = false

	report, err := PreviewBroadbandCommercialCatalog(cfg)
	require.NoError(t, err)

	assert.Equal(t, "blocked", report.Status)
	assert.False(t, report.ReadyForExternalValidation)
	assert.Contains(t, strings.Join(report.Blockers, " "), "coa_on_limit")
}

func TestPreviewBroadbandCommercialCatalogSkippedWhenDisabled(t *testing.T) {
	cfg := loadBroadbandCommercialCatalogTestConfig(t)
	cfg.Broadband.CommercialCatalog.Enabled = false

	report, err := PreviewBroadbandCommercialCatalog(cfg)
	require.NoError(t, err)

	assert.Equal(t, "skipped", report.Status)
	assert.True(t, report.ReadyForExternalValidation)
	assert.False(t, report.Summary.Enabled)
	assert.NotEmpty(t, report.Plans)
	assert.NotEmpty(t, report.PlanFingerprint)
}

func TestApplyBroadbandCommercialCatalogRecordsEvidenceAndRuntimeStatus(t *testing.T) {
	cfg := loadBroadbandCommercialCatalogTestConfig(t)
	previousDB := db.DB
	require.NoError(t, db.Init(":memory:"))
	db.DB.SetMaxOpenConns(1)
	require.NoError(t, db.Migrate())
	t.Cleanup(func() {
		_ = db.Close()
		db.DB = previousDB
	})

	report, eventID, err := ApplyBroadbandCommercialCatalog(context.Background(), cfg, "ops@example.test")
	require.NoError(t, err)

	assert.Equal(t, "applied", report.Status)
	assert.NotEmpty(t, eventID)

	events, err := db.ListBroadbandCommercialCatalogEvents(10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "apply", events[0].Operation)
	assert.Equal(t, "applied", events[0].Status)
	assert.Equal(t, 1, events[0].PlanCount)

	plans, err := db.ListBroadbandCommercialPlans(10)
	require.NoError(t, err)
	require.Len(t, plans, 1)
	assert.Equal(t, "fiber-100m", plans[0].Name)

	runtime, err := db.GetRuntimeStatus(BroadbandCommercialCatalogComponent())
	require.NoError(t, err)
	require.NotNil(t, runtime)
	assert.Equal(t, "ok", runtime.Status)
	assert.Contains(t, runtime.Message, "NAS-0084")
}

func loadBroadbandCommercialCatalogTestConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := loadBroadbandSubscriberStateTestConfig(t, "")
	cfg.Broadband.CommercialCatalog = config.BroadbandCommercialCatalog{
		Enabled:                       true,
		Mode:                          "enforce",
		FailClosed:                    true,
		DefaultBillingPeriod:          "monthly",
		DefaultCurrency:               "USD",
		AllowFamilyAccounts:           true,
		RequireActiveSubscription:     true,
		RequireBundleEligibility:      true,
		EnforceConcurrency:            true,
		AccountingCorrelationRequired: true,
		CoAOnLimit:                    true,
		MaxAccounts:                   100000,
		MaxSubscriptions:              250000,
		MaxSessionsPerAccount:         8,
		MaxSessionsPerSubscription:    4,
		EventRetentionLimit:           10000,
		Accounts: []config.BroadbandCommercialAccountConfig{
			{AccountID: "acct-lab-1", Tenant: "retail", Status: "active", BillingMode: "postpaid", OwnerName: "Lab Account", Contact: "noc@example.net", MaxSubscriptions: 4, MaxSessions: 8, Tags: []string{"lab", "retail"}},
		},
		Plans: []config.BroadbandCommercialPlanConfig{
			{Name: "fiber-100m", Enabled: true, Product: "residential-fiber", DisplayName: "Fiber 100M", BillingPeriod: "monthly", PriceMicros: 49990000, Currency: "USD", MaxSessions: 4, MaxDevices: 32, DownstreamKbps: 100000, UpstreamKbps: 25000, VendorPacks: []string{"standard", "aegisnas", "mikrotik", "huawei"}},
		},
		Bundles: []config.BroadbandCommercialBundleConfig{
			{Name: "home-internet", Enabled: true, DisplayName: "Home Internet", Plans: []string{"fiber-100m"}, RequiredPlans: []string{"fiber-100m"}, MaxConcurrentSubscriptions: 4, SharedConcurrency: true, Priority: 100, EligibilityTags: []string{"retail"}},
		},
		Subscriptions: []config.BroadbandCommercialSubscriptionConfig{
			{SubscriptionID: "sub-commercial-1", AccountID: "acct-lab-1", SubscriberID: "sub-lab-cpe-01", Username: "lab-cpe-01@example.net", Plan: "fiber-100m", Bundle: "home-internet", Status: "active", AutoRenew: true, MaxSessions: 4, DeviceLimit: 32, EligibilityTags: []string{"retail"}},
		},
		ConcurrencyPolicies: []config.BroadbandCommercialConcurrencyPolicyConfig{
			{Name: "fiber-plan-limit", Enabled: true, Scope: "plan", Plan: "fiber-100m", MaxSessions: 4, MaxSessionsPerSubscriber: 4, BurstSessions: 1, GraceSeconds: 60, Action: "reject", CoAAction: "disconnect-excess"},
		},
	}
	return cfg
}
