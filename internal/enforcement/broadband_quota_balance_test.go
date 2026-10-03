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

func TestPreviewBroadbandQuotaBalanceBuildsFullPlan(t *testing.T) {
	cfg := loadBroadbandQuotaBalanceTestConfig(t)

	report, err := PreviewBroadbandQuotaBalance(cfg)
	require.NoError(t, err)
	assert.Equal(t, BroadbandQuotaBalanceFeatureID, report.FeatureID)
	assert.Equal(t, "ready", report.Status)
	assert.Equal(t, 100.0, report.SoftwareCompletionPercent)
	assert.True(t, report.ReadyForExternalValidation)
	assert.Equal(t, 1, report.Summary.WalletCount)
	assert.Equal(t, 1, report.Summary.EnabledQuotaProfileCount)
	assert.Equal(t, 1, report.Summary.TopUpCount)
	assert.Equal(t, 1, report.Summary.EnabledRatingRuleCount)
	assert.Equal(t, 1, report.Summary.EnabledResetPolicyCount)
	assert.GreaterOrEqual(t, report.Summary.AuthorizationBindingCount, 4)
	assert.GreaterOrEqual(t, report.Summary.AccountingBindingCount, 4)
	assert.Equal(t, report.Summary.ComplianceCheckCount, report.Summary.PassedCheckCount)
	assert.Empty(t, report.Blockers)
	assert.NotEmpty(t, report.PlanFingerprint)
	assert.Contains(t, report.AccountingBindings[1].Attributes, "Acct-Input-Octets")
}

func TestPreviewBroadbandQuotaBalanceBlocksUnsafeConfig(t *testing.T) {
	cfg := loadBroadbandQuotaBalanceTestConfig(t)
	cfg.Radius.DynamicAuth.Enabled = false

	report, err := PreviewBroadbandQuotaBalance(cfg)
	require.NoError(t, err)
	assert.Equal(t, "blocked", report.Status)
	assert.NotEmpty(t, report.Blockers)
	assert.Contains(t, strings.Join(report.Blockers, "\n"), "coa_on_exhaustion")
}

func TestPreviewBroadbandQuotaBalanceSkippedWhenDisabled(t *testing.T) {
	cfg := loadBroadbandQuotaBalanceTestConfig(t)
	cfg.Broadband.QuotaBalance.Enabled = false

	report, err := PreviewBroadbandQuotaBalance(cfg)
	require.NoError(t, err)
	assert.Equal(t, "skipped", report.Status)
	assert.True(t, report.ReadyForExternalValidation)
	assert.Equal(t, 100.0, report.SoftwareCompletionPercent)
}

func TestApplyBroadbandQuotaBalanceRecordsEvidenceAndRuntimeStatus(t *testing.T) {
	cfg := loadBroadbandQuotaBalanceTestConfig(t)
	previousDB := db.DB
	require.NoError(t, db.Init(":memory:"))
	db.DB.SetMaxOpenConns(1)
	require.NoError(t, db.Migrate())
	t.Cleanup(func() {
		_ = db.Close()
		db.DB = previousDB
	})

	report, eventID, err := ApplyBroadbandQuotaBalance(context.Background(), cfg, "ops@example.test")
	require.NoError(t, err)
	assert.Equal(t, "applied", report.Status)
	assert.NotEmpty(t, eventID)

	events, err := db.ListBroadbandQuotaBalanceEvents(10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "applied", events[0].Status)
	assert.Equal(t, 1, events[0].WalletCount)

	wallets, err := db.ListBroadbandQuotaWallets(10)
	require.NoError(t, err)
	require.Len(t, wallets, 1)
	assert.Equal(t, "wallet-lab-1", wallets[0].WalletID)

	runtime, err := db.GetRuntimeStatus(BroadbandQuotaBalanceComponent())
	require.NoError(t, err)
	require.NotNil(t, runtime)
	assert.Equal(t, "ok", runtime.Status)
	assert.Contains(t, runtime.Message, "NAS-0085")
}

func loadBroadbandQuotaBalanceTestConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := loadBroadbandCommercialCatalogTestConfig(t)
	cfg.Radius.AccountingCharging = config.RadiusAccountingChargingConfig{
		Enabled:             true,
		RatingEnabled:       true,
		ExportEnabled:       true,
		ExportFormat:        "jsonl",
		DefaultPlan:         "fiber-100m",
		Currency:            "USD",
		InputMicrosPerGiB:   25000000,
		OutputMicrosPerGiB:  25000000,
		MinimumChargeMicros: 1000000,
	}
	cfg.Broadband.QuotaBalance = config.BroadbandQuotaBalanceConfig{
		Enabled:                       true,
		Mode:                          "enforce",
		FailClosed:                    true,
		DefaultCurrency:               "USD",
		DefaultQuotaPeriod:            "monthly",
		RequireCommercialCatalog:      true,
		RequireActiveWallet:           true,
		RequireQuotaProfile:           true,
		RatingEnabled:                 true,
		TopUpEnabled:                  true,
		PrepaidEnabled:                true,
		PostpaidEnabled:               true,
		AccountingCorrelationRequired: true,
		AutoSuspendOnExhaustion:       true,
		CoAOnExhaustion:               true,
		BalanceFloorMicros:            0,
		EventRetentionLimit:           10000,
		Wallets: []config.BroadbandQuotaWalletConfig{
			{WalletID: "wallet-lab-1", AccountID: "acct-lab-1", SubscriptionID: "sub-commercial-1", SubscriberID: "sub-lab-cpe-01", Username: "lab-cpe-01@example.net", BillingMode: "prepaid", Status: "active", Currency: "USD", BalanceMicros: 25000000, QuotaProfile: "monthly-500g", AutoRecharge: true, Tags: []string{"lab"}},
		},
		QuotaProfiles: []config.BroadbandQuotaProfileConfig{
			{Name: "monthly-500g", Enabled: true, Period: "monthly", IncludedTotalOctets: 536870912000, OverageRateMicrosPerMB: 25000, WarningThresholdPercent: 80, HardLimit: true, ThrottleProfile: "shape-10m", ExhaustedRole: "quota-exhausted", ResetPolicy: "monthly-reset", VendorPacks: []string{"standard", "aegisnas", "mikrotik"}},
		},
		TopUps: []config.BroadbandTopUpGrantConfig{
			{TopUpID: "topup-lab-1", WalletID: "wallet-lab-1", AmountMicros: 10000000, BonusMicros: 1000000, Currency: "USD", QuotaOctets: 107374182400, Status: "applied", PaymentRef: "pay-lab-1", IdempotencyKey: "topup-lab-1", Source: "operator"},
		},
		RatingRules: []config.BroadbandQuotaRatingRuleConfig{
			{Name: "fiber-100m-overage", Enabled: true, Plan: "fiber-100m", QuotaProfile: "monthly-500g", Unit: "total-octets", PriceMicros: 25000, Rounding: "up", MinimumChargeMicros: 1000000},
		},
		ResetPolicies: []config.BroadbandQuotaResetPolicyConfig{
			{Name: "monthly-reset", Enabled: true, Period: "monthly", ResetDay: 1, ResetHour: 3, CarryOverOctets: 107374182400, CarryOverBalanceMicros: 5000000},
		},
	}
	return cfg
}
