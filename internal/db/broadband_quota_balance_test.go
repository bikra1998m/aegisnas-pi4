package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBroadbandQuotaBalanceEventLedger(t *testing.T) {
	previousDB := DB
	require.NoError(t, Init(":memory:"))
	DB.SetMaxOpenConns(1)
	require.NoError(t, Migrate())
	t.Cleanup(func() {
		_ = Close()
		DB = previousDB
	})

	eventID, err := RecordBroadbandQuotaBalanceEvent(BroadbandQuotaBalanceEventInput{
		Operation:                "apply",
		Status:                   "applied",
		PlanFingerprint:          "quota-fp-1",
		Mode:                     "enforce",
		WalletCount:              1,
		QuotaProfileCount:        1,
		TopUpCount:               1,
		RatingRuleCount:          1,
		ResetPolicyCount:         1,
		ActiveWalletCount:        1,
		PrepaidWalletCount:       1,
		TotalBalanceMicros:       25000000,
		TotalCreditLimitMicros:   0,
		TotalTopUpMicros:         11000000,
		ComplianceCheckCount:     7,
		PassedCheckCount:         7,
		ExternalRequirementCount: 9,
		SummaryJSON:              `{"wallet_count":1}`,
		ReportJSON:               `{"feature_id":"NAS-0085"}`,
		Actor:                    "ops@example.test",
		Wallets: []BroadbandQuotaWalletInput{
			{WalletID: "wallet-lab-1", AccountID: "acct-lab-1", SubscriptionID: "sub-commercial-1", SubscriberID: "sub-lab-cpe-01", Username: "lab-cpe-01@example.net", BillingMode: "prepaid", Status: "active", Currency: "USD", BalanceMicros: 25000000, QuotaProfile: "monthly-500g", AutoRecharge: true, TagsJSON: `["lab"]`},
		},
		QuotaProfiles: []BroadbandQuotaProfileInput{
			{Name: "monthly-500g", Status: "active", Period: "monthly", IncludedTotalOctets: 536870912000, OverageRateMicrosPerMB: 25000, WarningThresholdPercent: 80, HardLimit: true, ThrottleProfile: "shape-10m", ExhaustedRole: "quota-exhausted", ResetPolicy: "monthly-reset", VendorPacksJSON: `["standard","aegisnas"]`},
		},
		TopUps: []BroadbandTopUpGrantInput{
			{TopUpID: "topup-lab-1", WalletID: "wallet-lab-1", Status: "applied", AmountMicros: 10000000, BonusMicros: 1000000, Currency: "USD", QuotaOctets: 107374182400, PaymentRef: "pay-lab-1", IdempotencyKey: "topup-lab-1", Source: "operator"},
		},
		RatingRules: []BroadbandQuotaRatingRuleInput{
			{Name: "fiber-100m-overage", Status: "active", PlanName: "fiber-100m", QuotaProfile: "monthly-500g", Unit: "total-octets", PriceMicros: 25000, Rounding: "up", MinimumChargeMicros: 1000000},
		},
		ResetPolicies: []BroadbandQuotaResetPolicyInput{
			{Name: "monthly-reset", Status: "active", Period: "monthly", ResetDay: 1, ResetHour: 3, CarryOverOctets: 107374182400, CarryOverBalanceMicros: 5000000},
		},
	})
	require.NoError(t, err)
	assert.NotEmpty(t, eventID)

	events, err := ListBroadbandQuotaBalanceEvents(10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "apply", events[0].Operation)
	assert.Equal(t, "applied", events[0].Status)
	assert.Equal(t, int64(11000000), events[0].TotalTopUpMicros)

	wallets, err := ListBroadbandQuotaWallets(10)
	require.NoError(t, err)
	require.Len(t, wallets, 1)
	assert.Equal(t, "wallet-lab-1", wallets[0].WalletID)
	assert.True(t, wallets[0].AutoRecharge)

	profiles, err := ListBroadbandQuotaProfiles(10)
	require.NoError(t, err)
	require.Len(t, profiles, 1)
	assert.True(t, profiles[0].HardLimit)

	topUps, err := ListBroadbandTopUpGrants(10)
	require.NoError(t, err)
	require.Len(t, topUps, 1)
	assert.Equal(t, "applied", topUps[0].Status)

	rules, err := ListBroadbandQuotaRatingRules(10)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	assert.Equal(t, "fiber-100m", rules[0].PlanName)

	resetPolicies, err := ListBroadbandQuotaResetPolicies(10)
	require.NoError(t, err)
	require.Len(t, resetPolicies, 1)
	assert.Equal(t, 3, resetPolicies[0].ResetHour)

	summary, err := GetBroadbandQuotaBalanceSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TotalEvents)
	assert.Equal(t, 1, summary.AppliedCount)
	assert.Equal(t, 1, summary.ActiveWallets)
	assert.Equal(t, 1, summary.ActiveQuotaProfiles)
	assert.Equal(t, 1, summary.AppliedTopUps)
	assert.Equal(t, 1, summary.ActiveRatingRules)
	assert.Equal(t, 1, summary.ActiveResetPolicies)
	assert.Equal(t, int64(25000000), summary.TotalBalanceMicros)
	assert.Equal(t, "quota-fp-1", summary.LastFingerprint)
}

func TestBroadbandQuotaBalanceEventValidation(t *testing.T) {
	previousDB := DB
	require.NoError(t, Init(":memory:"))
	DB.SetMaxOpenConns(1)
	require.NoError(t, Migrate())
	t.Cleanup(func() {
		_ = Close()
		DB = previousDB
	})

	_, err := RecordBroadbandQuotaBalanceEvent(BroadbandQuotaBalanceEventInput{
		Operation:       "apply",
		Status:          "applied",
		PlanFingerprint: "",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "plan fingerprint")

	_, err = RecordBroadbandQuotaBalanceEvent(BroadbandQuotaBalanceEventInput{
		Operation:       "apply",
		Status:          "applied",
		PlanFingerprint: "quota-fp",
		QuotaProfiles: []BroadbandQuotaProfileInput{
			{Name: "generated-profile", Status: "active"},
		},
	})
	require.NoError(t, err)
	profiles, err := ListBroadbandQuotaProfiles(10)
	require.NoError(t, err)
	require.Len(t, profiles, 1)
	assert.Equal(t, "monthly", profiles[0].Period)
}
