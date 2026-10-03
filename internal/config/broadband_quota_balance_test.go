package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateBroadbandQuotaBalanceAcceptsProductionCatalog(t *testing.T) {
	quota := broadbandQuotaBalanceValidationFixture()
	catalog := broadbandCommercialCatalogValidationFixture()
	subscriber := broadbandAddressLeaseSubscriberFixture()
	radius := broadbandQuotaBalanceRadiusFixture()

	require.NoError(t, validateBroadbandQuotaBalanceConfig(quota, catalog, subscriber, radius, "enterprise"))
}

func TestValidateBroadbandQuotaBalanceBlocksMissingChargingDependency(t *testing.T) {
	quota := broadbandQuotaBalanceValidationFixture()
	catalog := broadbandCommercialCatalogValidationFixture()
	subscriber := broadbandAddressLeaseSubscriberFixture()
	radius := broadbandQuotaBalanceRadiusFixture()
	radius.AccountingCharging.RatingEnabled = false

	err := validateBroadbandQuotaBalanceConfig(quota, catalog, subscriber, radius, "enterprise")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rating_enabled")
}

func TestValidateBroadbandQuotaBalanceBlocksUnknownWalletProfile(t *testing.T) {
	quota := broadbandQuotaBalanceValidationFixture()
	quota.Wallets[0].QuotaProfile = "missing-profile"
	catalog := broadbandCommercialCatalogValidationFixture()
	subscriber := broadbandAddressLeaseSubscriberFixture()
	radius := broadbandQuotaBalanceRadiusFixture()

	err := validateBroadbandQuotaBalanceConfig(quota, catalog, subscriber, radius, "enterprise")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "quota_profile")
}

func TestValidateBroadbandQuotaBalanceAllowsDisabledEmptyConfig(t *testing.T) {
	require.NoError(t, validateBroadbandQuotaBalanceConfig(BroadbandQuotaBalanceConfig{}, BroadbandCommercialCatalog{}, BroadbandSubscriberStateConfig{}, RadiusConfig{}, "lite"))
}

func broadbandQuotaBalanceValidationFixture() BroadbandQuotaBalanceConfig {
	return BroadbandQuotaBalanceConfig{
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
		Wallets: []BroadbandQuotaWalletConfig{
			{WalletID: "wallet-lab-1", AccountID: "acct-lab-1", SubscriptionID: "sub-commercial-1", SubscriberID: "sub-lab-cpe-01", Username: "lab-cpe-01@example.net", BillingMode: "prepaid", Status: "active", Currency: "USD", BalanceMicros: 25000000, QuotaProfile: "monthly-500g", AutoRecharge: true, Tags: []string{"lab"}},
		},
		QuotaProfiles: []BroadbandQuotaProfileConfig{
			{Name: "monthly-500g", Enabled: true, Period: "monthly", IncludedTotalOctets: 536870912000, OverageRateMicrosPerMB: 25000, WarningThresholdPercent: 80, HardLimit: true, ThrottleProfile: "shape-10m", ExhaustedRole: "quota-exhausted", ResetPolicy: "monthly-reset", VendorPacks: []string{"standard", "aegisnas", "mikrotik"}},
		},
		TopUps: []BroadbandTopUpGrantConfig{
			{TopUpID: "topup-lab-1", WalletID: "wallet-lab-1", AmountMicros: 10000000, BonusMicros: 1000000, Currency: "USD", QuotaOctets: 107374182400, Status: "applied", PaymentRef: "pay-lab-1", IdempotencyKey: "topup-lab-1", Source: "operator"},
		},
		RatingRules: []BroadbandQuotaRatingRuleConfig{
			{Name: "fiber-100m-overage", Enabled: true, Plan: "fiber-100m", QuotaProfile: "monthly-500g", Unit: "total-octets", PriceMicros: 25000, Rounding: "up", MinimumChargeMicros: 1000000, TaxPercent: 0},
		},
		ResetPolicies: []BroadbandQuotaResetPolicyConfig{
			{Name: "monthly-reset", Enabled: true, Period: "monthly", ResetDay: 1, ResetHour: 3, CarryOverOctets: 107374182400, CarryOverBalanceMicros: 5000000},
		},
	}
}

func broadbandQuotaBalanceRadiusFixture() RadiusConfig {
	radius := broadbandAddressLeaseRadiusFixture()
	radius.AccountingCharging = RadiusAccountingChargingConfig{Enabled: true, RatingEnabled: true, ExportEnabled: true, Currency: "USD"}
	return radius
}
