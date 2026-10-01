package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateBroadbandCommercialCatalogAcceptsProductionCatalog(t *testing.T) {
	catalog := broadbandCommercialCatalogValidationFixture()
	subscriber := broadbandAddressLeaseSubscriberFixture()
	radius := broadbandAddressLeaseRadiusFixture()

	require.NoError(t, validateBroadbandCommercialCatalog(catalog, subscriber, radius, "enterprise"))
}

func TestValidateBroadbandCommercialCatalogBlocksMissingDependencies(t *testing.T) {
	catalog := broadbandCommercialCatalogValidationFixture()
	subscriber := broadbandAddressLeaseSubscriberFixture()
	radius := broadbandAddressLeaseRadiusFixture()
	radius.DynamicAuth.Enabled = false

	err := validateBroadbandCommercialCatalog(catalog, subscriber, radius, "enterprise")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "coa_on_limit")
}

func TestValidateBroadbandCommercialCatalogAllowsDisabledEmptyConfig(t *testing.T) {
	require.NoError(t, validateBroadbandCommercialCatalog(BroadbandCommercialCatalog{}, BroadbandSubscriberStateConfig{}, RadiusConfig{}, "lite"))
}

func broadbandCommercialCatalogValidationFixture() BroadbandCommercialCatalog {
	return BroadbandCommercialCatalog{
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
		Accounts: []BroadbandCommercialAccountConfig{
			{AccountID: "acct-lab-1", Tenant: "retail", Status: "active", BillingMode: "postpaid", OwnerName: "Lab Account", Contact: "noc@example.net", MaxSubscriptions: 4, MaxSessions: 8, Tags: []string{"lab"}},
		},
		Plans: []BroadbandCommercialPlanConfig{
			{Name: "fiber-100m", Enabled: true, Product: "residential-fiber", BillingPeriod: "monthly", Currency: "USD", MaxSessions: 4, DownstreamKbps: 100000, UpstreamKbps: 25000, VendorPacks: []string{"standard", "aegisnas"}},
		},
		Bundles: []BroadbandCommercialBundleConfig{
			{Name: "home-internet", Enabled: true, Plans: []string{"fiber-100m"}, RequiredPlans: []string{"fiber-100m"}, MaxConcurrentSubscriptions: 4, SharedConcurrency: true, EligibilityTags: []string{"retail"}},
		},
		Subscriptions: []BroadbandCommercialSubscriptionConfig{
			{SubscriptionID: "sub-commercial-1", AccountID: "acct-lab-1", SubscriberID: "sub-lab-cpe-01", Username: "lab-cpe-01@example.net", Plan: "fiber-100m", Bundle: "home-internet", Status: "active", AutoRenew: true, MaxSessions: 4},
		},
		ConcurrencyPolicies: []BroadbandCommercialConcurrencyPolicyConfig{
			{Name: "fiber-plan-limit", Enabled: true, Scope: "plan", Plan: "fiber-100m", MaxSessions: 4, MaxSessionsPerSubscriber: 4, BurstSessions: 1, GraceSeconds: 60, Action: "reject", CoAAction: "disconnect-excess"},
		},
	}
}
