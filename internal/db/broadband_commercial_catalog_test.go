package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBroadbandCommercialCatalogEventLedger(t *testing.T) {
	previousDB := DB
	require.NoError(t, Init(":memory:"))
	DB.SetMaxOpenConns(1)
	require.NoError(t, Migrate())
	t.Cleanup(func() {
		_ = Close()
		DB = previousDB
	})

	eventID, err := RecordBroadbandCommercialCatalogEvent(BroadbandCommercialCatalogEventInput{
		Operation:                "apply",
		Status:                   "applied",
		PlanFingerprint:          "commercial-fp-1",
		Mode:                     "enforce",
		AccountCount:             1,
		PlanCount:                1,
		BundleCount:              1,
		SubscriptionCount:        1,
		ConcurrencyPolicyCount:   1,
		ActiveSubscriptionCount:  1,
		ComplianceCheckCount:     5,
		PassedCheckCount:         5,
		ExternalRequirementCount: 9,
		SummaryJSON:              `{"account_count":1}`,
		ReportJSON:               `{"feature_id":"NAS-0084"}`,
		Actor:                    "ops@example.test",
		Accounts: []BroadbandCommercialAccountInput{
			{AccountID: "acct-lab-1", Tenant: "retail", Status: "active", BillingMode: "postpaid", OwnerName: "Lab Account", MaxSubscriptions: 4, MaxSessions: 8, TagsJSON: `["lab"]`},
		},
		Plans: []BroadbandCommercialPlanInput{
			{Name: "fiber-100m", Product: "residential-fiber", Status: "active", BillingPeriod: "monthly", Currency: "USD", PriceMicros: 49990000, MaxSessions: 4, VendorPacksJSON: `["standard","aegisnas"]`},
		},
		Bundles: []BroadbandCommercialBundleInput{
			{Name: "home-internet", Status: "active", PlansJSON: `["fiber-100m"]`, RequiredPlansJSON: `["fiber-100m"]`, MaxConcurrentSubscriptions: 4, SharedConcurrency: true, EligibilityTagsJSON: `["retail"]`},
		},
		Subscriptions: []BroadbandCommercialSubscriptionInput{
			{SubscriptionID: "sub-commercial-1", AccountID: "acct-lab-1", SubscriberID: "sub-lab-cpe-01", Username: "lab-cpe-01@example.net", PlanName: "fiber-100m", BundleName: "home-internet", Status: "active", AutoRenew: true, MaxSessions: 4},
		},
		ConcurrencyPolicies: []BroadbandCommercialConcurrencyPolicyInput{
			{PolicyKey: "policy-fiber-plan", Name: "fiber-plan-limit", Scope: "plan", Target: "fiber-100m", PlanName: "fiber-100m", MaxSessions: 4, MaxSessionsPerSubscriber: 4, BurstSessions: 1, GraceSeconds: 60, Action: "reject", CoAAction: "disconnect-excess", Status: "active"},
		},
	})
	require.NoError(t, err)
	assert.NotEmpty(t, eventID)

	events, err := ListBroadbandCommercialCatalogEvents(10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "apply", events[0].Operation)
	assert.Equal(t, "applied", events[0].Status)
	assert.Equal(t, 1, events[0].SubscriptionCount)

	accounts, err := ListBroadbandCommercialAccounts(10)
	require.NoError(t, err)
	require.Len(t, accounts, 1)
	assert.Equal(t, "acct-lab-1", accounts[0].AccountID)
	assert.Equal(t, "retail", accounts[0].Tenant)

	plans, err := ListBroadbandCommercialPlans(10)
	require.NoError(t, err)
	require.Len(t, plans, 1)
	assert.Equal(t, int64(49990000), plans[0].PriceMicros)

	subscriptions, err := ListBroadbandCommercialSubscriptions(10)
	require.NoError(t, err)
	require.Len(t, subscriptions, 1)
	assert.True(t, subscriptions[0].AutoRenew)

	summary, err := GetBroadbandCommercialCatalogSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TotalEvents)
	assert.Equal(t, 1, summary.AppliedCount)
	assert.Equal(t, 1, summary.ActiveAccounts)
	assert.Equal(t, 1, summary.ActivePlans)
	assert.Equal(t, 1, summary.ActiveSubscriptions)
	assert.Equal(t, 1, summary.ActiveConcurrencyPolicies)
	assert.Equal(t, "commercial-fp-1", summary.LastFingerprint)
}

func TestBroadbandCommercialCatalogEventValidation(t *testing.T) {
	previousDB := DB
	require.NoError(t, Init(":memory:"))
	DB.SetMaxOpenConns(1)
	require.NoError(t, Migrate())
	t.Cleanup(func() {
		_ = Close()
		DB = previousDB
	})

	_, err := RecordBroadbandCommercialCatalogEvent(BroadbandCommercialCatalogEventInput{
		Operation:       "apply",
		Status:          "applied",
		PlanFingerprint: "",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "plan fingerprint")

	_, err = RecordBroadbandCommercialCatalogEvent(BroadbandCommercialCatalogEventInput{
		Operation:       "apply",
		Status:          "applied",
		PlanFingerprint: "commercial-fp",
		ConcurrencyPolicies: []BroadbandCommercialConcurrencyPolicyInput{
			{Name: "generated-key-policy", Scope: "subscriber", MaxSessions: 2, Action: "reject", Status: "active"},
		},
	})
	require.NoError(t, err)
	policies, err := ListBroadbandCommercialConcurrencyPolicies(10)
	require.NoError(t, err)
	require.Len(t, policies, 1)
	assert.NotEmpty(t, policies[0].PolicyKey)
}
