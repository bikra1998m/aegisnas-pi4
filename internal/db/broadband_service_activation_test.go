package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBroadbandServiceActivationEvidenceLifecycle(t *testing.T) {
	previousDB := DB
	require.NoError(t, Init(":memory:"))
	DB.SetMaxOpenConns(1)
	require.NoError(t, Migrate())
	t.Cleanup(func() {
		_ = Close()
		DB = previousDB
	})

	emptySummary, err := GetBroadbandServiceActivationSummary()
	require.NoError(t, err)
	assert.Equal(t, 0, emptySummary.TotalEvents)

	eventID, err := RecordBroadbandServiceActivationEvent(BroadbandServiceActivationEventInput{
		Operation:                "apply",
		Status:                   "applied",
		PlanFingerprint:          "sha256:test",
		Mode:                     "enforce",
		ServiceCount:             1,
		RoutePolicyCount:         1,
		MulticastProfileCount:    1,
		ActivationPolicyCount:    1,
		RouteAttributeCount:      4,
		MulticastAttributeCount:  3,
		RadiusAttributeCount:     9,
		ComplianceCheckCount:     12,
		PassedCheckCount:         12,
		ExternalRequirementCount: 1,
		SummaryJSON:              `{"status":"ready"}`,
		ReportJSON:               `{"feature_id":"NAS-0090"}`,
		Actor:                    "ops@example.test",
		Transactions: []BroadbandServiceActivationTransactionInput{
			{
				TransactionKey:          "bng-service-test",
				ServiceName:             "fiber-internet-activation",
				Product:                 "residential-fiber",
				SubscriberID:            "sub-lab-cpe-01",
				Username:                "lab-cpe-01@example.net",
				Tenant:                  "retail",
				ServiceChain:            "retail-internet",
				RoutePolicy:             "retail-bgp",
				MulticastProfile:        "iptv-basic",
				AddressPool:             "pppoe-v4",
				QoSProfile:              "silver",
				AccountingClass:         "internet",
				Status:                  "active",
				VendorPacksJSON:         `["standard","erx","huawei"]`,
				RouteAttributesJSON:     `[{"name":"Framed-Route","value":"100.64.0.0/24"}]`,
				MulticastAttributesJSON: `[{"name":"AegisNAS-Multicast-Group","value":"239.1.1.1"}]`,
				RadiusAttributesJSON:    `[{"name":"ERX-Service-Activate","value":"retail-internet"}]`,
				RollbackRequired:        true,
				PlanFingerprint:         "sha256:test",
			},
		},
	})
	require.NoError(t, err)
	assert.NotEmpty(t, eventID)

	events, err := ListBroadbandServiceActivationEvents(5)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "applied", events[0].Status)
	assert.Equal(t, 1, events[0].ServiceCount)
	assert.Equal(t, "ops@example.test", events[0].Actor)

	transactions, err := ListBroadbandServiceActivationTransactions(5, "active")
	require.NoError(t, err)
	require.Len(t, transactions, 1)
	assert.Equal(t, "fiber-internet-activation", transactions[0].ServiceName)
	assert.Equal(t, "retail-bgp", transactions[0].RoutePolicy)
	assert.Equal(t, "iptv-basic", transactions[0].MulticastProfile)
	assert.Equal(t, "sha256:test", transactions[0].PlanFingerprint)
	assert.True(t, transactions[0].RollbackRequired)

	summary, err := GetBroadbandServiceActivationSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TotalEvents)
	assert.Equal(t, 1, summary.ApplyEvents)
	assert.Equal(t, 1, summary.AppliedCount)
	assert.Equal(t, 1, summary.ActiveTransactions)
	assert.Equal(t, 1, summary.RollbackRequiredTransactions)
	assert.Equal(t, "sha256:test", summary.LastFingerprint)
	assert.Equal(t, 1, summary.LastServiceCount)
	assert.Equal(t, 1, summary.LastRoutePolicyCount)
	assert.Equal(t, 1, summary.LastMulticastProfileCount)
	assert.Equal(t, 9, summary.LastRadiusAttributeCount)
}
