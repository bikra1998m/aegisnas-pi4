package db

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBroadbandL2TPWholesaleEventAndSummary(t *testing.T) {
	require.NoError(t, Init(":memory:"))
	DB.SetMaxOpenConns(1)
	t.Cleanup(func() { Close() })
	require.NoError(t, Migrate())

	eventID, err := RecordBroadbandL2TPWholesaleEvent(BroadbandL2TPWholesaleEventInput{
		Operation:              "apply",
		Status:                 "applied",
		PlanFingerprint:        "sha256:l2tp",
		Mode:                   "monitor",
		RealmCount:             1,
		TunnelProfileCount:     2,
		FailoverPolicyCount:    1,
		ProxyRouteCount:        1,
		AccountingRouteCount:   1,
		CompiledAttributeCount: 8,
		SummaryJSON:            `{"realm_count":1}`,
		ReportJSON:             `{"feature_id":"NAS-0088"}`,
		Actor:                  "tester",
		Bindings: []BroadbandL2TPWholesaleBindingInput{
			{
				BindingKey:             "binding-1",
				RealmName:              "wholesale-retail",
				Realm:                  "retail.example.net",
				Tenant:                 "retail",
				Partner:                "partner-a",
				AccessMethod:           "pppoe",
				TunnelProfile:          "lns-primary",
				TunnelMode:             "lns",
				ProxyRoute:             "wholesale-retail-auth",
				AccountingRoute:        "wholesale-retail-acct",
				AddressPool:            "wholesale-v4",
				QoSProfile:             "silver",
				Product:                "residential-fiber",
				Status:                 "active",
				CompiledAttributesJSON: `[{"name":"Tunnel-Type","value":"L2TP"}]`,
				FailoverPolicy:         "retail-failover",
				PlanFingerprint:        "sha256:l2tp",
			},
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, eventID)

	events, err := ListBroadbandL2TPWholesaleEvents(10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	require.Contains(t, events[0].ReportJSON, "NAS-0088")

	bindings, err := ListBroadbandL2TPWholesaleBindings(10, "active")
	require.NoError(t, err)
	require.Len(t, bindings, 1)
	require.Equal(t, "wholesale-retail", bindings[0].RealmName)
	require.Equal(t, "lns-primary", bindings[0].TunnelProfile)

	summary, err := GetBroadbandL2TPWholesaleSummary()
	require.NoError(t, err)
	require.Equal(t, 1, summary.AppliedCount)
	require.Equal(t, 1, summary.ActiveBindings)
	require.Equal(t, 8, summary.LastCompiledAttributeCount)
}
