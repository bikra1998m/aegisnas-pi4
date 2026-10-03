package db

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBroadbandQoSServiceFlowEventAndSummary(t *testing.T) {
	require.NoError(t, Init(":memory:"))
	DB.SetMaxOpenConns(1)
	t.Cleanup(func() { Close() })
	require.NoError(t, Migrate())

	eventID, err := RecordBroadbandQoSServiceFlowEvent(BroadbandQoSServiceFlowEventInput{
		Operation:              "apply",
		Status:                 "applied",
		PlanFingerprint:        "sha256:qos",
		Mode:                   "monitor",
		ProfileCount:           1,
		ServiceFlowCount:       1,
		AggregatePolicyCount:   1,
		CompiledAttributeCount: 3,
		SummaryJSON:            `{"service_flow_count":1}`,
		ReportJSON:             `{"feature_id":"NAS-0087"}`,
		Actor:                  "tester",
		Flows: []BroadbandQoSServiceFlowInput{
			{
				FlowKey:                "flow-1",
				Name:                   "fiber-internet",
				Product:                "fiber-100m",
				ServiceLeg:             "internet",
				Direction:              "bidirectional",
				Profile:                "silver",
				TrafficClass:           "data",
				Scheduler:              "htb",
				Priority:               4,
				DownloadRateKbps:       100000,
				UploadRateKbps:         20000,
				Status:                 "active",
				VendorPacksJSON:        `["mikrotik"]`,
				CompiledAttributesJSON: `[{"name":"Mikrotik-Rate-Limit"}]`,
				DiagnosticsJSON:        `[]`,
				PlanFingerprint:        "sha256:qos",
			},
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, eventID)

	events, err := ListBroadbandQoSServiceFlowEvents(10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	require.Equal(t, "NAS-0087", mustContainReport(t, events[0].ReportJSON))

	flows, err := ListBroadbandQoSServiceFlows(10, "active")
	require.NoError(t, err)
	require.Len(t, flows, 1)
	require.Equal(t, "fiber-internet", flows[0].Name)

	summary, err := GetBroadbandQoSServiceFlowSummary()
	require.NoError(t, err)
	require.Equal(t, 1, summary.AppliedCount)
	require.Equal(t, 1, summary.ActiveFlows)
	require.Equal(t, 3, summary.LastCompiledAttributeCount)
}

func mustContainReport(t *testing.T, value string) string {
	t.Helper()
	require.Contains(t, value, "NAS-0087")
	return "NAS-0087"
}
