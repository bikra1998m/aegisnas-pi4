package db

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecordWiMAXServiceFlowEventPersistsEvidence(t *testing.T) {
	previousDB := DB
	require.NoError(t, Init(":memory:"))
	DB.SetMaxOpenConns(1)
	require.NoError(t, Migrate())
	t.Cleanup(func() {
		_ = Close()
		DB = previousDB
	})

	summaryPayload, err := json.Marshal(map[string]any{"status": "ready", "flows": 3})
	require.NoError(t, err)
	eventID, err := RecordWiMAXServiceFlowEvent(WiMAXServiceFlowEventInput{
		Operation:                "apply",
		Status:                   "applied",
		PlanFingerprint:          strings.Repeat("c", 64),
		Mode:                     "enforce",
		SubscriberProfileCount:   2,
		ServiceFlowCount:         3,
		ASNProfileCount:          2,
		MobilityPolicyCount:      2,
		RadiusAttributeCount:     15,
		ComplianceCheckCount:     11,
		PassedCheckCount:         11,
		ExternalRequirementCount: 1,
		SummaryJSON:              string(summaryPayload),
		ReportJSON:               "{}",
		Actor:                    "ops@example.test",
		Profiles: []WiMAXServiceFlowProfileInput{
			{ProfileKey: "wimax-retail", ProfileType: "subscriber_profile", Name: "wimax-retail", Status: "ready", ASNProfile: "asn-primary", AttributesJSON: `{"realm":"wimax.example.net"}`, PlanFingerprint: strings.Repeat("c", 64)},
			{ProfileKey: "internet-be", ProfileType: "service_flow", Name: "internet-be", Status: "ready", ServiceFlowID: 1001, ServiceClass: "best-effort", AttributesJSON: `{"scheduler":"be"}`, PlanFingerprint: strings.Repeat("c", 64)},
			{ProfileKey: "asn-primary", ProfileType: "asn_profile", Name: "asn-primary", Status: "ready", ASNProfile: "asn-primary", AttributesJSON: `{"realm":"wimax.example.net"}`, PlanFingerprint: strings.Repeat("c", 64)},
			{ProfileKey: "asn-handover", ProfileType: "mobility_policy", Name: "asn-handover", Status: "ready", ASNProfile: "asn-roaming", MobilityMode: "optimized", AttributesJSON: `{"coa":"wimax-handover"}`, PlanFingerprint: strings.Repeat("c", 64)},
		},
	})
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(eventID, "wimax-flow-"))

	events, err := ListWiMAXServiceFlowEvents(10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "applied", events[0].Status)
	assert.Equal(t, 2, events[0].SubscriberProfileCount)
	assert.Equal(t, 3, events[0].ServiceFlowCount)
	assert.Equal(t, 2, events[0].ASNProfileCount)
	assert.Equal(t, 2, events[0].MobilityPolicyCount)
	assert.Equal(t, 15, events[0].RadiusAttributeCount)

	profiles, err := ListWiMAXServiceFlowProfiles(10, "")
	require.NoError(t, err)
	assert.Len(t, profiles, 4)

	flows, err := ListWiMAXServiceFlowProfiles(10, "service_flow")
	require.NoError(t, err)
	require.Len(t, flows, 1)
	assert.Equal(t, 1001, flows[0].ServiceFlowID)
	assert.Equal(t, "best-effort", flows[0].ServiceClass)

	summary, err := GetWiMAXServiceFlowSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TotalEvents)
	assert.Equal(t, 1, summary.ApplyEvents)
	assert.Equal(t, 1, summary.AppliedCount)
	assert.Equal(t, 4, summary.ReadyProfileCount)
	assert.Equal(t, 2, summary.LastSubscriberProfileCount)
	assert.Equal(t, 3, summary.LastServiceFlowCount)
	assert.Equal(t, 2, summary.LastASNProfileCount)
	assert.Equal(t, 2, summary.LastMobilityPolicyCount)
	assert.Equal(t, 15, summary.LastRadiusAttributeCount)
	assert.NotEmpty(t, summary.LastFingerprint)
}
