package db

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecordDOCSISPolicyEventPersistsEvidence(t *testing.T) {
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
	eventID, err := RecordDOCSISPolicyEvent(DOCSISPolicyEventInput{
		Operation:                "apply",
		Status:                   "applied",
		PlanFingerprint:          strings.Repeat("d", 64),
		Mode:                     "enforce",
		ModemProfileCount:        2,
		ServiceFlowCount:         3,
		CMTSProfileCount:         2,
		ChargingPolicyCount:      2,
		RadiusAttributeCount:     14,
		ComplianceCheckCount:     11,
		PassedCheckCount:         11,
		ExternalRequirementCount: 1,
		SummaryJSON:              string(summaryPayload),
		ReportJSON:               "{}",
		Actor:                    "ops@example.test",
		Profiles: []DOCSISPolicyProfileInput{
			{ProfileKey: "docsis-retail", ProfileType: "modem_profile", Name: "docsis-retail", Status: "ready", CMTSProfile: "cmts-primary", AttributesJSON: `{"tier":"retail"}`, PlanFingerprint: strings.Repeat("d", 64)},
			{ProfileKey: "hsd-best-effort", ProfileType: "service_flow", Name: "hsd-best-effort", Status: "ready", ServiceFlowID: 11001, ServiceClass: "high-speed-data", AttributesJSON: `{"scheduler":"best-effort"}`, PlanFingerprint: strings.Repeat("d", 64)},
			{ProfileKey: "cmts-primary", ProfileType: "cmts_profile", Name: "cmts-primary", Status: "ready", CMTSProfile: "cmts-primary", AttributesJSON: `{"cmts":"primary"}`, PlanFingerprint: strings.Repeat("d", 64)},
			{ProfileKey: "retail-usage", ProfileType: "charging_policy", Name: "retail-usage", Status: "ready", ChargingPolicy: "retail-monthly-cap", AttributesJSON: `{"ipdr":"retail"}`, PlanFingerprint: strings.Repeat("d", 64)},
		},
	})
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(eventID, "docsis-policy-"))

	events, err := ListDOCSISPolicyEvents(10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "applied", events[0].Status)
	assert.Equal(t, 2, events[0].ModemProfileCount)
	assert.Equal(t, 3, events[0].ServiceFlowCount)
	assert.Equal(t, 2, events[0].CMTSProfileCount)
	assert.Equal(t, 2, events[0].ChargingPolicyCount)
	assert.Equal(t, 14, events[0].RadiusAttributeCount)

	profiles, err := ListDOCSISPolicyProfiles(10, "")
	require.NoError(t, err)
	assert.Len(t, profiles, 4)

	flows, err := ListDOCSISPolicyProfiles(10, "service_flow")
	require.NoError(t, err)
	require.Len(t, flows, 1)
	assert.Equal(t, 11001, flows[0].ServiceFlowID)
	assert.Equal(t, "high-speed-data", flows[0].ServiceClass)

	summary, err := GetDOCSISPolicySummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TotalEvents)
	assert.Equal(t, 1, summary.ApplyEvents)
	assert.Equal(t, 1, summary.AppliedCount)
	assert.Equal(t, 4, summary.ReadyProfileCount)
	assert.Equal(t, 2, summary.LastModemProfileCount)
	assert.Equal(t, 3, summary.LastServiceFlowCount)
	assert.Equal(t, 2, summary.LastCMTSProfileCount)
	assert.Equal(t, 2, summary.LastChargingPolicyCount)
	assert.Equal(t, 14, summary.LastRadiusAttributeCount)
	assert.NotEmpty(t, summary.LastFingerprint)
}
