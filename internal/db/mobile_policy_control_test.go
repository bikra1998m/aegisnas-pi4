package db

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecordMobilePolicyControlEventPersistsEvidence(t *testing.T) {
	previousDB := DB
	require.NoError(t, Init(":memory:"))
	DB.SetMaxOpenConns(1)
	require.NoError(t, Migrate())
	t.Cleanup(func() {
		_ = Close()
		DB = previousDB
	})

	summaryPayload, err := json.Marshal(map[string]any{"status": "ready", "profiles": 3})
	require.NoError(t, err)
	eventID, err := RecordMobilePolicyControlEvent(MobilePolicyControlEventInput{
		Operation:                "apply",
		Status:                   "applied",
		PlanFingerprint:          strings.Repeat("b", 64),
		Mode:                     "enforce",
		PolicyProfileCount:       3,
		QoSClassCount:            3,
		RoamingPolicyCount:       2,
		FeedbackRuleCount:        2,
		PolicyAttributeCount:     12,
		ComplianceCheckCount:     11,
		PassedCheckCount:         11,
		ExternalRequirementCount: 1,
		SummaryJSON:              string(summaryPayload),
		ReportJSON:               "{}",
		Actor:                    "ops@example.test",
		Profiles: []MobilePolicyControlProfileInput{
			{ProfileKey: "home-default", ProfileType: "policy_profile", Name: "home-default", Status: "ready", QoSClass: "default-5qi-9", RoamingPolicy: "home-plmn", AttributesJSON: `{"attributes":["Filter-Id"]}`, PlanFingerprint: strings.Repeat("b", 64)},
			{ProfileKey: "default-5qi-9", ProfileType: "qos_class", Name: "default-5qi-9", Status: "ready", QoSClass: "default-5qi-9", AttributesJSON: `{"qci":9}`, PlanFingerprint: strings.Repeat("b", 64)},
			{ProfileKey: "visited-lbo", ProfileType: "roaming_policy", Name: "visited-lbo", Status: "ready", RoamingPolicy: "visited-lbo", AttributesJSON: `{"realm":"roaming.example.net"}`, PlanFingerprint: strings.Repeat("b", 64)},
			{ProfileKey: "quota-threshold", ProfileType: "feedback_rule", Name: "quota-threshold", Status: "ready", TriggerName: "quota-threshold", AttributesJSON: `{"action":"coa"}`, PlanFingerprint: strings.Repeat("b", 64)},
		},
	})
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(eventID, "mobile-policy-"))

	events, err := ListMobilePolicyControlEvents(10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "applied", events[0].Status)
	assert.Equal(t, 3, events[0].PolicyProfileCount)
	assert.Equal(t, 3, events[0].QoSClassCount)
	assert.Equal(t, 2, events[0].RoamingPolicyCount)
	assert.Equal(t, 2, events[0].FeedbackRuleCount)
	assert.Equal(t, 12, events[0].PolicyAttributeCount)

	profiles, err := ListMobilePolicyControlProfiles(10, "")
	require.NoError(t, err)
	assert.Len(t, profiles, 4)

	qosClasses, err := ListMobilePolicyControlProfiles(10, "qos_class")
	require.NoError(t, err)
	require.Len(t, qosClasses, 1)
	assert.Equal(t, "default-5qi-9", qosClasses[0].QoSClass)

	summary, err := GetMobilePolicyControlSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TotalEvents)
	assert.Equal(t, 1, summary.ApplyEvents)
	assert.Equal(t, 1, summary.AppliedCount)
	assert.Equal(t, 4, summary.ReadyProfileCount)
	assert.Equal(t, 3, summary.LastPolicyProfileCount)
	assert.Equal(t, 3, summary.LastQoSClassCount)
	assert.Equal(t, 2, summary.LastRoamingPolicyCount)
	assert.Equal(t, 2, summary.LastFeedbackRuleCount)
	assert.Equal(t, 12, summary.LastPolicyAttributeCount)
	assert.NotEmpty(t, summary.LastFingerprint)
}
