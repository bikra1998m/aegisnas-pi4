package db

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecordMobileChargingEventPersistsEvidence(t *testing.T) {
	previousDB := DB
	require.NoError(t, Init(":memory:"))
	DB.SetMaxOpenConns(1)
	require.NoError(t, Migrate())
	t.Cleanup(func() {
		_ = Close()
		DB = previousDB
	})

	summaryPayload, err := json.Marshal(map[string]any{"status": "ready", "streams": 3})
	require.NoError(t, err)
	eventID, err := RecordMobileChargingEvent(MobileChargingEventInput{
		Operation:                 "apply",
		Status:                    "applied",
		PlanFingerprint:           strings.Repeat("a", 64),
		Mode:                      "enforce",
		StreamCount:               3,
		RatingGroupCount:          2,
		QuotaPolicyCount:          2,
		CorrelationAttributeCount: 6,
		MediationReferenceCount:   4,
		ComplianceCheckCount:      9,
		PassedCheckCount:          9,
		ExternalRequirementCount:  1,
		SummaryJSON:               string(summaryPayload),
		ReportJSON:                "{}",
		Actor:                     "ops@example.test",
		Profiles: []MobileChargingProfileInput{
			{ProfileKey: "ocs-online", ProfileType: "stream", Name: "OCS online", Status: "ready", StreamType: "online", AttributesJSON: `{"attributes":["3GPP-Charging-ID"]}`, PlanFingerprint: strings.Repeat("a", 64)},
			{ProfileKey: "internet-data", ProfileType: "rating_group", Name: "internet-data", Status: "ready", RatingGroup: 1001, AttributesJSON: `{"unit":"octets"}`, PlanFingerprint: strings.Repeat("a", 64)},
			{ProfileKey: "default-data-quota", ProfileType: "quota_policy", Name: "default-data-quota", Status: "ready", QuotaUnit: "octets", AttributesJSON: `{"grant":1073741824}`, PlanFingerprint: strings.Repeat("a", 64)},
		},
	})
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(eventID, "mobile-charging-"))

	events, err := ListMobileChargingEvents(10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "applied", events[0].Status)
	assert.Equal(t, 3, events[0].StreamCount)
	assert.Equal(t, 2, events[0].RatingGroupCount)
	assert.Equal(t, 2, events[0].QuotaPolicyCount)
	assert.Equal(t, 6, events[0].CorrelationAttributeCount)
	assert.Equal(t, 4, events[0].MediationReferenceCount)

	profiles, err := ListMobileChargingProfiles(10, "")
	require.NoError(t, err)
	assert.Len(t, profiles, 3)

	streams, err := ListMobileChargingProfiles(10, "stream")
	require.NoError(t, err)
	require.Len(t, streams, 1)
	assert.Equal(t, "online", streams[0].StreamType)

	summary, err := GetMobileChargingSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TotalEvents)
	assert.Equal(t, 1, summary.ApplyEvents)
	assert.Equal(t, 1, summary.AppliedCount)
	assert.Equal(t, 3, summary.ReadyProfileCount)
	assert.Equal(t, 3, summary.LastStreamCount)
	assert.Equal(t, 2, summary.LastRatingGroupCount)
	assert.Equal(t, 2, summary.LastQuotaPolicyCount)
	assert.Equal(t, 6, summary.LastCorrelationAttributeCount)
	assert.Equal(t, 4, summary.LastMediationReferenceCount)
	assert.NotEmpty(t, summary.LastFingerprint)
}
