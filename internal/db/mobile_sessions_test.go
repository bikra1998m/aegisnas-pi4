package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMobileSessionEventPersistence(t *testing.T) {
	previousDB := DB
	require.NoError(t, Init(":memory:"))
	DB.SetMaxOpenConns(1)
	require.NoError(t, Migrate())
	t.Cleanup(func() {
		_ = Close()
		DB = previousDB
	})

	eventID, err := RecordMobileSessionEvent(MobileSessionEventInput{
		Operation:                "apply",
		Status:                   "applied",
		PlanFingerprint:          "sha256:test-mobile-session",
		Mode:                     "enforce",
		APNProfileCount:          2,
		BearerTemplateCount:      2,
		RoamingPartnerCount:      2,
		RadiusAttributeCount:     14,
		StateStepCount:           6,
		ComplianceCheckCount:     7,
		PassedCheckCount:         7,
		ExternalRequirementCount: 1,
		SummaryJSON:              `{"status":"ready"}`,
		ReportJSON:               `{"feature_id":"NAS-0093"}`,
		Actor:                    "ops@example.test",
		Profiles: []MobileSessionProfileInput{
			{ProfileKey: "internet", ProfileType: "apn", Name: "default-internet", Status: "ready", APN: "internet", AttributesJSON: `{"apn":"internet"}`, PlanFingerprint: "sha256:test-mobile-session"},
			{ProfileKey: "default-bearer", ProfileType: "bearer", Name: "default-bearer", Status: "ready", BearerType: "default", AttributesJSON: `{"bearer_type":"default"}`, PlanFingerprint: "sha256:test-mobile-session"},
			{ProfileKey: "home-plmn", ProfileType: "roaming", Name: "home-plmn", Status: "ready", Realm: "mnc001.mcc001.3gppnetwork.org", AttributesJSON: `{"realm":"mnc001.mcc001.3gppnetwork.org"}`, PlanFingerprint: "sha256:test-mobile-session"},
		},
	})
	require.NoError(t, err)
	assert.NotEmpty(t, eventID)
	assert.Contains(t, eventID, "mobile-session-")

	events, err := ListMobileSessionEvents(5)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "apply", events[0].Operation)
	assert.Equal(t, "applied", events[0].Status)
	assert.Contains(t, events[0].ReportJSON, "NAS-0093")

	profiles, err := ListMobileSessionProfiles(10, "")
	require.NoError(t, err)
	require.Len(t, profiles, 3)

	apns, err := ListMobileSessionProfiles(10, "apn")
	require.NoError(t, err)
	require.Len(t, apns, 1)
	assert.Equal(t, "internet", apns[0].APN)

	summary, err := GetMobileSessionSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TotalEvents)
	assert.Equal(t, 1, summary.ApplyEvents)
	assert.Equal(t, 1, summary.AppliedCount)
	assert.Equal(t, 3, summary.ReadyProfileCount)
	assert.Equal(t, 2, summary.LastAPNProfileCount)
	assert.Equal(t, 2, summary.LastBearerTemplateCount)
	assert.Equal(t, 2, summary.LastRoamingPartnerCount)
	assert.Equal(t, 14, summary.LastRadiusAttributeCount)
	assert.Equal(t, 6, summary.LastStateStepCount)
}
