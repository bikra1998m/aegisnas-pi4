package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestArubaFamilyPackEventLifecycle(t *testing.T) {
	require.NoError(t, Init(":memory:"))
	defer Close()
	DB.SetMaxOpenConns(1)
	require.NoError(t, Migrate())

	var tableCount int
	require.NoError(t, DB.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='aruba_family_pack_events'").Scan(&tableCount))
	assert.Equal(t, 1, tableCount)

	eventID, err := RecordArubaFamilyPackEvent(ArubaFamilyPackEventInput{
		Operation:                 "record",
		Status:                    "recorded",
		ReleaseProfileID:          "freeradius-3.2.8",
		SourceSHA256:              "source-hash",
		AttributeCount:            125,
		NativeSemanticMappings:    58,
		TypedPassThroughMappings:  67,
		GrammarRuleCount:          16,
		SoftwareCertifiedMappings: 125,
		ExternalRequiredMappings:  125,
		VendorCount:               4,
		Fingerprint:               "fingerprint",
		SummaryJSON:               `{"attribute_count":125}`,
		ReportJSON:                `{"feature_id":"NAS-0062"}`,
		Actor:                     "ops",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, eventID)

	events, err := ListArubaFamilyPackEvents(5)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "recorded", events[0].Status)
	assert.Equal(t, 125, events[0].AttributeCount)
	assert.Equal(t, 16, events[0].GrammarRuleCount)
	assert.Equal(t, "ops", events[0].Actor)

	summary, err := GetArubaFamilyPackSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TotalEvents)
	assert.Equal(t, 1, summary.RecordedCount)
	assert.Equal(t, 125, summary.LastAttributeCount)
	assert.Equal(t, 125, summary.LastSoftwareCertified)
	assert.Equal(t, "fingerprint", summary.LastFingerprint)
}
