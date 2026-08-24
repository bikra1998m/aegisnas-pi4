package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCiscoFamilyPackEventLifecycle(t *testing.T) {
	require.NoError(t, Init(":memory:"))
	defer Close()
	DB.SetMaxOpenConns(1)
	require.NoError(t, Migrate())

	var tableCount int
	require.NoError(t, DB.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='cisco_family_pack_events'").Scan(&tableCount))
	assert.Equal(t, 1, tableCount)

	eventID, err := RecordCiscoFamilyPackEvent(CiscoFamilyPackEventInput{
		Operation:                 "record",
		Status:                    "recorded",
		ReleaseProfileID:          "freeradius-3.2.8",
		SourceSHA256:              "source-hash",
		AttributeCount:            922,
		NativeSemanticMappings:    14,
		TypedPassThroughMappings:  908,
		GrammarRuleCount:          17,
		SoftwareCertifiedMappings: 922,
		ExternalRequiredMappings:  922,
		VendorCount:               8,
		Fingerprint:               "fingerprint",
		SummaryJSON:               `{"attribute_count":922}`,
		ReportJSON:                `{"feature_id":"NAS-0061"}`,
		Actor:                     "ops",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, eventID)

	events, err := ListCiscoFamilyPackEvents(5)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "recorded", events[0].Status)
	assert.Equal(t, 922, events[0].AttributeCount)
	assert.Equal(t, 17, events[0].GrammarRuleCount)
	assert.Equal(t, "ops", events[0].Actor)

	summary, err := GetCiscoFamilyPackSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TotalEvents)
	assert.Equal(t, 1, summary.RecordedCount)
	assert.Equal(t, 922, summary.LastAttributeCount)
	assert.Equal(t, 922, summary.LastSoftwareCertified)
	assert.Equal(t, "fingerprint", summary.LastFingerprint)
}
