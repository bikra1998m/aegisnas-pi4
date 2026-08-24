package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVendorMappingCertificationEventLedger(t *testing.T) {
	require.NoError(t, Init(":memory:"))
	defer Close()
	DB.SetMaxOpenConns(1)
	require.NoError(t, Migrate())

	var tableCount int
	require.NoError(t, DB.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='vendor_mapping_certification_events'").Scan(&tableCount))
	assert.Equal(t, 1, tableCount)

	eventID, err := RecordVendorMappingCertificationEvent(VendorMappingCertificationEventInput{
		Operation:                "record",
		Status:                   "recorded",
		ReleaseProfileID:         "freeradius-3.2.8",
		SourceSHA256:             "0123456789abcdef",
		BaselinePartialMappings:  141,
		CertifiedMappings:        141,
		ExternalRequiredMappings: 141,
		VendorCount:              28,
		Fingerprint:              "sha256:test",
		SummaryJSON:              `{"certified_mappings":141}`,
		ReportJSON:               `{"records":[]}`,
		Actor:                    "ops",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, eventID)

	events, err := ListVendorMappingCertificationEvents(10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, eventID, events[0].EventID)
	assert.Equal(t, "recorded", events[0].Status)
	assert.Equal(t, 141, events[0].CertifiedMappings)
	assert.Equal(t, "ops", events[0].Actor)

	summary, err := GetVendorMappingCertificationSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TotalEvents)
	assert.Equal(t, 1, summary.RecordedCount)
	assert.Equal(t, "sha256:test", summary.LastFingerprint)
	assert.Equal(t, 141, summary.LastCertifiedMappings)
	assert.Equal(t, 141, summary.LastExternalRequired)
	assert.Equal(t, "freeradius-3.2.8", summary.LastReleaseProfileID)
}
