package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
)

func TestCloudControllerPackEventLifecycle(t *testing.T) {
	require.NoError(t, Init(":memory:"))
	DB.SetMaxOpenConns(1)
	t.Cleanup(func() { Close() })
	require.NoError(t, Migrate())

	var tableCount int
	require.NoError(t, DB.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='cloud_controller_pack_events'").Scan(&tableCount))
	assert.Equal(t, 1, tableCount)

	report, err := productconfigs.BuildCloudControllerPackReport()
	require.NoError(t, err)
	require.NoError(t, productconfigs.ValidateCloudControllerPackReport(report))

	eventID, err := RecordCloudControllerPackEvent(CloudControllerPackEventInput{
		Operation:                 "record",
		Status:                    "recorded",
		ReleaseProfileID:          report.ReleaseProfileID,
		SourceSHA256:              report.SourceSHA256,
		AttributeCount:            report.Summary.AttributeCount,
		NativeSemanticMappings:    report.Summary.NativeSemanticMappings,
		TypedPassThroughMappings:  report.Summary.TypedPassThroughMappings,
		SensitiveRedactedMappings: report.Summary.SensitiveRedactedMappings,
		GrammarRuleCount:          report.Summary.GrammarRuleCount,
		SoftwareCertifiedMappings: report.Summary.SoftwareCertifiedMappings,
		SoftwareBlockedMappings:   report.Summary.SoftwareBlockedMappings,
		ExternalRequiredMappings:  report.Summary.ExternalRequiredMappings,
		VendorCount:               report.Summary.VendorCount,
		ProductScopeCount:         report.Summary.ProductScopeCount,
		Fingerprint:               report.Summary.Fingerprint,
		SummaryJSON:               `{"attribute_count":7}`,
		ReportJSON:                `{"feature_id":"NAS-0066"}`,
		Actor:                     "ops",
	})
	require.NoError(t, err)
	assert.Contains(t, eventID, "nas-0066-")

	events, err := ListCloudControllerPackEvents(5)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "ops", events[0].Actor)
	assert.Equal(t, report.Summary.Fingerprint, events[0].Fingerprint)

	summary, err := GetCloudControllerPackSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TotalEvents)
	assert.Equal(t, 1, summary.RecordedCount)
	assert.Equal(t, productconfigs.CloudControllerPackExpectedAttributeCount, summary.LastAttributeCount)
	assert.Equal(t, productconfigs.CloudControllerPackExpectedAttributeCount, summary.LastSoftwareCertified)
	assert.Equal(t, productconfigs.CloudControllerPackExpectedAttributeCount, summary.LastExternalRequired)
	assert.Equal(t, 3, summary.LastVendorCount)
}
