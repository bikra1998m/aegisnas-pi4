package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
)

func TestJuniperExtremePackEventLifecycle(t *testing.T) {
	require.NoError(t, Init(":memory:"))
	defer Close()
	DB.SetMaxOpenConns(1)
	require.NoError(t, Migrate())

	var tableCount int
	require.NoError(t, DB.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='juniper_extreme_pack_events'").Scan(&tableCount))
	assert.Equal(t, 1, tableCount)

	report, err := productconfigs.BuildJuniperExtremePackReport()
	require.NoError(t, err)
	require.NoError(t, productconfigs.ValidateJuniperExtremePackReport(report))

	eventID, err := RecordJuniperExtremePackEvent(JuniperExtremePackEventInput{
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
		SummaryJSON:               `{"status":"ok"}`,
		ReportJSON:                `{"feature_id":"NAS-0063"}`,
		Actor:                     "tester",
	})
	require.NoError(t, err)
	assert.Contains(t, eventID, "nas-0063-")

	events, err := ListJuniperExtremePackEvents(5)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, eventID, events[0].EventID)
	assert.Equal(t, report.Summary.AttributeCount, events[0].AttributeCount)
	assert.Equal(t, report.Summary.SensitiveRedactedMappings, events[0].SensitiveRedactedMappings)
	assert.Equal(t, report.Summary.ProductScopeCount, events[0].ProductScopeCount)

	summary, err := GetJuniperExtremePackSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TotalEvents)
	assert.Equal(t, 1, summary.RecordedCount)
	assert.Equal(t, report.Summary.Fingerprint, summary.LastFingerprint)
	assert.Equal(t, productconfigs.JuniperExtremePackExpectedAttributeCount, summary.LastAttributeCount)
	assert.Equal(t, report.Summary.ProductScopeCount, summary.LastProductScopeCount)
}
