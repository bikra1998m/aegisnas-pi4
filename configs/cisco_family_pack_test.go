package configs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildCiscoFamilyPackReportCertifiesPinnedDictionaryRows(t *testing.T) {
	report, err := BuildCiscoFamilyPackReport()
	require.NoError(t, err)
	require.NoError(t, ValidateCiscoFamilyPackReport(report))

	assert.Equal(t, CiscoFamilyPackFeatureID, report.FeatureID)
	assert.Equal(t, CiscoFamilyPackExpectedAttributeCount, report.Summary.AttributeCount)
	assert.Equal(t, CiscoFamilyPackExpectedAttributeCount, report.Summary.SoftwareCertifiedMappings)
	assert.Equal(t, CiscoFamilyPackExpectedAttributeCount, report.Summary.ExternalRequiredMappings)
	assert.Equal(t, 0, report.Summary.SoftwareBlockedMappings)
	assert.Equal(t, 8, report.Summary.VendorCount)
	assert.GreaterOrEqual(t, report.Summary.GrammarRuleCount, 12)
	assert.Greater(t, report.Summary.NativeSemanticMappings, 0)
	assert.Greater(t, report.Summary.TypedPassThroughMappings, 700)
	assert.Equal(t, 100.0, report.Summary.SoftwareCompletionPercent)
	assert.NotEmpty(t, report.Summary.Fingerprint)
	assert.Equal(t, "docs/nas-0061-release-certification-checklist.md", report.ReleaseCertificationChecklist)

	byVendor := map[string]CiscoFamilyVendorSummary{}
	for _, vendor := range report.VendorSummaries {
		byVendor[vendor.Vendor] = vendor
	}
	assert.Equal(t, 110, byVendor["Cisco"].AttributeCount)
	assert.Equal(t, 149, byVendor["Cisco-ASA"].AttributeCount)
	assert.Equal(t, 520, byVendor["Starent"].AttributeCount)
	assert.Equal(t, 4, byVendor["Meraki"].AttributeCount)
}

func TestCiscoFamilyPackReportClassifiesMajorCapabilityFamilies(t *testing.T) {
	report, err := BuildCiscoFamilyPackReport()
	require.NoError(t, err)

	capabilities := map[string]int{}
	for _, summary := range report.CapabilitySummaries {
		capabilities[summary.Capability] = summary.AttributeCount
	}

	assert.Greater(t, capabilities["remote_access_vpn_policy"], 0)
	assert.Greater(t, capabilities["mobile_core_charging_and_accounting"], 0)
	assert.Greater(t, capabilities["enterprise_wireless_wlc_policy"], 0)
	assert.Greater(t, capabilities["controller_and_cloud_accounting_context"], 0)
	assert.Greater(t, capabilities["cisco_avpair_grammar"], 0)
}
