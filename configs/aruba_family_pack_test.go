package configs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildArubaFamilyPackReportCertifiesPinnedDictionaryRows(t *testing.T) {
	report, err := BuildArubaFamilyPackReport()
	require.NoError(t, err)
	require.NoError(t, ValidateArubaFamilyPackReport(report))

	assert.Equal(t, ArubaFamilyPackFeatureID, report.FeatureID)
	assert.Equal(t, ArubaFamilyPackExpectedAttributeCount, report.Summary.AttributeCount)
	assert.Equal(t, ArubaFamilyPackExpectedAttributeCount, report.Summary.SoftwareCertifiedMappings)
	assert.Equal(t, ArubaFamilyPackExpectedAttributeCount, report.Summary.ExternalRequiredMappings)
	assert.Equal(t, 0, report.Summary.SoftwareBlockedMappings)
	assert.Equal(t, 4, report.Summary.VendorCount)
	assert.GreaterOrEqual(t, report.Summary.GrammarRuleCount, 14)
	assert.Greater(t, report.Summary.NativeSemanticMappings, 40)
	assert.Greater(t, report.Summary.TypedPassThroughMappings, 30)
	assert.Greater(t, report.Summary.SensitiveRedactedMappings, 0)
	assert.Equal(t, 100.0, report.Summary.SoftwareCompletionPercent)
	assert.NotEmpty(t, report.Summary.Fingerprint)
	assert.Equal(t, "docs/nas-0062-release-certification-checklist.md", report.ReleaseCertificationChecklist)

	byVendor := map[string]ArubaFamilyVendorSummary{}
	for _, vendor := range report.VendorSummaries {
		byVendor[vendor.Vendor] = vendor
	}
	assert.Equal(t, 71, byVendor["Aruba"].AttributeCount)
	assert.Equal(t, 32, byVendor["HP"].AttributeCount)
	assert.Equal(t, 21, byVendor["Aerohive"].AttributeCount)
	assert.Equal(t, 1, byVendor["Colubris"].AttributeCount)
}

func TestArubaFamilyPackReportClassifiesMajorCapabilityFamilies(t *testing.T) {
	report, err := BuildArubaFamilyPackReport()
	require.NoError(t, err)

	capabilities := map[string]int{}
	for _, summary := range report.CapabilitySummaries {
		capabilities[summary.Capability] = summary.AttributeCount
	}

	assert.Greater(t, capabilities["clearpass_role_and_command_authorization"], 0)
	assert.Greater(t, capabilities["acl_and_firewall_enforcement"], 0)
	assert.Greater(t, capabilities["mpsk_dpp_and_authentication_lifecycle"], 0)
	assert.Greater(t, capabilities["hp_admin_command_and_uri_authorization"], 0)
	assert.Greater(t, capabilities["aerohive_ppsk_and_authentication"], 0)
	assert.Greater(t, capabilities["colubris_hotspot_intercept_and_quarantine"], 0)
}
