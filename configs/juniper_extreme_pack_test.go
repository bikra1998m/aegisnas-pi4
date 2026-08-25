package configs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildJuniperExtremePackReportCertifiesPinnedDictionaryRows(t *testing.T) {
	report, err := BuildJuniperExtremePackReport()
	require.NoError(t, err)
	require.NoError(t, ValidateJuniperExtremePackReport(report))

	assert.Equal(t, JuniperExtremePackFeatureID, report.FeatureID)
	assert.Equal(t, JuniperExtremePackExpectedAttributeCount, report.Summary.AttributeCount)
	assert.Equal(t, JuniperExtremePackExpectedAttributeCount, report.Summary.SoftwareCertifiedMappings)
	assert.Equal(t, JuniperExtremePackExpectedAttributeCount, report.Summary.ExternalRequiredMappings)
	assert.Equal(t, 0, report.Summary.SoftwareBlockedMappings)
	assert.Equal(t, 3, report.Summary.VendorCount)
	assert.Equal(t, 4, report.Summary.ProductScopeCount)
	assert.GreaterOrEqual(t, report.Summary.GrammarRuleCount, 12)
	assert.Greater(t, report.Summary.NativeSemanticMappings, 40)
	assert.Greater(t, report.Summary.TypedPassThroughMappings, 100)
	assert.Greater(t, report.Summary.SensitiveRedactedMappings, 0)
	assert.Equal(t, 100.0, report.Summary.SoftwareCompletionPercent)
	assert.NotEmpty(t, report.Summary.Fingerprint)
	assert.Equal(t, "docs/nas-0063-release-certification-checklist.md", report.ReleaseCertificationChecklist)

	byVendor := map[string]JuniperExtremeVendorSummary{}
	for _, vendor := range report.VendorSummaries {
		byVendor[vendor.Vendor] = vendor
	}
	assert.Equal(t, 206, byVendor["ERX"].AttributeCount)
	assert.Equal(t, 15, byVendor["Extreme"].AttributeCount)
	assert.Equal(t, 39, byVendor["Juniper"].AttributeCount)

	scopeKeys := map[string]bool{}
	for _, scope := range report.ProductScopes {
		scopeKeys[scope.Key] = true
	}
	assert.True(t, scopeKeys[VendorPackJuniper])
	assert.True(t, scopeKeys[VendorPackERX])
	assert.True(t, scopeKeys[VendorPackExtreme])
	assert.True(t, scopeKeys[VendorPackMist])
}

func TestJuniperExtremePackReportClassifiesMajorCapabilityFamilies(t *testing.T) {
	report, err := BuildJuniperExtremePackReport()
	require.NoError(t, err)

	capabilities := map[string]int{}
	for _, summary := range report.CapabilitySummaries {
		capabilities[summary.Capability] = summary.AttributeCount
	}

	assert.Greater(t, capabilities["junos_command_and_admin_authorization"], 0)
	assert.Greater(t, capabilities["junos_firewall_filter_and_avpair_policy"], 0)
	assert.Greater(t, capabilities["extreme_vlan_and_8021x_policy"], 0)
	assert.Greater(t, capabilities["extreme_vm_and_virtual_router_context"], 0)
	assert.Greater(t, capabilities["erx_bng_routing_addressing_and_ipv6"], 0)
	assert.Greater(t, capabilities["erx_broadband_subscriber_access_context"], 0)
	assert.Greater(t, capabilities["erx_qos_cos_and_access_line_rate"], 0)
	assert.Greater(t, capabilities["erx_dynamic_authorization"], 0)
	assert.Greater(t, capabilities["erx_secret_and_tunnel_authentication"], 0)
}
