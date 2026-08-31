package configs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildRuckusICXPackReportCertifiesPinnedDictionaryRows(t *testing.T) {
	report, err := BuildRuckusICXPackReport()
	require.NoError(t, err)
	require.NoError(t, ValidateRuckusICXPackReport(report))

	assert.Equal(t, RuckusICXPackFeatureID, report.FeatureID)
	assert.Equal(t, RuckusICXPackExpectedAttributeCount, report.Summary.AttributeCount)
	assert.Equal(t, RuckusICXPackExpectedAttributeCount, report.Summary.SoftwareCertifiedMappings)
	assert.Equal(t, RuckusICXPackExpectedAttributeCount, report.Summary.ExternalRequiredMappings)
	assert.Equal(t, 0, report.Summary.SoftwareBlockedMappings)
	assert.Equal(t, 2, report.Summary.VendorCount)
	assert.Equal(t, 5, report.Summary.ProductScopeCount)
	assert.GreaterOrEqual(t, report.Summary.GrammarRuleCount, 12)
	assert.Greater(t, report.Summary.NativeSemanticMappings, 30)
	assert.Greater(t, report.Summary.TypedPassThroughMappings, 20)
	assert.Greater(t, report.Summary.SensitiveRedactedMappings, 0)
	assert.Equal(t, 100.0, report.Summary.SoftwareCompletionPercent)
	assert.NotEmpty(t, report.Summary.Fingerprint)
	assert.Equal(t, "docs/nas-0064-release-certification-checklist.md", report.ReleaseCertificationChecklist)

	byVendor := map[string]RuckusICXVendorSummary{}
	for _, vendor := range report.VendorSummaries {
		byVendor[vendor.Vendor] = vendor
	}
	assert.Equal(t, 13, byVendor["Foundry"].AttributeCount)
	assert.Equal(t, 84, byVendor["Ruckus"].AttributeCount)

	scopeKeys := map[string]bool{}
	scopeLabels := map[string]bool{}
	for _, scope := range report.ProductScopes {
		scopeKeys[scope.Key] = true
		scopeLabels[scope.Label] = true
	}
	assert.True(t, scopeKeys[VendorPackRuckus])
	assert.True(t, scopeKeys[VendorPackFoundry])
	assert.True(t, scopeLabels["Ruckus SmartZone"])
	assert.True(t, scopeLabels["Ruckus ZoneDirector"])
	assert.True(t, scopeLabels["Ruckus Unleashed"])
	assert.True(t, scopeLabels["Ruckus One"])
	assert.True(t, scopeLabels["Ruckus ICX / Foundry"])
}

func TestRuckusICXPackReportClassifiesMajorCapabilityFamilies(t *testing.T) {
	report, err := BuildRuckusICXPackReport()
	require.NoError(t, err)

	capabilities := map[string]int{}
	for _, summary := range report.CapabilitySummaries {
		capabilities[summary.Capability] = summary.AttributeCount
	}

	assert.Greater(t, capabilities["ruckus_dpsk_ppsk_authentication"], 0)
	assert.Greater(t, capabilities["ruckus_qos_quota_and_traffic_class"], 0)
	assert.Greater(t, capabilities["ruckus_guest_hotspot_and_captive_portal"], 0)
	assert.Greater(t, capabilities["ruckus_wlan_roaming_and_station_context"], 0)
	assert.Greater(t, capabilities["ruckus_accounting_and_session_telemetry"], 0)
	assert.Greater(t, capabilities["ruckus_mobile_core_offload_and_charging"], 0)
	assert.Greater(t, capabilities["foundry_icx_command_authorization"], 0)
	assert.Greater(t, capabilities["foundry_icx_acl_policy"], 0)
	assert.Greater(t, capabilities["foundry_icx_dynamic_authorization"], 0)
	assert.Greater(t, capabilities["foundry_icx_voice_device_policy"], 0)
}
