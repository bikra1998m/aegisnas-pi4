package configs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildCloudControllerPackReportCertifiesPinnedAndRuntimeRows(t *testing.T) {
	report, err := BuildCloudControllerPackReport()
	require.NoError(t, err)
	require.NoError(t, ValidateCloudControllerPackReport(report))

	assert.Equal(t, CloudControllerPackFeatureID, report.FeatureID)
	assert.Equal(t, CloudControllerPackExpectedAttributeCount, report.Summary.AttributeCount)
	assert.Equal(t, CloudControllerPackExpectedAttributeCount, report.Summary.SoftwareCertifiedMappings)
	assert.Equal(t, CloudControllerPackExpectedAttributeCount, report.Summary.ExternalRequiredMappings)
	assert.Equal(t, 0, report.Summary.SoftwareBlockedMappings)
	assert.Equal(t, 3, report.Summary.VendorCount)
	assert.GreaterOrEqual(t, report.Summary.ProductScopeCount, 8)
	assert.GreaterOrEqual(t, report.Summary.GrammarRuleCount, 9)
	assert.Equal(t, CloudControllerPackExpectedAttributeCount, report.Summary.NativeSemanticMappings)
	assert.Equal(t, 0, report.Summary.SensitiveRedactedMappings)
	assert.Equal(t, 100.0, report.Summary.SoftwareCompletionPercent)
	assert.NotEmpty(t, report.Summary.Fingerprint)
	assert.Equal(t, "docs/nas-0066-release-certification-checklist.md", report.ReleaseCertificationChecklist)

	byVendor := map[string]CloudControllerVendorSummary{}
	for _, vendor := range report.VendorSummaries {
		byVendor[vendor.Vendor] = vendor
	}
	assert.Equal(t, 4, byVendor["Meraki"].AttributeCount)
	assert.Equal(t, 1, byVendor["OpenWiFi"].AttributeCount)
	assert.Equal(t, 2, byVendor["Ubiquiti"].AttributeCount)

	scopeLabels := map[string]bool{}
	for _, scope := range report.ProductScopes {
		scopeLabels[scope.Label] = true
	}
	assert.True(t, scopeLabels["Cisco Meraki MR RADIUS Telemetry"])
	assert.True(t, scopeLabels["Cisco Meraki Dashboard SSID Sync"])
	assert.True(t, scopeLabels["UniFi Network RADIUS Rate VSAs"])
	assert.True(t, scopeLabels["UniFi Network WiFi Broadcast Sync"])
	assert.True(t, scopeLabels["TIP OpenWiFi RADIUS Telemetry"])
	assert.True(t, scopeLabels["TIP OpenWiFi uCentral Sync"])
	assert.True(t, scopeLabels["Shared Cloud Adapter Lifecycle"])
}

func TestCloudControllerPackReportClassifiesCloudCapabilityFamilies(t *testing.T) {
	report, err := BuildCloudControllerPackReport()
	require.NoError(t, err)

	capabilities := map[string]int{}
	for _, summary := range report.CapabilitySummaries {
		capabilities[summary.Capability] = summary.AttributeCount
	}

	assert.Equal(t, 1, capabilities["meraki_device_nas_context"])
	assert.Equal(t, 1, capabilities["meraki_dashboard_network_tenant"])
	assert.Equal(t, 1, capabilities["meraki_ap_accounting_identity"])
	assert.Equal(t, 1, capabilities["meraki_ap_tag_posture"])
	assert.Equal(t, 2, capabilities["unifi_ubnt_rate_limit_qos"])
	assert.Equal(t, 1, capabilities["openwifi_ap_mac_accounting_identity"])
}
