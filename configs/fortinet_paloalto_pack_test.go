package configs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildFortinetPaloAltoPackReportCertifiesPinnedDictionaryRows(t *testing.T) {
	report, err := BuildFortinetPaloAltoPackReport()
	require.NoError(t, err)
	require.NoError(t, ValidateFortinetPaloAltoPackReport(report))

	assert.Equal(t, FortinetPaloAltoPackFeatureID, report.FeatureID)
	assert.Equal(t, FortinetPaloAltoPackExpectedAttributeCount, report.Summary.AttributeCount)
	assert.Equal(t, FortinetPaloAltoPackExpectedAttributeCount, report.Summary.SoftwareCertifiedMappings)
	assert.Equal(t, FortinetPaloAltoPackExpectedAttributeCount, report.Summary.ExternalRequiredMappings)
	assert.Equal(t, 0, report.Summary.SoftwareBlockedMappings)
	assert.Equal(t, 2, report.Summary.VendorCount)
	assert.GreaterOrEqual(t, report.Summary.ProductScopeCount, 7)
	assert.GreaterOrEqual(t, report.Summary.GrammarRuleCount, 10)
	assert.Greater(t, report.Summary.NativeSemanticMappings, 20)
	assert.Greater(t, report.Summary.SensitiveRedactedMappings, 0)
	assert.Equal(t, 100.0, report.Summary.SoftwareCompletionPercent)
	assert.NotEmpty(t, report.Summary.Fingerprint)
	assert.Equal(t, "docs/nas-0065-release-certification-checklist.md", report.ReleaseCertificationChecklist)

	byVendor := map[string]FortinetPaloAltoVendorSummary{}
	for _, vendor := range report.VendorSummaries {
		byVendor[vendor.Vendor] = vendor
	}
	assert.Equal(t, 32, byVendor["Fortinet"].AttributeCount)
	assert.Equal(t, 10, byVendor["PaloAlto"].AttributeCount)

	scopeLabels := map[string]bool{}
	for _, scope := range report.ProductScopes {
		scopeLabels[scope.Label] = true
	}
	assert.True(t, scopeLabels["Fortinet FortiGate / FortiWiFi"])
	assert.True(t, scopeLabels["Fortinet FortiAuthenticator"])
	assert.True(t, scopeLabels["Fortinet FortiNAC"])
	assert.True(t, scopeLabels["Fortinet FortiWAN"])
	assert.True(t, scopeLabels["Palo Alto PAN-OS / GlobalProtect"])
	assert.True(t, scopeLabels["Palo Alto Panorama"])
}

func TestFortinetPaloAltoPackReportClassifiesMajorCapabilityFamilies(t *testing.T) {
	report, err := BuildFortinetPaloAltoPackReport()
	require.NoError(t, err)

	capabilities := map[string]int{}
	for _, summary := range report.CapabilitySummaries {
		capabilities[summary.Capability] = summary.AttributeCount
	}

	assert.Greater(t, capabilities["fortinet_fortiauthenticator_challenge"], 0)
	assert.Greater(t, capabilities["fortinet_web_filter_policy"], 0)
	assert.Greater(t, capabilities["fortinet_application_control_policy"], 0)
	assert.Greater(t, capabilities["fortinet_wlan_controller_context"], 0)
	assert.Greater(t, capabilities["fortinet_fortiwan_host_port_avpair_policy"], 0)
	assert.Greater(t, capabilities["fortinet_fdd_admin_security_policy"], 0)
	assert.Greater(t, capabilities["paloalto_panos_admin_authorization"], 0)
	assert.Greater(t, capabilities["paloalto_userid_context"], 0)
	assert.Greater(t, capabilities["paloalto_globalprotect_posture"], 0)
	assert.Greater(t, capabilities["paloalto_panorama_admin_domain"], 0)
}
