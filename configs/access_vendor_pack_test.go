package configs

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildAccessVendorPackReportCertifiesPinnedRows(t *testing.T) {
	report, err := BuildAccessVendorPackReport()
	require.NoError(t, err)
	require.NoError(t, ValidateAccessVendorPackReport(report))

	assert.Equal(t, AccessVendorPackFeatureID, report.FeatureID)
	assert.Equal(t, AccessVendorPackExpectedAttributeCount, report.Summary.AttributeCount)
	assert.Equal(t, AccessVendorPackExpectedAttributeCount, report.Summary.SoftwareCertifiedMappings)
	assert.Equal(t, AccessVendorPackExpectedAttributeCount, report.Summary.ExternalRequiredMappings)
	assert.Equal(t, 3, report.Summary.VendorCount)
	assert.Equal(t, 2, report.Summary.SensitiveRedactedMappings)
	assert.Equal(t, float64(100), report.Summary.SoftwareCompletionPercent)
	assert.NotEmpty(t, report.Summary.Fingerprint)
	require.Len(t, report.Records, AccessVendorPackExpectedAttributeCount)
	require.GreaterOrEqual(t, len(report.Grammar), 10)
	require.GreaterOrEqual(t, len(report.ProductScopes), 9)

	byVendor := map[string]AccessVendorVendorSummary{}
	for _, summary := range report.VendorSummaries {
		byVendor[strings.ToLower(summary.Vendor)] = summary
	}
	assert.Equal(t, 31, byVendor["cambium"].AttributeCount)
	assert.Equal(t, 9, byVendor["dlink"].AttributeCount)
	assert.Equal(t, 9, byVendor["tplink"].AttributeCount)

	scopeLabels := map[string]bool{}
	for _, scope := range report.ProductScopes {
		scopeLabels[scope.Label] = true
	}
	assert.True(t, scopeLabels["Cambium cnMaestro Enterprise Wi-Fi"])
	assert.True(t, scopeLabels["Cambium ePMP / PMP Fixed Wireless"])
	assert.True(t, scopeLabels["TP-Link Omada Wireless"])
	assert.True(t, scopeLabels["TP-Link Portal and Key Exchange"])
	assert.True(t, scopeLabels["D-Link Access Switch Authorization"])
	assert.True(t, scopeLabels["D-Link Dynamic ACL Assignment"])
	assert.True(t, scopeLabels["Shared Access Vendor CoA Lifecycle"])
}

func TestAccessVendorPackReportClassifiesAccessCapabilityFamilies(t *testing.T) {
	report, err := BuildAccessVendorPackReport()
	require.NoError(t, err)

	records := map[string]AccessVendorAttributeRecord{}
	for _, record := range report.Records {
		records[record.Attribute] = record
	}

	assert.Equal(t, "cambium_authorize_class_tlv", records["Cambium-Authorize-Classes"].Capability)
	assert.Equal(t, "typed_tlv_evidence", records["Cambium-Authorize-Classes"].ImplementationClass)
	assert.Contains(t, records["Cambium-Authorize-Classes"].Semantic, VendorSemanticDataQuota)
	assert.Contains(t, records["Cambium-Authorize-Classes"].PacketProcessing, "grouped_tlv")

	assert.Equal(t, "cambium_quota_authorization", records["Cambium-Traffic-Quota-Limit-Total"].Capability)
	assert.Equal(t, "native_semantic_mapping", records["Cambium-Traffic-Quota-Limit-Total"].ImplementationClass)
	assert.Contains(t, records["Cambium-Traffic-Quota-Limit-Total"].Semantic, VendorSemanticDataQuota)

	assert.Equal(t, "tplink_auth_key_exchange", records["TPLink-Authentication-FindKey"].Capability)
	assert.Equal(t, "redacted_secret_evidence", records["TPLink-Authentication-FindKey"].ImplementationClass)
	assert.Contains(t, records["TPLink-Authentication-FindKey"].Storage, "no_cleartext_secret")

	assert.Equal(t, "dlink_dynamic_acl", records["Dlink-ACL-Script"].Capability)
	assert.Equal(t, "policy_parse_compile", records["Dlink-ACL-Script"].ImplementationClass)
	assert.Equal(t, VendorSemanticDynamicACL, records["Dlink-ACL-Script"].Semantic)

	assert.Equal(t, "dlink_qos_bandwidth", records["Dlink-1p-Priority"].Capability)
	assert.Equal(t, "native_semantic_mapping", records["Dlink-1p-Priority"].ImplementationClass)
	assert.Equal(t, VendorSemanticBandwidthProfile, records["Dlink-1p-Priority"].Semantic)
}
