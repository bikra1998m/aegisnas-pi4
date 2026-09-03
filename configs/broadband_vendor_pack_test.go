package configs

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildBroadbandVendorPackReportCertifiesPinnedRows(t *testing.T) {
	report, err := BuildBroadbandVendorPackReport()
	require.NoError(t, err)
	require.NoError(t, ValidateBroadbandVendorPackReport(report))

	assert.Equal(t, BroadbandVendorPackFeatureID, report.FeatureID)
	assert.Equal(t, BroadbandVendorPackExpectedAttributeCount, report.Summary.AttributeCount)
	assert.Equal(t, BroadbandVendorPackExpectedAttributeCount, report.Summary.SoftwareCertifiedMappings)
	assert.Equal(t, BroadbandVendorPackExpectedAttributeCount, report.Summary.ExternalRequiredMappings)
	assert.Equal(t, 3, report.Summary.VendorCount)
	assert.Equal(t, 3, report.Summary.SensitiveRedactedMappings)
	assert.Equal(t, float64(100), report.Summary.SoftwareCompletionPercent)
	assert.NotEmpty(t, report.Summary.Fingerprint)
	require.Len(t, report.Records, BroadbandVendorPackExpectedAttributeCount)
	require.GreaterOrEqual(t, len(report.Grammar), 14)
	require.GreaterOrEqual(t, len(report.ProductScopes), 10)

	byVendor := map[string]BroadbandVendorVendorSummary{}
	for _, summary := range report.VendorSummaries {
		byVendor[strings.ToLower(summary.Vendor)] = summary
	}
	assert.Equal(t, 197, byVendor["huawei"].AttributeCount)
	assert.Equal(t, 62, byVendor["h3c"].AttributeCount)
	assert.Equal(t, 49, byVendor["zte"].AttributeCount)

	scopeLabels := map[string]bool{}
	for _, scope := range report.ProductScopes {
		scopeLabels[scope.Label] = true
	}
	assert.True(t, scopeLabels["Huawei BRAS/BNG Subscriber Access"])
	assert.True(t, scopeLabels["Huawei NAT, DS-Lite, PCP, And Lawful-Intercept Boundary"])
	assert.True(t, scopeLabels["H3C Broadband NAT And Multicast"])
	assert.True(t, scopeLabels["ZTE Broadband QoS And IPv6 Rate Policy"])
	assert.True(t, scopeLabels["Shared Broadband CoA And Disconnect"])
}

func TestBroadbandVendorPackReportClassifiesBroadbandFamilies(t *testing.T) {
	report, err := BuildBroadbandVendorPackReport()
	require.NoError(t, err)

	records := map[string]BroadbandVendorAttributeRecord{}
	for _, record := range report.Records {
		records[record.Attribute] = record
	}

	assert.Equal(t, "huawei_qos_rate", records["Huawei-Input-Average-Rate"].Capability)
	assert.Equal(t, "native_semantic_mapping", records["Huawei-Input-Average-Rate"].ImplementationClass)
	assert.Equal(t, VendorSemanticUploadBandwidth, records["Huawei-Input-Average-Rate"].Semantic)

	assert.Equal(t, "huawei_address_route_pool", records["Huawei-Delegated-IPv6-Prefix-Pool"].Capability)
	assert.Contains(t, records["Huawei-Delegated-IPv6-Prefix-Pool"].Semantic, VendorSemanticDelegatedIPv6Prefix)

	assert.Equal(t, "huawei_nat_translation", records["Huawei-NAT-Public-Address"].Capability)
	assert.Equal(t, VendorSemanticTranslationPublicIPv4, records["Huawei-NAT-Public-Address"].Semantic)

	assert.Equal(t, "redacted_secret_evidence", records["Huawei-User-Password"].ImplementationClass)
	assert.Contains(t, records["Huawei-User-Password"].Storage, "no_cleartext_secret")

	assert.Equal(t, "h3c_nat_translation", records["H3C-NAT-IP-Address"].Capability)
	assert.Equal(t, VendorSemanticTranslationPublicIPv4, records["H3C-NAT-IP-Address"].Semantic)

	assert.Equal(t, "h3c_subscriber_service", records["H3C-Subscriber-ID"].Capability)
	assert.Contains(t, records["H3C-Subscriber-ID"].Semantic, VendorSemanticAccountingIdentity)

	assert.Equal(t, "zte_portal_hotspot", records["ZTE-PPPOE-URL"].Capability)
	assert.Contains(t, records["ZTE-PPPOE-URL"].Semantic, VendorSemanticPortalProfile)

	assert.Equal(t, "zte_qos_rate", records["ZTE-Rate-Ctrl-SCR-Up-v6"].Capability)
	assert.Equal(t, VendorSemanticUploadBandwidth, records["ZTE-Rate-Ctrl-SCR-Up-v6"].Semantic)

	assert.Equal(t, "zte_multicast_service", records["ZTE-Mcast-MaxGroups"].Capability)
	assert.Contains(t, records["ZTE-Mcast-MaxGroups"].Semantic, VendorSemanticPolicyTag)
}
