package configs

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLongTailNamespaceReportSoftwareCertification(t *testing.T) {
	report, err := BuildLongTailNamespaceReport()
	require.NoError(t, err)
	require.NoError(t, ValidateLongTailNamespaceReport(report))

	assert.Equal(t, LongTailNamespaceFeatureID, report.FeatureID)
	assert.Equal(t, LongTailNamespaceExpectedAttributeCount, report.Summary.AttributeCount)
	assert.Equal(t, LongTailNamespaceExpectedAttributeCount, report.Summary.SoftwareCertifiedMappings)
	assert.Equal(t, LongTailNamespaceExpectedAttributeCount, report.Summary.ExternalRequiredMappings)
	assert.Equal(t, LongTailNamespaceExpectedVendorCount, report.Summary.VendorCount)
	assert.GreaterOrEqual(t, report.Summary.ProductScopeCount, 12)
	assert.GreaterOrEqual(t, report.Summary.GrammarRuleCount, 16)
	assert.NotEmpty(t, report.Summary.Fingerprint)
	require.Len(t, report.Records, LongTailNamespaceExpectedAttributeCount)

	counts := map[string]int{}
	for _, record := range report.Records {
		counts[record.Vendor]++
		assert.Equal(t, LongTailNamespaceSoftwareCertified, record.SoftwareState)
		assert.True(t, record.ReadyForExternalValidation)
		assert.True(t, record.ExternalValidationRequired)
		assert.NotEmpty(t, record.PacketProcessing)
		assert.NotEmpty(t, record.PolicyEngine)
		assert.NotEmpty(t, record.Storage)
	}
	assert.Equal(t, LongTailNamespaceExpectedVendorCount, len(counts))
	assert.Greater(t, counts["Airespace"], 0)
	assert.Greater(t, counts["Nomadix"], 0)
	assert.Greater(t, counts["WISPr"], 0)
	assert.Greater(t, counts["Yubico"], 0)
}

func TestLongTailNamespaceAttributeClassifications(t *testing.T) {
	report, err := BuildLongTailNamespaceReport()
	require.NoError(t, err)

	records := map[string]LongTailNamespaceAttributeRecord{}
	for _, record := range report.Records {
		records[record.Attribute] = record
	}
	cases := []struct {
		attribute string
		semantic  string
		class     string
	}{
		{"ACL-Name", VendorSemanticDynamicACL, "policy_parse_compile"},
		{"Airespace-Wlan-Id", VendorSemanticVLAN, "native_semantic_mapping"},
		{"Nomadix-URL-Redirection", VendorSemanticPortalProfile, "native_semantic_mapping"},
		{"Nomadix-Net-VLAN", VendorSemanticVLAN, "native_semantic_mapping"},
		{"Pica8-IP-Downloadable-ACL-Rule", VendorSemanticDynamicACL, "policy_parse_compile"},
		{"WISPr-Bandwidth-Max-Up", VendorSemanticUploadBandwidth, "native_semantic_mapping"},
	}
	for _, tc := range cases {
		record, ok := records[tc.attribute]
		require.True(t, ok, "record %s should exist", tc.attribute)
		assert.Contains(t, record.Semantic, tc.semantic)
		assert.Equal(t, tc.class, record.ImplementationClass)
	}

	redacted := 0
	for _, record := range report.Records {
		if record.ImplementationClass == "redacted_secret_evidence" {
			redacted++
			assert.Contains(t, record.Storage, "hash")
		}
	}
	assert.Greater(t, redacted, 0)
}

func TestLongTailNamespaceRuntimeRegistryAnnotations(t *testing.T) {
	registry, err := BuiltInAttributeRegistry()
	require.NoError(t, err)
	require.NoError(t, registry.ValidateCompatibilityPacks(AegisNASVendorCompatibilityPacks()))

	cases := []struct {
		vendor    string
		attribute string
		semantic  string
	}{
		{"Airespace", "ACL-Name", VendorSemanticDynamicACL},
		{"Nomadix", "Nomadix-URL-Redirection", VendorSemanticPortalProfile},
		{"Pica8", "Pica8-IP-Downloadable-ACL-Rule", VendorSemanticDynamicACL},
		{"WISPr", "WISPr-Bandwidth-Max-Down", VendorSemanticDownloadBandwidth},
	}
	for _, tc := range cases {
		entry, ok := findLongTailNamespaceRegistryEntry(registry, tc.vendor, tc.attribute)
		require.True(t, ok, "registry entry %s/%s should exist", tc.vendor, tc.attribute)
		assert.NotEmpty(t, entry.PackKey)
		assert.NotEmpty(t, entry.DecodeKind)
		assert.Contains(t, entry.Semantic, tc.semantic)
		assert.Contains(t, entry.SemanticProvenance, "nas-0072")
	}

	longTailRuntimeMappings := 0
	for _, mapping := range registry.RuntimeMappings() {
		if mapping.PackKey == VendorPackLongTail {
			longTailRuntimeMappings++
		}
	}
	assert.Greater(t, longTailRuntimeMappings, 700)
}

func TestLongTailNamespaceVendorScopeMatchesRoadmap(t *testing.T) {
	report, err := BuildLongTailNamespaceReport()
	require.NoError(t, err)

	assert.Equal(t, LongTailNamespaceExpectedVendorCount, countLongTailNamespaceVendors(report.Records))
	for _, vendor := range []string{"Actelis", "Aptilo", "Big-Switch-Networks", "F5", "FreeRADIUS", "Infoblox", "Nomadix", "pfSense", "Yubico", "Zeus"} {
		assert.True(t, isLongTailNamespaceVendor(vendor), "vendor %s should be in NAS-0072", vendor)
	}
}

func findLongTailNamespaceRegistryEntry(registry *AttributeRegistry, vendor, attribute string) (AttributeRegistryEntry, bool) {
	if registry == nil {
		return AttributeRegistryEntry{}, false
	}
	for _, entry := range registry.Entries {
		if strings.EqualFold(entry.Vendor, vendor) && strings.EqualFold(entry.Attribute, attribute) {
			return entry, true
		}
	}
	return AttributeRegistryEntry{}, false
}
