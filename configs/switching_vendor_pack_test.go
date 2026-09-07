package configs

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSwitchingVendorPackReportSoftwareCertification(t *testing.T) {
	report, err := BuildSwitchingVendorPackReport()
	require.NoError(t, err)
	require.NoError(t, ValidateSwitchingVendorPackReport(report))

	assert.Equal(t, SwitchingVendorPackFeatureID, report.FeatureID)
	assert.Equal(t, SwitchingVendorPackExpectedAttributeCount, report.Summary.AttributeCount)
	assert.Equal(t, SwitchingVendorPackExpectedAttributeCount, report.Summary.SoftwareCertifiedMappings)
	assert.Equal(t, SwitchingVendorPackExpectedAttributeCount, report.Summary.ExternalRequiredMappings)
	assert.Equal(t, 8, report.Summary.VendorCount)
	assert.GreaterOrEqual(t, report.Summary.ProductScopeCount, 10)
	assert.GreaterOrEqual(t, report.Summary.GrammarRuleCount, 12)
	assert.NotEmpty(t, report.Summary.Fingerprint)
	require.Len(t, report.Records, SwitchingVendorPackExpectedAttributeCount)

	counts := map[string]int{}
	for _, record := range report.Records {
		counts[record.Vendor]++
		assert.Equal(t, SwitchingVendorSoftwareCertified, record.SoftwareState)
		assert.True(t, record.ReadyForExternalValidation)
		assert.True(t, record.ExternalValidationRequired)
		assert.NotEmpty(t, record.PacketProcessing)
		assert.NotEmpty(t, record.PolicyEngine)
		assert.NotEmpty(t, record.Storage)
	}
	assert.Equal(t, map[string]int{
		"3com":       12,
		"Arista":     10,
		"Brocade":    7,
		"DellEMC":    2,
		"Equallogic": 9,
		"Extreme":    15,
		"Force10":    1,
		"Foundry":    13,
	}, counts)
}

func TestSwitchingVendorPackAttributeClassifications(t *testing.T) {
	report, err := BuildSwitchingVendorPackReport()
	require.NoError(t, err)

	records := map[string]SwitchingVendorAttributeRecord{}
	for _, record := range report.Records {
		records[record.Attribute] = record
	}
	cases := []struct {
		attribute string
		semantic  string
		class     string
	}{
		{"3Com-VLAN-Name", VendorSemanticVLAN, "native_semantic_mapping"},
		{"Arista-BlockMac", VendorSemanticCoAReauth, "native_semantic_mapping"},
		{"Brocade-AVPairs1", VendorSemanticDynamicACL, "policy_parse_compile"},
		{"DellEMC-AVpair", VendorSemanticDynamicACL, "policy_parse_compile"},
		{"Equallogic-EQL-Admin-Privilege", VendorSemanticRole, "native_semantic_mapping"},
		{"Extreme-VM-VR-Name", VendorSemanticVRF, "native_semantic_mapping"},
		{"Force10-AVPair", VendorSemanticDynamicACL, "policy_parse_compile"},
		{"Foundry-COA-Command", VendorSemanticCoAReauth, "policy_parse_compile"},
	}
	for _, tc := range cases {
		record, ok := records[tc.attribute]
		require.True(t, ok, "record %s should exist", tc.attribute)
		assert.Contains(t, record.Semantic, tc.semantic)
		assert.Equal(t, tc.class, record.ImplementationClass)
	}
}

func TestSwitchingVendorRuntimeRegistryAnnotations(t *testing.T) {
	registry, err := BuiltInAttributeRegistry()
	require.NoError(t, err)
	require.NoError(t, registry.ValidateCompatibilityPacks(AegisNASVendorCompatibilityPacks()))

	cases := []struct {
		vendor    string
		attribute string
		packKey   string
		decoder   string
		semantic  string
	}{
		{"3com", "3Com-User-Access-Level", VendorPack3Com, "integer_text", VendorSemanticRole},
		{"Arista", "Arista-CVP-Role", VendorPackArista, "string", VendorSemanticRole},
		{"Brocade", "Brocade-AVPairs2", VendorPackBrocade, "avpairs", VendorSemanticDynamicACL},
		{"DellEMC", "DellEMC-AVpair", VendorPackDellEMC, "avpairs", VendorSemanticDynamicACL},
		{"Equallogic", "Equallogic-Admin-Pool-Access", VendorPackEquallogic, "string", VendorSemanticACL},
		{"Force10", "Force10-AVPair", VendorPackForce10, "avpairs", VendorSemanticDynamicACL},
	}
	for _, tc := range cases {
		entry, ok := findSwitchingVendorRegistryEntry(registry, tc.vendor, tc.attribute)
		require.True(t, ok, "registry entry %s/%s should exist", tc.vendor, tc.attribute)
		assert.Equal(t, tc.packKey, entry.PackKey)
		assert.Equal(t, tc.decoder, entry.DecodeKind)
		assert.Contains(t, entry.Semantic, tc.semantic)
		assert.Contains(t, entry.SemanticProvenance, "nas-0071")
	}
}

func findSwitchingVendorRegistryEntry(registry *AttributeRegistry, vendor, attribute string) (AttributeRegistryEntry, bool) {
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
