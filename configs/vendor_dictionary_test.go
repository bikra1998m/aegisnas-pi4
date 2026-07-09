package configs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAegisNASVendorDictionary(t *testing.T) {
	dict := AegisNASVendorDictionary()

	assert.Equal(t, "AegisNAS", dict.Name)
	assert.Equal(t, 55555, dict.ID)
	require.Len(t, dict.Attributes, 13)
	assert.Equal(t, VendorDictionaryAttribute{Name: "AegisNAS-Role", Number: 1, Type: "string"}, dict.Attributes[0])
	assert.Equal(t, VendorDictionaryAttribute{Name: "AegisNAS-Tenant", Number: 11, Type: "string"}, dict.Attributes[10])
	assert.Equal(t, VendorDictionaryAttribute{Name: "AegisNAS-ACL-Rule", Number: 13, Type: "string"}, dict.Attributes[12])
}

func TestAegisNASVendorDictionaryUsesEnvironmentVendorID(t *testing.T) {
	t.Setenv(AegisNASVendorIDEnv, "424242")

	dict := AegisNASVendorDictionary()
	assert.Equal(t, "AegisNAS", dict.Name)
	assert.Equal(t, 424242, dict.ID)
	assert.Contains(t, AegisNASVendorDictionaryText(), "VENDOR AegisNAS 424242")
}

func TestAegisNASVendorDictionaryCatalogForConfiguredIdentity(t *testing.T) {
	catalog := AegisNASVendorDictionaryCatalogFor("AegisNAS", 424242)
	vendor, ok := catalog.VendorByName("AegisNAS")
	require.True(t, ok)
	assert.Equal(t, 424242, vendor.ID)
	assert.Len(t, vendor.Attributes, 13)
}

func TestParseVendorDictionaryCatalog(t *testing.T) {
	catalog := ParseVendorDictionaryCatalog("fixture", `
VENDOR ExampleVendor 4242 format=1,1
ATTRIBUTE Example-Outside 1 string ExampleVendor has_tag
ATTRIBUTE ExampleVendor.Dotted 4 string
ATTRIBUTE ExampleVendor.PartialOID .14 string

BEGIN-VENDOR ExampleVendor format=2,1
ATTRIBUTE Example-Role 2 string
ATTRIBUTE Example-Mode 3 integer
VALUE Example-Mode guest 1
VALUE Example-Mode employee 2
END-VENDOR ExampleVendor

ATTRIBUTE User-Name 1 string
`)

	require.Len(t, catalog.Vendors, 1)
	vendor := catalog.Vendors[0]
	assert.Equal(t, "ExampleVendor", vendor.Name)
	assert.Equal(t, 4242, vendor.ID)
	assert.Equal(t, []string{"format=1,1", "format=2,1"}, vendor.Options)
	require.Len(t, vendor.Attributes, 5)

	outside := vendor.Attributes[0]
	assert.Equal(t, VendorDictionaryAttribute{Name: "Example-Outside", Number: 1, Type: "string", Options: []string{"has_tag"}}, outside)

	dotted, ok := catalog.Attribute("ExampleVendor", "Dotted")
	require.True(t, ok)
	assert.Equal(t, "ExampleVendor.Dotted", dotted.Name)

	partialOID, ok := catalog.Attribute("ExampleVendor", "PartialOID")
	require.True(t, ok)
	assert.Equal(t, ".14", partialOID.OID)
	assert.Zero(t, partialOID.Number)

	mode := vendor.Attributes[4]
	require.Len(t, mode.Values, 2)
	assert.Equal(t, VendorDictionaryValue{Attribute: "Example-Mode", Name: "guest", Value: "1"}, mode.Values[0])
	assert.Empty(t, catalog.Values)

	_, ok = catalog.Attribute("ExampleVendor", "User-Name")
	assert.False(t, ok)
}

func TestAegisNASVendorCompatibilityReport(t *testing.T) {
	report := AegisNASVendorCompatibilityReport()

	assert.Equal(t, "AegisNAS", report.Summary.ProductVendorName)
	assert.Equal(t, 55555, report.Summary.ProductVendorID)
	assert.Equal(t, DefaultDictionaryReleaseProfileID, report.Summary.DictionaryReleaseProfileID)
	assert.Equal(t, "3.2.8", report.Summary.DictionaryRelease)
	assert.Equal(t, report.DictionaryReleaseProfile.RegistrySourceSHA256, report.Summary.DictionaryReleaseSourceSHA256)
	assert.True(t, report.Summary.ProductVendorIDPlaceholder)
	assert.Equal(t, "dictionary.aegisnas", report.Summary.ProductVendorDictionaryFilename)
	assert.Equal(t, "$INCLUDE dictionary.aegisnas", report.Summary.ProductVendorDictionaryInclude)
	assert.Equal(t, 13, report.Summary.ProductAttributeCount)
	assert.Greater(t, report.Summary.SemanticCount, report.Summary.ProductAttributeCount)
	assert.Greater(t, report.Summary.PackCount, 5)
	assert.Greater(t, report.Summary.ImplementedCount, 0)
	assert.Greater(t, report.Summary.PlannedCount, 0)
	assert.NotEmpty(t, report.Packs)
	assert.NotEmpty(t, report.DictionaryReleaseProfile.FirmwareProfiles)

	role, ok := report.Catalog.Attribute("AegisNAS", "AegisNAS-Role")
	require.True(t, ok)
	assert.Equal(t, 1, role.Number)

	var foundACL bool
	for _, semantic := range report.Semantics {
		if semantic.Key == VendorSemanticDynamicACL {
			foundACL = true
			assert.Equal(t, "implemented", semantic.CompatibilityState)
			assert.Equal(t, "enterprise first", semantic.HardwareScope)
		}
	}
	assert.True(t, foundACL)
}

func TestAegisNASVendorCompatibilityPacks(t *testing.T) {
	defaults := DefaultVendorCompatibilityPackKeys()
	assert.Equal(t, []string{VendorPackStandard, VendorPackMikroTik, VendorPackWISPr}, defaults)

	aruba, ok := VendorCompatibilityPackByKey("aruba")
	require.True(t, ok)
	assert.Equal(t, "Aruba", aruba.VendorName)
	assert.Contains(t, aruba.HardwareProfiles, "branch")

	ubnt, ok := VendorCompatibilityPackByKey("unifi")
	require.True(t, ok)
	assert.Equal(t, VendorPackUBNT, ubnt.Key)

	cambium, ok := VendorCompatibilityPackByKey("canopy")
	require.True(t, ok)
	assert.Equal(t, VendorPackCambium, cambium.Key)

	juniper, ok := VendorCompatibilityPackByKey("junos")
	require.True(t, ok)
	assert.Equal(t, VendorPackJuniper, juniper.Key)

	tplink, ok := VendorCompatibilityPackByKey("omada")
	require.True(t, ok)
	assert.Equal(t, VendorPackTPLink, tplink.Key)

	aerohive, ok := VendorCompatibilityPackByKey("extreme-cloud-iq")
	require.True(t, ok)
	assert.Equal(t, VendorPackAerohive, aerohive.Key)
	assert.NotEmpty(t, aerohive.FeatureTemplates)
	assert.True(t, vendorPackTemplateContains(aerohive.FeatureTemplates, VendorSemanticVLAN, "Extreme-User-Vlan"))

	airespace, ok := VendorCompatibilityPackByKey("cisco-wlc")
	require.True(t, ok)
	assert.Equal(t, VendorPackAirespace, airespace.Key)

	hp, ok := VendorCompatibilityPackByKey("procurve")
	require.True(t, ok)
	assert.Equal(t, VendorPackHP, hp.Key)
	assert.True(t, vendorPackTemplateContains(hp.FeatureTemplates, VendorSemanticDynamicACL, "Ip-Filter-Raw"))

	chilli, ok := VendorCompatibilityPackByKey("coovachilli")
	require.True(t, ok)
	assert.Equal(t, VendorPackChilliSpot, chilli.Key)

	openwifi, ok := VendorCompatibilityPackByKey("open-wifi")
	require.True(t, ok)
	assert.Equal(t, VendorPackOpenWiFi, openwifi.Key)

	tplink, ok = VendorCompatibilityPackByKey("tp-link")
	require.True(t, ok)
	assert.Equal(t, VendorPackTPLink, tplink.Key)

	for _, item := range []struct {
		pack      string
		attribute string
	}{
		{VendorPackMeraki, "Meraki-Ap-Tags"},
		{VendorPackPaloAlto, "PaloAlto-Client-OS"},
		{VendorPackAirespace, "Wlan-Id"},
		{VendorPackHP, "Egress-VLANID"},
		{VendorPackArista, "Device-Profiling"},
		{VendorPackMeru, "Access-Point-Id"},
		{VendorPackColubris, "Intercept"},
		{VendorPackMist, "controller.policy_sync"},
	} {
		pack, found := VendorCompatibilityPackByKey(item.pack)
		require.True(t, found)
		assert.Equal(t, "implemented", vendorPackMappingState(pack, item.attribute), "%s %s", item.pack, item.attribute)
	}

	assert.True(t, ValidVendorCompatibilityPackKey("routeros"))
	assert.True(t, ValidVendorCompatibilityPackKey("arista-eos"))
	assert.False(t, ValidVendorCompatibilityPackKey("unknown-vendor"))
}

func vendorPackMappingState(pack VendorCompatibilityPack, attribute string) string {
	for _, mapping := range pack.Attributes {
		if mapping.Attribute == attribute {
			return mapping.CompatibilityState
		}
	}
	return ""
}

func vendorPackTemplateContains(templates []VendorPackFeatureTemplate, feature, attribute string) bool {
	for _, template := range templates {
		if template.Feature != feature {
			continue
		}
		for _, value := range template.Attributes {
			if value == attribute {
				return true
			}
		}
	}
	return false
}

func TestValidVendorDictionaryAttributeType(t *testing.T) {
	assert.True(t, ValidVendorDictionaryAttributeType("string"))
	assert.True(t, ValidVendorDictionaryAttributeType("text"))
	assert.True(t, ValidVendorDictionaryAttributeType("uint32"))
	assert.True(t, ValidVendorDictionaryAttributeType("ethernet"))
	assert.True(t, ValidVendorDictionaryAttributeType("octets[6]"))
	assert.True(t, ValidVendorDictionaryAttributeType("vsa"))

	assert.False(t, ValidVendorDictionaryAttributeType(""))
	assert.False(t, ValidVendorDictionaryAttributeType("blob"))
	assert.False(t, ValidVendorDictionaryAttributeType("octets[6"))
}
