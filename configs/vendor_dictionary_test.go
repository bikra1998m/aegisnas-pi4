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
	require.Len(t, dict.Attributes, 11)
	assert.Equal(t, VendorDictionaryAttribute{Name: "AegisNAS-Role", Number: 1, Type: "string"}, dict.Attributes[0])
	assert.Equal(t, VendorDictionaryAttribute{Name: "AegisNAS-Tenant", Number: 11, Type: "string"}, dict.Attributes[10])
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
	assert.Equal(t, 11, report.Summary.ProductAttributeCount)
	assert.Greater(t, report.Summary.SemanticCount, report.Summary.ProductAttributeCount)
	assert.Greater(t, report.Summary.PackCount, 5)
	assert.Greater(t, report.Summary.ImplementedCount, 0)
	assert.Greater(t, report.Summary.PlannedCount, 0)
	assert.NotEmpty(t, report.Packs)

	role, ok := report.Catalog.Attribute("AegisNAS", "AegisNAS-Role")
	require.True(t, ok)
	assert.Equal(t, 1, role.Number)

	var foundACL bool
	for _, semantic := range report.Semantics {
		if semantic.Key == VendorSemanticDynamicACL {
			foundACL = true
			assert.Equal(t, "planned", semantic.CompatibilityState)
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

	assert.True(t, ValidVendorCompatibilityPackKey("routeros"))
	assert.False(t, ValidVendorCompatibilityPackKey("unknown-vendor"))
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
