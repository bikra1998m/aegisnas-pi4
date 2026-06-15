package configs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildVendorDictionaryCoverageReport(t *testing.T) {
	catalog := ParseVendorDictionaryCatalog("combined-fixture", `
VENDOR AegisNAS 55555
BEGIN-VENDOR AegisNAS
ATTRIBUTE AegisNAS-Role 1 string
ATTRIBUTE AegisNAS-Bandwidth-Profile 2 string
ATTRIBUTE AegisNAS-VLAN 3 integer
ATTRIBUTE AegisNAS-Quarantine 4 integer
ATTRIBUTE AegisNAS-Policy-Tag 5 string
ATTRIBUTE AegisNAS-Session-Timeout 6 integer
ATTRIBUTE AegisNAS-Idle-Timeout 7 integer
ATTRIBUTE AegisNAS-Portal-Profile 9 string
ATTRIBUTE AegisNAS-Device-Group 10 string
ATTRIBUTE AegisNAS-Tenant 11 string
END-VENDOR AegisNAS

VENDOR Cisco 9
BEGIN-VENDOR Cisco
ATTRIBUTE Cisco-In-ACL 1 string
ATTRIBUTE Cisco-Out-ACL 2 string
END-VENDOR Cisco
`)

	report := BuildVendorDictionaryCoverageReport(catalog, AegisNASVendorCompatibilityPacks(), []string{"standard", "aegisnas", "cisco"})
	require.NotEmpty(t, report.Rows)
	assert.Equal(t, "combined-fixture", report.Source)
	assert.Equal(t, 2, report.CatalogVendorCount)
	assert.Equal(t, 12, report.CatalogAttributeCount)
	assert.Equal(t, 3, report.ActivePackCount)
	assert.Greater(t, report.DictionaryMatchedAttributeCount, 0)
	assert.Greater(t, report.MissingDictionaryAttributeCount, 0)
	assert.Greater(t, report.MissingDictionaryVendorCount, 0)

	rows := coverageRowsByKey(report.Rows)

	standard := rows[VendorPackStandard]
	assert.Equal(t, "standard-radius", standard.CoverageState)
	assert.Equal(t, standard.RadiusAttributeCount, standard.DictionaryMatchedAttributeCount)

	aegis := rows[VendorPackAegisNAS]
	assert.True(t, aegis.Active)
	assert.Equal(t, "dictionary-backed", aegis.CoverageState)
	assert.True(t, aegis.DictionaryVendorFound)

	cisco := rows[VendorPackCisco]
	assert.True(t, cisco.Active)
	assert.Equal(t, "partial-dictionary", cisco.CoverageState)
	assert.Equal(t, 2, cisco.DictionaryMatchedAttributeCount)
	assert.Equal(t, 1, cisco.MissingDictionaryAttributeCount)

	aruba := rows[VendorPackAruba]
	assert.False(t, aruba.DictionaryVendorFound)
	assert.Equal(t, "dictionary-missing", aruba.CoverageState)

	mist := rows["mist"]
	assert.Equal(t, "controller-api", mist.CoverageState)
	assert.Zero(t, mist.RadiusAttributeCount)
}

func coverageRowsByKey(rows []VendorDictionaryCoverageRow) map[string]VendorDictionaryCoverageRow {
	out := map[string]VendorDictionaryCoverageRow{}
	for _, row := range rows {
		out[row.PackKey] = row
	}
	return out
}
