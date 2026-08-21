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
ATTRIBUTE AegisNAS-Session-Action 8 string
ATTRIBUTE AegisNAS-Portal-Profile 9 string
ATTRIBUTE AegisNAS-Device-Group 10 string
ATTRIBUTE AegisNAS-Tenant 11 string
ATTRIBUTE AegisNAS-ACL-Name 12 string
ATTRIBUTE AegisNAS-ACL-Rule 13 string
ATTRIBUTE AegisNAS-Service-Chain 14 string
ATTRIBUTE AegisNAS-Service-Name 15 string
ATTRIBUTE AegisNAS-Data-VLAN 16 integer
ATTRIBUTE AegisNAS-Voice-VLAN 17 integer
ATTRIBUTE AegisNAS-Tagged-VLAN 18 integer
ATTRIBUTE AegisNAS-QinQ-Outer-VLAN 19 integer
ATTRIBUTE AegisNAS-QinQ-Inner-VLAN 20 integer
ATTRIBUTE AegisNAS-VLAN-Pool 21 string
ATTRIBUTE AegisNAS-Fallback-VLAN 22 integer
ATTRIBUTE AegisNAS-Auth-Fail-VLAN 23 integer
ATTRIBUTE AegisNAS-VLAN-Policy 24 string
ATTRIBUTE AegisNAS-Route-Policy 25 string
ATTRIBUTE AegisNAS-VRF 26 string
ATTRIBUTE AegisNAS-Route-Owner 27 string
ATTRIBUTE AegisNAS-Route-Revision 28 string
ATTRIBUTE AegisNAS-Framed-Route 29 string
ATTRIBUTE AegisNAS-Framed-IPv6-Route 30 string
ATTRIBUTE AegisNAS-Address-Policy 31 string
ATTRIBUTE AegisNAS-Address-Owner 32 string
ATTRIBUTE AegisNAS-Address-Revision 33 string
ATTRIBUTE AegisNAS-IPv4-Pool 34 string
ATTRIBUTE AegisNAS-IPv6-Pool 35 string
ATTRIBUTE AegisNAS-Delegated-IPv6-Pool 36 string
ATTRIBUTE AegisNAS-RA-Prefix-Pool 37 string
ATTRIBUTE AegisNAS-Framed-IP-Address 38 string
ATTRIBUTE AegisNAS-Framed-IPv6-Address 39 string
ATTRIBUTE AegisNAS-Framed-IPv6-Prefix 40 string
ATTRIBUTE AegisNAS-Delegated-IPv6-Prefix 41 string
ATTRIBUTE AegisNAS-RA-Prefix 42 string
ATTRIBUTE AegisNAS-DHCPv6-Mode 43 string
ATTRIBUTE AegisNAS-RA-Mode 44 string
ATTRIBUTE AegisNAS-Translation-Policy 45 string
ATTRIBUTE AegisNAS-Translation-Owner 46 string
ATTRIBUTE AegisNAS-Translation-Revision 47 string
ATTRIBUTE AegisNAS-Translation-Mode 48 string
ATTRIBUTE AegisNAS-Translation-Public-IPv4-Pool 49 string
ATTRIBUTE AegisNAS-Translation-Public-IPv4-Address 50 string
ATTRIBUTE AegisNAS-Translation-Private-IPv4-Prefix 51 string
ATTRIBUTE AegisNAS-Translation-Subscriber-IPv6-Prefix 52 string
ATTRIBUTE AegisNAS-Translation-NAT64-Prefix 53 string
ATTRIBUTE AegisNAS-Translation-Port-Block-Start 54 integer
ATTRIBUTE AegisNAS-Translation-Port-Block-End 55 integer
ATTRIBUTE AegisNAS-Translation-Port-Block-Size 56 integer
ATTRIBUTE AegisNAS-Translation-Logging-Profile 57 string
ATTRIBUTE AegisNAS-Translation-Accounting-Key 58 string
END-VENDOR AegisNAS

VENDOR Cisco 9
BEGIN-VENDOR Cisco
ATTRIBUTE Cisco-In-ACL 1 string
ATTRIBUTE Cisco-Out-ACL 2 string
ATTRIBUTE Cisco-AVPair 3 string
END-VENDOR Cisco
`)

	report := BuildVendorDictionaryCoverageReport(catalog, AegisNASVendorCompatibilityPacks(), []string{"standard", "aegisnas", "cisco"})
	require.NotEmpty(t, report.Rows)
	assert.Equal(t, "combined-fixture", report.Source)
	assert.Equal(t, 2, report.CatalogVendorCount)
	assert.Equal(t, 61, report.CatalogAttributeCount)
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
	assert.Equal(t, "dictionary-backed", cisco.CoverageState)
	assert.Equal(t, 12, cisco.DictionaryMatchedAttributeCount)
	assert.Zero(t, cisco.MissingDictionaryAttributeCount)

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
