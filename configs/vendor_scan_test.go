package configs

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildVendorDictionaryScanReportClassifiesSupportedPlannedAndIgnored(t *testing.T) {
	catalog := ParseVendorDictionaryCatalog("scan-fixture", `
VENDOR Cisco 9
BEGIN-VENDOR Cisco
ATTRIBUTE Cisco-In-ACL 1 string
ATTRIBUTE Cisco-Out-ACL 2 string
ATTRIBUTE Cisco-AVPair 3 string
ATTRIBUTE Cisco-Experimental 99 string
END-VENDOR Cisco

VENDOR Mystery 65000
BEGIN-VENDOR Mystery
ATTRIBUTE Mystery-Mode 1 string
END-VENDOR Mystery
`)

	report := BuildVendorDictionaryScanReport(catalog, AegisNASVendorCompatibilityPacks(), []string{"cisco"})

	assert.Equal(t, "scan-fixture", report.Source)
	assert.Equal(t, 2, report.CatalogVendorCount)
	assert.Equal(t, 5, report.CatalogAttributeCount)
	assert.Greater(t, report.Summary.SupportedAttributeCount, 0)
	assert.Greater(t, report.Summary.PlannedAttributeCount, 0)
	assert.Equal(t, 2, report.Summary.IgnoredAttributeCount)
	assert.Equal(t, 2, report.Summary.IgnoredVendorCount)
	assert.True(t, scanMappingsContain(report.SupportedAttributes, VendorPackCisco, "Cisco-AVPair"))
	assert.True(t, scanMappingsContain(report.PlannedAttributes, VendorPackCambium, "Cambium-Auth-Role"))
	assert.True(t, scanIgnoredContain(report.IgnoredAttributes, "Cisco", "Cisco-Experimental", "no compatibility mapping for this vendor attribute"))
	assert.True(t, scanIgnoredContain(report.IgnoredAttributes, "Mystery", "Mystery-Mode", "vendor has no compatibility pack"))
}

func TestScanVendorDictionariesLoadsPathsAndBuiltInDictionary(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dictionary.cisco"), []byte(`
VENDOR Cisco 9
BEGIN-VENDOR Cisco
ATTRIBUTE Cisco-AVPair 3 string
END-VENDOR Cisco
`), 0o600))

	report := ScanVendorDictionaries([]string{dir}, []string{"aegisnas", "cisco"}, true)

	assert.Equal(t, []string{dir}, report.ImportPaths)
	assert.True(t, report.IncludeBuiltIn)
	assert.Contains(t, report.Source, "built-in AegisNAS")
	assert.Contains(t, report.Source, dir)
	assert.True(t, scanMappingsContain(report.SupportedAttributes, VendorPackAegisNAS, "AegisNAS-Role"))
	assert.True(t, scanMappingsContain(report.SupportedAttributes, VendorPackCisco, "Cisco-AVPair"))
}

func scanMappingsContain(values []VendorDictionaryScannedMapping, packKey, attribute string) bool {
	for _, value := range values {
		if value.PackKey == packKey && value.Attribute == attribute {
			return true
		}
	}
	return false
}

func scanIgnoredContain(values []VendorDictionaryIgnoredAttribute, vendor, attribute, reason string) bool {
	for _, value := range values {
		if value.VendorName == vendor && value.Attribute == attribute && value.Reason == reason {
			return true
		}
	}
	return false
}
