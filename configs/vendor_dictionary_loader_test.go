package configs

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadVendorDictionaryCatalogExpandsIncludes(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "dictionary")
	cisco := filepath.Join(dir, "dictionary.cisco")
	aruba := filepath.Join(dir, "dictionary.aruba")

	require.NoError(t, os.WriteFile(root, []byte(`
$INCLUDE dictionary.cisco
$INCLUDE dictionary.aruba
`), 0o600))
	require.NoError(t, os.WriteFile(cisco, []byte(`
VENDOR Cisco 9
BEGIN-VENDOR Cisco
ATTRIBUTE Cisco-In-ACL 1 string
ATTRIBUTE Cisco-Out-ACL 2 string
ATTRIBUTE Cisco-AVPair 3 string
END-VENDOR Cisco
`), 0o600))
	require.NoError(t, os.WriteFile(aruba, []byte(`
VENDOR Aruba 14823
BEGIN-VENDOR Aruba
ATTRIBUTE Aruba-User-Role 1 string
ATTRIBUTE Aruba-User-Vlan 2 integer
END-VENDOR Aruba
`), 0o600))

	catalog := LoadVendorDictionaryCatalog([]string{root})
	require.Empty(t, catalog.Warnings)
	assert.Equal(t, root, catalog.Source)
	require.Len(t, catalog.Vendors, 2)

	ciscoAttr, ok := catalog.Attribute("Cisco", "Cisco-AVPair")
	require.True(t, ok)
	assert.Equal(t, 3, ciscoAttr.Number)

	arubaAttr, ok := catalog.Attribute("Aruba", "Aruba-User-Vlan")
	require.True(t, ok)
	assert.Equal(t, "integer", arubaAttr.Type)
}

func TestLoadVendorDictionaryCatalogScansDirectoryAndMergesBuiltIn(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dictionary.fortinet"), []byte(`
VENDOR Fortinet 12356
BEGIN-VENDOR Fortinet
ATTRIBUTE Fortinet-Group-Name 1 string
ATTRIBUTE Fortinet-Access-Profile 2 string
END-VENDOR Fortinet
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ignore.txt"), []byte(`
VENDOR Ignored 999
ATTRIBUTE Ignored-Attr 1 string Ignored
`), 0o600))

	imported := LoadVendorDictionaryCatalog([]string{dir})
	require.Empty(t, imported.Warnings)
	_, ok := imported.VendorByName("Fortinet")
	require.True(t, ok)
	_, ok = imported.VendorByName("Ignored")
	assert.False(t, ok)

	merged := MergeVendorDictionaryCatalogs("merged", AegisNASVendorDictionaryCatalog(), imported)
	assert.Equal(t, "merged", merged.Source)
	_, ok = merged.VendorByName("AegisNAS")
	assert.True(t, ok)
	_, ok = merged.VendorByName("Fortinet")
	assert.True(t, ok)
}
