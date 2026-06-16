package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
)

func TestNormalizeDictionaryScanPacks(t *testing.T) {
	packs, err := normalizeDictionaryScanPacks([]string{"routeros", "MikroTik", "wispr"})
	require.NoError(t, err)
	assert.Equal(t, []string{productconfigs.VendorPackMikroTik, productconfigs.VendorPackWISPr}, packs)

	_, err = normalizeDictionaryScanPacks([]string{"not-a-vendor"})
	assert.ErrorContains(t, err, "unknown compatibility pack")
}

func TestWriteVendorDictionaryScanOutputsMatrix(t *testing.T) {
	report := productconfigs.BuildVendorDictionaryScanReport(
		productconfigs.AegisNASVendorDictionaryCatalog(),
		productconfigs.AegisNASVendorCompatibilityPacks(),
		[]string{productconfigs.VendorPackAegisNAS},
	)

	var text bytes.Buffer
	writeVendorDictionaryScanText(&text, report)
	assert.Contains(t, text.String(), "Compatibility Matrix:")
	assert.Contains(t, text.String(), "aegisnas")
	assert.Contains(t, text.String(), "dictionary-backed")

	var csv bytes.Buffer
	require.NoError(t, writeVendorDictionaryMatrixCSV(&csv, report))
	lines := strings.Split(strings.TrimSpace(csv.String()), "\n")
	require.Greater(t, len(lines), 1)
	assert.Contains(t, lines[0], "pack_key,pack_label,active,coverage_state")
	assert.Contains(t, csv.String(), "aegisnas")
}
