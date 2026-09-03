package radius

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
)

func TestCompileVendorRatesBasicUnits(t *testing.T) {
	result := CompileVendorRates(RateCompilerRequest{
		PackKeys:         []string{productconfigs.VendorPackMikroTik, productconfigs.VendorPackWISPr, productconfigs.VendorPackUBNT, productconfigs.VendorPackHuawei, productconfigs.VendorPackH3C, productconfigs.VendorPackTPLink, productconfigs.VendorPackZTE},
		DownloadRateKbps: 50000,
		UploadRateKbps:   20000,
	})

	require.Equal(t, "ready", result.Status)
	assert.Equal(t, 19, result.AttributeCount)
	assertRateCompilerAttribute(t, result, "Mikrotik-Rate-Limit", "50000k/20000k", "mikrotik-rate-grammar")
	assertRateCompilerAttribute(t, result, "WISPr-Bandwidth-Max-Down", "50000", "integer-kbps")
	assertRateCompilerAttribute(t, result, "UBNT-Data-Rate-DL", "50000000", "integer-bps")
	assertRateCompilerAttribute(t, result, "Huawei-Input-Average-Rate", "20000", "integer-kbps")
	assertRateCompilerAttribute(t, result, "Huawei-Input-Peak-Information-Rate", "20000", "integer-kbps")
	assertRateCompilerAttribute(t, result, "H3C-Output-Peak-Rate", "50000", "integer-kbps")
	assertRateCompilerAttribute(t, result, "Rate-Ctrl-SCR-Up", "20000", "integer-kbps")
	assertRateCompilerAttribute(t, result, "Rate-Ctrl-SCR-Up-v6", "20000", "integer-kbps")
}

func TestCompileMikroTikExtendedRateGrammar(t *testing.T) {
	value, err := CompileMikroTikRateLimit(RateCompilerRequest{
		DownloadRateKbps:           50000,
		UploadRateKbps:             20000,
		DownloadBurstRateKbps:      80000,
		UploadBurstRateKbps:        30000,
		DownloadBurstThresholdKbps: 40000,
		UploadBurstThresholdKbps:   10000,
		DownloadBurstTimeSeconds:   10,
		UploadBurstTimeSeconds:     12,
		Priority:                   3,
		DownloadMinRateKbps:        10000,
		UploadMinRateKbps:          5000,
	})
	require.NoError(t, err)
	assert.Equal(t, "50000k/20000k 80000k/30000k 40000k/10000k 10s/12s 3 10000k/5000k", value)

	intent, err := DecompileMikroTikRateLimit(value)
	require.NoError(t, err)
	assert.Equal(t, 50000, intent.DownloadRateKbps)
	assert.Equal(t, 20000, intent.UploadRateKbps)
	assert.Equal(t, 80000, intent.DownloadBurstRateKbps)
	assert.Equal(t, 30000, intent.UploadBurstRateKbps)
	assert.Equal(t, 40000, intent.DownloadBurstThresholdKbps)
	assert.Equal(t, 10000, intent.UploadBurstThresholdKbps)
	assert.Equal(t, 10, intent.DownloadBurstTimeSeconds)
	assert.Equal(t, 12, intent.UploadBurstTimeSeconds)
	assert.Equal(t, 3, intent.Priority)
	assert.Equal(t, 10000, intent.DownloadMinRateKbps)
	assert.Equal(t, 5000, intent.UploadMinRateKbps)
}

func TestDecompileVendorRates(t *testing.T) {
	ubnt := DecompileVendorRates(RateDecompilerRequest{
		PackKey: productconfigs.VendorPackUBNT,
		Attributes: []RateCompilerAttribute{
			{Name: "UBNT-Data-Rate-DL", Value: "50000000"},
			{Name: "UBNT-Data-Rate-UL", Value: "20000000"},
		},
	})
	require.Equal(t, "ready", ubnt.Status)
	assert.Equal(t, 50000, ubnt.Intent.DownloadRateKbps)
	assert.Equal(t, 20000, ubnt.Intent.UploadRateKbps)
	assert.Equal(t, []string{productconfigs.VendorPackUBNT}, ubnt.Intent.PackKeys)

	fractional := DecompileVendorRates(RateDecompilerRequest{
		PackKey: productconfigs.VendorPackUBNT,
		Attributes: []RateCompilerAttribute{
			{Name: "UBNT-Data-Rate-DL", Value: "50000001"},
			{Name: "UBNT-Data-Rate-UL", Value: "20000000"},
		},
	})
	assert.Equal(t, "blocked", fractional.Status)
	require.NotEmpty(t, fractional.Diagnostics)
	assert.Equal(t, "invalid_download_rate", fractional.Diagnostics[0].Code)
}

func TestCompileVendorRatesBlocksOverflowAndIncompleteGrammar(t *testing.T) {
	overflow := CompileVendorRates(RateCompilerRequest{
		PackKeys:         []string{productconfigs.VendorPackUBNT},
		DownloadRateKbps: 5000000,
		UploadRateKbps:   20000,
	})
	assert.Equal(t, "blocked", overflow.Status)
	assert.Empty(t, overflow.Attributes)
	require.NotEmpty(t, overflow.Diagnostics)
	assert.Equal(t, "rate_bps_overflow", overflow.Diagnostics[0].Code)

	incomplete := CompileVendorRates(RateCompilerRequest{
		PackKeys:              []string{productconfigs.VendorPackMikroTik},
		DownloadRateKbps:      50000,
		UploadRateKbps:        20000,
		DownloadBurstRateKbps: 80000,
	})
	assert.Equal(t, "blocked", incomplete.Status)
	require.NotEmpty(t, incomplete.Diagnostics)
	assert.Equal(t, "invalid_mikrotik_rate_limit", incomplete.Diagnostics[0].Code)

	unsupported := CompileVendorRates(RateCompilerRequest{
		PackKeys:         []string{productconfigs.VendorPackCisco},
		DownloadRateKbps: 50000,
		UploadRateKbps:   20000,
	})
	assert.Equal(t, "blocked", unsupported.Status)
	require.NotEmpty(t, unsupported.Diagnostics)
	assert.Equal(t, "unsupported_pack", unsupported.Diagnostics[0].Code)
}

func assertRateCompilerAttribute(t *testing.T, result RateCompilerResult, name, value, unit string) {
	t.Helper()
	for _, attr := range result.Attributes {
		if attr.Name == name {
			assert.Equal(t, value, attr.Value)
			assert.Equal(t, unit, attr.Unit)
			return
		}
	}
	t.Fatalf("attribute %s not found in %#v", name, result.Attributes)
}
