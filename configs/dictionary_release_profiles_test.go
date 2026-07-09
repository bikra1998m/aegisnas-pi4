package configs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDictionaryReleaseProfileContract(t *testing.T) {
	registry := MustBuiltInAttributeRegistry()
	profile := DefaultDictionaryReleaseProfile()

	assert.Equal(t, DefaultDictionaryReleaseProfileID, profile.ID)
	assert.Equal(t, "3.2.8", profile.Release)
	assert.Equal(t, registry.SourceSHA256, profile.RegistrySourceSHA256)
	assert.Equal(t, registry.SourceAttributeCount, profile.SourceAttributeCount)
	assert.Equal(t, registry.AttributeCount, profile.EffectiveAttributeCount)
	assert.Equal(t, 134, profile.RuntimeDecoderCount)
	assert.GreaterOrEqual(t, profile.VendorAliasCount, 40)
	assert.GreaterOrEqual(t, profile.AttributeAliasCount, 8)
	assert.GreaterOrEqual(t, profile.FirmwareProfileCount, 8)
	require.NoError(t, ValidateDictionaryReleaseProfile(profile, registry, AegisNASVendorCompatibilityPacks()))
}

func TestDictionaryReleaseProfileAliasNormalization(t *testing.T) {
	assert.Equal(t, VendorPackUBNT, NormalizeVendorCompatibilityPackKey("unifi"))
	assert.Equal(t, VendorPackTPLink, NormalizeVendorCompatibilityPackKey("Omada"))
	assert.Equal(t, VendorPackOpenWiFi, NormalizeVendorCompatibilityPackKey("tip-openwifi"))
	assert.Equal(t, "Ubiquiti", NormalizeDictionaryVendorName(DefaultDictionaryReleaseProfileID, "UBNT"))
	assert.Equal(t, "TPLink", NormalizeDictionaryVendorName(DefaultDictionaryReleaseProfileID, "tp-link"))
	assert.Equal(t, "UBNT-Data-Rate-DL", NormalizeDictionaryAttributeName(DefaultDictionaryReleaseProfileID, "UBNT", "Ubiquiti-Data-Rate-DL"))

	registry := MustBuiltInAttributeRegistry()
	ubnt, ok := registry.LookupName("UBNT", "Ubiquiti-Data-Rate-DL")
	require.True(t, ok)
	assert.Equal(t, "UBNT-Data-Rate-DL", ubnt.Attribute)

	profiles := DictionaryFirmwareProfilesForPack(DefaultDictionaryReleaseProfileID, "unifi")
	require.NotEmpty(t, profiles)
	assert.Equal(t, "ubiquiti-unifi-network", profiles[0].Key)
}

func TestValidateDictionaryReleaseProfileRejectsDrift(t *testing.T) {
	registry := MustBuiltInAttributeRegistry()
	profile := DefaultDictionaryReleaseProfile()

	badHash := profile
	badHash.RegistrySourceSHA256 = "0"
	require.ErrorContains(t, ValidateDictionaryReleaseProfile(badHash, registry, AegisNASVendorCompatibilityPacks()), "source hash")

	badAlias := profile
	badAlias.AttributeAliases = append(badAlias.AttributeAliases, DictionaryAttributeAlias{
		Vendor: "Cisco", Alias: "Cisco-Impossible", CanonicalAttribute: "Cisco-Impossible", PEN: 9, Number: 250,
	})
	require.ErrorContains(t, ValidateDictionaryReleaseProfile(badAlias, registry, AegisNASVendorCompatibilityPacks()), "unknown registry entry")
}
