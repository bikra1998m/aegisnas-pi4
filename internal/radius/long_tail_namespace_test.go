package radius

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	layehradius "layeh.com/radius"
)

func TestLongTailNamespaceInboundNormalizationAndRedaction(t *testing.T) {
	packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	require.NoError(t, addVendorString(packet, 5468, 1, "network-admin"))
	require.NoError(t, AddVendorAttributeWithSpec(packet, VendorAttributeSpec{VendorID: 41482, Type: 1, WireType: "octets"}, layehradius.Attribute("clear-text-yubikey-secret")))

	result := ParseBrokerPacketWithConfig(packet, &config.Config{Radius: config.RadiusConfig{Vendor: vendorConfigForPacks(productconfigs.VendorPackLongTail)}})

	assert.Equal(t, "network-admin", result.VendorRole)
	assert.Contains(t, result.VendorAVPairs, "Actelis-Privilege=network-admin")
	joinedEvidence := strings.Join(result.VendorAVPairs, ",")
	assert.Contains(t, joinedEvidence, "Yubikey-Key=<redacted:")
	assert.NotContains(t, joinedEvidence, "clear-text-yubikey-secret")
}

func TestLongTailNamespaceNumericValuesRecordTypedEvidence(t *testing.T) {
	packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	require.NoError(t, addVendorInteger(packet, 13209, 37, 64000))

	result := ParseBrokerPacketWithConfig(packet, &config.Config{Radius: config.RadiusConfig{Vendor: vendorConfigForPacks(productconfigs.VendorPackLongTail)}})

	assert.Equal(t, 64000, result.WISPrBandwidthMaxUp)
	assert.Contains(t, result.VendorAVPairs, "Aptilo-Bw-Max-Up=64000")
}

func TestLongTailNamespacePackIsOptIn(t *testing.T) {
	packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	require.NoError(t, addVendorString(packet, 5468, 1, "network-admin"))

	result := ParseBrokerPacketWithConfig(packet, &config.Config{Radius: config.RadiusConfig{Vendor: vendorConfigForPacks(productconfigs.VendorPackStandard)}})

	assert.Empty(t, result.VendorRole)
	assert.Empty(t, result.VendorAVPairs)
}
