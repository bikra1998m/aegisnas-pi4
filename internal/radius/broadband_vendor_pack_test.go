package radius

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	layehradius "layeh.com/radius"
)

func TestBroadbandVendorPackParsesHuaweiAndH3CBroadbandState(t *testing.T) {
	packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	require.NoError(t, addVendorString(packet, 2011, 31, "gold-qos"))
	require.NoError(t, addVendorString(packet, 2011, 66, "vip-subscriber"))
	require.NoError(t, addVendorString(packet, 2011, 82, "huawei-access-filter"))
	require.NoError(t, addVendorString(packet, 2011, 140, "https://portal.example.test/huawei"))
	require.NoError(t, addVendorString(packet, 2011, 188, "vrf=tenant-a"))
	require.NoError(t, addVendorString(packet, 2011, 188, "framed-route=10.40.0.0/16 192.0.2.1"))
	require.NoError(t, addVendorString(packet, 2011, 188, "translation-policy=cgnat-deterministic"))
	require.NoError(t, addVendorString(packet, 2011, 188, "translation-public-ipv4=198.51.100.44"))
	require.NoError(t, addVendorString(packet, 2011, 188, "translation-port-block=10000-10511"))
	require.NoError(t, addVendorString(packet, 2011, 188, "translation-port-block-size=512"))
	require.NoError(t, addVendorInteger(packet, 2011, 2, 25000))
	require.NoError(t, addVendorInteger(packet, 2011, 5, 75000))
	require.NoError(t, addVendorAttribute(packet, 25506, 32, layehradius.Attribute(net.IPv4(198, 51, 100, 50).To4())))
	require.NoError(t, addVendorInteger(packet, 25506, 33, 11000))
	require.NoError(t, addVendorInteger(packet, 25506, 34, 11511))
	require.NoError(t, addVendorString(packet, 25506, 210, "nat64-prefix=64:ff9b::/96"))
	require.NoError(t, addVendorString(packet, 25506, 210, "address-pool=branch-pool"))

	result := ParseBrokerPacketWithConfig(packet, &config.Config{
		Radius: config.RadiusConfig{
			Vendor: vendorConfigForPacks(productconfigs.VendorPackHuawei, productconfigs.VendorPackH3C),
		},
	})

	assert.Equal(t, "vip-subscriber", result.VendorRole)
	assert.Equal(t, "gold-qos", result.VendorBandwidthProfile)
	assert.Equal(t, "huawei-access-filter", result.VendorInboundACL)
	assert.Equal(t, "https://portal.example.test/huawei", result.VendorPortalProfile)
	assert.Equal(t, "tenant-a", result.VendorVRF)
	assert.Equal(t, "framed-route=10.40.0.0/16 192.0.2.1", result.VendorRoutePolicy)
	assert.Equal(t, "cgnat-deterministic", result.VendorTranslationPolicy)
	assert.Equal(t, "198.51.100.44", result.VendorTranslationPublicIPv4Address)
	assert.True(t, result.HasVendorTranslationPortBlockStart)
	assert.Equal(t, 10000, result.VendorTranslationPortBlockStart)
	assert.True(t, result.HasVendorTranslationPortBlockEnd)
	assert.Equal(t, 10511, result.VendorTranslationPortBlockEnd)
	assert.True(t, result.HasVendorTranslationPortBlockSize)
	assert.Equal(t, 512, result.VendorTranslationPortBlockSize)
	assert.Equal(t, "branch-pool", result.VendorIPv4Pool)
	assert.Equal(t, "64:ff9b::/96", result.VendorTranslationNAT64Prefix)
	assert.Equal(t, 75000, result.WISPrBandwidthMaxDown)
	assert.Equal(t, 25000, result.WISPrBandwidthMaxUp)
}

func TestBroadbandVendorPackParsesZTEIPv6RatesAndRendersReplies(t *testing.T) {
	packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	require.NoError(t, addVendorString(packet, 3902, 27, "https://portal.example.test/zte"))
	require.NoError(t, addVendorString(packet, 3902, 82, "down-profile"))
	require.NoError(t, addVendorInteger(packet, 3902, 228, 45000))
	require.NoError(t, addVendorInteger(packet, 3902, 233, 120000))
	require.NoError(t, addVendorString(packet, 3902, 232, "up-profile-v6"))

	vendor := vendorConfigForPacks(productconfigs.VendorPackZTE)
	vendor.RoleMappings = []config.RadiusVendorRoleMapping{{Pack: productconfigs.VendorPackZTE, Role: "zte-admin", Value: 15}}
	require.NoError(t, addVendorInteger(packet, 3902, 104, 15))

	result := ParseBrokerPacketWithConfig(packet, &config.Config{
		Radius: config.RadiusConfig{Vendor: vendor},
	})

	assert.Equal(t, "zte-admin", result.VendorRole)
	assert.Equal(t, "https://portal.example.test/zte", result.VendorPortalProfile)
	assert.Equal(t, "down-profile", result.VendorBandwidthProfile)
	assert.Equal(t, 120000, result.WISPrBandwidthMaxDown)
	assert.Equal(t, 45000, result.WISPrBandwidthMaxUp)

	items := BuildReplyAttributeItems(&ReplyAttributes{
		BandwidthProfile:      "gold-qos",
		PortalProfile:         "https://portal.example.test/zte",
		WISPrBandwidthMaxUp:   45000,
		WISPrBandwidthMaxDown: 120000,
	}, []string{productconfigs.VendorPackHuawei, productconfigs.VendorPackH3C, productconfigs.VendorPackZTE})

	assert.Contains(t, items, ReplyAttributeItem{Name: "Huawei-Input-Peak-Information-Rate", Value: "45000", Quoted: false})
	assert.Contains(t, items, ReplyAttributeItem{Name: "Huawei-Output-Peak-Information-Rate", Value: "120000", Quoted: false})
	assert.Contains(t, items, ReplyAttributeItem{Name: "H3C-Input-Peak-Rate", Value: "45000", Quoted: false})
	assert.Contains(t, items, ReplyAttributeItem{Name: "H3C-Output-Peak-Rate", Value: "120000", Quoted: false})
	assert.Contains(t, items, ReplyAttributeItem{Name: "QoS-Profile-Up-v6", Value: "gold-qos", Quoted: true})
	assert.Contains(t, items, ReplyAttributeItem{Name: "Rate-Ctrl-SCR-Up-v6", Value: "45000", Quoted: false})
}
