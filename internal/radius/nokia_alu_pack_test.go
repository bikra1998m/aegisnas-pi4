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

func TestNokiaALUPackParsesServiceRouterSubscriberState(t *testing.T) {
	packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	require.NoError(t, addVendorString(packet, 6527, 11, "sub-1001"))
	require.NoError(t, addVendorString(packet, 6527, 12, "subscriber-gold"))
	require.NoError(t, addVendorString(packet, 6527, 13, "sla-gold"))
	require.NoError(t, addVendorString(packet, 6527, 121, "10000-10511"))
	require.NoError(t, addVendorAttribute(packet, 6527, 141, layehradius.Attribute(net.IPv4(198, 51, 100, 77).To4())))
	require.NoError(t, addVendorString(packet, 6527, 158, "permit in tcp from any to any 443"))
	require.NoError(t, addVendorString(packet, 6527, 177, "https://portal.example.test/alu"))
	require.NoError(t, addVendorString(packet, 6527, 206, "120"))
	require.NoError(t, addVendorString(packet, 831, 1, "deny out udp from any to 10.0.0.0/24 53"))
	require.NoError(t, addVendorString(packet, 831, 2, "vrf=tenant-a"))
	require.NoError(t, addVendorString(packet, 831, 2, "translation-nat64-prefix=64:ff9b::/96"))

	result := ParseBrokerPacketWithConfig(packet, &config.Config{
		Radius: config.RadiusConfig{
			Vendor: vendorConfigForPacks(productconfigs.VendorPackALUSR, productconfigs.VendorPackALUAAA),
		},
	})

	assert.Equal(t, "subscriber-gold", result.VendorRole)
	assert.Equal(t, "sla-gold", result.VendorBandwidthProfile)
	assert.Equal(t, "sub-1001", result.VendorAccountingIdentity)
	assert.Equal(t, "permit in tcp from any to any 443", result.VendorInboundACL)
	assert.Equal(t, "https://portal.example.test/alu", result.VendorPortalProfile)
	assert.True(t, result.HasVendorVLAN)
	assert.Equal(t, 120, result.VendorVLAN)
	assert.Equal(t, "tenant-a", result.VendorVRF)
	assert.Equal(t, "64:ff9b::/96", result.VendorTranslationNAT64Prefix)
	assert.Equal(t, "198.51.100.77", result.VendorTranslationPublicIPv4Address)
	assert.True(t, result.HasVendorTranslationPortBlockStart)
	assert.Equal(t, 10000, result.VendorTranslationPortBlockStart)
	assert.True(t, result.HasVendorTranslationPortBlockEnd)
	assert.Equal(t, 10511, result.VendorTranslationPortBlockEnd)
}

func TestNokiaALUPackParsesNokiaBCDAndAVPairs(t *testing.T) {
	packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	require.NoError(t, addVendorString(packet, 94, 1, "route-owner=network-team"))
	require.NoError(t, addVendorString(packet, 94, 1, "framed-route=10.40.0.0/16 192.0.2.1"))
	require.NoError(t, addVendorString(packet, 94, 1, "translation-port-block=12000-12511"))
	require.NoError(t, addVendorString(packet, 94, 2, "nokia-premium"))
	require.NoError(t, addVendorAttribute(packet, 94, 3, layehradius.Attribute([]byte{0x21, 0x43, 0x65, 0xf7})))

	result := ParseBrokerPacketWithConfig(packet, &config.Config{
		Radius: config.RadiusConfig{
			Vendor: vendorConfigForPacks(productconfigs.VendorPackNokia),
		},
	})

	assert.Equal(t, "nokia-premium", result.VendorRole)
	assert.Equal(t, "1234567", result.VendorDeviceGroup)
	assert.Equal(t, "network-team", result.VendorRouteOwner)
	assert.Equal(t, []string{"10.40.0.0/16 192.0.2.1"}, result.VendorFramedRoutes)
	assert.True(t, result.HasVendorTranslationPortBlockStart)
	assert.Equal(t, 12000, result.VendorTranslationPortBlockStart)
	assert.True(t, result.HasVendorTranslationPortBlockEnd)
	assert.Equal(t, 12511, result.VendorTranslationPortBlockEnd)
}

func TestNokiaALUPackACLCompilerExportsSupportedPacks(t *testing.T) {
	rules := []ACLRule{{
		Action: "permit", Direction: "in", Protocol: "tcp", Source: "any", Destination: "any", DestinationPort: "443",
	}}
	run, err := CompileACLPolicyForPacks(ACLCompilerRequest{
		PolicyName: "guest-internet",
		InboundACL: "guest-in",
		Rules:      rules,
		PackKeys: []string{
			productconfigs.VendorPackNokia,
			productconfigs.VendorPackAlcatel,
			productconfigs.VendorPackALUSR,
			productconfigs.VendorPackALUAAA,
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "degraded", run.Status)

	byPack := map[string]ACLCompileResult{}
	for _, result := range run.Results {
		byPack[result.PackKey] = result
	}
	assert.Equal(t, "profile_reference", byPack[productconfigs.VendorPackNokia].Status)
	assertACLCompileContains(t, byPack[productconfigs.VendorPackNokia], "Nokia-AVPair")
	assert.Equal(t, "profile_reference", byPack[productconfigs.VendorPackAlcatel].Status)
	assertACLCompileContains(t, byPack[productconfigs.VendorPackAlcatel], "AAT-Filter")
	assert.Equal(t, "compiled", byPack[productconfigs.VendorPackALUSR].Status)
	assertACLCompileContains(t, byPack[productconfigs.VendorPackALUSR], "Alc-Nas-Filter-Rule-Shared")
	assert.Equal(t, "compiled", byPack[productconfigs.VendorPackALUAAA].Status)
	assertACLCompileContains(t, byPack[productconfigs.VendorPackALUAAA], "ALU-AAA-Access-Rule")
}
