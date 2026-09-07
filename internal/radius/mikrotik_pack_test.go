package radius

import (
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	layehradius "layeh.com/radius"
)

func TestMikroTikPackParsesRouterOSSubscriberState(t *testing.T) {
	packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	require.NoError(t, addVendorString(packet, 14988, 8, "50000k/20000k"))
	require.NoError(t, addVendorString(packet, 14988, 3, "ppp-gold"))
	require.NoError(t, addVendorString(packet, 14988, 19, "guest-internet"))
	require.NoError(t, addVendorString(packet, 14988, 30, "switch-profile"))
	require.NoError(t, addVendorString(packet, 14988, 22, "pd-gold"))
	require.NoError(t, addVendorString(packet, 14988, 12, "https://portal.example.test/mikrotik"))
	require.NoError(t, addVendorString(packet, 14988, 9, "tenant-a"))
	require.NoError(t, addVendorString(packet, 14988, 11, "mark-a"))
	require.NoError(t, addVendorString(packet, 14988, 16, "routeros-secret"))
	require.NoError(t, addVendorString(packet, 14988, 21, "cap-comment"))
	require.NoError(t, addVendorString(packet, 14988, 23, "voice-options"))
	require.NoError(t, addVendorString(packet, 14988, 24, "client-class"))
	require.NoError(t, addVendorString(packet, 14988, 25, "vendor-class"))
	require.NoError(t, addVendorInteger(packet, 14988, 4, 1))
	require.NoError(t, addVendorInteger(packet, 14988, 5, 0))
	require.NoError(t, addVendorInteger(packet, 14988, 17, 1_073_741_824))
	require.NoError(t, addVendorInteger(packet, 14988, 18, 1))
	require.NoError(t, addVendorInteger(packet, 14988, 26, 120))
	require.NoError(t, addVendorInteger(packet, 14988, 27, 1))
	require.NoError(t, addVendorAttribute(packet, 14988, 10, layehradius.Attribute(net.IPv4(198, 51, 100, 10).To4())))

	result := ParseBrokerPacketWithConfig(packet, &config.Config{
		Radius: config.RadiusConfig{
			Vendor: vendorConfigForPacks(productconfigs.VendorPackMikroTik),
		},
	})

	assert.Equal(t, "50000k/20000k", result.MikrotikRateLimit)
	assert.Equal(t, "50000k/20000k", result.VendorBandwidthProfile)
	assert.Equal(t, 50000, result.WISPrBandwidthMaxDown)
	assert.Equal(t, 20000, result.WISPrBandwidthMaxUp)
	assert.Equal(t, "ppp-gold", result.VendorRole)
	assert.Equal(t, "guest-internet", result.VendorInboundACL)
	assert.Equal(t, "switch-profile", result.VendorOutboundACL)
	assert.Equal(t, "pd-gold", result.VendorDelegatedIPv6Pool)
	assert.Equal(t, "https://portal.example.test/mikrotik", result.VendorPortalProfile)
	assert.Equal(t, "tenant-a", result.VendorTenant)
	assert.Equal(t, "mark-a", result.VendorPolicyTag)
	assert.Equal(t, "cap-comment", result.VendorDeviceGroup)
	assert.Equal(t, "198.51.100.10", result.VendorFramedIPAddress)
	assert.True(t, result.HasVendorVLAN)
	assert.Equal(t, 120, result.VendorVLAN)
	assert.Equal(t, "routeros-vlan-id-type=use-customer-tag", result.VendorVLANPolicy)
	assert.True(t, result.HasVendorMaxTotalOctets)
	assert.Equal(t, uint64(5_368_709_120), result.VendorMaxTotalOctets)
	assert.Equal(t, "wireless-forward=enabled", result.VendorDevicePosture)
	assert.Contains(t, result.VendorAVPairs, "Mikrotik-Wireless-PSK=<redacted>")
	assert.Contains(t, result.VendorAVPairs, "Mikrotik-DHCP-Option-Set=voice-options")
	assert.Contains(t, result.VendorAVPairs, "Mikrotik-DHCP-Option-Param-STR1=client-class")
	assert.Contains(t, result.VendorAVPairs, "Mikrotik-DHCP-Option-ParamSTR2=vendor-class")
	assert.Contains(t, result.VendorAVPairs, "wireless-skip-dot1x=disabled")
}

func TestMikroTikPackNormalizesRedactsAndBoundsAttributes(t *testing.T) {
	secret, err := NormalizeMikroTikAttribute("Mikrotik", "Mikrotik-Wireless-PSK", "supersecret")
	require.NoError(t, err)
	assert.True(t, secret.Redacted)
	assert.Equal(t, "<redacted>", secret.Value)
	assert.Equal(t, "Mikrotik-Wireless-PSK=<redacted>", secret.Raw)

	_, err = NormalizeMikroTikAttribute("Mikrotik", "Mikrotik-Group", "bad\nvalue")
	assert.ErrorContains(t, err, "control characters")

	_, err = NormalizeMikroTikAttribute("Mikrotik", "Mikrotik-Group", strings.Repeat("a", MikroTikMaxValueLength+1))
	assert.ErrorContains(t, err, "exceeds")
}

func TestRenderReplyAttributesIncludesMikroTikRouterOSFields(t *testing.T) {
	attrs := &ReplyAttributes{
		Role:              "ppp-gold",
		VLAN:              120,
		MikrotikRateLimit: "50000k/20000k",
		InboundACL:        "guest-internet",
		OutboundACL:       "switch-profile",
		Tenant:            "tenant-a",
		PolicyTag:         "mark-a",
		PortalProfile:     "https://portal.example.test/mikrotik",
		FramedIPAddress:   "198.51.100.10",
		FramedIPv6Pool:    "pd-gold",
		DeviceGroup:       "cap-comment",
		VLANPolicyMode:    "access",
	}
	vendor := config.RadiusVendorConfig{QuotaMappings: []config.RadiusVendorQuotaMapping{
		{Pack: productconfigs.VendorPackMikroTik, Role: "ppp-gold", MaxTotalOctets: 4_294_967_296 + 5},
	}}

	rendered := RenderReplyAttributesForVendorConfigAndPacks(attrs, []string{productconfigs.VendorPackMikroTik}, vendor)

	assert.Contains(t, rendered, "\tMikrotik-Rate-Limit = \"50000k/20000k\"\n")
	assert.Contains(t, rendered, "\tMikrotik-Group = \"ppp-gold\"\n")
	assert.Contains(t, rendered, "\tMikrotik-Address-List = \"guest-internet\"\n")
	assert.Contains(t, rendered, "\tMikrotik-Switching-Filter = \"switch-profile\"\n")
	assert.Contains(t, rendered, "\tMikrotik-Realm = \"tenant-a\"\n")
	assert.Contains(t, rendered, "\tMikrotik-Mark-Id = \"mark-a\"\n")
	assert.Contains(t, rendered, "\tMikrotik-Advertise-URL = \"https://portal.example.test/mikrotik\"\n")
	assert.Contains(t, rendered, "\tMikrotik-Host-IP = 198.51.100.10\n")
	assert.Contains(t, rendered, "\tMikrotik-Delegated-IPv6-Pool = \"pd-gold\"\n")
	assert.Contains(t, rendered, "\tMikrotik-Wireless-VLANID = 120\n")
	assert.Contains(t, rendered, "\tMikrotik-Wireless-VLANID-Type = 0\n")
	assert.Contains(t, rendered, "\tMikrotik-Wireless-Comment = \"cap-comment\"\n")
	assert.Contains(t, rendered, "\tMikrotik-Total-Limit = 5\n")
	assert.Contains(t, rendered, "\tMikrotik-Total-Limit-Gigawords = 1\n")
}

func TestMikroTikPackACLCompilerExportsBothRouterOSProfiles(t *testing.T) {
	result, err := CompileACLPolicyForPack(ACLCompilerRequest{
		PolicyName:  "guest-internet",
		InboundACL:  "guest-in",
		OutboundACL: "switch-profile",
		Rules: []ACLRule{{
			Action: "permit", Direction: "in", Protocol: "tcp", Source: "any", Destination: "any", DestinationPort: "443",
		}},
	}, productconfigs.VendorPackMikroTik)
	require.NoError(t, err)

	assert.Equal(t, "profile_reference", result.Status)
	assert.False(t, result.Lossless)
	assertACLCompileContains(t, result, "Mikrotik-Address-List")
	assertACLCompileContains(t, result, "Mikrotik-Switching-Filter")
}
