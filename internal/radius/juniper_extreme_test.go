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

func TestNormalizeJuniperExtremeAttributeClassifiesAndRedacts(t *testing.T) {
	tests := []struct {
		vendor    string
		attribute string
		value     string
		kind      JuniperExtremeAttributeKind
		semantic  string
		redacted  bool
	}{
		{"juniper", "Juniper-Allow-Commands", "show.*", JuniperExtremeKindCommandAuth, productconfigs.VendorSemanticRole, false},
		{"juniper", "Juniper-Firewall-filter-name", "guest-in", JuniperExtremeKindACL, productconfigs.VendorSemanticACL, false},
		{"juniper", "Juniper-AV-Pair", "junos:vrf=tenant-a", JuniperExtremeKindVRF, productconfigs.VendorSemanticVRF, false},
		{"juniper", "Juniper-AV-Pair", "ipv6:delegated-prefix=branch-pd", JuniperExtremeKindAddressPool, productconfigs.VendorSemanticAddressPool, false},
		{"extreme", "Extreme-Netlogin-Extended-Vlan", "U20;T30;T40", JuniperExtremeKindVLAN, productconfigs.VendorSemanticVLAN, false},
		{"extreme", "Extreme-User-Location", "building-a", JuniperExtremeKindTenant, productconfigs.VendorSemanticTenant, false},
		{"erx", "ERX-Virtual-Router-Name", "vr-corp", JuniperExtremeKindVRF, productconfigs.VendorSemanticVRF, false},
		{"erx", "ERX-Service-Activate", "iptv-gold", JuniperExtremeKindSessionAction, productconfigs.VendorSemanticSessionAction, false},
		{"erx", "ERX-Bulk-CoA-Transaction-Id", "1001", JuniperExtremeKindCoA, productconfigs.VendorSemanticCoAReauth, false},
		{"erx", "ERX-Tunnel-Password", "super-secret", JuniperExtremeKindSecret, productconfigs.VendorSemanticPolicyTag, true},
	}
	for _, tc := range tests {
		t.Run(tc.attribute+"/"+tc.value, func(t *testing.T) {
			token, err := NormalizeJuniperExtremeAttribute(tc.vendor, tc.attribute, tc.value)
			require.NoError(t, err)
			assert.Equal(t, tc.kind, token.Kind)
			assert.Equal(t, tc.semantic, token.Semantic)
			assert.Equal(t, tc.redacted, token.Redacted)
			if tc.redacted {
				assert.Equal(t, "<redacted>", token.Value)
				assert.NotContains(t, token.Raw, tc.value)
			}
		})
	}
}

func TestNormalizeJuniperExtremeAttributeRejectsUnsafeValues(t *testing.T) {
	for _, raw := range []string{
		"",
		"role\x00bad",
		strings.Repeat("a", JuniperExtremeMaxValueLength+1),
	} {
		_, err := NormalizeJuniperExtremeAttribute("juniper", "Juniper-Allow-Commands", raw)
		require.Error(t, err)
	}

	_, err := NormalizeJuniperExtremeAttribute("juniper", "Juniper-AV-Pair", "bad token=value")
	require.Error(t, err)
}

func TestRenderReplyAttributesIncludesJuniperExtremeFamilyFields(t *testing.T) {
	rendered := RenderReplyAttributesForVendorConfig(&ReplyAttributes{
		Role:                     "operator",
		VLAN:                     20,
		VRF:                      "tenant-vr",
		BandwidthProfile:         "gold-qos",
		PortalProfile:            "https://guest.example.test/login",
		DeviceGroup:              "branch-edge",
		Tenant:                   "tenant-a",
		InboundACL:               "guest-in",
		OutboundACL:              "guest-out",
		FramedPool:               "corp-pool",
		JuniperAllowCommands:     "show.*",
		JuniperDenyCommands:      "request system halt",
		JuniperUserPermissions:   "view-configuration",
		JuniperVoIPVLAN:          "voice-40",
		JuniperPolicerParameter:  "policer=guest",
		JuniperAVPairs:           []string{"junos:vrf=tenant-vr", "firewall=guest-in"},
		ExtremeCLIAuthorization:  1,
		ExtremeShellCommand:      "show vlan",
		ExtremeNetloginURLDesc:   "Guest portal",
		ExtremeUserLocation:      "building-a",
		ExtremeVMName:            "tenant-vm",
		ExtremeVMVPPName:         "vpp-a",
		ExtremeVMIPAddr:          "192.0.2.10",
		ExtremeVMVLANID:          30,
		ExtremeVMVRName:          "vr-edge",
		ERXVirtualRouterName:     "vr-corp",
		ERXAddressPoolName:       "pool-a",
		ERXRedirectVRName:        "redirect-vr",
		ERXQoSProfileName:        "gold",
		ERXPppoeURL:              "https://subscriber.example.test/start",
		ERXServiceBundle:         "bundle-a",
		ERXServiceActivate:       "iptv-gold",
		ERXServiceDeactivate:     "walled-garden",
		ERXServiceTimeout:        3600,
		ERXClientProfileName:     "profile-a",
		ERXAPNName:               "internet",
		ERXCosShapingRate:        "50m",
		ERXInputInterfaceFilter:  "in-filter",
		ERXOutputInterfaceFilter: "out-filter",
		ERXIPv6DelegatedPoolName: "pd-pool",
		ERXBulkCoATransactionID:  1001,
		ERXBulkCoAIdentifier:     2002,
		ERXAdvPcefRuleName:       "pcef-rule",
	}, config.RadiusVendorConfig{
		CompatibilityPacks: []string{
			productconfigs.VendorPackJuniper,
			productconfigs.VendorPackExtreme,
			productconfigs.VendorPackERX,
		},
	})

	assert.Contains(t, rendered, "Juniper-Allow-Commands = \"show.*\"")
	assert.Contains(t, rendered, "Juniper-VoIP-Vlan = \"voice-40\"")
	assert.Contains(t, rendered, "Juniper-CoS-Traffic-Control-Profile = \"gold-qos\"")
	assert.Contains(t, rendered, "Juniper-AV-Pair = \"junos:vrf=tenant-vr\"")
	assert.Contains(t, rendered, "Extreme-Netlogin-Url-Desc = \"Guest portal\"")
	assert.Contains(t, rendered, "Extreme-VM-IP-Addr = \"192.0.2.10\"")
	assert.Contains(t, rendered, "Extreme-VM-VLAN-ID = 30")
	assert.Contains(t, rendered, "ERX-Virtual-Router-Name = \"vr-corp\"")
	assert.Contains(t, rendered, "ERX-Address-Pool-Name = \"pool-a\"")
	assert.Contains(t, rendered, "ERX-Service-Activate = \"iptv-gold\"")
	assert.Contains(t, rendered, "ERX-Input-Interface-Filter = \"in-filter\"")
	assert.Contains(t, rendered, "ERX-Bulk-CoA-Transaction-Id = 1001")
	assert.Contains(t, rendered, "ERX-Adv-Pcef-Rule-Name = \"pcef-rule\"")
}

func TestJuniperExtremeInboundNormalization(t *testing.T) {
	packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	require.NoError(t, addVendorString(packet, 2636, 52, "firewall=guest-in"))
	require.NoError(t, addVendorString(packet, 2636, 52, "ip:route=10.80.0.0/16 192.0.2.1"))
	require.NoError(t, addVendorString(packet, 2636, 52, "junos:vrf=tenant-a"))
	require.NoError(t, addVendorString(packet, 2636, 52, "translation-port-block=10000-10511"))
	require.NoError(t, addVendorString(packet, 2636, 50, "https://guest.example.test/login"))
	require.NoError(t, addVendorString(packet, 1916, 211, "U20;T30;T40"))
	require.NoError(t, addVendorString(packet, 1916, 208, "building-a"))
	require.NoError(t, addVendorString(packet, 4874, 1, "vr-erx"))
	require.NoError(t, addVendorString(packet, 4874, 2, "public-pool"))
	require.NoError(t, addVendorInteger(packet, 4874, 113, 25000))
	require.NoError(t, addVendorInteger(packet, 4874, 114, 75000))
	require.NoError(t, addVendorString(packet, 4874, 65, "iptv-gold"))
	require.NoError(t, addVendorString(packet, 4874, 9, "clear-text-secret"))

	result := ParseBrokerPacketWithConfig(packet, &config.Config{
		Radius: config.RadiusConfig{
			Vendor: vendorConfigForPacks(productconfigs.VendorPackJuniper, productconfigs.VendorPackExtreme, productconfigs.VendorPackERX),
		},
	})

	assert.Equal(t, "guest-in", result.VendorInboundACL)
	assert.Equal(t, []string{"10.80.0.0/16 192.0.2.1"}, result.VendorFramedRoutes)
	assert.Equal(t, "tenant-a", result.VendorVRF)
	assert.True(t, result.HasVendorTranslationPortBlockStart)
	assert.Equal(t, 10000, result.VendorTranslationPortBlockStart)
	assert.True(t, result.HasVendorTranslationPortBlockEnd)
	assert.Equal(t, 10511, result.VendorTranslationPortBlockEnd)
	assert.Equal(t, "https://guest.example.test/login", result.VendorPortalProfile)
	assert.True(t, result.HasVendorVLAN)
	assert.Equal(t, 20, result.VendorVLAN)
	assert.Equal(t, []int{30, 40}, result.VendorTaggedVLANs)
	assert.Equal(t, "building-a", result.VendorTenant)
	assert.Equal(t, "public-pool", result.VendorIPv4Pool)
	assert.Equal(t, "public-pool", result.VendorTranslationPublicIPv4Pool)
	assert.Equal(t, 25000, result.WISPrBandwidthMaxUp)
	assert.Equal(t, 75000, result.WISPrBandwidthMaxDown)
	assert.Equal(t, "iptv-gold", result.VendorSessionAction)
	assert.Contains(t, strings.Join(result.VendorAVPairs, ","), "ERX-Tunnel-Password=<redacted>")
	assert.NotContains(t, strings.Join(result.VendorAVPairs, ","), "clear-text-secret")
}

func TestJuniperExtremeInboundPreservesUnknownAVPair(t *testing.T) {
	packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	require.NoError(t, addVendorString(packet, 2636, 52, "juniper-one"))

	result := ParseBrokerPacketWithConfig(packet, &config.Config{
		Radius: config.RadiusConfig{Vendor: vendorConfigForPacks(productconfigs.VendorPackJuniper)},
	})

	assert.Equal(t, []string{"juniper-one"}, result.VendorAVPairs)
	assert.Empty(t, result.VendorInboundACL)
}
