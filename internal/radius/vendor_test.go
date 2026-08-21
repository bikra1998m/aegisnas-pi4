package radius

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	layehradius "layeh.com/radius"
)

func TestApplyVendorAttributesParsesAegisNASVSAs(t *testing.T) {
	vendor := config.RadiusVendorConfig{
		Enabled: true,
		Name:    "AegisNAS",
		ID:      55555,
	}
	packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	require.NoError(t, addVendorString(packet, uint32(vendor.ID), AegisNASVendorAttrRole, "guest-premium"))
	require.NoError(t, addVendorString(packet, uint32(vendor.ID), AegisNASVendorAttrBandwidthProfile, "50m-down-20m-up"))
	require.NoError(t, addVendorInteger(packet, uint32(vendor.ID), AegisNASVendorAttrVLAN, 20))
	require.NoError(t, addVendorInteger(packet, uint32(vendor.ID), AegisNASVendorAttrQuarantine, 1))
	require.NoError(t, addVendorString(packet, uint32(vendor.ID), AegisNASVendorAttrPolicyTag, "premium"))
	require.NoError(t, addVendorInteger(packet, uint32(vendor.ID), AegisNASVendorAttrSessionTimeout, 3600))
	require.NoError(t, addVendorInteger(packet, uint32(vendor.ID), AegisNASVendorAttrIdleTimeout, 600))
	require.NoError(t, addVendorInteger(packet, uint32(vendor.ID), AegisNASVendorAttrDataVLAN, 21))
	require.NoError(t, addVendorInteger(packet, uint32(vendor.ID), AegisNASVendorAttrVoiceVLAN, 30))
	require.NoError(t, addVendorInteger(packet, uint32(vendor.ID), AegisNASVendorAttrTaggedVLAN, 40))
	require.NoError(t, addVendorInteger(packet, uint32(vendor.ID), AegisNASVendorAttrTaggedVLAN, 50))
	require.NoError(t, addVendorInteger(packet, uint32(vendor.ID), AegisNASVendorAttrQinQOuterVLAN, 3000))
	require.NoError(t, addVendorInteger(packet, uint32(vendor.ID), AegisNASVendorAttrQinQInnerVLAN, 21))
	require.NoError(t, addVendorString(packet, uint32(vendor.ID), AegisNASVendorAttrVLANPool, "branch-data"))
	require.NoError(t, addVendorInteger(packet, uint32(vendor.ID), AegisNASVendorAttrFallbackVLAN, 99))
	require.NoError(t, addVendorInteger(packet, uint32(vendor.ID), AegisNASVendorAttrAuthFailVLAN, 98))
	require.NoError(t, addVendorString(packet, uint32(vendor.ID), AegisNASVendorAttrVLANPolicy, "voice-data"))
	require.NoError(t, addVendorString(packet, uint32(vendor.ID), AegisNASVendorAttrRoutePolicy, "authorize"))
	require.NoError(t, addVendorString(packet, uint32(vendor.ID), AegisNASVendorAttrVRF, "corp"))
	require.NoError(t, addVendorString(packet, uint32(vendor.ID), AegisNASVendorAttrRouteOwner, "network-team"))
	require.NoError(t, addVendorString(packet, uint32(vendor.ID), AegisNASVendorAttrRouteRevision, "sha256:route"))
	require.NoError(t, addVendorString(packet, uint32(vendor.ID), AegisNASVendorAttrFramedRoute, "10.80.0.0/16 192.0.2.1"))
	require.NoError(t, addVendorString(packet, uint32(vendor.ID), AegisNASVendorAttrFramedIPv6Route, "2001:db8:80::/48 2001:db8::1"))
	require.NoError(t, addVendorString(packet, uint32(vendor.ID), AegisNASVendorAttrAddressPolicy, "authorize"))
	require.NoError(t, addVendorString(packet, uint32(vendor.ID), AegisNASVendorAttrAddressOwner, "address-team"))
	require.NoError(t, addVendorString(packet, uint32(vendor.ID), AegisNASVendorAttrAddressRevision, "sha256:address"))
	require.NoError(t, addVendorString(packet, uint32(vendor.ID), AegisNASVendorAttrIPv4Pool, "branch-v4"))
	require.NoError(t, addVendorString(packet, uint32(vendor.ID), AegisNASVendorAttrIPv6Pool, "branch-v6"))
	require.NoError(t, addVendorString(packet, uint32(vendor.ID), AegisNASVendorAttrDelegatedIPv6Pool, "branch-pd"))
	require.NoError(t, addVendorString(packet, uint32(vendor.ID), AegisNASVendorAttrRAPrefixPool, "branch-ra"))
	require.NoError(t, addVendorString(packet, uint32(vendor.ID), AegisNASVendorAttrFramedIPAddress, "198.51.100.2"))
	require.NoError(t, addVendorString(packet, uint32(vendor.ID), AegisNASVendorAttrFramedIPv6Address, "2001:db8:10::10"))
	require.NoError(t, addVendorString(packet, uint32(vendor.ID), AegisNASVendorAttrFramedIPv6Prefix, "2001:db8:10::/64"))
	require.NoError(t, addVendorString(packet, uint32(vendor.ID), AegisNASVendorAttrDelegatedIPv6Prefix, "2001:db8:100::/56"))
	require.NoError(t, addVendorString(packet, uint32(vendor.ID), AegisNASVendorAttrRAPrefix, "2001:db8:200::/64"))
	require.NoError(t, addVendorString(packet, uint32(vendor.ID), AegisNASVendorAttrDHCPv6Mode, "stateful-pd"))
	require.NoError(t, addVendorString(packet, uint32(vendor.ID), AegisNASVendorAttrRAMode, "slaac"))
	require.NoError(t, addVendorString(packet, uint32(vendor.ID), AegisNASVendorAttrTranslationPolicy, "authorize"))
	require.NoError(t, addVendorString(packet, uint32(vendor.ID), AegisNASVendorAttrTranslationOwner, "nat-team"))
	require.NoError(t, addVendorString(packet, uint32(vendor.ID), AegisNASVendorAttrTranslationRevision, "sha256:translation"))
	require.NoError(t, addVendorString(packet, uint32(vendor.ID), AegisNASVendorAttrTranslationMode, "dual-stack"))
	require.NoError(t, addVendorString(packet, uint32(vendor.ID), AegisNASVendorAttrTranslationPublicIPv4Pool, "cgnat-public"))
	require.NoError(t, addVendorString(packet, uint32(vendor.ID), AegisNASVendorAttrTranslationPublicIPv4Address, "198.51.100.2"))
	require.NoError(t, addVendorString(packet, uint32(vendor.ID), AegisNASVendorAttrTranslationPrivateIPv4Prefix, "100.64.1.0/24"))
	require.NoError(t, addVendorString(packet, uint32(vendor.ID), AegisNASVendorAttrTranslationSubscriberIPv6Prefix, "2001:db8:57::/64"))
	require.NoError(t, addVendorString(packet, uint32(vendor.ID), AegisNASVendorAttrTranslationNAT64Prefix, "64:ff9b::/96"))
	require.NoError(t, addVendorInteger(packet, uint32(vendor.ID), AegisNASVendorAttrTranslationPortBlockStart, 10000))
	require.NoError(t, addVendorInteger(packet, uint32(vendor.ID), AegisNASVendorAttrTranslationPortBlockEnd, 10511))
	require.NoError(t, addVendorInteger(packet, uint32(vendor.ID), AegisNASVendorAttrTranslationPortBlockSize, 512))
	require.NoError(t, addVendorString(packet, uint32(vendor.ID), AegisNASVendorAttrTranslationLoggingProfile, "lawful-cgnat"))
	require.NoError(t, addVendorString(packet, uint32(vendor.ID), AegisNASVendorAttrTranslationAccountingKey, "acct-key"))

	result := ParseBrokerPacket(packet)
	ApplyVendorAttributes(result, packet, vendor)

	assert.Equal(t, "guest-premium", result.VendorRole)
	assert.Equal(t, "50m-down-20m-up", result.VendorBandwidthProfile)
	assert.Equal(t, "premium", result.VendorPolicyTag)
	assert.True(t, result.HasVendorVLAN)
	assert.Equal(t, 20, result.VendorVLAN)
	assert.True(t, result.HasVendorVoiceVLAN)
	assert.Equal(t, 30, result.VendorVoiceVLAN)
	assert.Equal(t, []int{40, 50}, result.VendorTaggedVLANs)
	assert.True(t, result.HasVendorQinQOuterVLAN)
	assert.Equal(t, 3000, result.VendorQinQOuterVLAN)
	assert.True(t, result.HasVendorQinQInnerVLAN)
	assert.Equal(t, 21, result.VendorQinQInnerVLAN)
	assert.Equal(t, "branch-data", result.VendorVLANPool)
	assert.True(t, result.HasVendorFallbackVLAN)
	assert.Equal(t, 99, result.VendorFallbackVLAN)
	assert.True(t, result.HasVendorAuthFailVLAN)
	assert.Equal(t, 98, result.VendorAuthFailVLAN)
	assert.Equal(t, "voice-data", result.VendorVLANPolicy)
	assert.Equal(t, "authorize", result.VendorRoutePolicy)
	assert.Equal(t, "corp", result.VendorVRF)
	assert.Equal(t, "network-team", result.VendorRouteOwner)
	assert.Equal(t, "sha256:route", result.VendorRouteRevision)
	assert.Equal(t, []string{"10.80.0.0/16 192.0.2.1"}, result.VendorFramedRoutes)
	assert.Equal(t, []string{"2001:db8:80::/48 2001:db8::1"}, result.VendorFramedIPv6Routes)
	assert.Equal(t, "authorize", result.VendorAddressPolicy)
	assert.Equal(t, "address-team", result.VendorAddressOwner)
	assert.Equal(t, "sha256:address", result.VendorAddressRevision)
	assert.Equal(t, "branch-v4", result.VendorIPv4Pool)
	assert.Equal(t, "branch-v6", result.VendorIPv6Pool)
	assert.Equal(t, "branch-pd", result.VendorDelegatedIPv6Pool)
	assert.Equal(t, "branch-ra", result.VendorRAPrefixPool)
	assert.Equal(t, "198.51.100.2", result.VendorFramedIPAddress)
	assert.Equal(t, "2001:db8:10::10", result.VendorFramedIPv6Address)
	assert.Equal(t, "2001:db8:10::/64", result.VendorFramedIPv6Prefix)
	assert.Equal(t, "2001:db8:100::/56", result.VendorDelegatedIPv6Prefix)
	assert.Equal(t, "2001:db8:200::/64", result.VendorRAPrefix)
	assert.Equal(t, "stateful-pd", result.VendorDHCPv6Mode)
	assert.Equal(t, "slaac", result.VendorRAMode)
	assert.Equal(t, "authorize", result.VendorTranslationPolicy)
	assert.Equal(t, "nat-team", result.VendorTranslationOwner)
	assert.Equal(t, "sha256:translation", result.VendorTranslationRevision)
	assert.Equal(t, "dual-stack", result.VendorTranslationMode)
	assert.Equal(t, "cgnat-public", result.VendorTranslationPublicIPv4Pool)
	assert.Equal(t, "198.51.100.2", result.VendorTranslationPublicIPv4Address)
	assert.Equal(t, "100.64.1.0/24", result.VendorTranslationPrivateIPv4Prefix)
	assert.Equal(t, "2001:db8:57::/64", result.VendorTranslationSubscriberIPv6Prefix)
	assert.Equal(t, "64:ff9b::/96", result.VendorTranslationNAT64Prefix)
	assert.True(t, result.HasVendorTranslationPortBlockStart)
	assert.Equal(t, 10000, result.VendorTranslationPortBlockStart)
	assert.True(t, result.HasVendorTranslationPortBlockEnd)
	assert.Equal(t, 10511, result.VendorTranslationPortBlockEnd)
	assert.True(t, result.HasVendorTranslationPortBlockSize)
	assert.Equal(t, 512, result.VendorTranslationPortBlockSize)
	assert.Equal(t, "lawful-cgnat", result.VendorTranslationLoggingProfile)
	assert.Equal(t, "acct-key", result.VendorTranslationAccountingKey)
	assert.True(t, result.HasVendorQuarantine)
	assert.True(t, result.VendorQuarantine)
	assert.True(t, result.HasVendorSessionTimeout)
	assert.Equal(t, 3600, result.VendorSessionTimeout)
	assert.True(t, result.HasVendorIdleTimeout)
	assert.Equal(t, 600, result.VendorIdleTimeout)
}

func TestApplyVendorAttributesParsesAegisNASDataVLANWithoutLegacyVLAN(t *testing.T) {
	vendor := config.RadiusVendorConfig{
		Enabled: true,
		Name:    "AegisNAS",
		ID:      55555,
	}
	packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	require.NoError(t, addVendorInteger(packet, uint32(vendor.ID), AegisNASVendorAttrDataVLAN, 21))

	result := ParseBrokerPacket(packet)
	ApplyVendorAttributes(result, packet, vendor)

	assert.True(t, result.HasVendorVLAN)
	assert.Equal(t, 21, result.VendorVLAN)
}

func TestApplyVendorCompatibilityAttributesParsesInboundVSAs(t *testing.T) {
	packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	require.NoError(t, addVendorString(packet, 14823, 1, "guest-premium"))
	require.NoError(t, addVendorInteger(packet, 14823, 2, 30))
	require.NoError(t, addVendorString(packet, 14823, 10, "branch-aps"))
	require.NoError(t, addVendorString(packet, 14823, 12, "ios"))
	require.NoError(t, addVendorString(packet, 14823, 19, "bikram-iphone"))
	require.NoError(t, addVendorString(packet, 14823, 43, "https://portal.example.test/login"))
	require.NoError(t, addVendorString(packet, 9, 57, "guest-in"))
	require.NoError(t, addVendorString(packet, 9, 58, "guest-out"))
	require.NoError(t, addVendorString(packet, 12356, 6, "quarantine-profile"))
	require.NoError(t, addVendorInteger(packet, 17713, 160, 1))
	require.NoError(t, addVendorString(packet, 29671, 2, "corp-network"))

	result := ParseBrokerPacketWithConfig(packet, &config.Config{
		Radius: config.RadiusConfig{
			Vendor: vendorConfigForPacks(productconfigs.VendorPackAruba, productconfigs.VendorPackCisco, productconfigs.VendorPackFortinet, productconfigs.VendorPackCambium, productconfigs.VendorPackMeraki),
		},
	})

	assert.Equal(t, "guest-premium", result.VendorRole)
	assert.True(t, result.HasVendorVLAN)
	assert.Equal(t, 30, result.VendorVLAN)
	assert.Equal(t, "branch-aps", result.VendorDeviceGroup)
	assert.Equal(t, "ios", result.VendorDevicePosture)
	assert.Equal(t, "bikram-iphone", result.VendorAccountingIdentity)
	assert.Equal(t, "https://portal.example.test/login", result.VendorPortalProfile)
	assert.Equal(t, "guest-in", result.VendorInboundACL)
	assert.Equal(t, "guest-out", result.VendorOutboundACL)
	assert.Equal(t, "quarantine-profile", result.VendorPolicyTag)
	assert.True(t, result.HasVendorQuarantine)
	assert.True(t, result.VendorQuarantine)
	assert.Equal(t, "corp-network", result.VendorTenant)
}

func TestApplyVendorCompatibilityAttributesParsesExpandedInboundVSAs(t *testing.T) {
	packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	require.NoError(t, addVendorInteger64(packet, 41112, 1, 75_000_000))
	require.NoError(t, addVendorInteger64(packet, 41112, 3, 25_000_000))
	require.NoError(t, addVendorString(packet, 1916, 212, "corp-secure"))
	require.NoError(t, addVendorString(packet, 1916, 203, "44"))
	require.NoError(t, addVendorString(packet, 1916, 204, "https://extreme.example.test/cwa"))
	require.NoError(t, addVendorString(packet, 2636, 44, "junos-in"))
	require.NoError(t, addVendorString(packet, 2011, 31, "gold-qos"))
	require.NoError(t, addVendorString(packet, 25506, 216, "ita-policy-1"))
	require.NoError(t, addVendorString(packet, 25461, 2, "tenant-a"))
	require.NoError(t, addVendorString(packet, 25461, 5, "vpn-users"))
	require.NoError(t, addVendorString(packet, 25461, 8, "Windows 11"))
	require.NoError(t, addVendorString(packet, 25461, 9, "laptop-42"))

	result := ParseBrokerPacketWithConfig(packet, &config.Config{
		Radius: config.RadiusConfig{
			Vendor: vendorConfigForPacks(productconfigs.VendorPackUBNT, productconfigs.VendorPackExtreme, productconfigs.VendorPackJuniper, productconfigs.VendorPackHuawei, productconfigs.VendorPackH3C, productconfigs.VendorPackPaloAlto),
		},
	})

	assert.Equal(t, 75000, result.WISPrBandwidthMaxDown)
	assert.Equal(t, 25000, result.WISPrBandwidthMaxUp)
	assert.Equal(t, "corp-secure", result.VendorRole)
	assert.True(t, result.HasVendorVLAN)
	assert.Equal(t, 44, result.VendorVLAN)
	assert.Equal(t, "https://extreme.example.test/cwa", result.VendorPortalProfile)
	assert.Equal(t, "junos-in", result.VendorInboundACL)
	assert.Equal(t, "gold-qos", result.VendorBandwidthProfile)
	assert.Equal(t, "ita-policy-1", result.VendorPolicyTag)
	assert.Equal(t, "tenant-a", result.VendorTenant)
	assert.Equal(t, "vpn-users", result.VendorDeviceGroup)
	assert.Equal(t, "Windows 11", result.VendorDevicePosture)
	assert.Equal(t, "laptop-42", result.VendorAccountingIdentity)
}

func TestApplyVendorCompatibilityAttributesParsesExtremeExtendedVLAN(t *testing.T) {
	packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	require.NoError(t, addVendorString(packet, 1916, 203, "10"))
	require.NoError(t, addVendorString(packet, 1916, 211, "U20;T30;T40;"))

	result := ParseBrokerPacketWithConfig(packet, &config.Config{Radius: config.RadiusConfig{Vendor: vendorConfigForPacks(productconfigs.VendorPackExtreme)}})

	assert.True(t, result.HasVendorVLAN)
	assert.Equal(t, 20, result.VendorVLAN)
	assert.Equal(t, []int{30, 40}, result.VendorTaggedVLANs)
}

func TestApplyVendorCompatibilityAttributesPreservesAVPairs(t *testing.T) {
	packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	require.NoError(t, addVendorString(packet, 2636, 52, "juniper-one"))
	require.NoError(t, addVendorString(packet, 2636, 52, "juniper-two"))
	require.NoError(t, addVendorString(packet, 2011, 188, "huawei-one"))
	require.NoError(t, addVendorString(packet, 25506, 210, "h3c-one"))
	require.NoError(t, addVendorString(packet, 30065, 1, "arista-one"))

	result := ParseBrokerPacketWithConfig(packet, &config.Config{Radius: config.RadiusConfig{Vendor: vendorConfigForPacks(
		productconfigs.VendorPackJuniper,
		productconfigs.VendorPackHuawei,
		productconfigs.VendorPackH3C,
		productconfigs.VendorPackArista,
	)}})

	assert.Equal(t, []string{"juniper-one", "juniper-two", "huawei-one", "h3c-one", "arista-one"}, result.VendorAVPairs)
	assert.Empty(t, result.VendorInboundACL)
}

func TestApplyVendorCompatibilityAttributesReversesTPLinkPortalStatus(t *testing.T) {
	packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	require.NoError(t, addVendorInteger(packet, 11863, 9, 7))
	vendor := vendorConfigForPacks(productconfigs.VendorPackTPLink)
	vendor.PortalStatusMappings = []config.RadiusVendorPortalStatusMapping{
		{Pack: "tplink", PortalProfile: "guest-authorized", Value: 7},
	}

	result := ParseBrokerPacketWithConfig(packet, &config.Config{Radius: config.RadiusConfig{Vendor: vendor}})

	assert.Equal(t, "guest-authorized", result.VendorPortalProfile)
}

func TestApplyVendorCompatibilityAttributesIgnoresUnknownTPLinkPortalStatus(t *testing.T) {
	packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	require.NoError(t, addVendorInteger(packet, 11863, 9, 99))
	vendor := vendorConfigForPacks(productconfigs.VendorPackTPLink)
	vendor.PortalStatusMappings = []config.RadiusVendorPortalStatusMapping{{Pack: "tplink", PortalProfile: "guest-authorized", Value: 7}}

	result := ParseBrokerPacketWithConfig(packet, &config.Config{Radius: config.RadiusConfig{Vendor: vendor}})

	assert.Empty(t, result.VendorPortalProfile)
}

func TestApplyVendorCompatibilityAttributesReversesNomadixSessionAction(t *testing.T) {
	packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	require.NoError(t, addVendorInteger(packet, 3309, 9, 7))
	vendor := vendorConfigForPacks(productconfigs.VendorPackNomadix)
	vendor.SessionActionMappings = []config.RadiusVendorSessionActionMapping{
		{Pack: "nomadix", Role: "expired-guest", Action: "disconnect", Value: 7},
	}

	result := ParseBrokerPacketWithConfig(packet, &config.Config{Radius: config.RadiusConfig{Vendor: vendor}})

	assert.Equal(t, "disconnect", result.VendorSessionAction)
}

func TestApplyVendorCompatibilityAttributesIgnoresUnknownNomadixSessionAction(t *testing.T) {
	packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	require.NoError(t, addVendorInteger(packet, 3309, 9, 99))
	vendor := vendorConfigForPacks(productconfigs.VendorPackNomadix)
	vendor.SessionActionMappings = []config.RadiusVendorSessionActionMapping{{Pack: "nomadix", Role: "guest", Action: "disconnect", Value: 7}}

	result := ParseBrokerPacketWithConfig(packet, &config.Config{Radius: config.RadiusConfig{Vendor: vendor}})

	assert.Empty(t, result.VendorSessionAction)
}

func TestApplyVendorCompatibilityAttributesParsesChilliSpotQuota(t *testing.T) {
	packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	require.NoError(t, addVendorInteger(packet, 14559, 3, 1_073_741_824))

	result := ParseBrokerPacketWithConfig(packet, &config.Config{Radius: config.RadiusConfig{Vendor: vendorConfigForPacks(productconfigs.VendorPackChilliSpot)}})

	assert.True(t, result.HasVendorMaxTotalOctets)
	assert.Equal(t, uint64(1_073_741_824), result.VendorMaxTotalOctets)
}

func TestApplyVendorCompatibilityAttributesDecodesNokiaServiceName(t *testing.T) {
	packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	require.NoError(t, addVendorAttribute(packet, 94, 3, layehradius.Attribute{0x00, 0x21, 0xf3}))

	result := ParseBrokerPacketWithConfig(packet, &config.Config{Radius: config.RadiusConfig{Vendor: vendorConfigForPacks(productconfigs.VendorPackNokia)}})

	assert.Equal(t, "00123", result.VendorDeviceGroup)
}

func TestDecodeNokiaBCDRejectsMalformedPayloads(t *testing.T) {
	for _, value := range [][]byte{nil, {0xfa}, {0x2f}, {0xf1, 0x23}} {
		_, ok := decodeNokiaBCD(value)
		assert.False(t, ok)
	}
}

func TestParseExtremeExtendedVLANRejectsUnsafeValues(t *testing.T) {
	for _, value := range []string{"", "U20;T20", "U20;U30", "T0", "T4095", "*20", "Udata", "T1;T2;T3;T4;T5;T6;T7;T8;T9;T10;T11"} {
		t.Run(value, func(t *testing.T) {
			_, _, _, ok := parseExtremeExtendedVLAN(value)
			assert.False(t, ok)
		})
	}
}

func TestApplyVendorCompatibilityAttributesParsesAdditionalInboundVSAs(t *testing.T) {
	packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	require.NoError(t, addVendorInteger(packet, 26928, 1, 88))
	require.NoError(t, addVendorString(packet, 26928, 8, "aerohive-policy"))
	require.NoError(t, addVendorString(packet, 26928, 211, "https://aerohive.example.test/redirect"))
	require.NoError(t, addVendorInteger(packet, 14179, 1, 1001))
	require.NoError(t, addVendorString(packet, 14179, 11, "wlc-guest"))
	require.NoError(t, addVendorInteger(packet, 3309, 1, 15000))
	require.NoError(t, addVendorInteger(packet, 3309, 2, 60000))
	require.NoError(t, addVendorString(packet, 35098, 3, "pica8-acl"))
	require.NoError(t, addVendorString(packet, 30065, 17, "profiled-iot"))
	require.NoError(t, addVendorInteger(packet, 30065, 20, 42))
	require.NoError(t, addVendorInteger(packet, 8744, 1, 1))
	require.NoError(t, addVendorString(packet, 58888, 1, "aa:bb:cc:dd:ee:ff"))

	result := ParseBrokerPacketWithConfig(packet, &config.Config{
		Radius: config.RadiusConfig{
			Vendor: vendorConfigForPacks(
				productconfigs.VendorPackAerohive,
				productconfigs.VendorPackAirespace,
				productconfigs.VendorPackNomadix,
				productconfigs.VendorPackPica8,
				productconfigs.VendorPackArista,
				productconfigs.VendorPackColubris,
				productconfigs.VendorPackOpenWiFi,
			),
		},
	})

	assert.Equal(t, "wlc-guest", result.VendorRole)
	assert.True(t, result.HasVendorVLAN)
	assert.Equal(t, 88, result.VendorVLAN)
	assert.Equal(t, 60000, result.WISPrBandwidthMaxDown)
	assert.Equal(t, 15000, result.WISPrBandwidthMaxUp)
	assert.Equal(t, "aerohive-policy", result.VendorPolicyTag)
	assert.Equal(t, "https://aerohive.example.test/redirect", result.VendorPortalProfile)
	assert.Equal(t, "1001", result.VendorDeviceGroup)
	assert.Equal(t, "42", result.VendorTenant)
	assert.Equal(t, "profiled-iot", result.VendorDevicePosture)
	assert.Equal(t, "pica8-acl", result.VendorInboundACL)
	assert.True(t, result.HasVendorQuarantine)
	assert.True(t, result.VendorQuarantine)
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", result.VendorAccountingIdentity)
}

func TestApplyVendorCompatibilityAttributesParsesAccountingContext(t *testing.T) {
	tests := []struct {
		name      string
		pack      string
		vendorID  uint32
		typeID    byte
		value     any
		assertion func(*testing.T, *BrokerAuthResult)
	}{
		{name: "meraki tags", pack: productconfigs.VendorPackMeraki, vendorID: 29671, typeID: 4, value: "iot,camera", assertion: func(t *testing.T, result *BrokerAuthResult) {
			assert.Equal(t, "iot,camera", result.VendorDevicePosture)
		}},
		{name: "palo alto os", pack: productconfigs.VendorPackPaloAlto, vendorID: 25461, typeID: 8, value: "Windows 11", assertion: func(t *testing.T, result *BrokerAuthResult) {
			assert.Equal(t, "Windows 11", result.VendorDevicePosture)
		}},
		{name: "airespace wlan", pack: productconfigs.VendorPackAirespace, vendorID: 14179, typeID: 1, value: uint32(1001), assertion: func(t *testing.T, result *BrokerAuthResult) {
			assert.Equal(t, "1001", result.VendorDeviceGroup)
		}},
		{name: "arista profiling", pack: productconfigs.VendorPackArista, vendorID: 30065, typeID: 17, value: "profiled-iot", assertion: func(t *testing.T, result *BrokerAuthResult) {
			assert.Equal(t, "profiled-iot", result.VendorDevicePosture)
		}},
		{name: "aerohive client monitor problem", pack: productconfigs.VendorPackAerohive, vendorID: 26928, typeID: 210, value: uint32(17), assertion: func(t *testing.T, result *BrokerAuthResult) {
			assert.Equal(t, "17", result.VendorDevicePosture)
		}},
		{name: "meru ap id", pack: productconfigs.VendorPackMeru, vendorID: 15983, typeID: 1, value: uint32(42), assertion: func(t *testing.T, result *BrokerAuthResult) {
			assert.Equal(t, "42", result.VendorDeviceGroup)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			packet := layehradius.New(layehradius.CodeAccountingRequest, []byte("secret"))
			switch value := tc.value.(type) {
			case string:
				require.NoError(t, addVendorString(packet, tc.vendorID, tc.typeID, value))
			case uint32:
				require.NoError(t, addVendorInteger(packet, tc.vendorID, tc.typeID, value))
			default:
				t.Fatalf("unsupported test value %T", tc.value)
			}
			result := ParseBrokerPacketWithConfig(packet, &config.Config{Radius: config.RadiusConfig{Vendor: vendorConfigForPacks(tc.pack)}})
			tc.assertion(t, result)
		})
	}
}

func TestApplyVendorCompatibilityAttributesReversesNumericRoleMappings(t *testing.T) {
	tests := []struct {
		pack     string
		vendorID uint32
		typeID   byte
		value    uint32
	}{
		{pack: productconfigs.VendorPackCambium, vendorID: 17713, typeID: 1, value: 2},
		{pack: productconfigs.VendorPackAerohive, vendorID: 26928, typeID: 6, value: 101},
		{pack: productconfigs.VendorPackDLink, vendorID: 171, typeID: 1, value: 5},
		{pack: productconfigs.VendorPackSonicWall, vendorID: 8741, typeID: 1, value: 7},
		{pack: productconfigs.VendorPackZTE, vendorID: 3902, typeID: 104, value: 15},
	}
	for _, tc := range tests {
		t.Run(tc.pack, func(t *testing.T) {
			packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
			require.NoError(t, addVendorInteger(packet, tc.vendorID, tc.typeID, tc.value))
			vendor := vendorConfigForPacks(tc.pack)
			vendor.RoleMappings = []config.RadiusVendorRoleMapping{{Pack: tc.pack, Role: "network-admin", Value: int(tc.value)}}

			result := ParseBrokerPacketWithConfig(packet, &config.Config{Radius: config.RadiusConfig{Vendor: vendor}})

			assert.Equal(t, "network-admin", result.VendorRole)
		})
	}
}

func TestApplyVendorCompatibilityAttributesRequiresEnabledPack(t *testing.T) {
	packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	require.NoError(t, addVendorString(packet, 14823, 1, "admin"))
	require.NoError(t, addVendorInteger(packet, 14823, 2, 10))

	result := ParseBrokerPacketWithConfig(packet, &config.Config{
		Radius: config.RadiusConfig{
			Vendor: vendorConfigForPacks(productconfigs.VendorPackStandard),
		},
	})

	assert.Empty(t, result.VendorRole)
	assert.False(t, result.HasVendorVLAN)
}

func TestApplyVendorAttributesPreferProductVSAOverCompatibilityVSA(t *testing.T) {
	packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	require.NoError(t, addVendorString(packet, 55555, AegisNASVendorAttrRole, "product-role"))
	require.NoError(t, addVendorString(packet, 14823, 1, "aruba-role"))

	result := ParseBrokerPacketWithConfig(packet, &config.Config{
		Radius: config.RadiusConfig{
			Vendor: vendorConfigForPacks(productconfigs.VendorPackAegisNAS, productconfigs.VendorPackAruba),
		},
	})

	assert.Equal(t, "product-role", result.VendorRole)
}

func TestVendorAttributeOverrideByName(t *testing.T) {
	productRole := productconfigs.AegisNASVendorDictionary().Attributes[0]
	vendor := config.RadiusVendorConfig{
		Enabled: true,
		Name:    "AegisNAS",
		ID:      55555,
		Attributes: []config.RadiusVendorAttribute{
			{Name: productRole.Name, Number: 20, Type: productRole.Type},
		},
	}
	packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	require.NoError(t, addVendorString(packet, uint32(vendor.ID), 20, "admin"))

	result := ParseBrokerPacketWithConfig(packet, &config.Config{Radius: config.RadiusConfig{Vendor: vendor}})

	assert.Equal(t, "admin", result.VendorRole)
	attrs := EffectiveVendorAttributes(vendor)
	assert.Equal(t, byte(20), vendorAttributeNumber(attrs, AegisNASVendorAttrRole))
}

func vendorConfigForPacks(packKeys ...string) config.RadiusVendorConfig {
	return config.RadiusVendorConfig{
		Enabled:            true,
		Name:               "AegisNAS",
		ID:                 55555,
		CompatibilityPacks: packKeys,
	}
}

func TestAddVendorAccountingAttributes(t *testing.T) {
	vendor := config.RadiusVendorConfig{
		Enabled: true,
		Name:    "AegisNAS",
		ID:      55555,
	}
	packet := layehradius.New(layehradius.CodeAccountingRequest, []byte("secret"))
	rec := &AccountingRecord{
		Role:             "guest-premium",
		BandwidthProfile: "50m-down-20m-up",
		FilterID:         "premium",
		VLAN:             20,
		SessionTimeout:   3600,
		IdleTimeout:      600,
	}

	require.NoError(t, AddVendorAccountingAttributes(packet, vendor, rec))
	result := ParseBrokerPacketWithConfig(packet, &config.Config{Radius: config.RadiusConfig{Vendor: vendor}})

	assert.Equal(t, rec.Role, result.VendorRole)
	assert.Equal(t, rec.BandwidthProfile, result.VendorBandwidthProfile)
	assert.Equal(t, rec.FilterID, result.VendorPolicyTag)
	assert.Equal(t, rec.VLAN, result.VendorVLAN)
	assert.Equal(t, rec.SessionTimeout, result.VendorSessionTimeout)
	assert.Equal(t, rec.IdleTimeout, result.VendorIdleTimeout)
}

func TestResolveSessionPolicyUsesVendorAttributes(t *testing.T) {
	oldDB := db.DB
	db.DB = nil
	defer func() { db.DB = oldDB }()

	policy, err := ResolveSessionPolicy("guest-basic", &BrokerAuthResult{
		VendorRole:              "guest-premium",
		VendorBandwidthProfile:  "50m-down-20m-up",
		VendorPolicyTag:         "premium",
		VendorVLAN:              20,
		HasVendorVLAN:           true,
		VendorSessionTimeout:    3600,
		HasVendorSessionTimeout: true,
		VendorIdleTimeout:       600,
		HasVendorIdleTimeout:    true,
	})
	require.NoError(t, err)

	assert.Equal(t, "guest-premium", policy.Role)
	assert.Equal(t, "50m-down-20m-up", policy.BandwidthProfile)
	assert.Equal(t, "premium", policy.FilterID)
	assert.Equal(t, 20, policy.VLAN)
	assert.Equal(t, 3600, policy.SessionTimeout)
	assert.Equal(t, 600, policy.IdleTimeout)
}
