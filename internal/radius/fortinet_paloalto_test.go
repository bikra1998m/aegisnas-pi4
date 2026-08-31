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

func TestNormalizeFortinetPaloAltoAttributeClassifiesAndRedacts(t *testing.T) {
	tests := []struct {
		vendor    string
		attribute string
		value     string
		kind      FortinetPaloAltoAttributeKind
		semantic  string
		direction string
		redacted  bool
	}{
		{"fortinet", "Fortinet-Group-Name", "employee", FortinetPaloAltoKindRole, productconfigs.VendorSemanticRole, "", false},
		{"fortinet", "Fortinet-Vdom-Name", "tenant-a", FortinetPaloAltoKindTenant, productconfigs.VendorSemanticTenant, "", false},
		{"fortinet", "Fortinet-FortiWAN-AVPair", "ip:inacl=branch-in", FortinetPaloAltoKindDynamicACL, productconfigs.VendorSemanticDynamicACL, "in", false},
		{"fortinet", "Fortinet-FortiWAN-AVPair", "route=198.51.100.0/24", FortinetPaloAltoKindRoute, productconfigs.VendorSemanticRoute, "", false},
		{"fortinet", "Fortinet-AppCtrl-Risk-Block", "0x0004", FortinetPaloAltoKindAppControl, productconfigs.VendorSemanticDevicePosture, "", false},
		{"fortinet", "Fortinet-FAC-Token-ID", "secret-token", FortinetPaloAltoKindSecret, productconfigs.VendorSemanticCertificateOnboarding, "", true},
		{"paloalto", "PaloAlto-Admin-Role", "superuser", FortinetPaloAltoKindRole, productconfigs.VendorSemanticRole, "", false},
		{"paloalto", "PaloAlto-GlobalProtect-Client-Version", "6.2.1", FortinetPaloAltoKindVPN, productconfigs.VendorSemanticDevicePosture, "", false},
	}
	for _, tc := range tests {
		t.Run(tc.attribute+"/"+tc.value, func(t *testing.T) {
			token, err := NormalizeFortinetPaloAltoAttribute(tc.vendor, tc.attribute, tc.value)
			require.NoError(t, err)
			assert.Equal(t, tc.kind, token.Kind)
			assert.Equal(t, tc.semantic, token.Semantic)
			assert.Equal(t, tc.direction, token.Direction)
			assert.Equal(t, tc.redacted, token.Redacted)
			if tc.redacted {
				assert.Equal(t, "<redacted>", token.Value)
				assert.NotContains(t, token.Raw, tc.value)
			}
		})
	}
}

func TestNormalizeFortinetPaloAltoAttributeRejectsUnsafeValues(t *testing.T) {
	for _, raw := range []string{
		"",
		"role\x00bad",
		strings.Repeat("a", FortinetPaloAltoMaxValueLength+1),
	} {
		_, err := NormalizeFortinetPaloAltoAttribute("fortinet", "Fortinet-Group-Name", raw)
		require.Error(t, err)
	}

	_, err := NormalizeFortinetPaloAltoAttribute("fortinet", "Fortinet-FortiWAN-AVPair", "bad token=value")
	require.Error(t, err)
}

func TestRenderReplyAttributesIncludesFortinetPaloAltoFamilyFields(t *testing.T) {
	rendered := RenderReplyAttributesForVendorConfig(&ReplyAttributes{
		Role:                               "employee",
		Tenant:                             "tenant-a",
		VRF:                                "root",
		PolicyTag:                          "security-profile",
		FilterID:                           "filter-a",
		DeviceGroup:                        "branch-aps",
		FramedIPAddress:                    "198.51.100.23",
		FramedIPv6Address:                  "2001:db8::23",
		FortinetInterfaceName:              "port1",
		FortinetSSID:                       "Corp",
		FortinetFACAuthStatus:              "challenge",
		FortinetFACChallengeCode:           "challenge-ref",
		FortinetWebfilterCategoryBlock:     "0x0010",
		FortinetAppCtrlRiskBlock:           "0x0004",
		FortinetFDDAccessProfile:           "fdd-admin",
		FortinetFDDTrustedHosts:            "198.51.100.0/24",
		FortinetFDDSPPName:                 "spp-a",
		FortinetFDDIsSystemAdmin:           fortinetPaloAltoBoolString(true),
		FortinetFDDIsSPPAdmin:              fortinetPaloAltoBoolString(false),
		FortinetFDDSPPPolicyGroup:          "spp-policy-a",
		FortinetFDDAllowAPIAccess:          fortinetPaloAltoBoolString(false),
		FortinetFortiWANAVPairs:            []string{"role=employee", "ip:inacl=branch-in"},
		FortinetHostPortAVPairs:            []string{"route=198.51.100.0/24"},
		PaloAltoPanoramaAdminRole:          "panorama-admin",
		PaloAltoPanoramaAdminAccessDomain:  "domain-a",
		PaloAltoUserDomain:                 "corp",
		PaloAltoClientSourceIP:             "198.51.100.24",
		PaloAltoClientOS:                   "Windows 11",
		PaloAltoClientHostname:             "laptop-42",
		PaloAltoGlobalProtectClientVersion: "6.2.1",
	}, config.RadiusVendorConfig{
		CompatibilityPacks: []string{productconfigs.VendorPackFortinet, productconfigs.VendorPackPaloAlto},
	})

	assert.Contains(t, rendered, "Fortinet-Group-Name = \"employee\"")
	assert.Contains(t, rendered, "Fortinet-Client-IP-Address = 198.51.100.23")
	assert.Contains(t, rendered, "Fortinet-Vdom-Name = \"tenant-a\"")
	assert.Contains(t, rendered, "Fortinet-Client-IPv6-Address = 2001:db8::23")
	assert.Contains(t, rendered, "Fortinet-Access-Profile = \"security-profile\"")
	assert.Contains(t, rendered, "Fortinet-Webfilter-Category-Block = 0x0010")
	assert.Contains(t, rendered, "Fortinet-AppCtrl-Risk-Block = 0x0004")
	assert.Contains(t, rendered, "Fortinet-FortiWAN-AVPair = \"ip:inacl=branch-in\"")
	assert.Contains(t, rendered, "Fortinet-Host-Port-AVPair = \"route=198.51.100.0/24\"")
	assert.Contains(t, rendered, "PaloAlto-Admin-Role = \"employee\"")
	assert.Contains(t, rendered, "PaloAlto-Panorama-Admin-Role = \"panorama-admin\"")
	assert.Contains(t, rendered, "PaloAlto-Client-Source-IP = 198.51.100.24")
	assert.Contains(t, rendered, "PaloAlto-GlobalProtect-Client-Version = \"6.2.1\"")
}

func TestFortinetPaloAltoInboundNormalization(t *testing.T) {
	packet := layehradius.New(layehradius.CodeAccountingRequest, []byte("secret"))
	require.NoError(t, addVendorString(packet, 12356, 1, "employee"))
	require.NoError(t, addVendorAttribute(packet, 12356, 2, layehradius.Attribute{198, 51, 100, 23}))
	require.NoError(t, addVendorString(packet, 12356, 3, "tenant-vdom"))
	require.NoError(t, addVendorAttribute(packet, 12356, 4, layehradius.Attribute(net.ParseIP("2001:db8::23").To16())))
	require.NoError(t, addVendorString(packet, 12356, 5, "port1"))
	require.NoError(t, addVendorString(packet, 12356, 6, "security-profile"))
	require.NoError(t, addVendorString(packet, 12356, 12, "clear-token"))
	require.NoError(t, addVendorAttribute(packet, 12356, 21, layehradius.Attribute{0x00, 0x04}))
	require.NoError(t, addVendorAttribute(packet, 12356, 23, layehradius.Attribute{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}))
	require.NoError(t, addVendorString(packet, 12356, 26, "ip:inacl=branch-in"))
	require.NoError(t, addVendorString(packet, 12356, 26, "route=198.51.100.0/24"))
	require.NoError(t, addVendorString(packet, 25461, 8, "Windows 11"))
	require.NoError(t, addVendorString(packet, 25461, 9, "laptop-42"))
	require.NoError(t, addVendorAttribute(packet, 25461, 7, layehradius.Attribute{198, 51, 100, 24}))

	result := ParseBrokerPacketWithConfig(packet, &config.Config{
		Radius: config.RadiusConfig{
			Vendor: vendorConfigForPacks(productconfigs.VendorPackFortinet, productconfigs.VendorPackPaloAlto),
		},
	})

	assert.Equal(t, "employee", result.VendorRole)
	assert.Equal(t, "198.51.100.23", result.VendorFramedIPAddress)
	assert.Equal(t, "2001:db8::23", result.VendorFramedIPv6Address)
	assert.Equal(t, "tenant-vdom", result.VendorTenant)
	assert.Equal(t, "tenant-vdom", result.VendorVRF)
	assert.Equal(t, "port1", result.VendorDeviceGroup)
	assert.Equal(t, "security-profile", result.VendorPolicyTag)
	assert.Equal(t, "0x0004", result.VendorDevicePosture)
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", result.VendorAccountingIdentity)
	assert.Equal(t, "branch-in", result.VendorInboundACL)
	assert.Contains(t, result.VendorFramedRoutes, "198.51.100.0/24")
	assert.Contains(t, strings.Join(result.VendorAVPairs, ","), "Fortinet-FAC-Token-ID=<redacted>")
	assert.NotContains(t, strings.Join(result.VendorAVPairs, ","), "clear-token")
}

func TestFortinetPaloAltoInboundIgnoresMalformedAVPair(t *testing.T) {
	packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	require.NoError(t, addVendorString(packet, 12356, 26, "bad token=value"))
	require.NoError(t, addVendorString(packet, 12356, 26, "role\x00bad"))

	result := ParseBrokerPacketWithConfig(packet, &config.Config{
		Radius: config.RadiusConfig{Vendor: vendorConfigForPacks(productconfigs.VendorPackFortinet)},
	})

	assert.Empty(t, result.VendorRole)
	assert.Empty(t, result.VendorAVPairs)
}
