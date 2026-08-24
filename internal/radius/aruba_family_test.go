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

func TestNormalizeArubaFamilyAttributeClassifiesAndRedacts(t *testing.T) {
	tests := []struct {
		vendor    string
		attribute string
		value     string
		kind      ArubaFamilyAttributeKind
		semantic  string
		redacted  bool
	}{
		{"aruba", "Aruba-CPPM-Role", "employee", ArubaFamilyKindRole, productconfigs.VendorSemanticRole, false},
		{"aruba", "Aruba-Named-User-Vlan", "corp-data", ArubaFamilyKindVLAN, productconfigs.VendorSemanticVLAN, false},
		{"aruba", "Aruba-NAS-Filter-Rule", "permit in tcp from any to any 443", ArubaFamilyKindACL, productconfigs.VendorSemanticACL, false},
		{"aruba", "Aruba-Captive-Portal-URL", "https://guest.example.test/login", ArubaFamilyKindPortal, productconfigs.VendorSemanticPortalProfile, false},
		{"aruba", "Aruba-AirGroup-Shared-Group", "room-201", ArubaFamilyKindAirGroup, productconfigs.VendorSemanticPolicyTag, false},
		{"aruba", "Aruba-MPSK-Passphrase", "super-secret-passphrase", ArubaFamilyKindKeyLifecycle, productconfigs.VendorSemanticCertificateOnboarding, true},
		{"hp", "HP-Privilege-Level", "15", ArubaFamilyKindRole, productconfigs.VendorSemanticRole, false},
		{"aerohive", "Extreme-IDM-Redirect-URL", "https://guest.example.test", ArubaFamilyKindPortal, productconfigs.VendorSemanticPortalProfile, false},
		{"colubris", "Colubris-Intercept", "1", ArubaFamilyKindQuarantine, productconfigs.VendorSemanticQuarantine, false},
	}
	for _, tc := range tests {
		t.Run(tc.attribute, func(t *testing.T) {
			token, err := NormalizeArubaFamilyAttribute(tc.vendor, tc.attribute, tc.value)
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

func TestNormalizeArubaFamilyAttributeRejectsUnsafeValues(t *testing.T) {
	for _, raw := range []string{
		"",
		"role\x00bad",
		strings.Repeat("a", ArubaFamilyMaxValueLength+1),
	} {
		_, err := NormalizeArubaFamilyAttribute("aruba", "Aruba-CPPM-Role", raw)
		require.Error(t, err)
	}

	_, err := NormalizeArubaFamilyAttribute("aruba", "Aruba-AVPair", "bad token=value")
	require.Error(t, err)
}

func TestRenderReplyAttributesIncludesArubaFamilyFields(t *testing.T) {
	rendered := RenderReplyAttributesForVendorConfig(&ReplyAttributes{
		Role:                         "employee",
		VLAN:                         20,
		PortalProfile:                "https://guest.example.test/login",
		DeviceGroup:                  "branch-aps",
		ArubaCPPMRole:                "contractor",
		ArubaAdminRole:               "net-admin",
		ArubaNamedUserVLAN:           "corp-data",
		ArubaDeviceType:              "managed-tablet",
		ArubaAirGroupSharedGroup:     "room-201",
		ArubaMPSKKeyName:             "iot-camera",
		ArubaDPPServiceType:          1,
		ArubaUBTGatewayRole:          "branch-gateway",
		ArubaQoSTrustMode:            1,
		HPPrivilegeLevel:             15,
		HPCPPMSecondaryRole:          "audit",
		HPBonjourInboundProfile:      "printers",
		HPURIString:                  "/rest/v10",
		AerohiveIDMMessage:           203,
		AerohiveClientMonitorProblem: 17,
		AerohiveAVPairs:              []string{"role=guest"},
		ColubrisAVPairs:              []string{"service=hotspot"},
		ACLRules: []ACLRule{{
			Action: "permit", Direction: "in", Protocol: "tcp", Source: "any", Destination: "any", DestinationPort: "443",
		}},
	}, config.RadiusVendorConfig{
		CompatibilityPacks: []string{
			productconfigs.VendorPackAruba,
			productconfigs.VendorPackHP,
			productconfigs.VendorPackAerohive,
			productconfigs.VendorPackColubris,
		},
	})

	assert.Contains(t, rendered, "Aruba-CPPM-Role = \"contractor\"")
	assert.Contains(t, rendered, "Aruba-Named-User-Vlan = \"corp-data\"")
	assert.Contains(t, rendered, "Aruba-NAS-Filter-Rule = \"permit in tcp from any to any 443\"")
	assert.Contains(t, rendered, "Aruba-MPSK-Key-Name = \"iot-camera\"")
	assert.Contains(t, rendered, "HP-Privilege-Level = 15")
	assert.Contains(t, rendered, "HP-Bonjour-Inbound-Profile = \"printers\"")
	assert.Contains(t, rendered, "Extreme-IDM-Message = 203")
	assert.Contains(t, rendered, "Extreme-AVPair = \"role=guest\"")
	assert.Contains(t, rendered, "AVPair = \"service=hotspot\"")
}

func TestArubaFamilyInboundNormalization(t *testing.T) {
	packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	require.NoError(t, addVendorString(packet, 14823, 23, "cppm-employee"))
	require.NoError(t, addVendorString(packet, 14823, 9, "named-vlan"))
	require.NoError(t, addVendorString(packet, 14823, 45, "permit in tcp from any to any 443"))
	require.NoError(t, addVendorString(packet, 14823, 54, "tenant-a"))
	require.NoError(t, addVendorString(packet, 14823, 62, "iot-camera"))
	require.NoError(t, addVendorString(packet, 14823, 44, "clear-text-key"))
	require.NoError(t, addVendorString(packet, 26928, 211, "https://aerohive.example.test/redirect"))
	require.NoError(t, addVendorInteger(packet, 26928, 210, 17))
	require.NoError(t, addVendorInteger(packet, 8744, 1, 1))

	result := ParseBrokerPacketWithConfig(packet, &config.Config{
		Radius: config.RadiusConfig{
			Vendor: vendorConfigForPacks(productconfigs.VendorPackAruba, productconfigs.VendorPackAerohive, productconfigs.VendorPackColubris),
		},
	})

	assert.Equal(t, "cppm-employee", result.VendorRole)
	assert.Equal(t, "named-vlan", result.VendorVLANPool)
	assert.Equal(t, "permit in tcp from any to any 443", result.VendorInboundACL)
	assert.Equal(t, "tenant-a", result.VendorTenant)
	assert.Equal(t, "iot-camera", result.VendorPolicyTag)
	assert.NotContains(t, strings.Join(result.VendorAVPairs, ","), "clear-text-key")
	assert.Equal(t, "https://aerohive.example.test/redirect", result.VendorPortalProfile)
	assert.Equal(t, "17", result.VendorDevicePosture)
	assert.True(t, result.HasVendorQuarantine)
	assert.True(t, result.VendorQuarantine)
}
