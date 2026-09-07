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

func TestSwitchingVendorPackNormalizesPolicyTokens(t *testing.T) {
	token, err := NormalizeSwitchingVendorAttribute("Arista", "Arista-AVPair", "acl=edge-in")
	require.NoError(t, err)
	assert.Equal(t, SwitchingVendorKindACL, token.Kind)
	assert.Equal(t, productconfigs.VendorSemanticDynamicACL, token.Semantic)
	assert.Equal(t, "acl", token.Name)
	assert.Equal(t, "edge-in", token.Value)

	vrf, err := NormalizeSwitchingVendorAttribute("Brocade", "Brocade-AVPairs2", "vrf=mgmt")
	require.NoError(t, err)
	assert.Equal(t, SwitchingVendorKindVRF, vrf.Kind)
	assert.Equal(t, productconfigs.VendorSemanticVRF, vrf.Semantic)

	_, err = NormalizeSwitchingVendorAttribute("Force10", "Force10-AVPair", "bad token=value")
	assert.ErrorContains(t, err, "invalid policy token")

	_, err = NormalizeSwitchingVendorAttribute("3com", "3Com-VLAN-Name", "corp\nbad")
	assert.ErrorContains(t, err, "control characters")

	_, err = NormalizeSwitchingVendorAttribute("DellEMC", "DellEMC-AVpair", strings.Repeat("a", SwitchingVendorMaxValueLength+1))
	assert.ErrorContains(t, err, "exceeds")
}

func TestSwitchingVendorPackParsesSwitchingState(t *testing.T) {
	t.Run("3Com native switching fields", func(t *testing.T) {
		packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
		require.NoError(t, addVendorInteger(packet, 43, 1, 4))
		require.NoError(t, addVendorString(packet, 43, 2, "corp-vlan"))
		require.NoError(t, addVendorString(packet, 43, 4, "wpa2-enterprise"))
		require.NoError(t, addVendorString(packet, 43, 6, "Corp"))
		require.NoError(t, addVendorString(packet, 43, 8, "https://portal.example.test/3com"))
		require.NoError(t, addVendorString(packet, 43, 60, "192.0.2.10"))

		result := ParseBrokerPacketWithConfig(packet, &config.Config{
			Radius: config.RadiusConfig{Vendor: vendorConfigForPacks(productconfigs.VendorPack3Com)},
		})

		assert.Equal(t, "access-level:4", result.VendorRole)
		assert.Equal(t, "corp-vlan", result.VendorVLANPool)
		assert.Equal(t, "https://portal.example.test/3com", result.VendorPortalProfile)
		assert.Equal(t, "192.0.2.10", result.VendorFramedIPAddress)
		assert.Equal(t, "3Com-Encryption-Type=wpa2-enterprise", result.VendorDevicePosture)
		assert.Equal(t, "Corp", result.VendorDeviceGroup)
	})

	t.Run("AVPair switching policies", func(t *testing.T) {
		packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
		require.NoError(t, addVendorString(packet, 30065, 1, "acl=edge-in"))
		require.NoError(t, addVendorString(packet, 1588, 3, "vrf=mgmt"))
		require.NoError(t, addVendorString(packet, 674, 1, "role=ops"))
		require.NoError(t, addVendorString(packet, 6027, 1, "qos=gold"))
		require.NoError(t, addVendorInteger(packet, 12740, 6, 2))
		require.NoError(t, addVendorString(packet, 12740, 8, "replication-a"))

		result := ParseBrokerPacketWithConfig(packet, &config.Config{
			Radius: config.RadiusConfig{Vendor: vendorConfigForPacks(
				productconfigs.VendorPackArista,
				productconfigs.VendorPackBrocade,
				productconfigs.VendorPackDellEMC,
				productconfigs.VendorPackEquallogic,
				productconfigs.VendorPackForce10,
			)},
		})

		assert.Equal(t, "ops", result.VendorRole)
		assert.Equal(t, "edge-in", result.VendorInboundACL)
		assert.Equal(t, "mgmt", result.VendorVRF)
		assert.Equal(t, "gold", result.VendorBandwidthProfile)
		assert.Equal(t, "replication-a", result.VendorTenant)
	})

	t.Run("Arista session remediation", func(t *testing.T) {
		packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
		require.NoError(t, addVendorString(packet, 30065, 7, "aa:bb:cc:dd:ee:ff"))
		require.NoError(t, addVendorInteger(packet, 30065, 9, 1))

		result := ParseBrokerPacketWithConfig(packet, &config.Config{
			Radius: config.RadiusConfig{Vendor: vendorConfigForPacks(productconfigs.VendorPackArista)},
		})

		assert.Equal(t, "block-mac:aa:bb:cc:dd:ee:ff", result.VendorSessionAction)
	})
}

func TestRenderReplyAttributesIncludesSwitchingVendorFields(t *testing.T) {
	attrs := &ReplyAttributes{
		Role:             "netadmin",
		VLAN:             120,
		PolicyTag:        "show running-config",
		PortalProfile:    "https://portal.example.test/switch",
		DeviceGroup:      "leaf-access",
		Tenant:           "tenant-a",
		ACLPolicyName:    "edge-in",
		InboundACL:       "edge-in",
		OutboundACL:      "edge-out",
		FramedIPAddress:  "198.51.100.44",
		SessionTimeout:   86400,
		IdleTimeout:      900,
		BandwidthProfile: "gold",
	}
	vendor := config.RadiusVendorConfig{
		RoleMappings: []config.RadiusVendorRoleMapping{
			{Pack: productconfigs.VendorPack3Com, Role: "netadmin", Value: 4},
			{Pack: productconfigs.VendorPackArista, Role: "netadmin", Value: 15},
			{Pack: productconfigs.VendorPackEquallogic, Role: "netadmin", Value: 2},
		},
		AVPairMappings: []config.RadiusVendorAVPairMapping{
			{Pack: productconfigs.VendorPackArista, Role: "netadmin", Values: []string{"acl=${inbound_acl}", "vrf=${tenant}"}},
			{Pack: productconfigs.VendorPackBrocade, Role: "netadmin", Values: []string{"acl=${inbound_acl}", "vrf=${tenant}"}},
			{Pack: productconfigs.VendorPackDellEMC, Role: "netadmin", Values: []string{"role=${role}", "acl=${acl_policy}"}},
			{Pack: productconfigs.VendorPackForce10, Role: "netadmin", Values: []string{"qos=${policy_tag}"}},
		},
	}

	rendered := RenderReplyAttributesForVendorConfigAndPacks(attrs, []string{
		productconfigs.VendorPack3Com,
		productconfigs.VendorPackArista,
		productconfigs.VendorPackBrocade,
		productconfigs.VendorPackDellEMC,
		productconfigs.VendorPackEquallogic,
		productconfigs.VendorPackForce10,
	}, vendor)

	assert.Contains(t, rendered, "\t3Com-User-Access-Level = 4\n")
	assert.Contains(t, rendered, "\t3Com-VLAN-Name = \"120\"\n")
	assert.Contains(t, rendered, "\t3Com-URL = \"https://portal.example.test/switch\"\n")
	assert.Contains(t, rendered, "\tArista-User-Role = \"netadmin\"\n")
	assert.Contains(t, rendered, "\tArista-User-Priv-Level = 15\n")
	assert.Contains(t, rendered, "\tArista-Captive-Portal = \"https://portal.example.test/switch\"\n")
	assert.Contains(t, rendered, "\tArista-Segment-Id = \"120\"\n")
	assert.Contains(t, rendered, "\tArista-AVPair = \"acl=edge-in\"\n")
	assert.Contains(t, rendered, "\tBrocade-Auth-Role = \"netadmin\"\n")
	assert.Contains(t, rendered, "\tBrocade-AVPairs1 = \"acl=edge-in\"\n")
	assert.Contains(t, rendered, "\tDellEMC-Group-Name = \"netadmin\"\n")
	assert.Contains(t, rendered, "\tDellEMC-AVpair = \"role=netadmin\"\n")
	assert.Contains(t, rendered, "\tEquallogic-EQL-Admin-Privilege = 2\n")
	assert.Contains(t, rendered, "\tEquallogic-Admin-Repl-Site-Access = \"tenant-a\"\n")
	assert.Contains(t, rendered, "\tForce10-AVPair = \"qos=show running-config\"\n")
}
