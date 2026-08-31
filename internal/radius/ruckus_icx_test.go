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

func TestNormalizeRuckusICXAttributeClassifiesAndRedacts(t *testing.T) {
	tests := []struct {
		vendor    string
		attribute string
		value     string
		kind      RuckusICXAttributeKind
		semantic  string
		direction string
		redacted  bool
	}{
		{"ruckus", "Ruckus-User-Groups", "employee", RuckusICXKindRole, productconfigs.VendorSemanticRole, "", false},
		{"ruckus", "Ruckus-FlexAuth-AVP", "ip:inacl=guest-in", RuckusICXKindACL, productconfigs.VendorSemanticDynamicACL, "in", false},
		{"ruckus", "Ruckus-FlexAuth-AVP", "qos=gold", RuckusICXKindQoS, productconfigs.VendorSemanticBandwidthProfile, "", false},
		{"ruckus", "Ruckus-Client-Local-IP", "198.51.100.7", RuckusICXKindIPv4Address, productconfigs.VendorSemanticIPv4Address, "", false},
		{"ruckus", "Ruckus-Gn-User-Name", "subscriber-42", RuckusICXKindMobile, productconfigs.VendorSemanticAccountingIdentity, "", false},
		{"ruckus", "Ruckus-DPSK", "clear-text-dpsk", RuckusICXKindSecret, productconfigs.VendorSemanticPolicyTag, "", true},
		{"foundry", "Foundry-Command-String", "show vlan", RuckusICXKindCommandAuth, productconfigs.VendorSemanticRole, "", false},
		{"foundry", "Foundry-Access-List", "guest-in", RuckusICXKindACL, productconfigs.VendorSemanticACL, "in", false},
	}
	for _, tc := range tests {
		t.Run(tc.attribute+"/"+tc.value, func(t *testing.T) {
			token, err := NormalizeRuckusICXAttribute(tc.vendor, tc.attribute, tc.value)
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

func TestNormalizeRuckusICXAttributeRejectsUnsafeValues(t *testing.T) {
	for _, raw := range []string{
		"",
		"role\x00bad",
		strings.Repeat("a", RuckusICXMaxValueLength+1),
	} {
		_, err := NormalizeRuckusICXAttribute("ruckus", "Ruckus-User-Groups", raw)
		require.Error(t, err)
	}

	_, err := NormalizeRuckusICXAttribute("ruckus", "Ruckus-FlexAuth-AVP", "bad token=value")
	require.Error(t, err)
}

func TestRenderReplyAttributesIncludesRuckusICXFamilyFields(t *testing.T) {
	rendered := RenderReplyAttributesForVendorConfig(&ReplyAttributes{
		Role:                           "employee",
		VLAN:                           20,
		BandwidthProfile:               "gold-qos",
		FilterID:                       "filter-a",
		PolicyTag:                      "policy-a",
		PortalProfile:                  "guest-portal",
		DeviceGroup:                    "branch-aps",
		InboundACL:                     "guest-in",
		VLANPool:                       "branch-pool",
		FramedPool:                     "framed-pool",
		TranslationPublicPool:          "cgnat-public",
		RuckusWLANName:                 "Corp",
		RuckusVLANName:                 "corp-data",
		RuckusGracePeriod:              120,
		RuckusStaExpiration:            3600,
		RuckusTrafficClassAttributeIDs: "tc-gold",
		RuckusCPToken:                  "portal-token-ref",
		RuckusClusterName:              "sz-cluster-a",
		RuckusAuthServerID:             "auth-a",
		RuckusFlexAuthAVPs:             []string{"role=employee", "ip:inacl=guest-in"},
		RuckusMaxDLULQuota:             1073741824,
		RuckusSCIRole:                  "sci-employee",
		RuckusSCIResourceGroup:         "resource-a",
		FoundryPrivilegeLevel:          15,
		FoundryINMPrivilege:            2,
		FoundryCommandExceptionFlag:    1,
		FoundryCommandString:           "show vlan",
		FoundryAccessList:              "icx-acl",
		FoundryMACAuthentNeeds8021X:    1,
		Foundry8021XValidLookup:        1,
		FoundryMACBasedVLANQoS:         20,
		FoundryINMRoleAORList:          "operator",
		FoundryCOACommand:              "reauth",
		FoundrySIContextRole:           "icx-context",
		FoundrySIRoleTemplate:          "template-a",
		FoundryVoicePhoneConfig:        "voice-auto",
	}, config.RadiusVendorConfig{
		CompatibilityPacks: []string{productconfigs.VendorPackRuckus, productconfigs.VendorPackFoundry},
	})

	assert.Contains(t, rendered, "Ruckus-User-Groups = \"employee\"")
	assert.Contains(t, rendered, "Ruckus-VLAN-ID = 20")
	assert.Contains(t, rendered, "Ruckus-Wispr-Redirect-Policy = \"guest-portal\"")
	assert.Contains(t, rendered, "Ruckus-Wlan-Name = \"Corp\"")
	assert.Contains(t, rendered, "Ruckus-Vlan-Pool = \"branch-pool\"")
	assert.Contains(t, rendered, "Ruckus-Vlan-Name = \"corp-data\"")
	assert.Contains(t, rendered, "Ruckus-Max-DL-UL-Quota = 1073741824")
	assert.Contains(t, rendered, "Ruckus-Traffic-Class-Attribute-Ids = \"tc-gold\"")
	assert.Contains(t, rendered, "Ruckus-Nat-Pool-Name = \"cgnat-public\"")
	assert.Contains(t, rendered, "Ruckus-CP-Token = \"portal-token-ref\"")
	assert.Contains(t, rendered, "Ruckus-Cluster-Name = \"sz-cluster-a\"")
	assert.Contains(t, rendered, "Ruckus-FlexAuth-AVP = \"ip:inacl=guest-in\"")
	assert.Contains(t, rendered, "Ruckus-SCI-Role = \"sci-employee\"")
	assert.Contains(t, rendered, "Foundry-Privilege-Level = 15")
	assert.Contains(t, rendered, "Foundry-Command-String = \"show vlan\"")
	assert.Contains(t, rendered, "Foundry-Access-List = \"icx-acl\"")
	assert.Contains(t, rendered, "Foundry-COA-Command = \"reauth\"")
	assert.Contains(t, rendered, "Foundry-Voice-Phone-Config = \"voice-auto\"")
}

func TestRuckusICXInboundNormalization(t *testing.T) {
	packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	require.NoError(t, addVendorString(packet, 25053, 20, "role=employee"))
	require.NoError(t, addVendorString(packet, 25053, 20, "ip:inacl=guest-in"))
	require.NoError(t, addVendorString(packet, 25053, 20, "qos=gold"))
	require.NoError(t, addVendorInteger(packet, 25053, 9, 44))
	require.NoError(t, addVendorAttribute(packet, 25053, 116, layehradius.Attribute{198, 51, 100, 7}))
	require.NoError(t, addVendorString(packet, 25053, 132, "guest-redirect"))
	require.NoError(t, addVendorString(packet, 25053, 134, "zone-a"))
	require.NoError(t, addVendorString(packet, 25053, 138, "laptop-42"))
	require.NoError(t, addVendorString(packet, 25053, 139, "Windows 11"))
	require.NoError(t, addVendorString(packet, 25053, 155, "tenant-a"))
	require.NoError(t, addVendorInteger(packet, 25053, 144, 1073741824))
	require.NoError(t, addVendorString(packet, 25053, 147, "nat-pool-a"))
	require.NoError(t, addVendorString(packet, 25053, 142, "clear-text-dpsk"))
	require.NoError(t, addVendorInteger(packet, 1991, 1, 15))
	require.NoError(t, addVendorString(packet, 1991, 5, "icx-acl"))

	result := ParseBrokerPacketWithConfig(packet, &config.Config{
		Radius: config.RadiusConfig{
			Vendor: vendorConfigForPacks(productconfigs.VendorPackRuckus, productconfigs.VendorPackFoundry),
		},
	})

	assert.Equal(t, "employee", result.VendorRole)
	assert.True(t, result.HasVendorVLAN)
	assert.Equal(t, 44, result.VendorVLAN)
	assert.Equal(t, "guest-in", result.VendorInboundACL)
	assert.Equal(t, "guest-redirect", result.VendorPortalProfile)
	assert.Equal(t, "gold", result.VendorBandwidthProfile)
	assert.Equal(t, "zone-a", result.VendorDeviceGroup)
	assert.Equal(t, "laptop-42", result.VendorAccountingIdentity)
	assert.Equal(t, "Windows 11", result.VendorDevicePosture)
	assert.Equal(t, "tenant-a", result.VendorTenant)
	assert.Equal(t, "198.51.100.7", result.VendorFramedIPAddress)
	assert.True(t, result.HasVendorMaxTotalOctets)
	assert.Equal(t, uint64(1073741824), result.VendorMaxTotalOctets)
	assert.Equal(t, "nat-pool-a", result.VendorIPv4Pool)
	assert.Equal(t, "nat-pool-a", result.VendorTranslationPublicIPv4Pool)
	assert.Contains(t, strings.Join(result.VendorAVPairs, ","), "Ruckus-DPSK=<redacted>")
	assert.NotContains(t, strings.Join(result.VendorAVPairs, ","), "clear-text-dpsk")
}

func TestRuckusICXInboundIgnoresMalformedFlexAuth(t *testing.T) {
	packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	require.NoError(t, addVendorString(packet, 25053, 20, "bad token=value"))
	require.NoError(t, addVendorString(packet, 25053, 20, "role\x00bad"))

	result := ParseBrokerPacketWithConfig(packet, &config.Config{
		Radius: config.RadiusConfig{Vendor: vendorConfigForPacks(productconfigs.VendorPackRuckus)},
	})

	assert.Empty(t, result.VendorRole)
	assert.Empty(t, result.VendorAVPairs)
}
