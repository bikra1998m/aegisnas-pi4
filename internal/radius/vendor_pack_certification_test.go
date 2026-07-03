package radius

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

func TestVendorPackCertificationMatrixRendersDeclaredOutboundAttributes(t *testing.T) {
	attrs := &ReplyAttributes{
		Role:                  "certification-user",
		BandwidthProfile:      "certification-bandwidth",
		FilterID:              "certification-filter",
		PolicyTag:             "certification-policy",
		SessionTimeout:        3600,
		IdleTimeout:           600,
		VLAN:                  4094,
		TunnelType:            "VLAN",
		TunnelMediumType:      "IEEE-802",
		TunnelPrivateGroupID:  "4094",
		MikrotikRateLimit:     "10000k/5000k",
		WISPrBandwidthMaxDown: 10000,
		WISPrBandwidthMaxUp:   5000,
		HasQuarantine:         true,
		Quarantine:            true,
		PortalProfile:         "https://portal.example.test/certification",
		DeviceGroup:           "certification-devices",
		Tenant:                "certification-tenant",
		ACLPolicyName:         "certification-acl",
		InboundACL:            "certification-in",
		OutboundACL:           "certification-out",
		ACLRules: []ACLRule{{
			Action: "permit", Direction: "in", Protocol: "tcp", Source: "any", Destination: "any", DestinationPort: "443",
		}},
	}

	for _, pack := range productconfigs.AegisNASVendorCompatibilityPacks() {
		pack := pack
		t.Run(pack.Key, func(t *testing.T) {
			vendor := config.RadiusVendorConfig{
				RoleMappings: []config.RadiusVendorRoleMapping{
					{Pack: productconfigs.VendorPackCambium, Role: attrs.Role, Value: 2},
					{Pack: productconfigs.VendorPackAerohive, Role: attrs.Role, Value: 101},
					{Pack: productconfigs.VendorPackDLink, Role: attrs.Role, Value: 5},
					{Pack: productconfigs.VendorPackSonicWall, Role: attrs.Role, Value: 7},
					{Pack: productconfigs.VendorPackZTE, Role: attrs.Role, Value: 15},
				},
				AVPairMappings: []config.RadiusVendorAVPairMapping{
					{Pack: productconfigs.VendorPackJuniper, Role: attrs.Role, Values: []string{"acl=${acl_policy}"}},
					{Pack: productconfigs.VendorPackHuawei, Role: attrs.Role, Values: []string{"acl=${acl_policy}"}},
					{Pack: productconfigs.VendorPackH3C, Role: attrs.Role, Values: []string{"acl=${acl_policy}"}},
					{Pack: productconfigs.VendorPackArista, Role: attrs.Role, Values: []string{"acl=${acl_policy}"}},
				},
				PortalStatusMappings: []config.RadiusVendorPortalStatusMapping{
					{Pack: productconfigs.VendorPackTPLink, PortalProfile: attrs.PortalProfile, Value: 1},
				},
			}
			items := BuildReplyAttributeItemsForVendorConfig(attrs, []string{pack.Key}, vendor)
			actual := make(map[string]struct{}, len(items))
			for _, item := range items {
				actual[item.Name] = struct{}{}
			}
			if pack.Key == productconfigs.VendorPackExtreme {
				vendor.ExtendedVLANMappings = []config.RadiusVendorExtendedVLANMapping{
					{Pack: productconfigs.VendorPackExtreme, Role: attrs.Role, UntaggedVLAN: 4094, TaggedVLANs: []int{100}},
				}
				for _, item := range BuildReplyAttributeItemsForVendorConfig(attrs, []string{pack.Key}, vendor) {
					actual[item.Name] = struct{}{}
				}
			}

			declared := 0
			for _, mapping := range pack.Attributes {
				if mapping.Direction != "outbound_reply" || mapping.CompatibilityState != "implemented" {
					continue
				}
				declared++
				_, rendered := actual[mapping.Attribute]
				assert.True(t, rendered, "declared implemented attribute %s was not rendered", mapping.Attribute)
			}
			if declared == 0 {
				require.Empty(t, items, "pack without implemented outbound mappings rendered undeclared attributes")
			}
		})
	}
}
