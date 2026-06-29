package radius

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
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
			items := BuildReplyAttributeItems(attrs, []string{pack.Key})
			actual := make(map[string]struct{}, len(items))
			for _, item := range items {
				actual[item.Name] = struct{}{}
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
