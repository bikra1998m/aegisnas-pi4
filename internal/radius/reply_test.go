package radius

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

func TestRenderReplyAttributesPreservesDefaultPacks(t *testing.T) {
	rendered := RenderReplyAttributes(&ReplyAttributes{
		SessionTimeout:        3600,
		IdleTimeout:           600,
		VLAN:                  20,
		TunnelType:            "VLAN",
		TunnelMediumType:      "IEEE-802",
		MikrotikRateLimit:     "50000k/20000k",
		WISPrBandwidthMaxDown: 50000,
		WISPrBandwidthMaxUp:   20000,
	})

	assert.Contains(t, rendered, "\tSession-Timeout = 3600\n")
	assert.Contains(t, rendered, "\tIdle-Timeout = 600\n")
	assert.Contains(t, rendered, "\tTunnel-Type = VLAN\n")
	assert.Contains(t, rendered, "\tTunnel-Medium-Type = IEEE-802\n")
	assert.Contains(t, rendered, "\tTunnel-Private-Group-Id = \"20\"\n")
	assert.Contains(t, rendered, "\tMikrotik-Rate-Limit = \"50000k/20000k\"\n")
	assert.Contains(t, rendered, "\tWISPr-Bandwidth-Max-Down = 50000\n")
	assert.Contains(t, rendered, "\tWISPr-Bandwidth-Max-Up = 20000\n")
	assert.NotContains(t, rendered, "AegisNAS-Role")
	assert.NotContains(t, rendered, "Aruba-User-Role")
}

func TestRenderReplyAttributesForVendorPacks(t *testing.T) {
	attrs := &ReplyAttributes{
		Role:                  `guest "premium"`,
		BandwidthProfile:      "50m-down-20m-up",
		FilterID:              "premium",
		PolicyTag:             "guest-acl",
		SessionTimeout:        3600,
		IdleTimeout:           600,
		VLAN:                  20,
		MikrotikRateLimit:     "50000k/20000k",
		WISPrBandwidthMaxDown: 50000,
		WISPrBandwidthMaxUp:   20000,
		HasQuarantine:         true,
		Quarantine:            true,
		PortalProfile:         "guest-portal",
		DeviceGroup:           "iot",
		Tenant:                "tenant-a",
		ACLPolicyName:         "guest-internet",
		InboundACL:            "acl-in",
		OutboundACL:           "acl-out",
		ACLRules: []ACLRule{
			{Action: "permit", Direction: "in", Protocol: "tcp", Source: "any", Destination: "any", DestinationPort: "443"},
		},
	}

	items := BuildReplyAttributeItems(attrs, []string{"standard", "aegisnas", "aruba", "ruckus", "fortinet", "cisco", "ubnt", "unknown"})
	require.NotEmpty(t, items)

	rendered := RenderReplyAttributesForPacks(attrs, []string{"standard", "aegisnas", "aruba", "ruckus", "fortinet", "cisco", "ubnt", "aruba"})

	assert.Contains(t, rendered, "\tFilter-Id = \"premium\"\n")
	assert.Contains(t, rendered, "\tAegisNAS-Role = \"guest \\\"premium\\\"\"\n")
	assert.Contains(t, rendered, "\tAegisNAS-Bandwidth-Profile = \"50m-down-20m-up\"\n")
	assert.Contains(t, rendered, "\tAegisNAS-VLAN = 20\n")
	assert.Contains(t, rendered, "\tAegisNAS-Quarantine = 1\n")
	assert.Contains(t, rendered, "\tAegisNAS-Policy-Tag = \"guest-acl\"\n")
	assert.Contains(t, rendered, "\tAegisNAS-Session-Timeout = 3600\n")
	assert.Contains(t, rendered, "\tAegisNAS-Idle-Timeout = 600\n")
	assert.Contains(t, rendered, "\tAegisNAS-Portal-Profile = \"guest-portal\"\n")
	assert.Contains(t, rendered, "\tAegisNAS-Device-Group = \"iot\"\n")
	assert.Contains(t, rendered, "\tAegisNAS-Tenant = \"tenant-a\"\n")
	assert.Contains(t, rendered, "\tAegisNAS-ACL-Name = \"guest-internet\"\n")
	assert.Contains(t, rendered, "\tAegisNAS-ACL-Rule = \"permit in tcp from any to any 443\"\n")
	assert.Contains(t, rendered, "\tAruba-User-Role = \"guest \\\"premium\\\"\"\n")
	assert.Contains(t, rendered, "\tAruba-User-Vlan = 20\n")
	assert.Contains(t, rendered, "\tAruba-NAS-Filter-Rule = \"permit in tcp from any to any 443\"\n")
	assert.Contains(t, rendered, "\tRuckus-User-Groups = \"guest \\\"premium\\\"\"\n")
	assert.Contains(t, rendered, "\tRuckus-VLAN-ID = 20\n")
	assert.Contains(t, rendered, "\tFortinet-Group-Name = \"guest \\\"premium\\\"\"\n")
	assert.Contains(t, rendered, "\tFortinet-Access-Profile = \"guest-acl\"\n")
	assert.Contains(t, rendered, "\tCisco-In-ACL = \"acl-in\"\n")
	assert.Contains(t, rendered, "\tCisco-Out-ACL = \"acl-out\"\n")
	assert.Contains(t, rendered, "\tCisco-AVPair = \"ip:inacl#1=permit tcp any any eq 443\"\n")
	assert.Contains(t, rendered, "\tUBNT-Data-Rate-DL = 50000000\n")
	assert.Contains(t, rendered, "\tUBNT-Data-Rate-UL = 20000000\n")
	assert.Equal(t, 1, countRenderedAttribute(rendered, "Aruba-User-Role"))
}

func TestRenderReplyAttributesForDynamicACLRules(t *testing.T) {
	attrs := &ReplyAttributes{
		Role:          "guest",
		ACLPolicyName: "guest-internet",
		ACLRules: []ACLRule{
			{Action: "permit", Direction: "in", Protocol: "tcp", Source: "any", Destination: "any", DestinationPort: "443", Log: true},
			{Action: "deny", Direction: "out", Protocol: "udp", Source: "any", Destination: "10.0.0.0/24", DestinationPort: "53"},
		},
	}

	rendered := RenderReplyAttributesForPacks(attrs, []string{"standard", "aegisnas", "mikrotik", "cisco", "aruba", "fortinet", "juniper", "huawei"})

	assert.Contains(t, rendered, "\tNAS-Filter-Rule = \"permit in tcp from any to any 443 log\"\n")
	assert.Contains(t, rendered, "\tNAS-Filter-Rule = \"deny out udp from any to 10.0.0.0/24 53\"\n")
	assert.Contains(t, rendered, "\tAegisNAS-ACL-Name = \"guest-internet\"\n")
	assert.Contains(t, rendered, "\tAegisNAS-ACL-Rule = \"permit in tcp from any to any 443 log\"\n")
	assert.Contains(t, rendered, "\tMikrotik-Address-List = \"guest-internet\"\n")
	assert.Contains(t, rendered, "\tCisco-AVPair = \"ip:inacl#1=permit tcp any any eq 443 log\"\n")
	assert.Contains(t, rendered, "\tCisco-AVPair = \"ip:outacl#1=deny udp any 10.0.0.0/24 eq 53\"\n")
	assert.Contains(t, rendered, "\tAruba-NAS-Filter-Rule = \"permit in tcp from any to any 443 log\"\n")
	assert.Contains(t, rendered, "\tFortinet-Access-Profile = \"guest-internet\"\n")
	assert.Contains(t, rendered, "\tJuniper-Firewall-filter-name = \"guest-internet\"\n")
	assert.Contains(t, rendered, "\tHuawei-Data-Filter = \"guest-internet\"\n")
}

func TestRenderReplyAttributesForVendorConfigUsesConfiguredPacks(t *testing.T) {
	rendered := RenderReplyAttributesForVendorConfig(&ReplyAttributes{
		Role: "guest",
		VLAN: 30,
	}, config.RadiusVendorConfig{
		CompatibilityPacks: []string{"aruba"},
	})

	assert.Contains(t, rendered, "\tAruba-User-Role = \"guest\"\n")
	assert.Contains(t, rendered, "\tAruba-User-Vlan = 30\n")
	assert.NotContains(t, rendered, "Mikrotik-Rate-Limit")
}

func TestRenderReplyAttributesForExpandedVendorPacks(t *testing.T) {
	attrs := &ReplyAttributes{
		Role:                  "operator",
		BandwidthProfile:      "branch-qos",
		FilterID:              "policy-a",
		PolicyTag:             "internet-only",
		VLAN:                  44,
		WISPrBandwidthMaxDown: 75000,
		WISPrBandwidthMaxUp:   25000,
		PortalProfile:         "https://portal.example.test/login",
		DeviceGroup:           "ap-group-a",
		Tenant:                "tenant-a",
		InboundACL:            "acl-in",
		OutboundACL:           "acl-out",
		HasQuarantine:         true,
		Quarantine:            true,
	}

	rendered := RenderReplyAttributesForPacks(attrs, []string{"cambium", "extreme", "juniper", "huawei", "h3c", "paloalto", "tplink"})

	assert.Contains(t, rendered, "\tCambium-ePMP-Data-VLAN-Id = 44\n")
	assert.Contains(t, rendered, "\tCambium-ePMP-Max-Burst-Downlink-Rate = 75000\n")
	assert.Contains(t, rendered, "\tCambium-ePMP-Max-Burst-Uplink-Rate = 25000\n")
	assert.Contains(t, rendered, "\tCambium-Walled-Garden-State = 1\n")
	assert.Contains(t, rendered, "\tExtreme-Security-Profile = \"operator\"\n")
	assert.Contains(t, rendered, "\tExtreme-Netlogin-Vlan = \"44\"\n")
	assert.Contains(t, rendered, "\tExtreme-Netlogin-Vlan-Tag = 44\n")
	assert.Contains(t, rendered, "\tExtreme-Netlogin-Url = \"https://portal.example.test/login\"\n")
	assert.Contains(t, rendered, "\tJuniper-Local-User-Name = \"operator\"\n")
	assert.Contains(t, rendered, "\tJuniper-Firewall-filter-name = \"acl-in\"\n")
	assert.Contains(t, rendered, "\tJuniper-CWA-Redirect = \"https://portal.example.test/login\"\n")
	assert.Contains(t, rendered, "\tHuawei-User-Class = \"operator\"\n")
	assert.Contains(t, rendered, "\tHuawei-Qos-Profile-Name = \"branch-qos\"\n")
	assert.Contains(t, rendered, "\tHuawei-Output-Average-Rate = 75000\n")
	assert.Contains(t, rendered, "\tHuawei-Input-Average-Rate = 25000\n")
	assert.Contains(t, rendered, "\tHuawei-Data-Filter = \"acl-in\"\n")
	assert.Contains(t, rendered, "\tH3C-User-Role = \"operator\"\n")
	assert.Contains(t, rendered, "\tH3C-User-Group = \"ap-group-a\"\n")
	assert.Contains(t, rendered, "\tH3C-Ita-Policy = \"internet-only\"\n")
	assert.Contains(t, rendered, "\tPaloAlto-Admin-Role = \"operator\"\n")
	assert.Contains(t, rendered, "\tPaloAlto-User-Group = \"ap-group-a\"\n")
	assert.Contains(t, rendered, "\tPaloAlto-Admin-Access-Domain = \"tenant-a\"\n")
	assert.Contains(t, rendered, "\tTPLink-Xmit-limit = 75000\n")
	assert.Contains(t, rendered, "\tTPLink-Recv-limit = 25000\n")
	assert.Contains(t, rendered, "\tTPLink-Omada = \"ap-group-a\"\n")
	assert.Contains(t, rendered, "\tTPLink-Site = \"tenant-a\"\n")
	assert.Contains(t, rendered, "\tTPLink-Redirect-Url = \"https://portal.example.test/login\"\n")
}

func TestRenderReplyAttributesForAdditionalVendorPacks(t *testing.T) {
	attrs := &ReplyAttributes{
		Role:                  "guest",
		BandwidthProfile:      "guest-qos",
		FilterID:              "filter-a",
		PolicyTag:             "policy-a",
		VLAN:                  77,
		WISPrBandwidthMaxDown: 60000,
		WISPrBandwidthMaxUp:   15000,
		PortalProfile:         "https://portal.example.test/start",
		DeviceGroup:           "edge-switches",
		ACLPolicyName:         "guest-acl",
		HasQuarantine:         true,
		Quarantine:            true,
		ACLRules: []ACLRule{
			{Action: "permit", Direction: "in", Protocol: "tcp", Source: "any", Destination: "any", DestinationPort: "443"},
		},
	}

	rendered := RenderReplyAttributesForPacks(attrs, []string{
		"aerohive",
		"airespace",
		"hp",
		"nomadix",
		"chillispot",
		"dlink",
		"sonicwall",
		"arista",
		"pica8",
		"zte",
		"nokia",
		"colubris",
	})

	assert.Contains(t, rendered, "\tExtreme-User-Vlan = 77\n")
	assert.Contains(t, rendered, "\tExtreme-AVPair = \"policy-a\"\n")
	assert.Contains(t, rendered, "\tExtreme-IDM-Redirect-URL = \"https://portal.example.test/start\"\n")
	assert.Contains(t, rendered, "\tGuest-Role-Name = \"guest\"\n")
	assert.Contains(t, rendered, "\tACL-Name = \"guest-acl\"\n")
	assert.Contains(t, rendered, "\tData-Bandwidth-Average-Contract = 60000\n")
	assert.Contains(t, rendered, "\tData-Bandwidth-Average-Contract-Upstream = 15000\n")
	assert.Contains(t, rendered, "\tUser-Role = \"guest\"\n")
	assert.Contains(t, rendered, "\tCaptive-Portal-URL = \"https://portal.example.test/start\"\n")
	assert.Contains(t, rendered, "\tIp-Filter-Raw = \"permit in tcp from any to any 443\"\n")
	assert.Contains(t, rendered, "\tEgress-VLANID = 77\n")
	assert.Contains(t, rendered, "\tNomadix-Bw-Down = 60000\n")
	assert.Contains(t, rendered, "\tNomadix-Bw-Up = 15000\n")
	assert.Contains(t, rendered, "\tNomadix-URL-Redirection = \"https://portal.example.test/start\"\n")
	assert.Contains(t, rendered, "\tNomadix-Net-VLAN = 77\n")
	assert.Contains(t, rendered, "\tBandwidth-Max-Down = 60000\n")
	assert.Contains(t, rendered, "\tBandwidth-Max-Up = 15000\n")
	assert.Contains(t, rendered, "\tUAM-Allowed = \"https://portal.example.test/start\"\n")
	assert.Contains(t, rendered, "\tVLAN-ID = \"77\"\n")
	assert.Contains(t, rendered, "\tACL-Profile = \"guest-acl\"\n")
	assert.Contains(t, rendered, "\tACL-Rule = \"permit in tcp from any to any 443\"\n")
	assert.Contains(t, rendered, "\tUser-Group = \"guest\"\n")
	assert.Contains(t, rendered, "\tSegment-Id = \"77\"\n")
	assert.Contains(t, rendered, "\tInterface-Profile = \"edge-switches\"\n")
	assert.Contains(t, rendered, "\tIP-Downloadable-ACL-Name = \"guest-acl\"\n")
	assert.Contains(t, rendered, "\tIP-Downloadable-ACL-Rule = \"permit in tcp from any to any 443\"\n")
	assert.Contains(t, rendered, "\tRedirect-URL = \"https://portal.example.test/start\"\n")
	assert.Contains(t, rendered, "\tAVPair = \"policy-a\"\n")
	assert.Contains(t, rendered, "\tQoS-Profile-Down = \"guest-qos\"\n")
	assert.Contains(t, rendered, "\tQOS-Profile-Up = \"guest-qos\"\n")
	assert.Contains(t, rendered, "\tRate-Ctrl-SCR-Down = 60000\n")
	assert.Contains(t, rendered, "\tRate-Ctrl-SCR-Up = 15000\n")
	assert.Contains(t, rendered, "\tPPPOE-URL = \"https://portal.example.test/start\"\n")
	assert.Contains(t, rendered, "\tUser-Profile = \"guest\"\n")
	assert.Contains(t, rendered, "\tIntercept = 1\n")
}

func TestRenderReplyAttributesUsesNumericRoleMappings(t *testing.T) {
	attrs := &ReplyAttributes{Role: "network-admin"}
	vendor := config.RadiusVendorConfig{RoleMappings: []config.RadiusVendorRoleMapping{
		{Pack: "cambium", Role: "network-admin", Value: 2},
		{Pack: "aerohive", Role: "network-admin", Value: 101},
		{Pack: "dlink", Role: "network-admin", Value: 5},
		{Pack: "sonicwall", Role: "network-admin", Value: 7},
		{Pack: "zte", Role: "network-admin", Value: 15},
	}}
	packs := []string{"cambium", "aerohive", "dlink", "sonicwall", "zte"}

	rendered := RenderReplyAttributesForVendorConfigAndPacks(attrs, packs, vendor)

	assert.Contains(t, rendered, "\tCambium-Auth-Role = 2\n")
	assert.Contains(t, rendered, "\tExtreme-User-Profile-Attribute = 101\n")
	assert.Contains(t, rendered, "\tUser-Level = 5\n")
	assert.Contains(t, rendered, "\tUser-Privilege = 7\n")
	assert.Contains(t, rendered, "\tSW-Privilege = 15\n")
	assert.NotContains(t, RenderReplyAttributesForPacks(attrs, packs), "Cambium-Auth-Role")
}

func TestRenderReplyAttributesUsesExtremeExtendedVLANMapping(t *testing.T) {
	attrs := &ReplyAttributes{Role: "voice-device", VLAN: 20}
	vendor := config.RadiusVendorConfig{
		CompatibilityPacks: []string{"standard", "extreme"},
		ExtendedVLANMappings: []config.RadiusVendorExtendedVLANMapping{
			{Pack: "extreme", Role: "voice-device", UntaggedVLAN: 20, TaggedVLANs: []int{30, 40}},
		},
	}

	rendered := RenderReplyAttributesForVendorConfig(attrs, vendor)

	assert.Contains(t, rendered, "\tExtreme-Netlogin-Extended-Vlan = \"U20;T30;T40\"\n")
	assert.NotContains(t, rendered, "Extreme-Netlogin-Vlan =")
	assert.NotContains(t, rendered, "Extreme-Netlogin-Vlan-Tag")
}

func TestRenderReplyAttributesUsesVendorAVPairMappings(t *testing.T) {
	attrs := &ReplyAttributes{
		Role: "guest", VLAN: 30, ACLPolicyName: "guest-policy", InboundACL: "guest-in",
		OutboundACL: "guest-out", PolicyTag: "internet", DeviceGroup: "branch", Tenant: "tenant-a",
	}
	vendor := config.RadiusVendorConfig{AVPairMappings: []config.RadiusVendorAVPairMapping{
		{Pack: "juniper", Role: "guest", Values: []string{"firewall=${inbound_acl}", "vlan=${vlan}"}},
		{Pack: "huawei", Role: "guest", Values: []string{"policy=${acl_policy}"}},
		{Pack: "h3c", Role: "guest", Values: []string{"group=${device_group};tag=${policy_tag}"}},
		{Pack: "arista", Role: "guest", Values: []string{"shell:roles=${role}", "tenant=${tenant}"}},
	}}

	rendered := RenderReplyAttributesForVendorConfigAndPacks(attrs, []string{"juniper", "huawei", "h3c", "arista"}, vendor)

	assert.Contains(t, rendered, "\tJuniper-AV-Pair = \"firewall=guest-in\"\n")
	assert.Contains(t, rendered, "\tJuniper-AV-Pair = \"vlan=30\"\n")
	assert.Contains(t, rendered, "\tHuawei-AVpair = \"policy=guest-policy\"\n")
	assert.Contains(t, rendered, "\tH3C-Av-Pair = \"group=branch;tag=internet\"\n")
	assert.Contains(t, rendered, "\tArista-AVPair = \"shell:roles=guest\"\n")
	assert.Contains(t, rendered, "\tArista-AVPair = \"tenant=tenant-a\"\n")
}

func TestRenderReplyAttributesOmitsOversizedExpandedAVPair(t *testing.T) {
	role := strings.Repeat("r", 241)
	vendor := config.RadiusVendorConfig{AVPairMappings: []config.RadiusVendorAVPairMapping{
		{Pack: "arista", Role: role, Values: []string{"${role}"}},
	}}

	rendered := RenderReplyAttributesForVendorConfigAndPacks(&ReplyAttributes{Role: role}, []string{"arista"}, vendor)

	assert.NotContains(t, rendered, "Arista-AVPair")
}

func TestRenderReplyAttributesUsesTPLinkPortalStatusMapping(t *testing.T) {
	attrs := &ReplyAttributes{PortalProfile: "https://portal.example.test/guest"}
	vendor := config.RadiusVendorConfig{PortalStatusMappings: []config.RadiusVendorPortalStatusMapping{
		{Pack: "tplink", PortalProfile: attrs.PortalProfile, Value: 7},
	}}

	rendered := RenderReplyAttributesForVendorConfigAndPacks(attrs, []string{"tplink"}, vendor)

	assert.Contains(t, rendered, "\tTPLink-Redirect-Url = \"https://portal.example.test/guest\"\n")
	assert.Contains(t, rendered, "\tTPLink-Portal-Access-Status = 7\n")
	assert.NotContains(t, RenderReplyAttributesForPacks(attrs, []string{"tplink"}), "TPLink-Portal-Access-Status")
}

func TestRenderReplyAttributesUsesNomadixSessionActionMapping(t *testing.T) {
	attrs := &ReplyAttributes{Role: "expired-guest"}
	vendor := config.RadiusVendorConfig{SessionActionMappings: []config.RadiusVendorSessionActionMapping{
		{Pack: "nomadix", Role: attrs.Role, Action: "disconnect", Value: 7},
	}}

	rendered := RenderReplyAttributesForVendorConfigAndPacks(attrs, []string{"nomadix"}, vendor)

	assert.Contains(t, rendered, "\tNomadix-EndofSession = 7\n")
	assert.NotContains(t, RenderReplyAttributesForPacks(attrs, []string{"nomadix"}), "Nomadix-EndofSession")
}

func TestNormalizeClientNASType(t *testing.T) {
	assert.Equal(t, "aruba", NormalizeClientNASType(" Aruba "))
	assert.Equal(t, "ubnt", NormalizeClientNASType("unifi"))
	assert.Equal(t, "mikrotik", NormalizeClientNASType("routeros"))
	assert.Equal(t, "cambium", NormalizeClientNASType("canopy"))
	assert.Equal(t, "juniper", NormalizeClientNASType("junos"))
	assert.Equal(t, "tplink", NormalizeClientNASType("omada"))
	assert.Equal(t, "custom-ap", NormalizeClientNASType("Custom-AP"))
	assert.Equal(t, "other", NormalizeClientNASType(""))
	assert.Equal(t, "other", NormalizeClientNASType("bad\nprofile"))
}

func TestReplyCompatibilityPacksForClientUsesNASProfile(t *testing.T) {
	packs := ReplyCompatibilityPacksForClient(config.RadiusVendorConfig{
		CompatibilityPacks: []string{"standard", "mikrotik", "wispr", "aegisnas"},
	}, config.RadiusClient{
		NASType: "aruba",
	})

	assert.Equal(t, []string{"standard", "aruba", "aegisnas", "wispr"}, packs)

	rendered := RenderReplyAttributesForClient(&ReplyAttributes{
		Role:                  "guest",
		VLAN:                  20,
		MikrotikRateLimit:     "50000k/20000k",
		WISPrBandwidthMaxDown: 50000,
		WISPrBandwidthMaxUp:   20000,
	}, config.RadiusVendorConfig{
		CompatibilityPacks: []string{"standard", "mikrotik", "wispr", "aegisnas"},
	}, config.RadiusClient{
		NASType: "aruba",
	})

	assert.Contains(t, rendered, "\tAruba-User-Role = \"guest\"\n")
	assert.Contains(t, rendered, "\tAruba-User-Vlan = 20\n")
	assert.Contains(t, rendered, "\tAegisNAS-Role = \"guest\"\n")
	assert.Contains(t, rendered, "\tWISPr-Bandwidth-Max-Down = 50000\n")
	assert.NotContains(t, rendered, "Mikrotik-Rate-Limit")
}

func TestRenderReplyAttributesForClientUsesVendorMappings(t *testing.T) {
	vendor := config.RadiusVendorConfig{
		CompatibilityPacks: []string{"standard", "extreme"},
		ExtendedVLANMappings: []config.RadiusVendorExtendedVLANMapping{
			{Pack: "extreme", Role: "trunk", TaggedVLANs: []int{100, 200}},
		},
	}
	rendered := RenderReplyAttributesForClient(&ReplyAttributes{Role: "trunk"}, vendor, config.RadiusClient{NASType: "extreme"})

	assert.Contains(t, rendered, "\tExtreme-Netlogin-Extended-Vlan = \"T100;T200\"\n")
}

func TestReplyCompatibilityPacksForUnknownNASUsesConfiguredPacks(t *testing.T) {
	packs := ReplyCompatibilityPacksForNASType(config.RadiusVendorConfig{
		CompatibilityPacks: []string{"standard", "mikrotik"},
	}, "custom-ap")

	assert.Equal(t, []string{"standard", "mikrotik"}, packs)
}

func countRenderedAttribute(rendered, name string) int {
	count := 0
	for _, line := range splitRenderedAttributes(rendered) {
		if len(line) > len(name)+2 && line[1:1+len(name)] == name {
			count++
		}
	}
	return count
}

func splitRenderedAttributes(rendered string) []string {
	var out []string
	start := 0
	for i, r := range rendered {
		if r != '\n' {
			continue
		}
		out = append(out, rendered[start:i+1])
		start = i + 1
	}
	if start < len(rendered) {
		out = append(out, rendered[start:])
	}
	return out
}
