package radius

import (
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
		InboundACL:            "acl-in",
		OutboundACL:           "acl-out",
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
	assert.Contains(t, rendered, "\tAruba-User-Role = \"guest \\\"premium\\\"\"\n")
	assert.Contains(t, rendered, "\tAruba-User-Vlan = 20\n")
	assert.Contains(t, rendered, "\tRuckus-User-Groups = \"guest \\\"premium\\\"\"\n")
	assert.Contains(t, rendered, "\tRuckus-VLAN-ID = 20\n")
	assert.Contains(t, rendered, "\tFortinet-Group-Name = \"guest \\\"premium\\\"\"\n")
	assert.Contains(t, rendered, "\tFortinet-Access-Profile = \"guest-acl\"\n")
	assert.Contains(t, rendered, "\tCisco-In-ACL = \"acl-in\"\n")
	assert.Contains(t, rendered, "\tCisco-Out-ACL = \"acl-out\"\n")
	assert.Contains(t, rendered, "\tUBNT-Data-Rate-DL = 50000000\n")
	assert.Contains(t, rendered, "\tUBNT-Data-Rate-UL = 20000000\n")
	assert.Equal(t, 1, countRenderedAttribute(rendered, "Aruba-User-Role"))
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
	}

	rendered := RenderReplyAttributesForPacks(attrs, []string{"cambium", "extreme", "juniper", "huawei", "h3c", "paloalto", "tplink"})

	assert.Contains(t, rendered, "\tCambium-ePMP-Data-VLAN-Id = 44\n")
	assert.Contains(t, rendered, "\tCambium-ePMP-Max-Burst-Downlink-Rate = 75000\n")
	assert.Contains(t, rendered, "\tCambium-ePMP-Max-Burst-Uplink-Rate = 25000\n")
	assert.Contains(t, rendered, "\tExtreme-Security-Profile = \"operator\"\n")
	assert.Contains(t, rendered, "\tExtreme-Netlogin-Vlan = \"44\"\n")
	assert.Contains(t, rendered, "\tExtreme-Netlogin-Vlan-Tag = 44\n")
	assert.Contains(t, rendered, "\tExtreme-Netlogin-Url = \"https://portal.example.test/login\"\n")
	assert.Contains(t, rendered, "\tJuniper-Local-User-Name = \"operator\"\n")
	assert.Contains(t, rendered, "\tJuniper-Firewall-filter-name = \"acl-in\"\n")
	assert.Contains(t, rendered, "\tJuniper-CWA-Redirect = \"https://portal.example.test/login\"\n")
	assert.Contains(t, rendered, "\tHuawei-User-Group = \"operator\"\n")
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
