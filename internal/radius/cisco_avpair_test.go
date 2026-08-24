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

func TestParseCiscoAVPairClassifiesKnownGrammar(t *testing.T) {
	tests := []struct {
		raw       string
		kind      CiscoAVPairKind
		semantic  string
		direction string
		sequence  int
	}{
		{"ip:inacl#7=permit tcp any any eq 443", CiscoAVPairKindDynamicACL, productconfigs.VendorSemanticDynamicACL, "in", 7},
		{"ip:outacl#1=deny udp any any eq 53", CiscoAVPairKindDynamicACL, productconfigs.VendorSemanticDynamicACL, "out", 1},
		{"cts:security-group-tag=42", CiscoAVPairKindTrustSecSGT, productconfigs.VendorSemanticPolicyTag, "", 0},
		{"vpn:group-policy=employees", CiscoAVPairKindVPN, productconfigs.VendorSemanticPolicyTag, "", 0},
		{"device-traffic-class=voice", CiscoAVPairKindVoice, productconfigs.VendorSemanticDeviceGroup, "", 0},
		{"shell:priv-lvl=15", CiscoAVPairKindCommandAuth, productconfigs.VendorSemanticRole, "", 0},
		{"posture:status=compliant", CiscoAVPairKindPosture, productconfigs.VendorSemanticDevicePosture, "", 0},
		{"ip:route=10.80.0.0/16 192.0.2.1 10", CiscoAVPairKindRoute, productconfigs.VendorSemanticRoute, "", 0},
		{"translation-port-block=10000-10511", CiscoAVPairKindTranslation, productconfigs.VendorSemanticTranslationPolicy, "", 0},
		{"subscriber:charging-profile=prepaid-gold", CiscoAVPairKindCharging, productconfigs.VendorSemanticAccountingCounters, "", 0},
	}

	for _, tc := range tests {
		t.Run(tc.raw, func(t *testing.T) {
			pair, err := ParseCiscoAVPair(tc.raw)
			require.NoError(t, err)
			assert.Equal(t, tc.kind, pair.Kind)
			assert.Equal(t, tc.semantic, pair.Semantic)
			assert.Equal(t, tc.direction, pair.Direction)
			assert.Equal(t, tc.sequence, pair.Sequence)
		})
	}
}

func TestParseCiscoAVPairRejectsUnsafeValues(t *testing.T) {
	for _, raw := range []string{
		"",
		"shell:priv-lvl",
		"shell:priv-lvl=",
		"shell:bad token=1",
		"shell:priv-lvl=15\nshell:cmd=show",
		"ip:inacl#0=permit ip any any",
		strings.Repeat("a", CiscoAVPairMaxValueLength+1) + "=1",
	} {
		t.Run(raw, func(t *testing.T) {
			_, err := ParseCiscoAVPair(raw)
			assert.Error(t, err)
		})
	}
}

func TestBuildCiscoAVPairsForIntentEmitsEnterpriseGrammar(t *testing.T) {
	pairs, err := BuildCiscoAVPairsForIntent(CiscoAVPairIntent{
		SecurityGroupTag:     42,
		VPNGroupPolicy:       "employees",
		VPNTunnelGroup:       "corp-vpn",
		VPNSplitTunnelList:   "corp-split",
		VoiceTrafficClass:    "voice",
		ShellPrivilegeLevel:  15,
		ShellRoles:           []string{"network-admin", "auditor"},
		PostureStatus:        "compliant",
		AuditSessionID:       "0A000001000000000001",
		IPv4Routes:           []string{"10.80.0.0/16 192.0.2.1 10"},
		IPv6Routes:           []string{"2001:db8:80::/48 2001:db8::1 10"},
		VRF:                  "tenant-a",
		IPv4Pool:             "corp-pool",
		IPv6Pool:             "v6-pool",
		DelegatedIPv6Prefix:  "2001:db8:100::/56",
		TranslationPolicy:    "authorize",
		TranslationPublicIP:  "198.51.100.10",
		TranslationPortBlock: "10000-10511",
		ChargingProfile:      "prepaid-gold",
	})
	require.NoError(t, err)

	assert.Contains(t, pairs, "cts:security-group-tag=42")
	assert.Contains(t, pairs, "vpn:group-policy=employees")
	assert.Contains(t, pairs, "vpn:tunnel-group=corp-vpn")
	assert.Contains(t, pairs, "vpn:split-tunnel-list=corp-split")
	assert.Contains(t, pairs, "device-traffic-class=voice")
	assert.Contains(t, pairs, "shell:priv-lvl=15")
	assert.Contains(t, pairs, "shell:roles=network-admin,auditor")
	assert.Contains(t, pairs, "posture:status=compliant")
	assert.Contains(t, pairs, "audit-session-id=0A000001000000000001")
	assert.Contains(t, pairs, "ip:route=10.80.0.0/16 192.0.2.1 10")
	assert.Contains(t, pairs, "ipv6:route=2001:db8:80::/48 2001:db8::1 10")
	assert.Contains(t, pairs, "ip:vrf-id=tenant-a")
	assert.Contains(t, pairs, "ip:addr-pool=corp-pool")
	assert.Contains(t, pairs, "ipv6:addr-pool=v6-pool")
	assert.Contains(t, pairs, "ipv6:delegated-prefix=2001:db8:100::/56")
	assert.Contains(t, pairs, "translation-policy=authorize")
	assert.Contains(t, pairs, "translation-public-ipv4=198.51.100.10")
	assert.Contains(t, pairs, "translation-port-block=10000-10511")
	assert.Contains(t, pairs, "subscriber:charging-profile=prepaid-gold")
}

func TestRenderReplyAttributesIncludesCiscoFamilyAVPairs(t *testing.T) {
	rendered := RenderReplyAttributesForPacks(&ReplyAttributes{
		CiscoSecurityGroupTag:    42,
		CiscoVPNGroupPolicy:      "employees",
		CiscoVoiceTrafficClass:   "voice",
		CiscoShellPrivilegeLevel: 15,
		CiscoPostureStatus:       "compliant",
		CiscoChargingProfile:     "prepaid-gold",
	}, []string{productconfigs.VendorPackCisco})

	assert.Contains(t, rendered, "\tCisco-AVPair = \"cts:security-group-tag=42\"\n")
	assert.Contains(t, rendered, "\tCisco-AVPair = \"vpn:group-policy=employees\"\n")
	assert.Contains(t, rendered, "\tCisco-AVPair = \"device-traffic-class=voice\"\n")
	assert.Contains(t, rendered, "\tCisco-AVPair = \"shell:priv-lvl=15\"\n")
	assert.Contains(t, rendered, "\tCisco-AVPair = \"posture:status=compliant\"\n")
	assert.Contains(t, rendered, "\tCisco-AVPair = \"subscriber:charging-profile=prepaid-gold\"\n")
}

func TestCiscoAVPairInboundNormalization(t *testing.T) {
	packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	require.NoError(t, addVendorString(packet, 9, 1, "ip:inacl#1=permit tcp any any eq 443"))
	require.NoError(t, addVendorString(packet, 9, 1, "ip:outacl#1=deny udp any any eq 53"))
	require.NoError(t, addVendorString(packet, 9, 1, "cts:security-group-tag=42"))
	require.NoError(t, addVendorString(packet, 9, 1, "posture:status=compliant"))
	require.NoError(t, addVendorString(packet, 9, 1, "ip:route=10.80.0.0/16 192.0.2.1 10"))
	require.NoError(t, addVendorString(packet, 9, 1, "ip:vrf-id=tenant-a"))
	require.NoError(t, addVendorString(packet, 9, 1, "ip:addr-pool=corp-pool"))
	require.NoError(t, addVendorString(packet, 9, 1, "translation-port-block=10000-10511"))

	result := ParseBrokerPacketWithConfig(packet, &config.Config{Radius: config.RadiusConfig{Vendor: vendorConfigForPacks(productconfigs.VendorPackCisco)}})

	assert.Equal(t, "permit tcp any any eq 443", result.VendorInboundACL)
	assert.Equal(t, "deny udp any any eq 53", result.VendorOutboundACL)
	assert.Equal(t, "sgt:42", result.VendorPolicyTag)
	assert.Equal(t, "compliant", result.VendorDevicePosture)
	assert.Equal(t, []string{"10.80.0.0/16 192.0.2.1 10"}, result.VendorFramedRoutes)
	assert.Equal(t, "tenant-a", result.VendorVRF)
	assert.Equal(t, "corp-pool", result.VendorIPv4Pool)
	assert.True(t, result.HasVendorTranslationPortBlockStart)
	assert.Equal(t, 10000, result.VendorTranslationPortBlockStart)
	assert.True(t, result.HasVendorTranslationPortBlockEnd)
	assert.Equal(t, 10511, result.VendorTranslationPortBlockEnd)
	assert.Len(t, result.VendorAVPairs, 8)
}
