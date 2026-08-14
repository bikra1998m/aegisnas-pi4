package radius

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

func TestCompileVLANPolicyVoiceDataQinQPool(t *testing.T) {
	cfg := testVLANPolicyConfig()

	result := CompileVLANPolicy(cfg, VLANPolicyCompileRequest{
		Role:             "voice-device",
		CallingStationID: "00:11:22:33:44:55",
		NASIdentifier:    "switch-a",
		PackKeys:         []string{"standard", "aegisnas", "extreme", "hp"},
	})

	require.Equal(t, "compiled", result.Status, result.Diagnostics)
	assert.Equal(t, "pool", result.Decision.AssignmentMode)
	assert.Equal(t, 21, result.Decision.EffectiveVLAN)
	assert.Equal(t, 30, result.Decision.VoiceVLAN)
	assert.Equal(t, []int{40}, result.Decision.TaggedVLANs)
	assert.True(t, result.Decision.QinQEnabled)
	assert.Equal(t, 3000, result.Decision.QinQOuterVLAN)
	assert.Equal(t, 21, result.Decision.QinQInnerVLAN)
	assert.Equal(t, "sha256:", result.Fingerprint[:7])
	assertVLANAttribute(t, result.Attributes, "standard", "Tunnel-Private-Group-Id", "21")
	assertVLANAttribute(t, result.Attributes, "standard", "Egress-VLANID", strconv.FormatUint(uint64(EncodeEgressVLANID(30, true)), 10))
	assertVLANAttribute(t, result.Attributes, "aegisnas", "AegisNAS-Voice-VLAN", "30")
	assertVLANAttribute(t, result.Attributes, "aegisnas", "AegisNAS-QinQ-Outer-VLAN", "3000")
	assertVLANAttribute(t, result.Attributes, "extreme", "Extreme-Netlogin-Extended-Vlan", "U21;T30;T40")
}

func TestCompileVLANPolicyAuthFailAndFallback(t *testing.T) {
	cfg := testVLANPolicyConfig()

	authFailed := CompileVLANPolicy(cfg, VLANPolicyCompileRequest{Role: "voice-device", AuthFailed: true})
	require.Equal(t, "compiled", authFailed.Status, authFailed.Diagnostics)
	assert.Equal(t, "auth-fail", authFailed.Decision.AssignmentMode)
	assert.Equal(t, 98, authFailed.Decision.EffectiveVLAN)

	fallback := CompileVLANPolicy(cfg, VLANPolicyCompileRequest{Role: "missing-role"})
	require.Equal(t, "degraded", fallback.Status, fallback.Diagnostics)
	assert.Equal(t, "fallback", fallback.Decision.AssignmentMode)
	assert.Equal(t, 99, fallback.Decision.EffectiveVLAN)
}

func TestDecompileVLANPolicyAttributes(t *testing.T) {
	compiled := CompileVLANPolicy(testVLANPolicyConfig(), VLANPolicyCompileRequest{
		Role:     "voice-device",
		PackKeys: []string{productconfigs.VendorPackStandard, productconfigs.VendorPackAegisNAS, productconfigs.VendorPackExtreme},
	})
	require.Equal(t, "compiled", compiled.Status, compiled.Diagnostics)

	decompiled := DecompileVLANPolicyAttributes(VLANPolicyDecompileRequest{
		PackKey:    productconfigs.VendorPackAegisNAS,
		Role:       "voice-device",
		Attributes: compiled.Attributes,
	})

	require.Equal(t, "decompiled", decompiled.Status, decompiled.Diagnostics)
	assert.Equal(t, 21, decompiled.Decision.EffectiveVLAN)
	assert.Equal(t, 30, decompiled.Decision.VoiceVLAN)
	assert.Equal(t, []int{40}, decompiled.Decision.TaggedVLANs)
	assert.Equal(t, "pool", decompiled.Decision.AssignmentMode)
	assert.True(t, decompiled.Decision.QinQEnabled)
	assert.Equal(t, 3000, decompiled.Decision.QinQOuterVLAN)
}

func TestEgressVLANIDRoundTrip(t *testing.T) {
	value := EncodeEgressVLANID(30, true)
	assert.NotZero(t, value)

	vlan, tagged, ok := DecodeEgressVLANID(strconv.FormatUint(uint64(value), 10))
	require.True(t, ok)
	assert.Equal(t, 30, vlan)
	assert.True(t, tagged)

	vlan, tagged, ok = DecodeEgressVLANID("77")
	require.True(t, ok)
	assert.Equal(t, 77, vlan)
	assert.False(t, tagged)
}

func TestApplyVLANPolicyToReplyAttributesRendersAdvancedAttributes(t *testing.T) {
	compiled := CompileVLANPolicy(testVLANPolicyConfig(), VLANPolicyCompileRequest{Role: "voice-device"})
	require.Equal(t, "compiled", compiled.Status, compiled.Diagnostics)

	attrs := &ReplyAttributes{Role: "voice-device"}
	ApplyVLANPolicyToReplyAttributes(attrs, compiled)
	rendered := RenderReplyAttributesForPacks(attrs, []string{"standard", "aegisnas", "extreme", "hp"})

	assert.Contains(t, rendered, "\tTunnel-Private-Group-Id = \"21\"\n")
	assert.Contains(t, rendered, "\tEgress-VLANID = "+strconv.FormatUint(uint64(EncodeEgressVLANID(30, true)), 10)+"\n")
	assert.Contains(t, rendered, "\tAegisNAS-VLAN-Policy = \"pool\"\n")
	assert.Contains(t, rendered, "\tAegisNAS-Voice-VLAN = 30\n")
	assert.Contains(t, rendered, "\tAegisNAS-QinQ-Outer-VLAN = 3000\n")
	assert.Contains(t, rendered, "\tExtreme-Netlogin-Extended-Vlan = \"U21;T30;T40\"\n")
	assert.NotContains(t, rendered, "\tExtreme-Netlogin-Vlan =")
}

func testVLANPolicyConfig() *config.Config {
	return &config.Config{
		Radius: config.RadiusConfig{
			Vendor: config.RadiusVendorConfig{
				CompatibilityPacks: []string{"standard", "aegisnas"},
			},
			VLANPolicy: config.RadiusVLANPolicyConfig{
				Enabled:             true,
				FailClosed:          true,
				MaxTaggedVLANs:      10,
				DefaultFallbackVLAN: 99,
				DefaultAuthFailVLAN: 98,
				Pools: []config.RadiusVLANPoolConfig{
					{Name: "branch-data", VLANs: []int{21, 22}, Strategy: "first"},
				},
				RolePolicies: []config.RadiusVLANRolePolicy{
					{
						Role:         "voice-device",
						VoiceVLAN:    30,
						TaggedVLANs:  []int{40},
						Pool:         "branch-data",
						FallbackVLAN: 99,
						AuthFailVLAN: 98,
						QinQ:         config.RadiusQinQConfig{Enabled: true, OuterVLAN: 3000, InnerVLAN: 21, Mode: "provider-bridge"},
						VendorPacks:  []string{"standard", "aegisnas", "extreme"},
					},
				},
			},
		},
	}
}

func assertVLANAttribute(t *testing.T, attrs []VLANPolicyAttribute, pack, name, value string) {
	t.Helper()
	for _, attr := range attrs {
		if attr.PackKey == pack && attr.Name == name && attr.Value == value {
			return
		}
	}
	t.Fatalf("missing VLAN attribute %s/%s=%s in %#v", pack, name, value, attrs)
}
