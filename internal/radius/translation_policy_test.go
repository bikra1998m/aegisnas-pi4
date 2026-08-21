package radius

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

func TestCompileTranslationPolicyCGNATNAT64AndPortBlocks(t *testing.T) {
	cfg := testTranslationPolicyConfig()

	result := CompileTranslationPolicy(cfg, TranslationPolicyCompileRequest{
		Role:             "branch-dualstack",
		SessionID:        "session-1",
		AcctSessionID:    "acct-1",
		CallingStationID: "00:11:22:33:44:55",
		NASIdentifier:    "bng-01",
		PackKeys: []string{
			productconfigs.VendorPackAegisNAS,
			productconfigs.VendorPackCisco,
			productconfigs.VendorPackJuniper,
			productconfigs.VendorPackHuawei,
			productconfigs.VendorPackH3C,
			productconfigs.VendorPackNokia,
			productconfigs.VendorPackStarent,
			productconfigs.VendorPackERX,
			productconfigs.VendorPackRuckus,
		},
	})

	require.Equal(t, "compiled", result.Status, result.Diagnostics)
	assert.True(t, result.Decision.PolicyMatched)
	assert.Equal(t, "nat-team", result.Decision.Owner)
	assert.Equal(t, "dual-stack", result.Decision.TranslationMode)
	assert.Equal(t, "cgnat-public", result.Decision.PublicPool)
	assertTranslationAddressInPrefix(t, result.Decision.PublicIPv4, "198.51.100.0/29")
	assert.Equal(t, "100.64.1.0/24", result.Decision.PrivateIPv4Prefix)
	assert.Equal(t, "2001:db8:57::/64", result.Decision.SubscriberIPv6Prefix)
	assert.Equal(t, "64:ff9b::/96", result.Decision.NAT64Prefix)
	assert.Equal(t, 512, result.Decision.PortBlockSize)
	assert.GreaterOrEqual(t, result.Decision.PortBlockStart, 10000)
	assert.LessOrEqual(t, result.Decision.PortBlockEnd, 12047)
	assert.Equal(t, 511, result.Decision.PortBlockEnd-result.Decision.PortBlockStart)
	assert.Equal(t, "lawful-cgnat", result.Decision.LoggingProfile)
	assert.NotEmpty(t, result.Decision.AccountingKey)
	assert.NotEmpty(t, result.Decision.Revision)
	assert.NotEmpty(t, result.Decision.OwnershipKey)
	assert.Equal(t, "sha256:", result.Fingerprint[:7])

	assertTranslationPolicyAttribute(t, result.Attributes, productconfigs.VendorPackAegisNAS, "AegisNAS-Translation-Public-IPv4-Address", result.Decision.PublicIPv4)
	assertTranslationPolicyAttribute(t, result.Attributes, productconfigs.VendorPackAegisNAS, "AegisNAS-Translation-Port-Block-Start", fmt.Sprintf("%d", result.Decision.PortBlockStart))
	assertTranslationPolicyAttribute(t, result.Attributes, productconfigs.VendorPackCisco, "Cisco-AVPair", fmt.Sprintf("translation-port-block=%d-%d", result.Decision.PortBlockStart, result.Decision.PortBlockEnd))
	assertTranslationPolicyAttribute(t, result.Attributes, productconfigs.VendorPackJuniper, "Juniper-AV-Pair", "translation-nat64-prefix=64:ff9b::/96")
	assertTranslationPolicyAttribute(t, result.Attributes, productconfigs.VendorPackHuawei, "Huawei-AVpair", "translation-log-profile=lawful-cgnat")
	assertTranslationPolicyAttribute(t, result.Attributes, productconfigs.VendorPackH3C, "H3C-NAT-IP-Address", result.Decision.PublicIPv4)
	assertTranslationPolicyAttribute(t, result.Attributes, productconfigs.VendorPackNokia, "Nokia-AVPair", "translation-accounting-correlation=1")
	assertTranslationPolicyAttribute(t, result.Attributes, productconfigs.VendorPackStarent, "SN-NAT-IP-Address", result.Decision.PublicIPv4)
	assertTranslationPolicyAttribute(t, result.Attributes, productconfigs.VendorPackERX, "ERX-Address-Pool-Name", "cgnat-public")
	assertTranslationPolicyAttribute(t, result.Attributes, productconfigs.VendorPackRuckus, "Ruckus-Nat-Pool-Name", "cgnat-public")
}

func TestDecompileTranslationPolicyAttributesRoundTrips(t *testing.T) {
	compiled := CompileTranslationPolicy(testTranslationPolicyConfig(), TranslationPolicyCompileRequest{
		Role:     "branch-dualstack",
		PackKeys: []string{productconfigs.VendorPackAegisNAS, productconfigs.VendorPackCisco},
	})
	require.Equal(t, "compiled", compiled.Status, compiled.Diagnostics)

	decompiled := DecompileTranslationPolicyAttributes(TranslationPolicyDecompileRequest{
		PackKey:    productconfigs.VendorPackAegisNAS,
		Role:       "branch-dualstack",
		SessionID:  "session-1",
		Attributes: compiled.Attributes,
	})

	require.Equal(t, "decompiled", decompiled.Status, decompiled.Diagnostics)
	assert.Equal(t, "nat-team", decompiled.Decision.Owner)
	assert.Equal(t, compiled.Decision.TranslationMode, decompiled.Decision.TranslationMode)
	assert.Equal(t, compiled.Decision.PublicPool, decompiled.Decision.PublicPool)
	assert.Equal(t, compiled.Decision.PublicIPv4, decompiled.Decision.PublicIPv4)
	assert.Equal(t, compiled.Decision.PrivateIPv4Prefix, decompiled.Decision.PrivateIPv4Prefix)
	assert.Equal(t, compiled.Decision.SubscriberIPv6Prefix, decompiled.Decision.SubscriberIPv6Prefix)
	assert.Equal(t, compiled.Decision.NAT64Prefix, decompiled.Decision.NAT64Prefix)
	assert.Equal(t, compiled.Decision.PortBlockStart, decompiled.Decision.PortBlockStart)
	assert.Equal(t, compiled.Decision.PortBlockEnd, decompiled.Decision.PortBlockEnd)
}

func TestCompileTranslationPolicyConflictsAndWithdrawals(t *testing.T) {
	cfg := testTranslationPolicyConfig()

	conflict := CompileTranslationPolicy(cfg, TranslationPolicyCompileRequest{
		Role:            "branch-dualstack",
		TranslationMode: "nat64",
	})
	require.Equal(t, "blocked", conflict.Status)
	assertTranslationPolicyDiagnostic(t, conflict.Diagnostics, "translation_conflict")

	withdraw := CompileTranslationPolicy(cfg, TranslationPolicyCompileRequest{
		Role:            "branch-dualstack",
		LifecycleAction: "accounting-stop",
		PackKeys:        []string{productconfigs.VendorPackAegisNAS, productconfigs.VendorPackCisco},
	})
	require.Equal(t, "compiled", withdraw.Status, withdraw.Diagnostics)
	assert.True(t, withdraw.Decision.Withdraw)
	assert.Equal(t, 1, withdraw.Summary.WithdrawCount)
	assertTranslationPolicyAttribute(t, withdraw.Attributes, productconfigs.VendorPackAegisNAS, "AegisNAS-Translation-Policy", "accounting-stop")
	assertTranslationPolicyAttribute(t, withdraw.Attributes, productconfigs.VendorPackCisco, "Cisco-AVPair", "translation-policy=withdraw")
	assertNoTranslationPolicyAttribute(t, withdraw.Attributes, productconfigs.VendorPackAegisNAS, "AegisNAS-Translation-Public-IPv4-Address")
}

func TestApplyTranslationPolicyToReplyAttributesRendersPacks(t *testing.T) {
	compiled := CompileTranslationPolicy(testTranslationPolicyConfig(), TranslationPolicyCompileRequest{Role: "branch-dualstack"})
	require.Equal(t, "compiled", compiled.Status, compiled.Diagnostics)

	attrs := &ReplyAttributes{Role: "branch-dualstack"}
	ApplyTranslationPolicyToReplyAttributes(attrs, compiled)
	rendered := RenderReplyAttributesForPacks(attrs, []string{productconfigs.VendorPackAegisNAS, productconfigs.VendorPackCisco, productconfigs.VendorPackStarent})

	assert.Contains(t, rendered, "\tAegisNAS-Translation-Public-IPv4-Address = \""+compiled.Decision.PublicIPv4+"\"\n")
	assert.Contains(t, rendered, fmt.Sprintf("\tAegisNAS-Translation-Port-Block-End = %d\n", compiled.Decision.PortBlockEnd))
	assert.Contains(t, rendered, fmt.Sprintf("\tCisco-AVPair = \"translation-port-block=%d-%d\"\n", compiled.Decision.PortBlockStart, compiled.Decision.PortBlockEnd))
	assert.Contains(t, rendered, "\tSN-NAT-IP-Address = "+compiled.Decision.PublicIPv4+"\n")
}

func testTranslationPolicyConfig() *config.Config {
	return &config.Config{
		Radius: config.RadiusConfig{
			Vendor: config.RadiusVendorConfig{
				CompatibilityPacks: []string{productconfigs.VendorPackAegisNAS, productconfigs.VendorPackCisco},
			},
			TranslationPolicy: config.RadiusTranslationPolicyConfig{
				Enabled:               true,
				FailClosed:            true,
				MaxMappings:           16,
				DefaultOwner:          "aegisnas",
				ConflictMode:          "block",
				StopWithdrawal:        true,
				AllocationMode:        "deterministic",
				DefaultPortBlockSize:  512,
				MinPort:               10000,
				MaxPort:               12047,
				DefaultNAT64Prefix:    "64:ff9b::/96",
				LoggingRequired:       true,
				AccountingCorrelation: true,
				Pools: []config.RadiusTranslationPoolConfig{
					{Name: "cgnat-public", Family: "ipv4", CIDR: "198.51.100.0/29", Start: "198.51.100.2", End: "198.51.100.6", PortStart: 10000, PortEnd: 12047, PortBlockSize: 512, Mode: "cgnat"},
				},
				RolePolicies: []config.RadiusTranslationRolePolicy{
					{
						Role:                  "branch-dualstack",
						Owner:                 "nat-team",
						TranslationMode:       "dual-stack",
						PublicPool:            "cgnat-public",
						PrivateIPv4Prefix:     "100.64.1.0/24",
						SubscriberIPv6Prefix:  "2001:db8:57::/64",
						NAT64Prefix:           "64:ff9b::/96",
						PortBlockSize:         512,
						LoggingProfile:        "lawful-cgnat",
						AccountingCorrelation: true,
						VendorPacks: []string{
							productconfigs.VendorPackAegisNAS,
							productconfigs.VendorPackCisco,
							productconfigs.VendorPackJuniper,
							productconfigs.VendorPackHuawei,
							productconfigs.VendorPackH3C,
							productconfigs.VendorPackNokia,
							productconfigs.VendorPackStarent,
							productconfigs.VendorPackERX,
						},
					},
				},
			},
		},
	}
}

func assertTranslationPolicyAttribute(t *testing.T, attrs []TranslationPolicyAttribute, pack, name, value string) {
	t.Helper()
	for _, attr := range attrs {
		if attr.PackKey == pack && attr.Name == name && attr.Value == value {
			return
		}
	}
	t.Fatalf("missing translation policy attribute %s/%s=%s in %#v", pack, name, value, attrs)
}

func assertNoTranslationPolicyAttribute(t *testing.T, attrs []TranslationPolicyAttribute, pack, name string) {
	t.Helper()
	for _, attr := range attrs {
		if attr.PackKey == pack && attr.Name == name {
			t.Fatalf("unexpected translation policy attribute %s/%s in %#v", pack, name, attrs)
		}
	}
}

func assertTranslationPolicyDiagnostic(t *testing.T, diagnostics []TranslationPolicyDiagnostic, code string) {
	t.Helper()
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == code {
			return
		}
	}
	t.Fatalf("missing translation policy diagnostic %s in %#v", code, diagnostics)
}

func assertTranslationAddressInPrefix(t *testing.T, address, cidr string) {
	t.Helper()
	addr, err := netip.ParseAddr(address)
	require.NoError(t, err)
	prefix, err := netip.ParsePrefix(cidr)
	require.NoError(t, err)
	assert.True(t, prefix.Contains(addr), "%s should be inside %s", address, cidr)
}
