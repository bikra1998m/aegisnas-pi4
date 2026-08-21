package radius

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

func TestCompileAddressPolicyPoolsDHCPv6RAPrefixDelegation(t *testing.T) {
	cfg := testAddressPolicyConfig()

	result := CompileAddressPolicy(cfg, AddressPolicyCompileRequest{
		Role:             "branch-dualstack",
		SessionID:        "session-1",
		AcctSessionID:    "acct-1",
		CallingStationID: "00:11:22:33:44:55",
		NASIdentifier:    "bng-01",
		PackKeys: []string{
			productconfigs.VendorPackStandard,
			productconfigs.VendorPackAegisNAS,
			productconfigs.VendorPackCisco,
			productconfigs.VendorPackJuniper,
			productconfigs.VendorPackHuawei,
			productconfigs.VendorPackMikroTik,
			productconfigs.VendorPackNokia,
		},
	})

	require.Equal(t, "compiled", result.Status, result.Diagnostics)
	assert.True(t, result.Decision.PolicyMatched)
	assert.Equal(t, "address-team", result.Decision.Owner)
	assert.Equal(t, "branch-v4", result.Decision.IPv4Pool)
	assert.Equal(t, "255.255.255.248", result.Decision.IPv4Netmask)
	assertAddressInPrefix(t, result.Decision.IPv4Address, "198.51.100.0/29")
	assert.Equal(t, "branch-v6", result.Decision.IPv6Pool)
	assertAddressInPrefix(t, result.Decision.IPv6Address, "2001:db8:10::/120")
	assertPrefixInPrefix(t, result.Decision.DelegatedIPv6Prefix, "2001:db8:100::/48", 56)
	assertPrefixInPrefix(t, result.Decision.RAPrefix, "2001:db8:200::/56", 64)
	assert.Equal(t, "stateful-pd", result.Decision.DHCPv6Mode)
	assert.Equal(t, "slaac", result.Decision.RAMode)
	assert.True(t, result.Decision.PrefixDelegation)
	assert.NotEmpty(t, result.Decision.Revision)
	assert.NotEmpty(t, result.Decision.OwnershipKey)
	assert.Equal(t, "sha256:", result.Fingerprint[:7])

	assertAddressPolicyAttribute(t, result.Attributes, productconfigs.VendorPackStandard, "Framed-IP-Address", result.Decision.IPv4Address)
	assertAddressPolicyAttribute(t, result.Attributes, productconfigs.VendorPackStandard, "Framed-Pool", "branch-v4")
	assertAddressPolicyAttribute(t, result.Attributes, productconfigs.VendorPackStandard, "Framed-IPv6-Address", result.Decision.IPv6Address)
	assertAddressPolicyAttribute(t, result.Attributes, productconfigs.VendorPackStandard, "Delegated-IPv6-Prefix", result.Decision.DelegatedIPv6Prefix)
	assertAddressPolicyAttribute(t, result.Attributes, productconfigs.VendorPackAegisNAS, "AegisNAS-Address-Owner", "address-team")
	assertAddressPolicyAttribute(t, result.Attributes, productconfigs.VendorPackAegisNAS, "AegisNAS-RA-Prefix", result.Decision.RAPrefix)
	assertAddressPolicyAttribute(t, result.Attributes, productconfigs.VendorPackCisco, "Cisco-AVPair", "delegated-ipv6-prefix="+result.Decision.DelegatedIPv6Prefix)
	assertAddressPolicyAttribute(t, result.Attributes, productconfigs.VendorPackJuniper, "Juniper-Ip-Pool-Name", "branch-v4")
	assertAddressPolicyAttribute(t, result.Attributes, productconfigs.VendorPackHuawei, "Huawei-Delegated-IPv6-Prefix-Pool", "branch-pd")
	assertAddressPolicyAttribute(t, result.Attributes, productconfigs.VendorPackMikroTik, "Mikrotik-Delegated-IPv6-Pool", "branch-pd")
	assertAddressPolicyAttribute(t, result.Attributes, productconfigs.VendorPackNokia, "Nokia-AVPair", "ra-prefix="+result.Decision.RAPrefix)
}

func TestDecompileAddressPolicyAttributesRoundTrips(t *testing.T) {
	compiled := CompileAddressPolicy(testAddressPolicyConfig(), AddressPolicyCompileRequest{
		Role:     "branch-dualstack",
		PackKeys: []string{productconfigs.VendorPackAegisNAS, productconfigs.VendorPackCisco},
	})
	require.Equal(t, "compiled", compiled.Status, compiled.Diagnostics)

	decompiled := DecompileAddressPolicyAttributes(AddressPolicyDecompileRequest{
		PackKey:    productconfigs.VendorPackAegisNAS,
		Role:       "branch-dualstack",
		SessionID:  "session-1",
		Attributes: compiled.Attributes,
	})

	require.Equal(t, "decompiled", decompiled.Status, decompiled.Diagnostics)
	assert.Equal(t, "address-team", decompiled.Decision.Owner)
	assert.Equal(t, "branch-v4", decompiled.Decision.IPv4Pool)
	assert.Equal(t, compiled.Decision.IPv4Address, decompiled.Decision.IPv4Address)
	assert.Equal(t, compiled.Decision.IPv6Address, decompiled.Decision.IPv6Address)
	assert.Equal(t, compiled.Decision.DelegatedIPv6Prefix, decompiled.Decision.DelegatedIPv6Prefix)
	assert.Equal(t, compiled.Decision.RAPrefix, decompiled.Decision.RAPrefix)
}

func TestCompileAddressPolicyConflictsAndWithdrawals(t *testing.T) {
	cfg := testAddressPolicyConfig()

	conflict := CompileAddressPolicy(cfg, AddressPolicyCompileRequest{
		Role:     "branch-dualstack",
		IPv4Pool: "branch-pd",
	})
	require.Equal(t, "blocked", conflict.Status)
	assertAddressPolicyDiagnostic(t, conflict.Diagnostics, "address_conflict")

	withdraw := CompileAddressPolicy(cfg, AddressPolicyCompileRequest{
		Role:            "branch-dualstack",
		LifecycleAction: "accounting-stop",
		PackKeys:        []string{productconfigs.VendorPackStandard, productconfigs.VendorPackAegisNAS, productconfigs.VendorPackCisco},
	})
	require.Equal(t, "compiled", withdraw.Status, withdraw.Diagnostics)
	assert.True(t, withdraw.Decision.Withdraw)
	assert.GreaterOrEqual(t, withdraw.Summary.WithdrawCount, 4)
	assertAddressPolicyAttribute(t, withdraw.Attributes, productconfigs.VendorPackAegisNAS, "AegisNAS-Address-Policy", "accounting-stop")
	assertAddressPolicyAttribute(t, withdraw.Attributes, productconfigs.VendorPackCisco, "Cisco-AVPair", "address-policy=withdraw")
	assertNoAddressPolicyAttribute(t, withdraw.Attributes, productconfigs.VendorPackStandard, "Framed-IP-Address")
	assertNoAddressPolicyAttribute(t, withdraw.Attributes, productconfigs.VendorPackStandard, "Delegated-IPv6-Prefix")
}

func TestApplyAddressPolicyToReplyAttributesRendersPacks(t *testing.T) {
	compiled := CompileAddressPolicy(testAddressPolicyConfig(), AddressPolicyCompileRequest{Role: "branch-dualstack"})
	require.Equal(t, "compiled", compiled.Status, compiled.Diagnostics)

	attrs := &ReplyAttributes{Role: "branch-dualstack"}
	ApplyAddressPolicyToReplyAttributes(attrs, compiled)
	rendered := RenderReplyAttributesForPacks(attrs, []string{productconfigs.VendorPackStandard, productconfigs.VendorPackAegisNAS, productconfigs.VendorPackCisco})

	assert.Contains(t, rendered, "\tFramed-IP-Address = "+compiled.Decision.IPv4Address+"\n")
	assert.Contains(t, rendered, "\tDelegated-IPv6-Prefix = "+compiled.Decision.DelegatedIPv6Prefix+"\n")
	assert.Contains(t, rendered, "\tAegisNAS-Address-Owner = \"address-team\"\n")
	assert.Contains(t, rendered, "\tCisco-AVPair = \"delegated-ipv6-prefix="+compiled.Decision.DelegatedIPv6Prefix+"\"\n")
}

func testAddressPolicyConfig() *config.Config {
	return &config.Config{
		Radius: config.RadiusConfig{
			Vendor: config.RadiusVendorConfig{
				CompatibilityPacks: []string{productconfigs.VendorPackStandard, productconfigs.VendorPackAegisNAS},
			},
			AddressPolicy: config.RadiusAddressPolicyConfig{
				Enabled:        true,
				FailClosed:     true,
				MaxAssignments: 16,
				DefaultOwner:   "aegisnas",
				ConflictMode:   "block",
				StopWithdrawal: true,
				DHCPv6: config.RadiusDHCPv6PolicyConfig{
					Enabled:          true,
					ManagedAddress:   true,
					OtherConfig:      true,
					PrefixDelegation: true,
				},
				RA: config.RadiusRAPolicyConfig{
					Enabled:                 true,
					OtherConfigFlag:         true,
					DefaultRouterPreference: "medium",
				},
				Pools: []config.RadiusAddressPoolConfig{
					{Name: "branch-v4", Family: "ipv4", CIDR: "198.51.100.0/29", Start: "198.51.100.2", End: "198.51.100.6", Gateway: "198.51.100.1", Mode: "address"},
					{Name: "branch-v6", Family: "ipv6", CIDR: "2001:db8:10::/120", Mode: "address"},
					{Name: "branch-pd", Family: "ipv6", CIDR: "2001:db8:100::/48", DelegatedPrefixLength: 56, Mode: "delegated-prefix"},
					{Name: "branch-ra", Family: "ipv6", CIDR: "2001:db8:200::/56", PrefixLength: 64, Mode: "ra-prefix"},
				},
				RolePolicies: []config.RadiusAddressRolePolicy{
					{
						Role:              "branch-dualstack",
						Owner:             "address-team",
						IPv4Pool:          "branch-v4",
						IPv6Pool:          "branch-v6",
						DelegatedIPv6Pool: "branch-pd",
						RAPrefixPool:      "branch-ra",
						VendorPacks:       []string{productconfigs.VendorPackStandard, productconfigs.VendorPackAegisNAS, productconfigs.VendorPackCisco},
					},
				},
			},
		},
	}
}

func assertAddressPolicyAttribute(t *testing.T, attrs []AddressPolicyAttribute, pack, name, value string) {
	t.Helper()
	for _, attr := range attrs {
		if attr.PackKey == pack && attr.Name == name && attr.Value == value {
			return
		}
	}
	t.Fatalf("missing address policy attribute %s/%s=%s in %#v", pack, name, value, attrs)
}

func assertNoAddressPolicyAttribute(t *testing.T, attrs []AddressPolicyAttribute, pack, name string) {
	t.Helper()
	for _, attr := range attrs {
		if attr.PackKey == pack && attr.Name == name {
			t.Fatalf("unexpected address policy attribute %s/%s in %#v", pack, name, attrs)
		}
	}
}

func assertAddressPolicyDiagnostic(t *testing.T, diagnostics []AddressPolicyDiagnostic, code string) {
	t.Helper()
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == code {
			return
		}
	}
	t.Fatalf("missing address policy diagnostic %s in %#v", code, diagnostics)
}

func assertAddressInPrefix(t *testing.T, address, cidr string) {
	t.Helper()
	addr, err := netip.ParseAddr(address)
	require.NoError(t, err)
	prefix, err := netip.ParsePrefix(cidr)
	require.NoError(t, err)
	assert.True(t, prefix.Contains(addr), "%s should be inside %s", address, cidr)
}

func assertPrefixInPrefix(t *testing.T, child, parent string, bits int) {
	t.Helper()
	childPrefix, err := netip.ParsePrefix(child)
	require.NoError(t, err)
	parentPrefix, err := netip.ParsePrefix(parent)
	require.NoError(t, err)
	assert.True(t, parentPrefix.Contains(childPrefix.Addr()), "%s should be inside %s", child, parent)
	assert.Equal(t, bits, childPrefix.Bits())
}
