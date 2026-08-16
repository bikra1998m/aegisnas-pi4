package radius

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

func TestCompileRoutePolicyStandardProductAndVendorAVPairs(t *testing.T) {
	cfg := testRoutePolicyConfig()

	result := CompileRoutePolicy(cfg, RoutePolicyCompileRequest{
		Role:             "branch-vpn",
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
			productconfigs.VendorPackNokia,
		},
	})

	require.Equal(t, "compiled", result.Status, result.Diagnostics)
	assert.True(t, result.Decision.PolicyMatched)
	assert.Equal(t, "corp", result.Decision.VRF)
	assert.Equal(t, "network-team", result.Decision.Owner)
	assert.Equal(t, "authorize", result.Decision.LifecycleAction)
	assert.Len(t, result.Decision.IPv4Routes, 1)
	assert.Len(t, result.Decision.IPv6Routes, 1)
	assert.Equal(t, "10.80.0.0/16", result.Decision.IPv4Routes[0].Destination)
	assert.Equal(t, "192.0.2.1", result.Decision.IPv4Routes[0].Gateway)
	assert.Equal(t, "2001:db8:80::/48", result.Decision.IPv6Routes[0].Destination)
	assert.NotEmpty(t, result.Decision.Revision)
	assert.NotEmpty(t, result.Decision.OwnershipKey)
	assert.Equal(t, "sha256:", result.Fingerprint[:7])

	assertRoutePolicyAttribute(t, result.Attributes, productconfigs.VendorPackStandard, "Framed-Route", "10.80.0.0/16 192.0.2.1 10")
	assertRoutePolicyAttribute(t, result.Attributes, productconfigs.VendorPackStandard, "Framed-IPv6-Route", "2001:db8:80::/48 2001:db8::1 20")
	assertRoutePolicyAttribute(t, result.Attributes, productconfigs.VendorPackAegisNAS, "AegisNAS-VRF", "corp")
	assertRoutePolicyAttribute(t, result.Attributes, productconfigs.VendorPackAegisNAS, "AegisNAS-Route-Owner", "network-team")
	assertRoutePolicyAttribute(t, result.Attributes, productconfigs.VendorPackCisco, "Cisco-AVPair", "ip:route=10.80.0.0/16 192.0.2.1 10")
	assertRoutePolicyAttribute(t, result.Attributes, productconfigs.VendorPackJuniper, "Juniper-AV-Pair", "vrf=corp")
	assertRoutePolicyAttribute(t, result.Attributes, productconfigs.VendorPackHuawei, "Huawei-AVpair", "framed-ipv6-route=2001:db8:80::/48 2001:db8::1 20")
	assertRoutePolicyAttribute(t, result.Attributes, productconfigs.VendorPackNokia, "Nokia-AVPair", "route-owner=network-team")
}

func TestDecompileRoutePolicyAttributesRoundTripsRoutesAndVRF(t *testing.T) {
	compiled := CompileRoutePolicy(testRoutePolicyConfig(), RoutePolicyCompileRequest{
		Role:     "branch-vpn",
		PackKeys: []string{productconfigs.VendorPackAegisNAS, productconfigs.VendorPackCisco},
	})
	require.Equal(t, "compiled", compiled.Status, compiled.Diagnostics)

	decompiled := DecompileRoutePolicyAttributes(RoutePolicyDecompileRequest{
		PackKey:    productconfigs.VendorPackCisco,
		Role:       "branch-vpn",
		SessionID:  "session-1",
		Attributes: compiled.Attributes,
	})

	require.Equal(t, "decompiled", decompiled.Status, decompiled.Diagnostics)
	assert.Equal(t, "corp", decompiled.Decision.VRF)
	assert.Equal(t, "network-team", decompiled.Decision.Owner)
	assert.Len(t, decompiled.Decision.IPv4Routes, 1)
	assert.Len(t, decompiled.Decision.IPv6Routes, 1)
	assert.Equal(t, "10.80.0.0/16", decompiled.Decision.IPv4Routes[0].Destination)
	assert.Equal(t, "2001:db8:80::/48", decompiled.Decision.IPv6Routes[0].Destination)
}

func TestCompileRoutePolicyConflictsAndWithdrawals(t *testing.T) {
	cfg := testRoutePolicyConfig()

	conflict := CompileRoutePolicy(cfg, RoutePolicyCompileRequest{
		Role: "branch-vpn",
		Routes: []RoutePolicyRoute{{
			Family:      "ipv4",
			Destination: "10.80.0.0/16",
			Gateway:     "192.0.2.99",
		}},
	})
	require.Equal(t, "blocked", conflict.Status)
	assertRoutePolicyDiagnostic(t, conflict.Diagnostics, "route_conflict")

	withdraw := CompileRoutePolicy(cfg, RoutePolicyCompileRequest{
		Role:            "branch-vpn",
		LifecycleAction: "accounting-stop",
		PackKeys:        []string{productconfigs.VendorPackStandard, productconfigs.VendorPackAegisNAS, productconfigs.VendorPackCisco},
	})
	require.Equal(t, "compiled", withdraw.Status, withdraw.Diagnostics)
	assert.True(t, withdraw.Decision.Withdraw)
	assert.Equal(t, 2, withdraw.Summary.WithdrawCount)
	assertRoutePolicyAttribute(t, withdraw.Attributes, productconfigs.VendorPackAegisNAS, "AegisNAS-Route-Policy", "accounting-stop")
	assertRoutePolicyAttribute(t, withdraw.Attributes, productconfigs.VendorPackCisco, "Cisco-AVPair", "route-policy=withdraw")
	assertNoRoutePolicyAttribute(t, withdraw.Attributes, productconfigs.VendorPackStandard, "Framed-Route")
	assertNoRoutePolicyAttribute(t, withdraw.Attributes, productconfigs.VendorPackStandard, "Framed-IPv6-Route")
}

func TestApplyRoutePolicyToReplyAttributesRendersPacks(t *testing.T) {
	compiled := CompileRoutePolicy(testRoutePolicyConfig(), RoutePolicyCompileRequest{Role: "branch-vpn"})
	require.Equal(t, "compiled", compiled.Status, compiled.Diagnostics)

	attrs := &ReplyAttributes{Role: "branch-vpn"}
	ApplyRoutePolicyToReplyAttributes(attrs, compiled)
	rendered := RenderReplyAttributesForPacks(attrs, []string{productconfigs.VendorPackStandard, productconfigs.VendorPackAegisNAS, productconfigs.VendorPackCisco})

	assert.Contains(t, rendered, "\tFramed-Route = \"10.80.0.0/16 192.0.2.1 10\"\n")
	assert.Contains(t, rendered, "\tFramed-IPv6-Route = \"2001:db8:80::/48 2001:db8::1 20\"\n")
	assert.Contains(t, rendered, "\tAegisNAS-VRF = \"corp\"\n")
	assert.Contains(t, rendered, "\tCisco-AVPair = \"ip:route=10.80.0.0/16 192.0.2.1 10\"\n")
}

func testRoutePolicyConfig() *config.Config {
	return &config.Config{
		Radius: config.RadiusConfig{
			Vendor: config.RadiusVendorConfig{
				CompatibilityPacks: []string{productconfigs.VendorPackStandard, productconfigs.VendorPackAegisNAS},
			},
			RoutePolicy: config.RadiusRoutePolicyConfig{
				Enabled:        true,
				FailClosed:     true,
				MaxRoutes:      8,
				DefaultVRF:     "default",
				DefaultOwner:   "aegisnas",
				ConflictMode:   "block",
				StopWithdrawal: true,
				VRFs: []config.RadiusVRFConfig{
					{Name: "corp", RouteDistinguisher: "65000:10"},
				},
				RolePolicies: []config.RadiusRouteRolePolicy{
					{
						Role:  "branch-vpn",
						VRF:   "corp",
						Owner: "network-team",
						IPv4Routes: []config.RadiusRouteConfig{
							{Destination: "10.80.0.0/16", Gateway: "192.0.2.1", Metric: 10, Interface: "pppoe0", Tag: "branch"},
						},
						IPv6Routes: []config.RadiusRouteConfig{
							{Destination: "2001:db8:80::/48", Gateway: "2001:db8::1", Metric: 20},
						},
						VendorPacks: []string{productconfigs.VendorPackStandard, productconfigs.VendorPackAegisNAS, productconfigs.VendorPackCisco},
					},
				},
			},
		},
	}
}

func assertRoutePolicyAttribute(t *testing.T, attrs []RoutePolicyAttribute, pack, name, value string) {
	t.Helper()
	for _, attr := range attrs {
		if attr.PackKey == pack && attr.Name == name && attr.Value == value {
			return
		}
	}
	t.Fatalf("missing route policy attribute %s/%s=%s in %#v", pack, name, value, attrs)
}

func assertNoRoutePolicyAttribute(t *testing.T, attrs []RoutePolicyAttribute, pack, name string) {
	t.Helper()
	for _, attr := range attrs {
		if attr.PackKey == pack && attr.Name == name {
			t.Fatalf("unexpected route policy attribute %s/%s in %#v", pack, name, attrs)
		}
	}
}

func assertRoutePolicyDiagnostic(t *testing.T, diagnostics []RoutePolicyDiagnostic, code string) {
	t.Helper()
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == code {
			return
		}
	}
	t.Fatalf("missing route policy diagnostic %s in %#v", code, diagnostics)
}
