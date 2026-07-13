package radius

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	layehradius "layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

func TestBuildProxyPolicyReport(t *testing.T) {
	cfg := proxyPolicyTestConfig()

	report := BuildProxyPolicyReport(cfg)

	require.Equal(t, "ready", report.Status)
	assert.True(t, report.Enabled)
	assert.Equal(t, ProxyPolicySchemaVersion, report.SchemaVersion)
	assert.True(t, report.FreeRADIUS.LoopMarkerEnforced)
	assert.GreaterOrEqual(t, report.Summary.RoutePolicyCount, 2)
	assert.Greater(t, report.Summary.AllowStandardCount, 0)
	assert.Equal(t, 1, report.Summary.AllowVendorIDCount)
	assert.Equal(t, 1, report.Summary.DenyStandardCount)
	assert.Equal(t, 1, report.Summary.RewriteRuleCount)
}

func TestEvaluateProxyPolicyRejectsLoopMarker(t *testing.T) {
	policy, err := ProxyPolicyFromConfig(proxyPolicyTestConfig())
	require.NoError(t, err)
	packet := layehradius.New(layehradius.CodeAccessRequest, []byte("secret"))
	require.NoError(t, rfc2865.UserName_SetString(packet, "alice@corp.example.com"))
	packet.Add(layehradius.Type(radiusTypeProxyState), []byte("aegisnas:corp:192.0.2.10:corp.example.com"))

	decision := EvaluateProxyPolicy(packet, ProxyPolicyContext{Route: "corp", Direction: "proxy_request", SourceRealm: "corp.example.com"}, policy)

	assert.False(t, decision.Allowed)
	assert.Equal(t, "loop_marker_detected", decision.Reason)
}

func TestEvaluateProxyPolicyRejectsUntrustedSourceRealm(t *testing.T) {
	policy, err := ProxyPolicyFromConfig(proxyPolicyTestConfig())
	require.NoError(t, err)
	packet := layehradius.New(layehradius.CodeAccessRequest, []byte("secret"))
	require.NoError(t, rfc2865.UserName_SetString(packet, "alice@corp.example.com"))

	decision := EvaluateProxyPolicy(packet, ProxyPolicyContext{Route: "corp", Direction: "proxy_request", SourceRealm: "evil.example.net"}, policy)

	assert.False(t, decision.Allowed)
	assert.Equal(t, "untrusted_source_realm", decision.Reason)
}

func TestEvaluateProxyPolicyAllowsConfiguredVendorAndDropsUnknownVendor(t *testing.T) {
	policy, err := ProxyPolicyFromConfig(proxyPolicyTestConfig())
	require.NoError(t, err)
	packet := layehradius.New(layehradius.CodeAccessRequest, []byte("secret"))
	require.NoError(t, rfc2865.UserName_SetString(packet, "alice@corp.example.com"))
	require.NoError(t, AddVendorAttributeWithSpec(packet, VendorAttributeSpec{VendorID: 9, Type: 1}, layehradius.Attribute("shell:priv-lvl=15")))
	require.NoError(t, AddVendorAttributeWithSpec(packet, VendorAttributeSpec{VendorID: 311, Type: 99}, layehradius.Attribute("blocked")))

	decision := EvaluateProxyPolicy(packet, ProxyPolicyContext{Route: "corp", Direction: "proxy_request", SourceRealm: "corp.example.com"}, policy)

	assert.True(t, decision.Allowed)
	assert.Contains(t, proxyDecisionReasons(decision.Accepted), "vendor_allow")
	assert.Contains(t, proxyDecisionReasons(decision.Dropped), "default_drop")
}

func TestEvaluateProxyPolicyRejectsDeniedStandardAttribute(t *testing.T) {
	policy, err := ProxyPolicyFromConfig(proxyPolicyTestConfig())
	require.NoError(t, err)
	packet := layehradius.New(layehradius.CodeAccessRequest, []byte("secret"))
	require.NoError(t, rfc2865.UserName_SetString(packet, "alice@corp.example.com"))
	require.NoError(t, rfc2865.FilterID_SetString(packet, "do-not-forward"))

	decision := EvaluateProxyPolicy(packet, ProxyPolicyContext{Route: "corp", Direction: "proxy_request", SourceRealm: "corp.example.com"}, policy)

	assert.False(t, decision.Allowed)
	assert.Equal(t, "attribute_denied", decision.Reason)
	require.NotEmpty(t, decision.Rejected)
	assert.Equal(t, "Filter-Id", decision.Rejected[0].Name)
}

func TestEvaluateProxyPolicyRecordsRewriteAction(t *testing.T) {
	policy, err := ProxyPolicyFromConfig(proxyPolicyTestConfig())
	require.NoError(t, err)
	packet := layehradius.New(layehradius.CodeAccessRequest, []byte("secret"))
	require.NoError(t, rfc2865.UserName_SetString(packet, "alice@employees.example.com"))

	decision := EvaluateProxyPolicy(packet, ProxyPolicyContext{Route: "corp", Direction: "proxy_request", SourceRealm: "employees.example.com"}, policy)

	assert.True(t, decision.Allowed)
	require.Len(t, decision.RewriteActions, 1)
	assert.Equal(t, "alice@corp.example.com", decision.RewriteActions[0].After)
}

func TestFreeRADIUSProxyPolicyUnlang(t *testing.T) {
	text, err := FreeRADIUSProxyPolicyUnlang(proxyPolicyTestConfig(), "proxy-request")
	require.NoError(t, err)

	assert.Contains(t, text, "NAS-0011 proxy loop prevention")
	assert.Contains(t, text, "Proxy-State += \"aegisnas:corp")
	assert.Contains(t, text, "Filter-Id")
	assert.Contains(t, text, "User-Name := \"%{1}@corp.example.com\"")
}

func proxyPolicyTestConfig() *config.Config {
	cfg := proxyRoutingTestConfig()
	cfg.Radius.Upstream.ProxyPolicy = config.RadiusProxyPolicyConfig{
		Enabled:          true,
		FailClosed:       true,
		DefaultAction:    "drop",
		LoopMarker:       "aegisnas",
		AddLoopMarker:    true,
		RejectLoopMarker: true,
		MaxHops:          8,
		RoutePolicies: []config.RadiusProxyRoutePolicyConfig{{
			Route:               "corp",
			Direction:           "any",
			TrustedSourceRealms: []string{"corp.example.com", "employees.example.com"},
			AllowVendorIDs:      []int{9},
			DenyStandard:        []string{"Filter-Id"},
			RewriteRules: []config.RadiusProxyRewriteRuleConfig{{
				Attribute:   "User-Name",
				Action:      "replace_realm",
				MatchRealm:  "employees.example.com",
				Replacement: "corp.example.com",
			}},
		}},
	}
	return cfg
}

func proxyDecisionReasons(items []ProxyAttributeDecision) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.Reason)
	}
	return out
}
