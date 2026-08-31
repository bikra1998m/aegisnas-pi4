package radius

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestACLCompilerRoundTripsCertifiedLinePacks(t *testing.T) {
	rules := []ACLRule{
		{Action: "permit", Direction: "in", Protocol: "tcp", Source: "any", Destination: "any", DestinationPort: "443", Log: true},
		{Action: "deny", Direction: "out", Protocol: "udp", Source: "any", Destination: "10.0.0.0/24", DestinationPort: "53"},
	}
	cases := []struct {
		packKey        string
		wantAttributes []string
		wantGrammar    string
	}{
		{packKey: "standard", wantAttributes: []string{"NAS-Filter-Rule"}, wantGrammar: "nas-filter-rule-v1"},
		{packKey: "aegisnas", wantAttributes: []string{"AegisNAS-ACL-Name", "AegisNAS-ACL-Rule"}, wantGrammar: "aegisnas-acl-v1"},
		{packKey: "cisco", wantAttributes: []string{"Cisco-In-ACL", "Cisco-Out-ACL", "Cisco-AVPair"}, wantGrammar: "cisco-avpair-acl-v1"},
		{packKey: "aruba", wantAttributes: []string{"Aruba-NAS-Filter-Rule"}, wantGrammar: "nas-filter-rule-v1"},
		{packKey: "hp", wantAttributes: []string{"Ip-Filter-Raw"}, wantGrammar: "nas-filter-rule-v1"},
		{packKey: "dlink", wantAttributes: []string{"Dlink-ACL-Profile", "Dlink-ACL-Rule"}, wantGrammar: "nas-filter-rule-v1"},
		{packKey: "pica8", wantAttributes: []string{"IP-Downloadable-ACL-Name", "IP-Downloadable-ACL-Rule"}, wantGrammar: "nas-filter-rule-v1"},
	}

	for _, tc := range cases {
		t.Run(tc.packKey, func(t *testing.T) {
			result, err := CompileACLPolicyForPack(ACLCompilerRequest{
				PolicyName:  "guest-internet",
				InboundACL:  "guest-in",
				OutboundACL: "guest-out",
				Rules:       rules,
			}, tc.packKey)
			require.NoError(t, err)
			assert.Equal(t, "compiled", result.Status)
			assert.Equal(t, "software-certified", result.CertificationState)
			assert.Equal(t, ACLCompilerVersion, result.CompilerVersion)
			assert.Equal(t, tc.wantGrammar, result.Grammar)
			assert.True(t, result.Lossless)
			assert.True(t, result.DecompileSupported)
			assert.NotEmpty(t, result.ArtifactFingerprint)
			assert.NotEmpty(t, result.FreeRADIUS)
			assert.Empty(t, result.Diagnostics)
			for _, attr := range tc.wantAttributes {
				assertACLCompileContains(t, result, attr)
			}

			decompiled, err := DecompileACLAttributes(ACLDecompileRequest{
				PackKey:    tc.packKey,
				PolicyName: "guest-internet",
				Attributes: result.Attributes,
			})
			require.NoError(t, err)
			assert.Equal(t, "compiled", decompiled.Status)
			assert.Equal(t, result.ArtifactFingerprint, decompiled.ArtifactFingerprint)
			assert.Equal(t, renderNASFilterRules(rules), renderNASFilterRules(decompiled.Rules))
			assert.True(t, decompiled.ACLRoundTrip.Lossless)
		})
	}
}

func TestACLCompilerProfileReferencePacksAreExplicitlyNonLossless(t *testing.T) {
	run, err := CompileACLPolicyForPacks(ACLCompilerRequest{
		PolicyName: "guest-internet",
		Rules: []ACLRule{{
			Action: "permit", Direction: "in", Protocol: "tcp", Source: "any", Destination: "any", DestinationPort: "443",
		}},
		PackKeys: []string{"mikrotik", "fortinet", "ruckus", "juniper", "huawei", "h3c"},
	})
	require.NoError(t, err)
	assert.Equal(t, "degraded", run.Status)
	assert.Equal(t, 6, run.Summary.ProfileReferenceCount)
	assert.Equal(t, 6, run.Summary.NonLosslessCount)

	byPack := map[string]ACLCompileResult{}
	for _, result := range run.Results {
		byPack[result.PackKey] = result
	}
	expectedAttrs := map[string]string{
		"mikrotik": "Mikrotik-Address-List",
		"fortinet": "Fortinet-Access-Profile",
		"ruckus":   "Ruckus-User-Groups",
		"juniper":  "Juniper-Firewall-filter-name",
		"huawei":   "Huawei-Data-Filter",
		"h3c":      "H3C-Ita-Policy",
	}
	for packKey, attr := range expectedAttrs {
		result := byPack[packKey]
		require.NotEmpty(t, result.PackKey)
		assert.Equal(t, "profile_reference", result.Status)
		assert.Equal(t, "profile-reference", result.CertificationState)
		assert.False(t, result.Lossless)
		assert.Contains(t, result.RoundTrip.UnsupportedFields, "attributes")
		assertACLCompileContains(t, result, attr)
		assertACLDiagnosticCode(t, result.Diagnostics, "profile_reference_only")

		decompiled, err := DecompileACLAttributes(ACLDecompileRequest{PackKey: packKey, Attributes: result.Attributes})
		require.NoError(t, err)
		assert.Equal(t, "profile_reference", decompiled.Status)
		assert.Empty(t, decompiled.Rules)
		assert.NotEmpty(t, decompiled.ProfileReferences)
	}
}

func TestACLCompilerBlocksUnsupportedPackWithIntent(t *testing.T) {
	result, err := CompileACLPolicyForPack(ACLCompilerRequest{
		PolicyName: "datacenter-firewall",
		Rules: []ACLRule{{
			Action: "deny", Direction: "in", Protocol: "tcp", Source: "any", Destination: "198.51.100.10", DestinationPort: "22",
		}},
	}, "paloalto")
	require.NoError(t, err)
	assert.Equal(t, "blocked", result.Status)
	assert.False(t, result.Lossless)
	assert.Empty(t, result.Attributes)
	assertACLDiagnosticCode(t, result.Diagnostics, "vendor_acl_compiler_unsupported")
}

func TestACLCompilerBlocksOversizedWireValues(t *testing.T) {
	result, err := CompileACLPolicyForPack(ACLCompilerRequest{
		PolicyName: "oversized",
		Rules: []ACLRule{{
			Action:      "permit",
			Direction:   "in",
			Protocol:    "tcp",
			Source:      "any",
			Destination: strings.Repeat("a", 260),
		}},
	}, "standard")
	require.NoError(t, err)
	assert.Equal(t, "blocked", result.Status)
	assert.False(t, result.Lossless)
	assertACLDiagnosticCode(t, result.Diagnostics, "compiler_value_limit")
}

func assertACLCompileContains(t *testing.T, result ACLCompileResult, name string) {
	t.Helper()
	for _, item := range result.Attributes {
		if item.Name == name {
			return
		}
	}
	t.Fatalf("compiled ACL result for %s did not include attribute %s: %#v", result.PackKey, name, result.Attributes)
}

func assertACLDiagnosticCode(t *testing.T, diagnostics []ACLDiagnostic, code string) {
	t.Helper()
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == code {
			return
		}
	}
	t.Fatalf("diagnostic code %s not found in %#v", code, diagnostics)
}
