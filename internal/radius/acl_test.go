package radius

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRenderACLRulesForNASFilterAndCiscoAVPair(t *testing.T) {
	rules := []ACLRule{
		{
			Action:          "permit",
			Direction:       "in",
			Protocol:        "tcp",
			Source:          "any",
			Destination:     "any",
			DestinationPort: "443",
			Log:             true,
		},
		{
			Action:          "deny",
			Direction:       "out",
			Protocol:        "udp",
			Source:          "any",
			Destination:     "10.0.0.0/24",
			DestinationPort: "53",
		},
	}

	require.NoError(t, ValidateACLRules(rules))
	assert.Equal(t, []string{
		"permit in tcp from any to any 443 log",
		"deny out udp from any to 10.0.0.0/24 53",
	}, renderNASFilterRules(rules))
	assert.Equal(t, []string{
		"ip:inacl#1=permit tcp any any eq 443 log",
		"ip:outacl#1=deny udp any 10.0.0.0/24 eq 53",
	}, renderCiscoAVPairACLRules(rules))
}

func TestBuildACLVendorExports(t *testing.T) {
	rules := []ACLRule{
		{Action: "permit", Direction: "in", Protocol: "tcp", Source: "any", Destination: "any", DestinationPort: "443", Log: true},
		{Action: "deny", Direction: "out", Protocol: "udp", Source: "any", Destination: "10.0.0.0/24", DestinationPort: "53"},
	}

	exports := BuildACLVendorExports("guest-internet", "guest-in", "guest-out", rules, []string{
		"standard",
		"cisco",
		"aruba",
		"mikrotik",
		"fortinet",
		"ruckus",
		"dlink",
		"pica8",
	})

	byPack := aclExportsByPack(exports)
	assert.Equal(t, "line_rules", byPack["standard"].ExportMode)
	assertACLExportContains(t, byPack["standard"], "NAS-Filter-Rule", "permit in tcp from any to any 443 log")
	assertACLExportContains(t, byPack["cisco"], "Cisco-In-ACL", "guest-in")
	assertACLExportContains(t, byPack["cisco"], "Cisco-Out-ACL", "guest-out")
	assertACLExportContains(t, byPack["cisco"], "Cisco-AVPair", "ip:inacl#1=permit tcp any any eq 443 log")
	assertACLExportContains(t, byPack["cisco"], "Cisco-AVPair", "ip:outacl#1=deny udp any 10.0.0.0/24 eq 53")
	assertACLExportContains(t, byPack["aruba"], "Aruba-NAS-Filter-Rule", "permit in tcp from any to any 443 log")
	assert.Equal(t, "profile_reference", byPack["mikrotik"].ExportMode)
	assert.Equal(t, "profile_reference", byPack["mikrotik"].CompilerStatus)
	assert.False(t, byPack["mikrotik"].Lossless)
	assertACLExportContains(t, byPack["mikrotik"], "Mikrotik-Address-List", "guest-internet")
	assert.NotEmpty(t, byPack["mikrotik"].Warnings)
	assertACLExportContains(t, byPack["fortinet"], "Fortinet-Access-Profile", "guest-internet")
	assertACLExportContains(t, byPack["ruckus"], "Ruckus-User-Groups", "guest-internet")
	assert.Equal(t, "mixed", byPack["dlink"].ExportMode)
	assertACLExportContains(t, byPack["dlink"], "ACL-Rule", "deny out udp from any to 10.0.0.0/24 53")
	assertACLExportContains(t, byPack["pica8"], "IP-Downloadable-ACL-Rule", "permit in tcp from any to any 443 log")
	assert.Contains(t, byPack["cisco"].FreeRADIUS, "Cisco-AVPair = \"ip:inacl#1=permit tcp any any eq 443 log\"")
}

func TestValidateACLRulesRejectsUnsafeTokens(t *testing.T) {
	err := ValidateACLRules([]ACLRule{{
		Action:      "permit",
		Direction:   "in",
		Protocol:    "tcp",
		Source:      "any",
		Destination: "any\"",
	}})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "acl_rules[0]")
}

func TestRenderCiscoDownloadableACLOmitsOutboundRules(t *testing.T) {
	lines, omitted, err := RenderCiscoDownloadableACL([]ACLRule{
		{Action: "permit", Direction: "in", Protocol: "tcp", Source: "any", Destination: "any", DestinationPort: "443"},
		{Action: "deny", Direction: "out", Protocol: "udp", Source: "any", Destination: "10.0.0.0/24", DestinationPort: "53"},
	})

	require.NoError(t, err)
	assert.Equal(t, []string{"permit tcp any any eq 443"}, lines)
	assert.Equal(t, 1, omitted)
}

func TestNormalizeACLPolicyIntentBuildsLosslessASTFromFlatRules(t *testing.T) {
	normalization, err := NormalizeACLPolicyIntent("ipv6-web", "dual-stack web", "web-in", "", []ACLRule{{
		Action:          "permit",
		Direction:       "in",
		Protocol:        "tcp",
		Source:          "2001:db8:10::/64",
		Destination:     "any",
		DestinationPort: "443",
		Log:             true,
	}}, nil)

	require.NoError(t, err)
	require.Len(t, normalization.Rules, 1)
	require.Len(t, normalization.AST.Rules, 1)
	assert.Equal(t, ACLASTSchemaVersion, normalization.AST.SchemaVersion)
	assert.Equal(t, "ipv6", normalization.AST.Rules[0].Match.AddressFamily)
	assert.True(t, normalization.RoundTrip.Lossless)
	assert.NotEmpty(t, normalization.Fingerprint)
}

func TestNormalizeACLPolicyIntentPreservesRichASTWithDiagnostics(t *testing.T) {
	ast := ACLPolicyAST{
		SchemaVersion: ACLASTSchemaVersion,
		Name:          "corp-apps",
		ObjectGroups: []ACLObjectGroup{{
			Name:   "corp-nets",
			Values: []string{"10.0.0.0/8", "2001:db8::/32"},
		}},
		ServiceGroups: []ACLServiceGroup{{
			Name:      "web",
			Protocols: []string{"tcp"},
			Ports:     []string{"443"},
		}},
		Rules: []ACLASTRule{{
			ID:        "allow-managed-web",
			Sequence:  10,
			Action:    "reject",
			Direction: "both",
			Match: ACLASTMatch{
				Protocols: []string{"tcp"},
				Source: ACLEndpoint{
					ObjectGroups: []string{"corp-nets"},
					PortGroups:   []string{"web"},
				},
				Destination:   ACLEndpoint{Any: true},
				Applications:  []string{"web-browsing"},
				URLCategories: []string{"business"},
				States:        []string{"established"},
			},
			Log: true,
		}},
	}

	normalization, err := NormalizeACLPolicyIntent("corp-apps", "", "", "", nil, &ast)

	require.NoError(t, err)
	assert.False(t, normalization.RoundTrip.Lossless)
	assert.NotEmpty(t, normalization.RoundTrip.UnsupportedFields)
	assert.GreaterOrEqual(t, len(normalization.Rules), 4)
	assert.Equal(t, "deny", normalization.Rules[0].Action)
	assert.Contains(t, aclDiagnosticCodes(normalization.Diagnostics), "action_degraded")
	assert.Contains(t, aclDiagnosticCodes(normalization.Diagnostics), "field_not_rendered")
}

func TestNormalizeACLPolicyIntentReportsFlatProjectionTruncation(t *testing.T) {
	values := make([]string, 65)
	for idx := range values {
		values[idx] = fmt.Sprintf("10.10.%d.0/24", idx)
	}
	ast := ACLPolicyAST{
		SchemaVersion: ACLASTSchemaVersion,
		ObjectGroups: []ACLObjectGroup{{
			Name:   "many-sources",
			Values: values,
		}},
		Rules: []ACLASTRule{{
			ID:        "allow-web",
			Sequence:  10,
			Action:    "permit",
			Direction: "in",
			Match: ACLASTMatch{
				Protocols:   []string{"tcp"},
				Source:      ACLEndpoint{ObjectGroups: []string{"many-sources"}},
				Destination: ACLEndpoint{Any: true, Ports: []string{"443"}},
			},
		}},
	}

	normalization, err := NormalizeACLPolicyIntent("wide-policy", "", "", "", nil, &ast)

	require.NoError(t, err)
	require.Len(t, normalization.Rules, 64)
	assert.False(t, normalization.RoundTrip.Lossless)
	assert.Contains(t, aclDiagnosticCodes(normalization.Diagnostics), "flat_rule_limit")
	assert.Contains(t, normalization.RoundTrip.UnsupportedFields, "rules")
}

func TestNormalizeACLPolicyIntentRejectsInvalidAddressFamily(t *testing.T) {
	_, err := NormalizeACLPolicyIntent("bad-family", "", "", "", nil, &ACLPolicyAST{
		SchemaVersion: ACLASTSchemaVersion,
		Rules: []ACLASTRule{{
			ID:        "bad-family",
			Action:    "permit",
			Direction: "in",
			Match: ACLASTMatch{
				AddressFamily: "ipx",
				Protocols:     []string{"tcp"},
				Source:        ACLEndpoint{Any: true},
				Destination:   ACLEndpoint{Any: true},
			},
		}},
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "address_family")
}

func aclExportsByPack(exports []ACLVendorExport) map[string]ACLVendorExport {
	out := map[string]ACLVendorExport{}
	for _, export := range exports {
		out[export.PackKey] = export
	}
	return out
}

func assertACLExportContains(t *testing.T, export ACLVendorExport, name, value string) {
	t.Helper()
	for _, attr := range export.Attributes {
		if attr.Name == name && attr.Value == value {
			return
		}
	}
	t.Fatalf("attribute %s=%s not found in %#v", name, value, export.Attributes)
}

func aclDiagnosticCodes(diagnostics []ACLDiagnostic) []string {
	out := make([]string, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		out = append(out, diagnostic.Code)
	}
	return out
}
