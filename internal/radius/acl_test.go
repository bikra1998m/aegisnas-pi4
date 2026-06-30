package radius

import (
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
	assert.Equal(t, "rules", byPack["standard"].ExportMode)
	assertACLExportContains(t, byPack["standard"], "NAS-Filter-Rule", "permit in tcp from any to any 443 log")
	assertACLExportContains(t, byPack["cisco"], "Cisco-In-ACL", "guest-in")
	assertACLExportContains(t, byPack["cisco"], "Cisco-Out-ACL", "guest-out")
	assertACLExportContains(t, byPack["cisco"], "Cisco-AVPair", "ip:inacl#1=permit tcp any any eq 443 log")
	assertACLExportContains(t, byPack["cisco"], "Cisco-AVPair", "ip:outacl#1=deny udp any 10.0.0.0/24 eq 53")
	assertACLExportContains(t, byPack["aruba"], "Aruba-NAS-Filter-Rule", "permit in tcp from any to any 443 log")
	assert.Equal(t, "profile", byPack["mikrotik"].ExportMode)
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
