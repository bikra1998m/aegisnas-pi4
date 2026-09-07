package configs

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildMikroTikPackReportCertifiesPinnedRows(t *testing.T) {
	report, err := BuildMikroTikPackReport()
	require.NoError(t, err)
	require.NoError(t, ValidateMikroTikPackReport(report))

	assert.Equal(t, MikroTikPackFeatureID, report.FeatureID)
	assert.Equal(t, MikroTikPackExpectedAttributeCount, report.Summary.AttributeCount)
	assert.Equal(t, MikroTikPackExpectedAttributeCount, report.Summary.SoftwareCertifiedMappings)
	assert.Equal(t, MikroTikPackExpectedAttributeCount, report.Summary.ExternalRequiredMappings)
	assert.Equal(t, 1, report.Summary.VendorCount)
	assert.Equal(t, 3, report.Summary.SensitiveRedactedMappings)
	assert.Equal(t, float64(100), report.Summary.SoftwareCompletionPercent)
	assert.NotEmpty(t, report.Summary.Fingerprint)
	require.Len(t, report.Records, MikroTikPackExpectedAttributeCount)
	require.GreaterOrEqual(t, len(report.Grammar), 13)
	require.GreaterOrEqual(t, len(report.ProductScopes), 10)

	require.Len(t, report.VendorSummaries, 1)
	assert.Equal(t, "Mikrotik", report.VendorSummaries[0].Vendor)
	assert.Equal(t, uint32(14988), report.VendorSummaries[0].PEN)
	assert.Equal(t, MikroTikPackExpectedAttributeCount, report.VendorSummaries[0].SoftwareCertifiedMappings)

	scopeLabels := map[string]bool{}
	for _, scope := range report.ProductScopes {
		scopeLabels[scope.Label] = true
	}
	assert.True(t, scopeLabels["RouterOS PPP And PPPoE Profiles"])
	assert.True(t, scopeLabels["RouterOS Simple Queues And Rate Limits"])
	assert.True(t, scopeLabels["RouterOS Firewall Address Lists"])
	assert.True(t, scopeLabels["CAPsMAN Wireless Authorization"])
	assert.True(t, scopeLabels["Shared RouterOS CoA And Disconnect"])
}

func TestMikroTikPackReportClassifiesRouterOSAttributes(t *testing.T) {
	report, err := BuildMikroTikPackReport()
	require.NoError(t, err)

	records := map[string]MikroTikAttributeRecord{}
	for _, record := range report.Records {
		records[record.Attribute] = record
	}

	rate := records["Mikrotik-Rate-Limit"]
	assert.Equal(t, "mikrotik_rate_quota_queue", rate.Capability)
	assert.Contains(t, rate.Semantic, VendorSemanticBandwidthProfile)
	assert.Contains(t, rate.Semantic, VendorSemanticDownloadBandwidth)
	assert.Contains(t, rate.Semantic, VendorSemanticUploadBandwidth)
	assert.Contains(t, rate.PacketProcessing, "rate_grammar")

	addressList := records["Mikrotik-Address-List"]
	assert.Equal(t, "mikrotik_acl_firewall_policy", addressList.Capability)
	assert.Equal(t, "policy_parse_compile", addressList.ImplementationClass)
	assert.Contains(t, addressList.Semantic, VendorSemanticDynamicACL)

	switchingFilter := records["Mikrotik-Switching-Filter"]
	assert.Equal(t, "mikrotik_acl_firewall_policy", switchingFilter.Capability)
	assert.Contains(t, switchingFilter.Semantic, VendorSemanticACL)

	assert.Equal(t, "redacted_secret_evidence", records["Mikrotik-Wireless-PSK"].ImplementationClass)
	assert.Equal(t, "redacted_secret_evidence", records["Mikrotik-Wireless-Enc-Key"].ImplementationClass)
	assert.Equal(t, "redacted_secret_evidence", records["Mikrotik-Wireless-MPKey"].ImplementationClass)

	assert.Equal(t, uint32(25), records["Mikrotik-DHCP-Option-ParamSTR2"].Number)
	assert.Equal(t, uint32(25), records["Mikrotik-DHCP-Option-Param-STR2"].Number)
	assert.Equal(t, uint32(27), records["Mikrotik-Wireless-VLANIDtype"].Number)
	assert.Equal(t, uint32(27), records["Mikrotik-Wireless-VLANID-Type"].Number)

	registry := MustBuiltInAttributeRegistry()
	vlanType, ok := registry.LookupName("Mikrotik", "Mikrotik-Wireless-VLANID-Type")
	require.True(t, ok)
	assert.Equal(t, "integer_text", vlanType.DecodeKind)
	assert.Contains(t, vlanType.Semantic, VendorSemanticVLAN)

	var sawHotspot bool
	for _, grammar := range report.Grammar {
		if strings.Contains(grammar.Key, "hotspot") {
			sawHotspot = true
			assert.Equal(t, "passed", grammar.ParserState)
			assert.Equal(t, MikroTikExternalRequired, grammar.ExternalState)
		}
	}
	assert.True(t, sawHotspot)
}
