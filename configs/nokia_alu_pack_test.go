package configs

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildNokiaALUPackReportCertifiesPinnedRows(t *testing.T) {
	report, err := BuildNokiaALUPackReport()
	require.NoError(t, err)
	require.NoError(t, ValidateNokiaALUPackReport(report))

	assert.Equal(t, NokiaALUPackFeatureID, report.FeatureID)
	assert.Equal(t, NokiaALUPackExpectedAttributeCount, report.Summary.AttributeCount)
	assert.Equal(t, NokiaALUPackExpectedAttributeCount, report.Summary.SoftwareCertifiedMappings)
	assert.Equal(t, NokiaALUPackExpectedAttributeCount, report.Summary.ExternalRequiredMappings)
	assert.Equal(t, 5, report.Summary.VendorCount)
	assert.GreaterOrEqual(t, report.Summary.SensitiveRedactedMappings, 10)
	assert.Equal(t, float64(100), report.Summary.SoftwareCompletionPercent)
	assert.NotEmpty(t, report.Summary.Fingerprint)
	require.Len(t, report.Records, NokiaALUPackExpectedAttributeCount)
	require.GreaterOrEqual(t, len(report.Grammar), 16)
	require.GreaterOrEqual(t, len(report.ProductScopes), 12)

	byVendor := map[string]NokiaALUVendorSummary{}
	for _, summary := range report.VendorSummaries {
		byVendor[strings.ToLower(summary.Vendor)] = summary
	}
	assert.Equal(t, 15, byVendor["nokia"].AttributeCount)
	assert.Equal(t, 41, byVendor["alcatel"].AttributeCount)
	assert.Equal(t, 33, byVendor["alcatel-esam"].AttributeCount)
	assert.Equal(t, 181, byVendor["alcatel-lucent-service-router"].AttributeCount)
	assert.Equal(t, 64, byVendor["alu-aaa"].AttributeCount)

	scopeLabels := map[string]bool{}
	for _, scope := range report.ProductScopes {
		scopeLabels[scope.Label] = true
	}
	assert.True(t, scopeLabels["Nokia SR OS Service Router"])
	assert.True(t, scopeLabels["Alcatel ESAM VLAN, VRF, QoS, DHCP, And PPPoE"])
	assert.True(t, scopeLabels["Alcatel-Lucent SR OS Route, NAT, IPv6, And DHCPv6"])
	assert.True(t, scopeLabels["ALU-AAA Mobile Auth, Location, Voice, And Event Evidence"])
	assert.True(t, scopeLabels["Shared Nokia/ALU CoA And Disconnect"])
}

func TestNokiaALUPackReportClassifiesServiceRouterFamilies(t *testing.T) {
	report, err := BuildNokiaALUPackReport()
	require.NoError(t, err)

	records := map[string]NokiaALUAttributeRecord{}
	for _, record := range report.Records {
		records[record.Attribute] = record
	}

	assert.Equal(t, "nokia_acl_policy", records["Nokia-AVPair"].Capability)
	assert.Contains(t, records["Nokia-AVPair"].Semantic, VendorSemanticPolicyTag)
	assert.Equal(t, "nokia_subscriber_service", records["Nokia-Service-Name"].Capability)
	assert.Contains(t, strings.Join(records["Nokia-Service-Name"].Notes, " "), "BCD")

	assert.Equal(t, "alcatel_address_route_pool", records["AAT-PPP-Address"].Capability)
	assert.Contains(t, records["AAT-PPP-Address"].Semantic, VendorSemanticIPv4Address)
	assert.Equal(t, "alcatel_qos_sla", records["AAT-Qos"].Capability)
	assert.Contains(t, records["AAT-Qos"].Semantic, VendorSemanticBandwidthProfile)
	assert.Equal(t, "alcatel_acl_policy", records["AAT-Data-Filter"].Capability)
	assert.Contains(t, records["AAT-Data-Filter"].Semantic, VendorSemanticDynamicACL)

	assert.Equal(t, "alcatel_esam_route_vrf", records["A-ESAM-VRF-Name"].Capability)
	assert.Contains(t, records["A-ESAM-VRF-Name"].Semantic, VendorSemanticVRF)
	assert.Equal(t, "alcatel_esam_service_router_state", records["A-ESAM-Vlan-Id"].Capability)
	assert.Contains(t, records["A-ESAM-Vlan-Id"].Semantic, VendorSemanticVLAN)

	assert.Equal(t, "alu_sr_subscriber_service", records["Alc-Subsc-ID-Str"].Capability)
	assert.Contains(t, records["Alc-Subsc-ID-Str"].Semantic, VendorSemanticAccountingIdentity)
	assert.Equal(t, "alu_sr_qos_sla", records["Alc-SLA-Prof-Str"].Capability)
	assert.Contains(t, records["Alc-SLA-Prof-Str"].Semantic, VendorSemanticBandwidthProfile)
	assert.Equal(t, "alu_sr_nat_translation", records["Alc-Nat-Port-Range"].Capability)
	assert.Contains(t, records["Alc-Nat-Port-Range"].Semantic, VendorSemanticTranslationPortBlock)
	assert.Equal(t, "alu_sr_address_route_pool", records["Alc-Delegated-IPv6-Pool"].Capability)
	assert.Contains(t, records["Alc-Delegated-IPv6-Pool"].Semantic, VendorSemanticDelegatedIPv6Prefix)

	assert.Equal(t, "alu_aaa_acl_policy", records["ALU-AAA-Access-Rule"].Capability)
	assert.Contains(t, records["ALU-AAA-Access-Rule"].Semantic, VendorSemanticDynamicACL)
	assert.Equal(t, "redacted_secret_evidence", records["ALU-AAA-GSM-Triplet"].ImplementationClass)
	assert.Contains(t, records["ALU-AAA-GSM-Triplet"].Storage, "no_cleartext_secret")
	assert.Equal(t, "alu_aaa_tenant_location", records["ALU-AAA-Civic-Location"].Capability)
	assert.Contains(t, records["ALU-AAA-Civic-Location"].Semantic, VendorSemanticTenant)

	registry := MustBuiltInAttributeRegistry()
	serviceName, ok := registry.LookupName("Nokia", "Nokia-Service-Name")
	require.True(t, ok)
	assert.Equal(t, "nokia_bcd", serviceName.DecodeKind)
}
