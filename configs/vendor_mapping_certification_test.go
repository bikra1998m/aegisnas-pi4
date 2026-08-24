package configs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVendorMappingCertificationReportCertifiesAuditPartialBaseline(t *testing.T) {
	report, err := BuildVendorMappingCertificationReport(
		AegisNASVendorDictionaryCatalog(),
		AegisNASVendorCompatibilityPacks(),
		DefaultVendorCompatibilityPackKeys(),
	)
	require.NoError(t, err)
	require.NoError(t, ValidateVendorMappingCertificationReport(report))

	assert.Equal(t, VendorMappingCertificationSchemaVersion, report.SchemaVersion)
	assert.Equal(t, DefaultDictionaryReleaseProfileID, report.ReleaseProfileID)
	assert.Equal(t, FreeRADIUSRegistryRelease, report.SourceRelease)
	assert.Equal(t, VendorMappingCertificationBaselineCount, report.BaselinePartialMappings)
	assert.Equal(t, VendorMappingCertificationBaselineCount, report.Summary.BaselinePartialMappings)
	assert.Equal(t, VendorMappingCertificationBaselineCount, report.Summary.CertifiedMappings)
	assert.Equal(t, VendorMappingCertificationBaselineCount, report.Summary.ReadyForExternalMappings)
	assert.Equal(t, VendorMappingCertificationBaselineCount, report.Summary.ExternalRequiredMappings)
	assert.Zero(t, report.Summary.SoftwareBlockedMappings)
	assert.Equal(t, 28, report.Summary.VendorCount)
	assert.Equal(t, float64(100), report.Summary.SoftwareCompletionPercent)
	assert.NotEmpty(t, report.Summary.Fingerprint)
	assert.Len(t, report.SourceSHA256, 64)
	require.Len(t, report.Records, VendorMappingCertificationBaselineCount)

	for _, record := range report.Records {
		assert.Equal(t, VendorMappingCertificationStateReady, record.SoftwareState, record.ID)
		assert.True(t, record.SoftwareCertified, record.ID)
		assert.True(t, record.ReadyForExternalValidation, record.ID)
		assert.Equal(t, EvidenceCertificationRequired, record.CertificationState, record.ID)
		assert.Equal(t, EvidenceClaimSoftwareReadyExternalNeeded, record.ClaimState, record.ID)
		assert.Empty(t, record.Blockers, record.ID)
	}
}

func TestVendorMappingCertificationDimensionsCoverRepresentativeCapabilities(t *testing.T) {
	report, err := BuildVendorMappingCertificationReport(
		AegisNASVendorDictionaryCatalog(),
		AegisNASVendorCompatibilityPacks(),
		[]string{VendorPackStandard, VendorPackAruba, VendorPackCisco, VendorPackCambium, VendorPackAerohive},
	)
	require.NoError(t, err)

	cases := map[string][]string{
		"Aruba:Aruba-User-Role":                   {"dictionary_metadata=passed", "packet_processing=passed", "reply_render=passed", "policy_wiring=passed", "external_certification=external_required"},
		"Cambium:Cambium-Acct-Input-Octets":       {"packet_processing=passed", "reply_render=not_applicable", "enforcement_wiring=passed"},
		"Aerohive:Extreme-Client-Monitor-Problem": {"packet_processing=passed", "reply_render=not_applicable", "enforcement_wiring=passed"},
		"Cisco:Cisco-AVPair":                      {"packet_processing=passed", "reply_render=passed", "enforcement_wiring=passed"},
	}
	for key, expected := range cases {
		record := findVendorMappingCertificationRecord(t, report, key)
		states := vendorMappingCertificationDimensionStates(record)
		for _, item := range expected {
			assert.Contains(t, states, item, key)
		}
	}
}

func TestValidateVendorMappingCertificationRejectsIncompleteReports(t *testing.T) {
	report, err := BuildVendorMappingCertificationReport(
		AegisNASVendorDictionaryCatalog(),
		AegisNASVendorCompatibilityPacks(),
		DefaultVendorCompatibilityPackKeys(),
	)
	require.NoError(t, err)
	report.Records[0].SoftwareState = VendorMappingCertificationStateBlocked
	report.Records[0].SoftwareCertified = false
	report.Summary.CertifiedMappings--
	report.Summary.SoftwareBlockedMappings++

	require.ErrorContains(t, ValidateVendorMappingCertificationReport(report), "software coverage is incomplete")
}

func findVendorMappingCertificationRecord(t *testing.T, report VendorMappingCertificationReport, key string) VendorMappingCertificationRecord {
	t.Helper()
	for _, record := range report.Records {
		if record.Vendor+":"+record.Attribute == key {
			return record
		}
	}
	t.Fatalf("vendor mapping certification record %s not found", key)
	return VendorMappingCertificationRecord{}
}

func vendorMappingCertificationDimensionStates(record VendorMappingCertificationRecord) []string {
	out := make([]string, 0, len(record.Dimensions))
	for _, dim := range record.Dimensions {
		out = append(out, dim.Key+"="+dim.State)
	}
	return out
}
