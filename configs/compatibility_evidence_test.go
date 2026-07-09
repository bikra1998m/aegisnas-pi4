package configs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompatibilityEvidenceReportSeparatesSoftwareAndCertification(t *testing.T) {
	catalog := MergeVendorDictionaryCatalogs("test", AegisNASVendorDictionaryCatalog(), ParseVendorDictionaryCatalog("dictionary.cisco", `
VENDOR Cisco 9
BEGIN-VENDOR Cisco
ATTRIBUTE Cisco-In-ACL 57 string
ATTRIBUTE Cisco-Out-ACL 58 string
ATTRIBUTE Cisco-AVPair 1 string
END-VENDOR Cisco
`))
	report := BuildCompatibilityEvidenceReport(catalog, AegisNASVendorCompatibilityPacks(), []string{VendorPackStandard, VendorPackAegisNAS, VendorPackCisco})
	require.NoError(t, ValidateCompatibilityEvidenceReport(report))
	assert.Equal(t, CompatibilityEvidenceSchemaVersion, report.SchemaVersion)
	assert.Equal(t, DefaultDictionaryReleaseProfileID, report.ReleaseProfileID)
	assert.Greater(t, report.Summary.TotalRecords, 100)
	assert.Greater(t, report.Summary.SoftwareReadyCount, 0)
	assert.Greater(t, report.Summary.ExternalRequiredCount, 0)
	assert.Zero(t, report.Summary.ExternallyCertifiedCount)

	var ciscoAVPair CompatibilityEvidenceRecord
	for _, record := range report.Records {
		if record.PackKey == VendorPackCisco && record.Attribute == "Cisco-AVPair" {
			ciscoAVPair = record
			break
		}
	}
	require.NotEmpty(t, ciscoAVPair.ID)
	assert.True(t, ciscoAVPair.Active)
	assert.Equal(t, EvidenceSoftwareStateReady, ciscoAVPair.SoftwareState)
	assert.Equal(t, EvidenceCertificationRequired, ciscoAVPair.CertificationState)
	assert.Equal(t, EvidenceClaimSoftwareReadyExternalNeeded, ciscoAVPair.ClaimState)
	assert.True(t, ciscoAVPair.ReadyForExternal)
	assert.Contains(t, evidenceDimensionStates(ciscoAVPair), "external_certification=external_required")
}

func TestCompatibilityEvidenceBlocksActiveMissingDictionary(t *testing.T) {
	report := BuildCompatibilityEvidenceReport(AegisNASVendorDictionaryCatalog(), AegisNASVendorCompatibilityPacks(), []string{VendorPackAruba})
	require.NoError(t, ValidateCompatibilityEvidenceReport(report))

	var blockedActive int
	for _, record := range report.Records {
		if record.Active && record.SoftwareState == EvidenceSoftwareStateBlocked {
			blockedActive++
		}
	}
	assert.Greater(t, blockedActive, 0)
}

func TestSemanticEvidenceUsesProductOwnedClaims(t *testing.T) {
	semantics := AttachSemanticEvidence(AegisNASSemanticRegistry())
	require.NotEmpty(t, semantics)
	for _, semantic := range semantics {
		if semantic.Key == VendorSemanticRole {
			assert.Equal(t, EvidenceSoftwareStateReady, semantic.Evidence.SoftwareState)
			assert.Equal(t, EvidenceCertificationNotRequired, semantic.Evidence.CertificationState)
			return
		}
	}
	t.Fatal("role semantic not found")
}

func evidenceDimensionStates(record CompatibilityEvidenceRecord) []string {
	out := make([]string, 0, len(record.Dimensions))
	for _, dim := range record.Dimensions {
		out = append(out, dim.Key+"="+dim.State)
	}
	return out
}
