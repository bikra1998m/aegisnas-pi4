package configs

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const ubntExternalDictionaryFixture = `
VENDOR Ubiquiti 41112
BEGIN-VENDOR Ubiquiti
ATTRIBUTE UBNT-Data-Rate-DL 1 integer
ATTRIBUTE UBNT-Data-Rate-UL 3 integer
ATTRIBUTE UBNT-User-Role 10 string
ATTRIBUTE UBNT-PSK 11 octets
VALUE UBNT-User-Role guest 1
VALUE UBNT-User-Role employee 2
END-VENDOR Ubiquiti
`

func TestExternalVendorIntakeGovernanceReport(t *testing.T) {
	report := BuildExternalVendorIntakeGovernanceReport()
	require.NoError(t, ValidateExternalVendorIntakeGovernanceReport(report))

	assert.Equal(t, ExternalVendorIntakeFeatureID, report.FeatureID)
	assert.Equal(t, ExternalVendorIntakeSoftwareReady, report.Status)
	assert.Equal(t, DefaultDictionaryReleaseProfileID, report.DictionaryReleaseProfileID)
	assert.Contains(t, report.RequiredProvenanceFields, "source_sha256")
	assert.Contains(t, report.SupportedDictionaryDirectives, "ATTRIBUTE")
	assert.Contains(t, report.SupportedWireTypes, "integer")
	assert.Equal(t, "docs/nas-0073-release-certification-checklist.md", report.ReleaseCertificationChecklist)
}

func TestExternalVendorIntakeReportSoftwareReady(t *testing.T) {
	req := validExternalVendorIntakeRequest()
	report := BuildExternalVendorIntakeReport(req)
	require.NoError(t, ValidateExternalVendorIntakeReport(report))

	assert.Equal(t, ExternalVendorIntakeFeatureID, report.FeatureID)
	assert.Equal(t, ExternalVendorIntakeSoftwareReady, report.Status)
	assert.Equal(t, "Ubiquiti", report.Vendor.CanonicalName)
	assert.Equal(t, uint32(41112), report.Vendor.PEN)
	assert.True(t, report.Vendor.OutOfCorpus)
	assert.False(t, report.Vendor.InPinnedCorpus)
	assert.True(t, report.Vendor.RuntimeExtensionKnown)
	assert.Equal(t, 4, report.Summary.AttributeCount)
	assert.Equal(t, 4, report.Summary.SoftwareReadyAttributes)
	assert.Equal(t, 4, report.Summary.ExternalCertificationRequirements)
	assert.Equal(t, 2, report.Summary.EnumeratedValueCount)
	assert.Equal(t, 1, report.Summary.SensitiveRedactedMappings)
	assert.NotEmpty(t, report.Summary.Fingerprint)
	assert.Len(t, report.ProductScopes, 3)

	records := map[string]ExternalVendorIntakeAttribute{}
	for _, record := range report.Records {
		records[record.Attribute] = record
		assert.Equal(t, ExternalVendorIntakeSoftwareReady, record.SoftwareState)
		assert.True(t, record.ReadyForExternalValidation)
		assert.True(t, record.ExternalValidationRequired)
		assert.NotEmpty(t, record.PacketProcessing)
		assert.NotEmpty(t, record.PolicyEngine)
		assert.NotEmpty(t, record.Storage)
	}
	assert.Contains(t, records["UBNT-Data-Rate-DL"].Semantic, VendorSemanticDownloadBandwidth)
	assert.Contains(t, records["UBNT-Data-Rate-UL"].Semantic, VendorSemanticUploadBandwidth)
	assert.Contains(t, records["UBNT-User-Role"].Semantic, VendorSemanticRole)
	assert.Equal(t, "redacted_secret_evidence", records["UBNT-PSK"].ImplementationClass)
	assert.Contains(t, records["UBNT-PSK"].Storage, "hash")

	mappings, err := ExternalVendorIntakeRuntimeMappings(report)
	require.NoError(t, err)
	require.Len(t, mappings, 4)
	assert.Equal(t, uint32(41112), mappings[0].VendorID)
	assert.Equal(t, "ubnt", mappings[0].PackKey)
	assert.Contains(t, []string{VendorSemanticDownloadBandwidth, VendorSemanticUploadBandwidth, VendorSemanticRole, VendorSemanticCertificateOnboarding}, mappings[0].Semantic)
}

func TestExternalVendorIntakeRejectsBadProvenanceAndDictionary(t *testing.T) {
	req := validExternalVendorIntakeRequest()
	req.SourceSHA256 = strings.Repeat("0", 64)
	req.LicenseID = "unknown"
	req.RetrievedAt = "not-a-date"
	req.DictionaryText = strings.Replace(req.DictionaryText, "ATTRIBUTE UBNT-Data-Rate-UL 3 integer", "ATTRIBUTE UBNT-Other 1 string", 1)

	report := BuildExternalVendorIntakeReport(req)
	require.Error(t, ValidateExternalVendorIntakeReport(report))
	assert.Equal(t, ExternalVendorIntakeSoftwareBlock, report.Status)
	assert.GreaterOrEqual(t, report.Summary.BlockerCount, 3)
	assert.Contains(t, strings.Join(report.Blockers, "\n"), "source_sha256 does not match")
	assert.Contains(t, strings.Join(report.Blockers, "\n"), "license_id")
	assert.Contains(t, strings.Join(report.Blockers, "\n"), "retrieved_at")
	assert.Contains(t, strings.Join(report.Blockers, "\n"), "share numeric type")
}

func TestExternalVendorIntakeRejectsPinnedCorpusVendor(t *testing.T) {
	dictionary := `
VENDOR Cisco 9
BEGIN-VENDOR Cisco
ATTRIBUTE Cisco-AVPair 1 string
END-VENDOR Cisco
`
	req := validExternalVendorIntakeRequest()
	req.VendorName = "Cisco"
	req.PEN = 9
	req.IntendedPackKey = "external-cisco"
	req.DictionaryName = "dictionary.cisco"
	req.DictionaryText = dictionary
	req.SourceSHA256 = externalVendorFixtureSHA(dictionary)

	report := BuildExternalVendorIntakeReport(req)
	require.Error(t, ValidateExternalVendorIntakeReport(report))
	assert.True(t, report.Vendor.InPinnedCorpus)
	assert.False(t, report.Vendor.OutOfCorpus)
	assert.Equal(t, ExternalVendorIntakeSoftwareBlock, report.Status)
	assert.Contains(t, strings.Join(report.Blockers, "\n"), "already exists in the pinned FreeRADIUS")
}

func validExternalVendorIntakeRequest() ExternalVendorIntakeRequest {
	return ExternalVendorIntakeRequest{
		VendorName:       "UBNT",
		PEN:              41112,
		IntendedPackKey:  "ubnt",
		ProductFamilies:  []string{"UniFi Network", "airMAX"},
		DictionaryName:   "dictionary.ubnt",
		DictionaryText:   ubntExternalDictionaryFixture,
		SourceURL:        "https://ui.com/download/dictionary.ubnt",
		SourceSHA256:     externalVendorFixtureSHA(ubntExternalDictionaryFixture),
		LicenseID:        "Proprietary-Allowed-With-Grant",
		LicenseReference: "https://ui.com/legal",
		UpstreamVersion:  "unifi-network-9",
		RetrievedAt:      "2026-09-08T00:00:00Z",
		Submitter:        "test",
	}
}

func externalVendorFixtureSHA(value string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return hex.EncodeToString(sum[:])
}
