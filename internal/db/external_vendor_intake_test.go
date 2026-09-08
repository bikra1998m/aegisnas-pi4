package db

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
)

func TestExternalVendorIntakeEventLifecycle(t *testing.T) {
	require.NoError(t, Init(":memory:"))
	DB.SetMaxOpenConns(1)
	t.Cleanup(func() { Close() })
	require.NoError(t, Migrate())

	var tableCount int
	require.NoError(t, DB.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='external_vendor_intake_events'").Scan(&tableCount))
	assert.Equal(t, 1, tableCount)

	report := productconfigs.BuildExternalVendorIntakeReport(externalVendorIntakeDBFixtureRequest())
	require.NoError(t, productconfigs.ValidateExternalVendorIntakeReport(report))

	eventID, err := RecordExternalVendorIntakeEvent(ExternalVendorIntakeEventInput{
		Operation:                  "record",
		Status:                     "recorded",
		ReleaseProfileID:           report.DictionaryReleaseProfileID,
		ReleaseSourceSHA256:        report.SourceSHA256,
		VendorName:                 report.Vendor.CanonicalName,
		PEN:                        report.Vendor.PEN,
		PackKey:                    report.Vendor.IntendedPackKey,
		DictionaryName:             report.Vendor.DictionaryName,
		SourceURL:                  report.Provenance.SourceURL,
		DictionarySHA256:           report.Provenance.ComputedSHA256,
		LicenseID:                  report.Provenance.LicenseID,
		LicenseState:               report.Provenance.LicenseState,
		ProvenanceState:            report.Provenance.ProvenanceState,
		PENState:                   report.Provenance.PENState,
		SemanticState:              report.Provenance.SemanticState,
		AttributeCount:             report.Summary.AttributeCount,
		RuntimeDecodableAttributes: report.Summary.RuntimeDecodableAttributes,
		MetadataOnlyAttributes:     report.Summary.MetadataOnlyAttributes,
		NativeSemanticMappings:     report.Summary.NativeSemanticMappings,
		TypedPassthroughMappings:   report.Summary.TypedPassthroughMappings,
		SensitiveRedactedMappings:  report.Summary.SensitiveRedactedMappings,
		SoftwareReadyAttributes:    report.Summary.SoftwareReadyAttributes,
		SoftwareBlockedAttributes:  report.Summary.SoftwareBlockedAttributes,
		ExternalRequiredAttributes: report.Summary.ExternalCertificationRequirements,
		Fingerprint:                report.Summary.Fingerprint,
		SummaryJSON:                `{"attribute_count":4}`,
		ReportJSON:                 `{"feature_id":"NAS-0073"}`,
		Actor:                      "ops",
	})
	require.NoError(t, err)
	assert.Contains(t, eventID, "nas-0073-")

	events, err := ListExternalVendorIntakeEvents(5)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "ops", events[0].Actor)
	assert.Equal(t, "Ubiquiti", events[0].VendorName)
	assert.Equal(t, uint32(41112), events[0].PEN)
	assert.Equal(t, report.Summary.Fingerprint, events[0].Fingerprint)

	summary, err := GetExternalVendorIntakeSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TotalEvents)
	assert.Equal(t, 1, summary.RecordedCount)
	assert.Equal(t, report.Summary.Fingerprint, summary.LastFingerprint)
	assert.Equal(t, "Ubiquiti", summary.LastVendorName)
	assert.Equal(t, uint32(41112), summary.LastPEN)
	assert.Equal(t, 4, summary.LastAttributeCount)
	assert.Equal(t, 4, summary.LastSoftwareReadyAttributes)
	assert.Equal(t, 4, summary.LastExternalRequiredAttributes)
}

func externalVendorIntakeDBFixtureRequest() productconfigs.ExternalVendorIntakeRequest {
	dictionary := `
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
	return productconfigs.ExternalVendorIntakeRequest{
		VendorName:       "UBNT",
		PEN:              41112,
		IntendedPackKey:  "ubnt",
		ProductFamilies:  []string{"UniFi Network"},
		DictionaryName:   "dictionary.ubnt",
		DictionaryText:   dictionary,
		SourceURL:        "https://ui.com/download/dictionary.ubnt",
		SourceSHA256:     externalVendorIntakeDBFixtureSHA(dictionary),
		LicenseID:        "Proprietary-Allowed-With-Grant",
		LicenseReference: "https://ui.com/legal",
		UpstreamVersion:  "unifi-network-9",
		RetrievedAt:      "2026-09-08T00:00:00Z",
	}
}

func externalVendorIntakeDBFixtureSHA(value string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return hex.EncodeToString(sum[:])
}
