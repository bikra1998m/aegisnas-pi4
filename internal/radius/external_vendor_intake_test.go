package radius

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	layehradius "layeh.com/radius"
)

const externalVendorIntakeRadiusDictionaryFixture = `
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

func TestExternalVendorIntakeVSASpecsDecodePacket(t *testing.T) {
	report := productconfigs.BuildExternalVendorIntakeReport(externalVendorIntakeRadiusRequest())
	require.NoError(t, productconfigs.ValidateExternalVendorIntakeReport(report))

	specs, err := ExternalVendorIntakeVSASpecs(report)
	require.NoError(t, err)
	require.Len(t, specs, 4)

	byType := map[uint32]VendorAttributeSpec{}
	for _, spec := range specs {
		assert.Equal(t, uint32(41112), spec.VendorID)
		assert.Equal(t, DefaultVendorAttributeFormat(), spec.Format)
		byType[spec.Type] = spec
	}

	downloadRate := make([]byte, 4)
	binary.BigEndian.PutUint32(downloadRate, 25000000)
	packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	require.NoError(t, AddVendorAttributeWithSpec(packet, byType[1], layehradius.Attribute(downloadRate)))
	require.NoError(t, AddVendorAttributeWithSpec(packet, byType[10], layehradius.Attribute("guest")))
	require.NoError(t, AddVendorAttributeWithSpec(packet, byType[11], layehradius.Attribute{0xde, 0xad, 0xbe, 0xef}))

	decoded, errs := DecodeVendorAttributes(packet, VSADecodeOptions{VendorID: 41112, Specs: specs})
	require.Empty(t, errs)
	require.Len(t, decoded, 3)

	values := map[uint32][]byte{}
	for _, attr := range decoded {
		values[attr.Type] = []byte(attr.Value)
	}
	assert.Equal(t, downloadRate, values[1])
	assert.Equal(t, []byte("guest"), values[10])
	assert.Equal(t, []byte{0xde, 0xad, 0xbe, 0xef}, values[11])
}

func TestExternalVendorIntakeVSASpecsRejectBlockedReport(t *testing.T) {
	req := externalVendorIntakeRadiusRequest()
	req.SourceSHA256 = strings.Repeat("0", 64)
	report := productconfigs.BuildExternalVendorIntakeReport(req)

	specs, err := ExternalVendorIntakeVSASpecs(report)
	require.Error(t, err)
	assert.Empty(t, specs)
}

func externalVendorIntakeRadiusRequest() productconfigs.ExternalVendorIntakeRequest {
	return productconfigs.ExternalVendorIntakeRequest{
		VendorName:       "UBNT",
		PEN:              41112,
		IntendedPackKey:  "ubnt",
		ProductFamilies:  []string{"UniFi Network", "airMAX"},
		DictionaryName:   "dictionary.ubnt",
		DictionaryText:   externalVendorIntakeRadiusDictionaryFixture,
		SourceURL:        "https://ui.com/download/dictionary.ubnt",
		SourceSHA256:     externalVendorIntakeRadiusSHA(externalVendorIntakeRadiusDictionaryFixture),
		LicenseID:        "Proprietary-Allowed-With-Grant",
		LicenseReference: "https://ui.com/legal",
		UpstreamVersion:  "unifi-network-9",
		RetrievedAt:      "2026-09-08T00:00:00Z",
		Submitter:        "radius-test",
	}
}

func externalVendorIntakeRadiusSHA(value string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return hex.EncodeToString(sum[:])
}
