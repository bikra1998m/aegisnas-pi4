package radius

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	layehradius "layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

func TestVSACodecDecodesRepeatedAndPackedAttributes(t *testing.T) {
	packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	require.NoError(t, addVendorString(packet, 424242, 1, "first"))
	require.NoError(t, addVendorString(packet, 424242, 1, "second"))

	one, err := EncodeVendorAttribute(VendorAttributeSpec{VendorID: 424242, Type: 2}, layehradius.Attribute("packed-one"))
	require.NoError(t, err)
	two, err := EncodeVendorAttribute(VendorAttributeSpec{VendorID: 424242, Type: 2}, layehradius.Attribute("packed-two"))
	require.NoError(t, err)
	vsa, err := layehradius.NewVendorSpecific(424242, append(one, two...))
	require.NoError(t, err)
	packet.Add(rfc2865.VendorSpecific_Type, vsa)

	repeated := LookupVendorAttributeValues(packet, 424242, 1)
	require.Len(t, repeated, 2)
	assert.Equal(t, "first", string(repeated[0]))
	assert.Equal(t, "second", string(repeated[1]))

	packed := LookupVendorAttributeValues(packet, 424242, 2)
	require.Len(t, packed, 2)
	assert.Equal(t, "packed-one", string(packed[0]))
	assert.Equal(t, "packed-two", string(packed[1]))
}

func TestVSACodecSupportsTaggedAttributes(t *testing.T) {
	packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	spec := VendorAttributeSpec{VendorID: 424242, Type: 64, WireType: "string", HasTag: true}
	require.NoError(t, AddVendorAttributeWithSpec(packet, spec, layehradius.Attribute{7, 'v', 'o', 'i', 'c', 'e'}))

	decoded, errs := DecodeVendorAttributes(packet, VSADecodeOptions{VendorID: 424242, Specs: []VendorAttributeSpec{spec}})
	require.Empty(t, errs)
	require.Len(t, decoded, 1)
	assert.True(t, decoded[0].HasTag)
	assert.Equal(t, byte(7), decoded[0].Tag)
	assert.Equal(t, "voice", string(decoded[0].Value))
}

func TestVSACodecSupportsMultiOctetVendorFormats(t *testing.T) {
	packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	spec := VendorAttributeSpec{
		VendorID: 424242,
		Type:     300,
		WireType: "octets",
		Format:   VendorAttributeFormat{TypeOctets: 2, LengthOctets: 1},
	}
	require.NoError(t, AddVendorAttributeWithSpec(packet, spec, layehradius.Attribute{0xde, 0xad, 0xbe, 0xef}))

	decoded, errs := DecodeVendorAttributes(packet, VSADecodeOptions{VendorID: 424242, Specs: []VendorAttributeSpec{spec}})
	require.Empty(t, errs)
	require.Len(t, decoded, 1)
	assert.Equal(t, uint32(300), decoded[0].Type)
	assert.Equal(t, []byte{0xde, 0xad, 0xbe, 0xef}, []byte(decoded[0].Value))
}

func TestVSACodecExpandsGroupedOIDAttributes(t *testing.T) {
	packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	parent := VendorAttributeSpec{VendorID: 24757, Type: 37, WireType: "tlv"}
	child := VendorAttributeSpec{VendorID: 24757, Type: 12, OIDPath: []uint32{37, 12}, WireType: "byte"}
	childWire, err := EncodeVendorAttribute(child, layehradius.Attribute{5})
	require.NoError(t, err)
	require.NoError(t, AddVendorAttributeWithSpec(packet, parent, childWire))

	decoded, errs := DecodeVendorAttributes(packet, VSADecodeOptions{VendorID: 24757, Specs: []VendorAttributeSpec{parent, child}})
	require.Empty(t, errs)
	require.Len(t, decoded, 2)
	assert.Equal(t, []uint32{37}, decoded[0].OIDPath)
	assert.Equal(t, []uint32{37, 12}, decoded[1].OIDPath)
	assert.True(t, decoded[1].Grouped)
	assert.Equal(t, []byte{5}, []byte(decoded[1].Value))
}

func TestVSACodecRejectsMalformedLengths(t *testing.T) {
	packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	vsa, err := layehradius.NewVendorSpecific(424242, layehradius.Attribute{1, 9, 'x'})
	require.NoError(t, err)
	packet.Add(rfc2865.VendorSpecific_Type, vsa)

	decoded, errs := DecodeVendorAttributes(packet, VSADecodeOptions{VendorID: 424242})
	assert.Empty(t, decoded)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), "exceeds remaining")
}

func TestVendorAttributeFormatOptions(t *testing.T) {
	format, err := ParseVendorAttributeFormatOptions([]string{"format=2,1"})
	require.NoError(t, err)
	assert.Equal(t, VendorAttributeFormat{TypeOctets: 2, LengthOctets: 1}, format)

	_, err = ParseVendorAttributeFormatOptions([]string{"format=3,1"})
	require.ErrorContains(t, err, "type octets")
}
