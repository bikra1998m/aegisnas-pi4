package radius

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	layehradius "layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

const (
	VSACodecSchemaVersion = 1

	defaultVSACodecTypeOctets   = 1
	defaultVSACodecLengthOctets = 1
	maxVendorPayloadLen         = 249
	maxVendorTypeValue          = ^uint32(0)
)

type VendorAttributeFormat struct {
	TypeOctets   int `json:"type_octets"`
	LengthOctets int `json:"length_octets"`
}

type VendorAttributeSpec struct {
	VendorID uint32
	Type     uint32
	OIDPath  []uint32
	WireType string
	HasTag   bool
	Format   VendorAttributeFormat
}

type DecodedVendorAttribute struct {
	VendorID   uint32                `json:"vendor_id"`
	Type       uint32                `json:"type"`
	OIDPath    []uint32              `json:"oid_path,omitempty"`
	WireType   string                `json:"wire_type,omitempty"`
	Value      layehradius.Attribute `json:"-"`
	Raw        layehradius.Attribute `json:"-"`
	HasTag     bool                  `json:"has_tag,omitempty"`
	Tag        byte                  `json:"tag,omitempty"`
	Grouped    bool                  `json:"grouped,omitempty"`
	OuterIndex int                   `json:"outer_index"`
	InnerIndex int                   `json:"inner_index"`
	Format     VendorAttributeFormat `json:"format"`
}

type VSADecodeOptions struct {
	VendorID uint32
	Format   VendorAttributeFormat
	Specs    []VendorAttributeSpec
}

type VSACodecReport struct {
	SchemaVersion    int                     `json:"schema_version"`
	ReleaseProfileID string                  `json:"release_profile_id"`
	SourceRelease    string                  `json:"source_release"`
	SourceSHA256     string                  `json:"source_sha256"`
	Status           string                  `json:"status"`
	Summary          VSACodecSummary         `json:"summary"`
	Limits           VSACodecLimits          `json:"limits"`
	SupportedFormats []VendorAttributeFormat `json:"supported_formats"`
	Notes            []string                `json:"notes,omitempty"`
}

type VSACodecSummary struct {
	SourceAttributeCount   int `json:"source_attribute_count"`
	RuntimeDecoderCount    int `json:"runtime_decoder_count"`
	NumericAttributeCount  int `json:"numeric_attribute_count"`
	OIDAttributeCount      int `json:"oid_attribute_count"`
	GroupedAttributeCount  int `json:"grouped_attribute_count"`
	RepeatedAttributeCount int `json:"repeated_attribute_count"`
	TaggedAttributeCount   int `json:"tagged_attribute_count"`
	CatalogVendorCount     int `json:"catalog_vendor_count"`
	FormattedVendorCount   int `json:"formatted_vendor_count"`
}

type VSACodecLimits struct {
	MaxRADIUSPacketBytes     int `json:"max_radius_packet_bytes"`
	MaxVendorSpecificValue   int `json:"max_vendor_specific_value_bytes"`
	MaxDefaultVendorValue    int `json:"max_default_vendor_value_bytes"`
	MaxGroupedDepth          int `json:"max_grouped_depth"`
	MaxDecodedAttributes     int `json:"max_decoded_attributes"`
	MaxRepeatedValuesPerType int `json:"max_repeated_values_per_type"`
	SupportedTypeOctetsMax   int `json:"supported_type_octets_max"`
	SupportedLengthOctetsMax int `json:"supported_length_octets_max"`
}

func DefaultVendorAttributeFormat() VendorAttributeFormat {
	return VendorAttributeFormat{TypeOctets: defaultVSACodecTypeOctets, LengthOctets: defaultVSACodecLengthOctets}
}

func ParseVendorAttributeFormatOptions(options []string) (VendorAttributeFormat, error) {
	format := DefaultVendorAttributeFormat()
	for _, option := range options {
		option = strings.TrimSpace(strings.TrimSuffix(option, ","))
		if !strings.HasPrefix(strings.ToLower(option), "format=") {
			continue
		}
		parts := strings.Split(strings.TrimPrefix(option, "format="), ",")
		if len(parts) != 2 {
			return VendorAttributeFormat{}, fmt.Errorf("invalid vendor format %q", option)
		}
		typeOctets, err := strconv.Atoi(parts[0])
		if err != nil {
			return VendorAttributeFormat{}, fmt.Errorf("invalid vendor type octets %q", parts[0])
		}
		lengthOctets, err := strconv.Atoi(parts[1])
		if err != nil {
			return VendorAttributeFormat{}, fmt.Errorf("invalid vendor length octets %q", parts[1])
		}
		format = VendorAttributeFormat{TypeOctets: typeOctets, LengthOctets: lengthOctets}
	}
	if err := format.Validate(); err != nil {
		return VendorAttributeFormat{}, err
	}
	return format, nil
}

func (f VendorAttributeFormat) Validate() error {
	switch f.TypeOctets {
	case 1, 2, 4:
	default:
		return fmt.Errorf("vendor type octets must be 1, 2, or 4")
	}
	switch f.LengthOctets {
	case 0, 1, 2:
	default:
		return fmt.Errorf("vendor length octets must be 0, 1, or 2")
	}
	if f.headerLen() > maxVendorPayloadLen {
		return fmt.Errorf("vendor format header exceeds payload limit")
	}
	return nil
}

func (f VendorAttributeFormat) headerLen() int {
	return f.TypeOctets + f.LengthOctets
}

func (f VendorAttributeFormat) normalized() VendorAttributeFormat {
	if err := f.Validate(); err == nil {
		return f
	}
	return DefaultVendorAttributeFormat()
}

func (s VendorAttributeSpec) normalized() VendorAttributeSpec {
	s.Format = s.Format.normalized()
	s.WireType = strings.ToLower(strings.TrimSpace(s.WireType))
	s.OIDPath = normalizeOIDPath(s.Type, s.OIDPath)
	if s.Type == 0 && len(s.OIDPath) > 0 {
		s.Type = s.OIDPath[0]
	}
	return s
}

func DecodeVendorAttributes(packet *layehradius.Packet, opts VSADecodeOptions) ([]DecodedVendorAttribute, []error) {
	if packet == nil {
		return nil, nil
	}
	format := opts.Format.normalized()
	specs := normalizeVendorAttributeSpecs(opts.Specs)
	var out []DecodedVendorAttribute
	var errs []error
	for outerIndex, avp := range packet.Attributes {
		if avp.Type != rfc2865.VendorSpecific_Type {
			continue
		}
		vendorID, payload, err := layehradius.VendorSpecific(avp.Attribute)
		if err != nil {
			errs = append(errs, fmt.Errorf("vendor-specific attribute %d: %w", outerIndex, err))
			continue
		}
		if opts.VendorID > 0 && vendorID != opts.VendorID {
			continue
		}
		vendorFormat := formatForVendor(specs, vendorID, format)
		decoded, decodeErrs := decodeVendorPayload(vendorID, payload, vendorFormat, specs, outerIndex, false, nil, 0)
		out = append(out, decoded...)
		errs = append(errs, decodeErrs...)
	}
	return out, errs
}

func LookupVendorAttributeValues(packet *layehradius.Packet, vendorID uint32, typ uint32) []layehradius.Attribute {
	values := make([]layehradius.Attribute, 0, 2)
	decoded, _ := DecodeVendorAttributes(packet, VSADecodeOptions{VendorID: vendorID})
	for _, attr := range decoded {
		if attr.Grouped || attr.Type != typ {
			continue
		}
		value := make(layehradius.Attribute, len(attr.Value))
		copy(value, attr.Value)
		values = append(values, value)
	}
	return values
}

func LookupVendorAttributeValue(packet *layehradius.Packet, vendorID uint32, typ uint32) (layehradius.Attribute, bool) {
	values := LookupVendorAttributeValues(packet, vendorID, typ)
	if len(values) == 0 {
		return nil, false
	}
	return values[0], true
}

func EncodeVendorAttribute(spec VendorAttributeSpec, value layehradius.Attribute) (layehradius.Attribute, error) {
	spec = spec.normalized()
	if spec.Type == 0 {
		return nil, fmt.Errorf("vendor attribute type is required")
	}
	if spec.Type > maxTypeForOctets(spec.Format.TypeOctets) || spec.Type > maxVendorTypeValue {
		return nil, fmt.Errorf("vendor attribute type %d exceeds %d-octet format", spec.Type, spec.Format.TypeOctets)
	}
	payload := make([]byte, len(value))
	copy(payload, value)
	if spec.HasTag {
		if len(payload) == 0 {
			return nil, fmt.Errorf("tagged vendor attribute requires a value")
		}
		if payload[0] > 31 {
			return nil, fmt.Errorf("vendor attribute tag must be between 0 and 31")
		}
	}
	headerLen := spec.Format.headerLen()
	totalLen := headerLen + len(payload)
	if totalLen > maxVendorPayloadLen {
		return nil, fmt.Errorf("vendor attribute %d too long: %d bytes exceeds %d", spec.Type, totalLen, maxVendorPayloadLen)
	}
	if spec.Format.LengthOctets > 0 && uint32(totalLen) > maxTypeForOctets(spec.Format.LengthOctets) {
		return nil, fmt.Errorf("vendor attribute %d length %d exceeds %d-octet length field", spec.Type, totalLen, spec.Format.LengthOctets)
	}
	out := make(layehradius.Attribute, totalLen)
	writeUint(out[:spec.Format.TypeOctets], spec.Type)
	if spec.Format.LengthOctets > 0 {
		writeUint(out[spec.Format.TypeOctets:headerLen], uint32(totalLen))
	}
	copy(out[headerLen:], payload)
	return out, nil
}

func AddVendorAttributeWithSpec(packet *layehradius.Packet, spec VendorAttributeSpec, value layehradius.Attribute) error {
	if packet == nil {
		return fmt.Errorf("packet is required")
	}
	spec = spec.normalized()
	encoded, err := EncodeVendorAttribute(spec, value)
	if err != nil {
		return err
	}
	vsa, err := layehradius.NewVendorSpecific(spec.VendorID, encoded)
	if err != nil {
		return err
	}
	packet.Add(rfc2865.VendorSpecific_Type, vsa)
	return nil
}

func BuildVSACodecReport(registry *productconfigs.AttributeRegistry, catalog productconfigs.VendorDictionaryCatalog) VSACodecReport {
	if registry == nil {
		registry = productconfigs.MustBuiltInAttributeRegistry()
	}
	summary := VSACodecSummary{
		SourceAttributeCount:   registry.SourceAttributeCount,
		RuntimeDecoderCount:    len(registry.RuntimeMappings()),
		RepeatedAttributeCount: registry.AttributeCount,
	}
	for _, entry := range registry.Entries {
		if entry.Number > 0 {
			summary.NumericAttributeCount++
		}
		if len(entry.OIDPath) > 1 || strings.TrimSpace(entry.OID) != "" {
			summary.OIDAttributeCount++
		}
		if entry.WireCodec.Grouped {
			summary.GroupedAttributeCount++
		}
		if entry.WireCodec.Tagged {
			summary.TaggedAttributeCount++
		}
	}
	summary.CatalogVendorCount = len(catalog.Vendors)
	for _, vendor := range catalog.Vendors {
		format, err := ParseVendorAttributeFormatOptions(vendor.Options)
		if err == nil && format != DefaultVendorAttributeFormat() {
			summary.FormattedVendorCount++
		}
	}
	return VSACodecReport{
		SchemaVersion:    VSACodecSchemaVersion,
		ReleaseProfileID: registry.ReleaseProfileID,
		SourceRelease:    registry.SourceRelease,
		SourceSHA256:     registry.SourceSHA256,
		Status:           "ready",
		Summary:          summary,
		Limits: VSACodecLimits{
			MaxRADIUSPacketBytes:     layehradius.MaxPacketLength,
			MaxVendorSpecificValue:   maxVendorPayloadLen,
			MaxDefaultVendorValue:    maxVendorPayloadLen - DefaultVendorAttributeFormat().headerLen(),
			MaxGroupedDepth:          4,
			MaxDecodedAttributes:     4096,
			MaxRepeatedValuesPerType: 256,
			SupportedTypeOctetsMax:   4,
			SupportedLengthOctetsMax: 2,
		},
		SupportedFormats: []VendorAttributeFormat{
			{TypeOctets: 1, LengthOctets: 0}, {TypeOctets: 1, LengthOctets: 1}, {TypeOctets: 1, LengthOctets: 2},
			{TypeOctets: 2, LengthOctets: 0}, {TypeOctets: 2, LengthOctets: 1}, {TypeOctets: 2, LengthOctets: 2},
			{TypeOctets: 4, LengthOctets: 0}, {TypeOctets: 4, LengthOctets: 1}, {TypeOctets: 4, LengthOctets: 2},
		},
		Notes: []string{
			"Software codec readiness is separate from real vendor hardware certification.",
			"Grouped telecom, WiMAX, and charging semantics remain owned by later domain features.",
		},
	}
}

func decodeVendorPayload(vendorID uint32, payload layehradius.Attribute, format VendorAttributeFormat, specs []VendorAttributeSpec, outerIndex int, grouped bool, parentOID []uint32, depth int) ([]DecodedVendorAttribute, []error) {
	if depth > 4 {
		return nil, []error{fmt.Errorf("vendor %d grouped VSA exceeds maximum depth", vendorID)}
	}
	if err := format.Validate(); err != nil {
		return nil, []error{err}
	}
	var out []DecodedVendorAttribute
	var errs []error
	offset := 0
	innerIndex := 0
	for offset < len(payload) {
		if len(payload[offset:]) < format.headerLen() {
			errs = append(errs, fmt.Errorf("vendor %d VSA at offset %d is shorter than %d-byte header", vendorID, offset, format.headerLen()))
			return out, errs
		}
		typ := readUint(payload[offset : offset+format.TypeOctets])
		length := len(payload) - offset
		if format.LengthOctets > 0 {
			length = int(readUint(payload[offset+format.TypeOctets : offset+format.headerLen()]))
			if length < format.headerLen() {
				errs = append(errs, fmt.Errorf("vendor %d type %d has invalid length %d", vendorID, typ, length))
				return out, errs
			}
			if length > len(payload[offset:]) {
				errs = append(errs, fmt.Errorf("vendor %d type %d length %d exceeds remaining %d", vendorID, typ, length, len(payload[offset:])))
				return out, errs
			}
		}
		raw := append(layehradius.Attribute(nil), payload[offset:offset+length]...)
		value := append(layehradius.Attribute(nil), raw[format.headerLen():]...)
		spec := firstSpecForType(specs, vendorID, typ, parentOID)
		hasTag := spec.HasTag
		tag := byte(0)
		if hasTag {
			var tagErr error
			tag, value, tagErr = splitTaggedValue(value)
			if tagErr != nil {
				errs = append(errs, fmt.Errorf("vendor %d type %d: %w", vendorID, typ, tagErr))
				return out, errs
			}
		}
		oid := appendOID(parentOID, typ)
		if len(spec.OIDPath) > 0 {
			oid = append([]uint32(nil), spec.OIDPath...)
		}
		record := DecodedVendorAttribute{
			VendorID: vendorID, Type: typ, OIDPath: oid, WireType: spec.WireType,
			Value: value, Raw: raw, HasTag: hasTag, Tag: tag, Grouped: grouped,
			OuterIndex: outerIndex, InnerIndex: innerIndex, Format: format,
		}
		out = append(out, record)
		if shouldDecodeGrouped(record, specs) {
			children, childErrs := decodeVendorPayload(vendorID, value, DefaultVendorAttributeFormat(), specs, outerIndex, true, oid, depth+1)
			out = append(out, children...)
			errs = append(errs, childErrs...)
		}
		offset += length
		innerIndex++
		if format.LengthOctets == 0 {
			break
		}
	}
	return out, errs
}

func normalizeVendorAttributeSpecs(specs []VendorAttributeSpec) []VendorAttributeSpec {
	out := make([]VendorAttributeSpec, 0, len(specs))
	for _, spec := range specs {
		spec = spec.normalized()
		if spec.VendorID == 0 || spec.Type == 0 {
			continue
		}
		out = append(out, spec)
	}
	return out
}

func formatForVendor(specs []VendorAttributeSpec, vendorID uint32, fallback VendorAttributeFormat) VendorAttributeFormat {
	for _, spec := range specs {
		if spec.VendorID == vendorID {
			return spec.Format.normalized()
		}
	}
	return fallback.normalized()
}

func firstSpecForType(specs []VendorAttributeSpec, vendorID, typ uint32, parentOID []uint32) VendorAttributeSpec {
	for _, spec := range specs {
		if spec.VendorID != vendorID || spec.Type != typ {
			continue
		}
		if len(parentOID) > 0 {
			if hasOIDPrefix(spec.OIDPath, parentOID) {
				return spec
			}
			continue
		}
		if len(spec.OIDPath) <= 1 {
			return spec
		}
	}
	return VendorAttributeSpec{VendorID: vendorID, Type: typ, Format: DefaultVendorAttributeFormat()}
}

func shouldDecodeGrouped(record DecodedVendorAttribute, specs []VendorAttributeSpec) bool {
	if len(record.Value) == 0 || strings.EqualFold(record.WireType, "string") {
		return false
	}
	if record.WireType == "tlv" || record.WireType == "group" || record.WireType == "struct" || record.WireType == "vsa" || record.WireType == "vendor" {
		return true
	}
	for _, spec := range specs {
		if spec.VendorID != record.VendorID || len(spec.OIDPath) <= len(record.OIDPath) {
			continue
		}
		if hasOIDPrefix(spec.OIDPath, record.OIDPath) {
			return true
		}
	}
	return false
}

func splitTaggedValue(value layehradius.Attribute) (byte, layehradius.Attribute, error) {
	if len(value) == 0 {
		return 0, nil, fmt.Errorf("tagged value is empty")
	}
	tag := value[0]
	if tag > 31 {
		return 0, nil, fmt.Errorf("tag %d is outside the RADIUS tag range 0..31", tag)
	}
	out := make(layehradius.Attribute, len(value)-1)
	copy(out, value[1:])
	return tag, out, nil
}

func normalizeOIDPath(typ uint32, oid []uint32) []uint32 {
	if len(oid) == 0 {
		if typ == 0 {
			return nil
		}
		return []uint32{typ}
	}
	out := make([]uint32, 0, len(oid))
	for _, value := range oid {
		if value == 0 {
			return nil
		}
		out = append(out, value)
	}
	return out
}

func appendOID(parent []uint32, typ uint32) []uint32 {
	out := make([]uint32, 0, len(parent)+1)
	out = append(out, parent...)
	out = append(out, typ)
	return out
}

func hasOIDPrefix(oid, prefix []uint32) bool {
	if len(prefix) == 0 || len(prefix) > len(oid) {
		return false
	}
	for idx := range prefix {
		if oid[idx] != prefix[idx] {
			return false
		}
	}
	return true
}

func readUint(value []byte) uint32 {
	switch len(value) {
	case 1:
		return uint32(value[0])
	case 2:
		return uint32(binary.BigEndian.Uint16(value))
	case 4:
		return binary.BigEndian.Uint32(value)
	default:
		var out uint32
		for _, b := range value {
			out = (out << 8) | uint32(b)
		}
		return out
	}
}

func writeUint(dst []byte, value uint32) {
	switch len(dst) {
	case 1:
		dst[0] = byte(value)
	case 2:
		binary.BigEndian.PutUint16(dst, uint16(value))
	case 4:
		binary.BigEndian.PutUint32(dst, value)
	default:
		for idx := len(dst) - 1; idx >= 0; idx-- {
			dst[idx] = byte(value)
			value >>= 8
		}
	}
}

func maxTypeForOctets(octets int) uint32 {
	switch octets {
	case 1:
		return 255
	case 2:
		return 65535
	default:
		return maxVendorTypeValue
	}
}
