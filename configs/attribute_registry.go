package configs

import (
	"crypto/sha256"
	_ "embed"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const (
	AttributeRegistrySchemaVersion = 1
	FreeRADIUSRegistryRelease      = "3.2.8"
	FreeRADIUSRegistryFileCount    = 246
)

//go:generate go run ../cmd/aegis-attribute-registry-gen -input ../docs/freeradius-3.2.8-vsa-audit.csv -output attribute_registry/freeradius-3.2.8-vsa-audit.csv
//go:embed attribute_registry/freeradius-3.2.8-vsa-audit.csv
var freeRADIUSRegistryCSV []byte

type AttributeRegistry struct {
	SchemaVersion        int                      `json:"schema_version"`
	ReleaseProfileID     string                   `json:"release_profile_id"`
	SourceRelease        string                   `json:"source_release"`
	SourceFileCount      int                      `json:"source_file_count"`
	SourceSHA256         string                   `json:"source_sha256"`
	VendorCount          int                      `json:"vendor_count"`
	SourceAttributeCount int                      `json:"source_attribute_count"`
	AttributeCount       int                      `json:"attribute_count"`
	MappedCount          int                      `json:"mapped_count"`
	Entries              []AttributeRegistryEntry `json:"entries"`
	byName               map[string]int
	byWire               map[string][]int
}

type AttributeRegistryEntry struct {
	Source             string             `json:"source"`
	Key                string             `json:"key"`
	WireKey            string             `json:"wire_key"`
	ReleaseProfileID   string             `json:"release_profile_id"`
	Vendor             string             `json:"vendor"`
	PEN                uint32             `json:"pen"`
	Attribute          string             `json:"attribute"`
	Number             uint32             `json:"number,omitempty"`
	OID                string             `json:"oid,omitempty"`
	OIDPath            []uint32           `json:"oid_path,omitempty"`
	WireType           string             `json:"wire_type"`
	WireCodec          AttributeWireCodec `json:"wire_codec"`
	EnumeratedValues   int                `json:"enumerated_values,omitempty"`
	CapabilityFamily   string             `json:"capability_family"`
	DictionaryStatus   string             `json:"dictionary_status"`
	PackKey            string             `json:"pack_key,omitempty"`
	Semantic           string             `json:"semantic,omitempty"`
	SemanticProvenance string             `json:"semantic_provenance,omitempty"`
	Directions         []string           `json:"directions,omitempty"`
	Functionality      string             `json:"functionality,omitempty"`
	DecodeKind         string             `json:"decode_kind,omitempty"`
	DecodeSemantic     string             `json:"decode_semantic,omitempty"`
	DecodeScale        int                `json:"decode_scale,omitempty"`
}

type AttributeWireCodec struct {
	TypeOctets   int      `json:"type_octets"`
	LengthOctets int      `json:"length_octets"`
	OIDPath      []uint32 `json:"oid_path,omitempty"`
	Repeated     bool     `json:"repeated"`
	Grouped      bool     `json:"grouped"`
	Tagged       bool     `json:"tagged"`
	Extended     bool     `json:"extended"`
}

type AttributeRuntimeMapping struct {
	PackKey   string
	VendorID  uint32
	Type      byte
	Attribute string
	Semantic  string
	Kind      string
	Scale     int
}

var (
	builtInAttributeRegistryOnce sync.Once
	builtInAttributeRegistry     *AttributeRegistry
	builtInAttributeRegistryErr  error
)

func BuiltInAttributeRegistry() (*AttributeRegistry, error) {
	builtInAttributeRegistryOnce.Do(func() {
		builtInAttributeRegistry, builtInAttributeRegistryErr = ParseAttributeRegistryCSV(freeRADIUSRegistryCSV)
	})
	return builtInAttributeRegistry, builtInAttributeRegistryErr
}

func MustBuiltInAttributeRegistry() *AttributeRegistry {
	registry, err := BuiltInAttributeRegistry()
	if err != nil {
		panic(err)
	}
	return registry
}

func ParseAttributeRegistryCSV(payload []byte) (*AttributeRegistry, error) {
	digest := sha256.Sum256(payload)
	registry := &AttributeRegistry{
		SchemaVersion:    AttributeRegistrySchemaVersion,
		ReleaseProfileID: DefaultDictionaryReleaseProfileID,
		SourceRelease:    FreeRADIUSRegistryRelease,
		SourceFileCount:  FreeRADIUSRegistryFileCount,
		SourceSHA256:     hex.EncodeToString(digest[:]),
		byName:           map[string]int{},
		byWire:           map[string][]int{},
	}

	reader := csv.NewReader(strings.NewReader(string(payload)))
	reader.FieldsPerRecord = 13
	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("read attribute registry header: %w", err)
	}
	expected := []string{"Vendor", "PEN", "Attribute", "Number", "OID", "Type", "EnumeratedValues", "CapabilityFamily", "Status", "Pack", "Semantic", "Direction", "Functionality"}
	if strings.Join(header, "\x00") != strings.Join(expected, "\x00") {
		return nil, fmt.Errorf("attribute registry has an unsupported header")
	}

	vendors := map[string]struct{}{}
	for line := 2; ; line++ {
		record, readErr := reader.Read()
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("read attribute registry line %d: %w", line, readErr)
		}
		entry, parseErr := parseAttributeRegistryRecord(record)
		if parseErr != nil {
			return nil, fmt.Errorf("parse attribute registry line %d: %w", line, parseErr)
		}
		nameKey := attributeRegistryNameKey(entry.Vendor, entry.Attribute)
		if _, exists := registry.byName[nameKey]; exists {
			return nil, fmt.Errorf("attribute registry line %d duplicates %s/%s", line, entry.Vendor, entry.Attribute)
		}
		registry.addEntry(entry)
		vendors[strings.ToLower(entry.Vendor)+"\x00"+strconv.FormatUint(uint64(entry.PEN), 10)] = struct{}{}
	}
	if len(registry.Entries) == 0 {
		return nil, fmt.Errorf("attribute registry is empty")
	}
	registry.SourceAttributeCount = len(registry.Entries)
	registry.applyRuntimeAnnotations(vendors)
	registry.VendorCount = len(vendors)
	registry.AttributeCount = len(registry.Entries)
	return registry, nil
}

func parseAttributeRegistryRecord(record []string) (AttributeRegistryEntry, error) {
	pen, err := strconv.ParseUint(strings.TrimSpace(record[1]), 10, 32)
	if err != nil || pen == 0 {
		return AttributeRegistryEntry{}, fmt.Errorf("invalid PEN %q", record[1])
	}
	number, err := parseOptionalUint32(record[3])
	if err != nil {
		return AttributeRegistryEntry{}, fmt.Errorf("invalid attribute number %q", record[3])
	}
	enums, err := parseOptionalInt(record[6])
	if err != nil {
		return AttributeRegistryEntry{}, fmt.Errorf("invalid enumerated value count %q", record[6])
	}
	vendor := NormalizeDictionaryVendorName(DefaultDictionaryReleaseProfileID, record[0])
	attribute := NormalizeDictionaryAttributeName(DefaultDictionaryReleaseProfileID, vendor, record[2])
	wireType := strings.ToLower(strings.TrimSpace(record[5]))
	status := strings.ToLower(strings.TrimSpace(record[8]))
	if vendor == "" || attribute == "" || !ValidVendorDictionaryAttributeType(wireType) {
		return AttributeRegistryEntry{}, fmt.Errorf("vendor, attribute, and valid wire type are required")
	}
	if status != "missing" && status != "partial" && status != "implemented" {
		return AttributeRegistryEntry{}, fmt.Errorf("invalid dictionary status %q", status)
	}
	oid := strings.TrimSpace(record[4])
	if number == 0 && !validDictionaryOID(oid) {
		return AttributeRegistryEntry{}, fmt.Errorf("attribute requires a number or OID")
	}

	entry := AttributeRegistryEntry{
		Source: "freeradius-" + FreeRADIUSRegistryRelease, ReleaseProfileID: DefaultDictionaryReleaseProfileID,
		Vendor: vendor, PEN: uint32(pen), Attribute: attribute, Number: number, OID: oid,
		WireType: wireType, EnumeratedValues: enums, CapabilityFamily: strings.TrimSpace(record[7]),
		DictionaryStatus: status, PackKey: NormalizeVendorCompatibilityPackKey(record[9]),
		Semantic: strings.TrimSpace(record[10]), Directions: parseRegistryDirections(record[11]),
		SemanticProvenance: "freeradius-audit:" + FreeRADIUSRegistryRelease,
		Functionality:      strings.TrimSpace(record[12]),
	}
	entry.Key = fmt.Sprintf("freeradius:%s:%d:%s", FreeRADIUSRegistryRelease, entry.PEN, strings.ToLower(entry.Attribute))
	if entry.Number > 0 {
		entry.WireKey = fmt.Sprintf("vsa:%d:%d", entry.PEN, entry.Number)
	} else {
		entry.WireKey = fmt.Sprintf("vsa:%d:%s", entry.PEN, entry.OID)
	}
	entry.OIDPath = attributeRegistryOIDPath(entry.Number, entry.OID)
	entry.WireCodec = attributeRegistryWireCodec(entry)
	entry.DecodeKind, entry.DecodeScale = attributeRegistryDecoder(entry)
	if entry.DecodeKind != "" {
		entry.DecodeSemantic = firstRegistrySemantic(entry.Semantic)
	}
	return entry, nil
}

func (r *AttributeRegistry) addEntry(entry AttributeRegistryEntry) {
	entry.OIDPath = attributeRegistryOIDPath(entry.Number, entry.OID)
	entry.WireCodec = attributeRegistryWireCodec(entry)
	r.Entries = append(r.Entries, entry)
	idx := len(r.Entries) - 1
	r.byName[attributeRegistryNameKey(entry.Vendor, entry.Attribute)] = idx
	r.byWire[entry.WireKey] = append(r.byWire[entry.WireKey], idx)
	if entry.DictionaryStatus != "missing" {
		r.MappedCount++
	}
}

func runtimeAttributeRegistryAnnotations() []AttributeRegistryEntry {
	entries := []AttributeRegistryEntry{
		{
			ReleaseProfileID: DefaultDictionaryReleaseProfileID, Vendor: "Cisco", PEN: 9, Attribute: "Cisco-AVPair", Number: 1, WireType: "string",
			PackKey: VendorPackCisco, Semantic: VendorSemanticDynamicACL + "," + VendorSemanticRoute + "," + VendorSemanticVRF + "," + VendorSemanticAddressPool + "," + VendorSemanticDelegatedIPv6Prefix + "," + VendorSemanticDHCPv6 + "," + VendorSemanticRouterAdvertisement + "," + VendorSemanticTranslationPolicy + "," + VendorSemanticTranslationPublicIPv4 + "," + VendorSemanticTranslationPortBlock + "," + VendorSemanticNAT64Prefix + "," + VendorSemanticTranslationLogging, Directions: []string{"inbound", "outbound_reply"}, DecodeKind: "string", DecodeSemantic: VendorSemanticDynamicACL,
		},
		{
			ReleaseProfileID: DefaultDictionaryReleaseProfileID, Vendor: "Juniper", PEN: 2636, Attribute: "Juniper-AV-Pair", Number: 52, WireType: "string",
			PackKey: VendorPackJuniper, Semantic: VendorSemanticDynamicACL + "," + VendorSemanticRoute + "," + VendorSemanticVRF + "," + VendorSemanticAddressPool + "," + VendorSemanticDelegatedIPv6Prefix + "," + VendorSemanticDHCPv6 + "," + VendorSemanticRouterAdvertisement + "," + VendorSemanticTranslationPolicy + "," + VendorSemanticTranslationPublicIPv4 + "," + VendorSemanticTranslationPortBlock + "," + VendorSemanticNAT64Prefix + "," + VendorSemanticTranslationLogging, Directions: []string{"inbound", "outbound_reply"}, DecodeKind: "string", DecodeSemantic: VendorSemanticDynamicACL,
		},
		{
			ReleaseProfileID: DefaultDictionaryReleaseProfileID, Vendor: "Huawei", PEN: 2011, Attribute: "Huawei-AVpair", Number: 188, WireType: "string",
			PackKey: VendorPackHuawei, Semantic: VendorSemanticDynamicACL + "," + VendorSemanticRoute + "," + VendorSemanticVRF + "," + VendorSemanticAddressPool + "," + VendorSemanticDelegatedIPv6Prefix + "," + VendorSemanticDHCPv6 + "," + VendorSemanticRouterAdvertisement + "," + VendorSemanticTranslationPolicy + "," + VendorSemanticTranslationPublicIPv4 + "," + VendorSemanticTranslationPortBlock + "," + VendorSemanticNAT64Prefix + "," + VendorSemanticTranslationLogging, Directions: []string{"inbound", "outbound_reply"}, DecodeKind: "string", DecodeSemantic: VendorSemanticDynamicACL,
		},
		{
			ReleaseProfileID: DefaultDictionaryReleaseProfileID, Vendor: "H3C", PEN: 25506, Attribute: "H3C-Av-Pair", Number: 210, WireType: "string",
			PackKey: VendorPackH3C, Semantic: VendorSemanticDynamicACL + "," + VendorSemanticRoute + "," + VendorSemanticVRF + "," + VendorSemanticAddressPool + "," + VendorSemanticDelegatedIPv6Prefix + "," + VendorSemanticDHCPv6 + "," + VendorSemanticRouterAdvertisement + "," + VendorSemanticTranslationPolicy + "," + VendorSemanticTranslationPublicIPv4 + "," + VendorSemanticTranslationPortBlock + "," + VendorSemanticNAT64Prefix + "," + VendorSemanticTranslationLogging, Directions: []string{"inbound", "outbound_reply"}, DecodeKind: "string", DecodeSemantic: VendorSemanticDynamicACL,
		},
		{
			ReleaseProfileID: DefaultDictionaryReleaseProfileID, Vendor: "Nokia", PEN: 94, Attribute: "Nokia-AVPair", Number: 1, WireType: "string",
			PackKey: VendorPackNokia, Semantic: VendorSemanticPolicyTag + "," + VendorSemanticRoute + "," + VendorSemanticVRF + "," + VendorSemanticAddressPool + "," + VendorSemanticDelegatedIPv6Prefix + "," + VendorSemanticDHCPv6 + "," + VendorSemanticRouterAdvertisement + "," + VendorSemanticTranslationPolicy + "," + VendorSemanticTranslationPublicIPv4 + "," + VendorSemanticTranslationPortBlock + "," + VendorSemanticNAT64Prefix + "," + VendorSemanticTranslationLogging, Directions: []string{"inbound", "outbound_reply"}, DecodeKind: "string", DecodeSemantic: VendorSemanticPolicyTag,
		},
		{
			ReleaseProfileID: DefaultDictionaryReleaseProfileID, Vendor: "ERX", PEN: 4874, Attribute: "ERX-Address-Pool-Name", Number: 2, WireType: "string",
			PackKey: VendorPackERX, Semantic: VendorSemanticAddressPool + "," + VendorSemanticTranslationPublicIPv4, Directions: []string{"inbound", "outbound_reply"}, DecodeKind: "string", DecodeSemantic: VendorSemanticAddressPool,
		},
		{
			ReleaseProfileID: DefaultDictionaryReleaseProfileID, Vendor: "Juniper", PEN: 2636, Attribute: "Juniper-Ip-Pool-Name", Number: 36, WireType: "string",
			PackKey: VendorPackJuniper, Semantic: VendorSemanticAddressPool, Directions: []string{"inbound", "outbound_reply"}, DecodeKind: "string", DecodeSemantic: VendorSemanticAddressPool,
		},
		{
			ReleaseProfileID: DefaultDictionaryReleaseProfileID, Vendor: "Huawei", PEN: 2011, Attribute: "Huawei-Framed-Pool", Number: 88, WireType: "string",
			PackKey: VendorPackHuawei, Semantic: VendorSemanticAddressPool, Directions: []string{"inbound", "outbound_reply"}, DecodeKind: "string", DecodeSemantic: VendorSemanticAddressPool,
		},
		{
			ReleaseProfileID: DefaultDictionaryReleaseProfileID, Vendor: "Huawei", PEN: 2011, Attribute: "Huawei-Framed-IPv6-Address", Number: 158, WireType: "ipv6addr",
			PackKey: VendorPackHuawei, Semantic: VendorSemanticIPv6Address, Directions: []string{"inbound", "outbound_reply"}, DecodeKind: "string", DecodeSemantic: VendorSemanticIPv6Address,
		},
		{
			ReleaseProfileID: DefaultDictionaryReleaseProfileID, Vendor: "Huawei", PEN: 2011, Attribute: "Huawei-Delegated-IPv6-Prefix-Pool", Number: 191, WireType: "string",
			PackKey: VendorPackHuawei, Semantic: VendorSemanticDelegatedIPv6Prefix, Directions: []string{"inbound", "outbound_reply"}, DecodeKind: "string", DecodeSemantic: VendorSemanticDelegatedIPv6Prefix,
		},
		{
			ReleaseProfileID: DefaultDictionaryReleaseProfileID, Vendor: "H3C", PEN: 25506, Attribute: "H3C-NAT-IP-Address", Number: 32, WireType: "ipaddr",
			PackKey: VendorPackH3C, Semantic: VendorSemanticTranslationPublicIPv4, Directions: []string{"inbound", "outbound_reply"}, DecodeKind: "string", DecodeSemantic: VendorSemanticTranslationPublicIPv4,
		},
		{
			ReleaseProfileID: DefaultDictionaryReleaseProfileID, Vendor: "Mikrotik", PEN: 14988, Attribute: "Mikrotik-Delegated-IPv6-Pool", Number: 22, WireType: "string",
			PackKey: VendorPackMikroTik, Semantic: VendorSemanticDelegatedIPv6Prefix, Directions: []string{"inbound", "outbound_reply"}, DecodeKind: "string", DecodeSemantic: VendorSemanticDelegatedIPv6Prefix,
		},
		{
			ReleaseProfileID: DefaultDictionaryReleaseProfileID, Vendor: "Nomadix", PEN: 3309, Attribute: "Nomadix-Bw-Class-Name", Number: 27, WireType: "string",
			PackKey: VendorPackNomadix, Semantic: VendorSemanticBandwidthProfile, Directions: []string{"inbound"}, DecodeKind: "string", DecodeSemantic: VendorSemanticBandwidthProfile,
		},
		{
			ReleaseProfileID: DefaultDictionaryReleaseProfileID, Vendor: "Meraki", PEN: 29671, Attribute: "Meraki-Ap-Name", Number: 3, WireType: "string",
			PackKey: VendorPackMeraki, Semantic: VendorSemanticAccountingIdentity, Directions: []string{"accounting", "inbound"}, DecodeKind: "string", DecodeSemantic: VendorSemanticAccountingIdentity,
		},
		{
			ReleaseProfileID: DefaultDictionaryReleaseProfileID, Vendor: "Arista", PEN: 30065, Attribute: "Arista-Segment-Id", Number: 11, WireType: "string",
			PackKey: VendorPackArista, Semantic: VendorSemanticVLAN, Directions: []string{"inbound", "outbound_reply"}, DecodeKind: "vlan", DecodeSemantic: VendorSemanticVLAN,
		},
		{
			ReleaseProfileID: DefaultDictionaryReleaseProfileID, Vendor: "Arista", PEN: 30065, Attribute: "Arista-Device-Profiling", Number: 17, WireType: "string",
			PackKey: VendorPackArista, Semantic: VendorSemanticDevicePosture, Directions: []string{"accounting", "inbound"}, DecodeKind: "string", DecodeSemantic: VendorSemanticDevicePosture,
		},
		{
			ReleaseProfileID: DefaultDictionaryReleaseProfileID, Vendor: "Arista", PEN: 30065, Attribute: "Arista-Tenant-Id", Number: 20, WireType: "integer",
			PackKey: VendorPackArista, Semantic: VendorSemanticTenant, Directions: []string{"inbound"}, DecodeKind: "integer_text", DecodeSemantic: VendorSemanticTenant,
		},
		{
			ReleaseProfileID: DefaultDictionaryReleaseProfileID, Vendor: "Arista", PEN: 30065, Attribute: "Arista-Interface-Profile", Number: 21, WireType: "string",
			PackKey: VendorPackArista, Semantic: VendorSemanticDeviceGroup, Directions: []string{"inbound", "outbound_reply"}, DecodeKind: "string", DecodeSemantic: VendorSemanticDeviceGroup,
		},
		{
			ReleaseProfileID: DefaultDictionaryReleaseProfileID, Vendor: "Starent", PEN: 8164, Attribute: "SN-IP-Pool-Name", Number: 8, WireType: "string",
			PackKey: VendorPackStarent, Semantic: VendorSemanticAddressPool, Directions: []string{"inbound", "outbound_reply"}, DecodeKind: "string", DecodeSemantic: VendorSemanticAddressPool,
		},
		{
			ReleaseProfileID: DefaultDictionaryReleaseProfileID, Vendor: "Starent", PEN: 8164, Attribute: "SN-NAT-IP-Address", Number: 297, WireType: "ipaddr",
			PackKey: VendorPackStarent, Semantic: VendorSemanticTranslationPublicIPv4, Directions: []string{"outbound_reply"}, DecodeKind: "string", DecodeSemantic: VendorSemanticTranslationPublicIPv4,
		},
		{
			Source: "aegisnas-runtime", ReleaseProfileID: DefaultDictionaryReleaseProfileID, Vendor: "Ubiquiti", PEN: 41112, Attribute: "UBNT-Data-Rate-DL", Number: 1,
			WireType: "integer", CapabilityFamily: "Bandwidth/QoS", DictionaryStatus: "partial", PackKey: VendorPackUBNT,
			Semantic: VendorSemanticDownloadBandwidth, Directions: []string{"inbound", "outbound_reply"},
			SemanticProvenance: "aegisnas-runtime",
			Functionality:      "Ubiquiti downstream data-rate assignment and accounting context.", DecodeKind: "rate_bps", DecodeSemantic: VendorSemanticDownloadBandwidth, DecodeScale: 1000,
		},
		{
			Source: "aegisnas-runtime", ReleaseProfileID: DefaultDictionaryReleaseProfileID, Vendor: "Ubiquiti", PEN: 41112, Attribute: "UBNT-Data-Rate-UL", Number: 3,
			WireType: "integer", CapabilityFamily: "Bandwidth/QoS", DictionaryStatus: "partial", PackKey: VendorPackUBNT,
			Semantic: VendorSemanticUploadBandwidth, Directions: []string{"inbound", "outbound_reply"},
			SemanticProvenance: "aegisnas-runtime",
			Functionality:      "Ubiquiti upstream data-rate assignment and accounting context.", DecodeKind: "rate_bps", DecodeSemantic: VendorSemanticUploadBandwidth, DecodeScale: 1000,
		},
	}
	entries = append(entries, arubaFamilyRuntimeAnnotations()...)
	return entries
}

func arubaFamilyRuntimeAnnotations() []AttributeRegistryEntry {
	return []AttributeRegistryEntry{
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-User-Role", 1, "string", VendorPackAruba, VendorSemanticRole, "string", VendorSemanticRole),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-User-Vlan", 2, "integer", VendorPackAruba, VendorSemanticVLAN, "vlan", VendorSemanticVLAN),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-Admin-Role", 4, "string", VendorPackAruba, VendorSemanticRole, "string", VendorSemanticRole),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-Essid-Name", 5, "string", VendorPackAruba, VendorSemanticDeviceGroup, "string", VendorSemanticDeviceGroup),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-Location-Id", 6, "string", VendorPackAruba, VendorSemanticTenant, "string", VendorSemanticTenant),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-Port-Identifier", 7, "string", VendorPackAruba, VendorSemanticAccountingIdentity, "string", VendorSemanticAccountingIdentity),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-Named-User-Vlan", 9, "string", VendorPackAruba, VendorSemanticVLAN, "string", VendorSemanticVLAN),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-AP-Group", 10, "string", VendorPackAruba, VendorSemanticDeviceGroup, "string", VendorSemanticDeviceGroup),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-Device-Type", 12, "string", VendorPackAruba, VendorSemanticDevicePosture, "string", VendorSemanticDevicePosture),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-Mdps-Device-Udid", 15, "string", VendorPackAruba, VendorSemanticAccountingIdentity, "string", VendorSemanticAccountingIdentity),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-Mdps-Device-Name", 19, "string", VendorPackAruba, VendorSemanticAccountingIdentity, "string", VendorSemanticAccountingIdentity),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-Mdps-Device-Product", 20, "string", VendorPackAruba, VendorSemanticDevicePosture, "string", VendorSemanticDevicePosture),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-Mdps-Device-Version", 21, "string", VendorPackAruba, VendorSemanticDevicePosture, "string", VendorSemanticDevicePosture),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-Mdps-Device-Serial", 22, "string", VendorPackAruba, VendorSemanticAccountingIdentity, "string", VendorSemanticAccountingIdentity),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-CPPM-Role", 23, "string", VendorPackAruba, VendorSemanticRole, "string", VendorSemanticRole),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-AirGroup-User-Name", 24, "string", VendorPackAruba, VendorSemanticPolicyTag, "string", VendorSemanticPolicyTag),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-AirGroup-Shared-User", 25, "string", VendorPackAruba, VendorSemanticPolicyTag, "string", VendorSemanticPolicyTag),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-AirGroup-Shared-Role", 26, "string", VendorPackAruba, VendorSemanticRole, "string", VendorSemanticRole),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-AirGroup-Device-Type", 27, "integer", VendorPackAruba, VendorSemanticDevicePosture, "integer_text", VendorSemanticDevicePosture),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-Auth-Survivability", 28, "string", VendorPackAruba, VendorSemanticCoAReauth, "string", VendorSemanticCoAReauth),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-Mdps-Device-Profile", 33, "string", VendorPackAruba, VendorSemanticDevicePosture, "string", VendorSemanticDevicePosture),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-AirGroup-Shared-Group", 35, "string", VendorPackAruba, VendorSemanticPolicyTag, "string", VendorSemanticPolicyTag),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-User-Group", 36, "string", VendorPackAruba, VendorSemanticDeviceGroup, "string", VendorSemanticDeviceGroup),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-Auth-SurvMethod", 39, "integer", VendorPackAruba, VendorSemanticCoAReauth, "integer_text", VendorSemanticCoAReauth),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-Port-Bounce-Host", 40, "integer", VendorPackAruba, VendorSemanticCoAReauth, "integer_text", VendorSemanticCoAReauth),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-Captive-Portal-URL", 43, "string", VendorPackAruba, VendorSemanticPortalProfile, "string", VendorSemanticPortalProfile),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-ACL-Server-Query-Info", 45, "string", VendorPackAruba, VendorSemanticDynamicACL, "string", VendorSemanticDynamicACL),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-Command-String", 46, "string", VendorPackAruba, VendorSemanticRole, "string", VendorSemanticRole),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-Admin-Device-Group", 48, "string", VendorPackAruba, VendorSemanticDeviceGroup, "string", VendorSemanticDeviceGroup),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-PoE-Priority", 49, "integer", VendorPackAruba, VendorSemanticBandwidthProfile, "integer_text", VendorSemanticBandwidthProfile),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-Port-Auth-Mode", 50, "integer", VendorPackAruba, VendorSemanticCoAReauth, "integer_text", VendorSemanticCoAReauth),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-NAS-Filter-Rule", 51, "string", VendorPackAruba, VendorSemanticACL, "string", VendorSemanticACL),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-QoS-Trust-Mode", 52, "integer", VendorPackAruba, VendorSemanticBandwidthProfile, "integer_text", VendorSemanticBandwidthProfile),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-UBT-Gateway-Role", 53, "string", VendorPackAruba, VendorSemanticVRF, "string", VendorSemanticVRF),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-Gateway-Zone", 54, "string", VendorPackAruba, VendorSemanticTenant, "string", VendorSemanticTenant),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-STP-Admin-Edge-Port", 58, "integer", VendorPackAruba, VendorSemanticCoAReauth, "integer_text", VendorSemanticCoAReauth),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-UBT-Gateway-CPPM-Role", 59, "string", VendorPackAruba, VendorSemanticRole, "string", VendorSemanticRole),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-AP-MAC-Address", 60, "string", VendorPackAruba, VendorSemanticAccountingIdentity, "string", VendorSemanticAccountingIdentity),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-Device-MAC-Address", 61, "string", VendorPackAruba, VendorSemanticAccountingIdentity, "string", VendorSemanticAccountingIdentity),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-MPSK-Key-Name", 62, "string", VendorPackAruba, VendorSemanticPolicyTag, "string", VendorSemanticPolicyTag),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-Device-Traffic-Class", 63, "integer", VendorPackAruba, VendorSemanticBandwidthProfile, "integer_text", VendorSemanticBandwidthProfile),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-PVLAN-Port-Type", 64, "integer", VendorPackAruba, VendorSemanticVLAN, "integer_text", VendorSemanticVLAN),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-AVPair", 67, "string", VendorPackAruba, VendorSemanticPolicyTag, "string", VendorSemanticPolicyTag),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-DPP-Service-Type", 68, "integer", VendorPackAruba, VendorSemanticCertificateOnboarding, "integer_text", VendorSemanticCertificateOnboarding),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-User-Mgmt-Interface", 69, "string", VendorPackAruba, VendorSemanticAccountingIdentity, "string", VendorSemanticAccountingIdentity),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-DPP-AKMs", 71, "string", VendorPackAruba, VendorSemanticCertificateOnboarding, "string", VendorSemanticCertificateOnboarding),
		arubaRuntimeAnnotation("HP", 11, "HP-Captive-Portal-URL", 24, "string", VendorPackHP, VendorSemanticPortalProfile, "string", VendorSemanticPortalProfile),
		arubaRuntimeAnnotation("HP", 11, "HP-User-Role", 25, "string", VendorPackHP, VendorSemanticRole, "string", VendorSemanticRole),
		arubaRuntimeAnnotation("HP", 11, "HP-CPPM-Role", 27, "string", VendorPackHP, VendorSemanticRole, "string", VendorSemanticRole),
		arubaRuntimeAnnotation("HP", 11, "HP-Privilege-Level", 1, "integer", VendorPackHP, VendorSemanticRole, "integer_text", VendorSemanticRole),
		arubaRuntimeAnnotation("HP", 11, "HP-Command-String", 2, "string", VendorPackHP, VendorSemanticRole, "string", VendorSemanticRole),
		arubaRuntimeAnnotation("HP", 11, "HP-Command-Exception", 3, "integer", VendorPackHP, VendorSemanticSessionAction, "integer_text", VendorSemanticSessionAction),
		arubaRuntimeAnnotation("HP", 11, "HP-Port-Bounce-Host", 23, "integer", VendorPackHP, VendorSemanticCoAReauth, "integer_text", VendorSemanticCoAReauth),
		arubaRuntimeAnnotation("HP", 11, "HP-CPPM-Secondary-Role", 28, "string", VendorPackHP, VendorSemanticRole, "string", VendorSemanticRole),
		arubaRuntimeAnnotation("HP", 11, "HP-Cos", 40, "string", VendorPackHP, VendorSemanticBandwidthProfile, "string", VendorSemanticBandwidthProfile),
		arubaRuntimeAnnotation("HP", 11, "HP-Bandwidth-Max-Ingress", 46, "integer", VendorPackHP, VendorSemanticUploadBandwidth, "rate_kbps", VendorSemanticUploadBandwidth),
		arubaRuntimeAnnotation("HP", 11, "HP-Bandwidth-Max-Egress", 48, "integer", VendorPackHP, VendorSemanticDownloadBandwidth, "rate_kbps", VendorSemanticDownloadBandwidth),
		arubaRuntimeAnnotation("HP", 11, "HP-Ip-Filter-Raw", 61, "string", VendorPackHP, VendorSemanticDynamicACL, "string", VendorSemanticDynamicACL),
		arubaRuntimeAnnotation("HP", 11, "HP-Access-Profile", 62, "string", VendorPackHP, VendorSemanticPolicyTag, "string", VendorSemanticPolicyTag),
		arubaRuntimeAnnotation("HP", 11, "HP-Nas-Rules-IPv6", 63, "integer", VendorPackHP, VendorSemanticDynamicACL, "integer_text", VendorSemanticDynamicACL),
		arubaRuntimeAnnotation("HP", 11, "HP-Egress-VLANID", 64, "integer", VendorPackHP, VendorSemanticVLAN, "vlan", VendorSemanticVLAN),
		arubaRuntimeAnnotation("HP", 11, "HP-Egress-VLAN-Name", 65, "string", VendorPackHP, VendorSemanticVLAN, "string", VendorSemanticVLAN),
		arubaRuntimeAnnotation("HP", 11, "HP-Bonjour-Inbound-Profile", 66, "string", VendorPackHP, VendorSemanticPolicyTag, "string", VendorSemanticPolicyTag),
		arubaRuntimeAnnotation("HP", 11, "HP-Bonjour-Outbound-Profile", 67, "string", VendorPackHP, VendorSemanticPolicyTag, "string", VendorSemanticPolicyTag),
		arubaRuntimeAnnotation("HP", 11, "HP-URI-String", 80, "string", VendorPackHP, VendorSemanticRole, "string", VendorSemanticRole),
		arubaRuntimeAnnotation("HP", 11, "HP-URI-Access", 82, "string", VendorPackHP, VendorSemanticRole, "string", VendorSemanticRole),
		arubaRuntimeAnnotation("HP", 11, "HP-VC-groups", 192, "string", VendorPackHP, VendorSemanticDeviceGroup, "string", VendorSemanticDeviceGroup),
		arubaRuntimeAnnotation("Aerohive", 26928, "Extreme-User-Vlan", 1, "integer", VendorPackAerohive, VendorSemanticVLAN, "vlan", VendorSemanticVLAN),
		arubaRuntimeAnnotation("Aerohive", 26928, "Extreme-User-Profile-Attribute", 6, "integer", VendorPackAerohive, VendorSemanticRole, "mapped_role", VendorSemanticRole),
		arubaRuntimeAnnotation("Aerohive", 26928, "Extreme-AVPair", 8, "string", VendorPackAerohive, VendorSemanticPolicyTag, "string", VendorSemanticPolicyTag),
		arubaRuntimeAnnotation("Aerohive", 26928, "Extreme-IDM-Message", 203, "integer", VendorPackAerohive, VendorSemanticPolicyTag, "integer_text", VendorSemanticPolicyTag),
		arubaRuntimeAnnotation("Aerohive", 26928, "Extreme-User-Language", 205, "string", VendorPackAerohive, VendorSemanticPolicyTag, "string", VendorSemanticPolicyTag),
		arubaRuntimeAnnotation("Aerohive", 26928, "Extreme-Client-Monitor-Problem", 210, "integer", VendorPackAerohive, VendorSemanticDevicePosture, "integer_text", VendorSemanticDevicePosture),
		arubaRuntimeAnnotation("Aerohive", 26928, "Extreme-IDM-Redirect-URL", 211, "string", VendorPackAerohive, VendorSemanticPortalProfile, "string", VendorSemanticPortalProfile),
		arubaRuntimeAnnotation("Aerohive", 26928, "Extreme-Auth-Source", 213, "integer", VendorPackAerohive, VendorSemanticCertificateOnboarding, "integer_text", VendorSemanticCertificateOnboarding),
		arubaRuntimeAnnotation("Colubris", 8744, "Colubris-Intercept", 1, "integer", VendorPackColubris, VendorSemanticQuarantine, "bool", VendorSemanticQuarantine),
	}
}

func arubaRuntimeAnnotation(vendor string, pen uint32, attribute string, number uint32, wireType, packKey, semantic, decodeKind, decodeSemantic string) AttributeRegistryEntry {
	scale := 0
	if decodeKind == "rate_kbps" {
		scale = 1
	}
	return AttributeRegistryEntry{
		ReleaseProfileID: DefaultDictionaryReleaseProfileID,
		Vendor:           vendor,
		PEN:              pen,
		Attribute:        attribute,
		Number:           number,
		WireType:         wireType,
		PackKey:          packKey,
		Semantic:         semantic,
		Directions:       []string{"inbound", "outbound_reply", "accounting"},
		DecodeKind:       decodeKind,
		DecodeSemantic:   decodeSemantic,
		DecodeScale:      scale,
	}
}

func (r *AttributeRegistry) applyRuntimeAnnotations(vendors map[string]struct{}) {
	for _, annotation := range runtimeAttributeRegistryAnnotations() {
		nameKey := attributeRegistryNameKey(annotation.Vendor, annotation.Attribute)
		if idx, exists := r.byName[nameKey]; exists {
			wasMissing := r.Entries[idx].DictionaryStatus == "missing"
			r.Entries[idx].PackKey = annotation.PackKey
			r.Entries[idx].Semantic = mergeRegistrySemantics(r.Entries[idx].Semantic, annotation.Semantic)
			r.Entries[idx].SemanticProvenance = mergeRegistrySemantics(r.Entries[idx].SemanticProvenance, "aegisnas-runtime")
			r.Entries[idx].Directions = append([]string(nil), annotation.Directions...)
			r.Entries[idx].DecodeKind = annotation.DecodeKind
			r.Entries[idx].DecodeSemantic = annotation.DecodeSemantic
			r.Entries[idx].DecodeScale = annotation.DecodeScale
			if wasMissing {
				r.Entries[idx].DictionaryStatus = "partial"
				r.MappedCount++
			}
			continue
		}
		annotation.Source = "aegisnas-runtime"
		annotation.ReleaseProfileID = DefaultDictionaryReleaseProfileID
		annotation.DictionaryStatus = "partial"
		if annotation.SemanticProvenance == "" {
			annotation.SemanticProvenance = "aegisnas-runtime"
		}
		if annotation.CapabilityFamily == "" {
			annotation.CapabilityFamily = "Vendor-specific/other"
		}
		annotation.Key = fmt.Sprintf("aegisnas-runtime:%d:%s", annotation.PEN, strings.ToLower(annotation.Attribute))
		annotation.WireKey = fmt.Sprintf("vsa:%d:%d", annotation.PEN, annotation.Number)
		r.addEntry(annotation)
		vendors[strings.ToLower(annotation.Vendor)+"\x00"+strconv.FormatUint(uint64(annotation.PEN), 10)] = struct{}{}
	}
}

func firstRegistrySemantic(value string) string {
	for _, semantic := range strings.Split(value, ",") {
		if semantic = strings.TrimSpace(semantic); semantic != "" {
			return semantic
		}
	}
	return ""
}

func registrySemanticContains(value, target string) bool {
	target = strings.ToLower(strings.TrimSpace(target))
	for _, semantic := range strings.Split(value, ",") {
		if strings.ToLower(strings.TrimSpace(semantic)) == target {
			return true
		}
	}
	return false
}

func mergeRegistrySemantics(current, addition string) string {
	out := make([]string, 0, 2)
	seen := map[string]struct{}{}
	for _, value := range strings.Split(current+","+addition, ",") {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	return strings.Join(out, ",")
}

func parseOptionalUint32(value string) (uint32, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}
	parsed, err := strconv.ParseUint(value, 0, 32)
	return uint32(parsed), err
}

func parseOptionalInt(value string) (int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}
	return strconv.Atoi(value)
}

func parseRegistryDirections(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, part := range parts {
		part = strings.ToLower(strings.TrimSpace(part))
		if part == "" {
			continue
		}
		if _, exists := seen[part]; exists {
			continue
		}
		seen[part] = struct{}{}
		out = append(out, part)
	}
	sort.Strings(out)
	return out
}

func attributeRegistryOIDPath(number uint32, oid string) []uint32 {
	if strings.TrimSpace(oid) == "" {
		if number == 0 {
			return nil
		}
		return []uint32{number}
	}
	oid = strings.TrimPrefix(strings.TrimSpace(oid), ".")
	parts := strings.Split(oid, ".")
	out := make([]uint32, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			return nil
		}
		parsed, err := strconv.ParseUint(part, 10, 32)
		if err != nil || parsed == 0 {
			return nil
		}
		out = append(out, uint32(parsed))
	}
	return out
}

func attributeRegistryWireCodec(entry AttributeRegistryEntry) AttributeWireCodec {
	wireType := baseDictionaryWireType(entry.WireType)
	grouped := len(entry.OIDPath) > 1
	switch wireType {
	case "group", "tlv", "struct":
		grouped = true
	}
	extended := false
	switch wireType {
	case "extended", "vendor", "vsa":
		extended = true
	}
	return AttributeWireCodec{
		TypeOctets:   1,
		LengthOctets: 1,
		OIDPath:      append([]uint32(nil), entry.OIDPath...),
		Repeated:     true,
		Grouped:      grouped,
		Tagged:       false,
		Extended:     extended,
	}
}

func baseDictionaryWireType(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if idx := strings.Index(value, "["); idx >= 0 {
		value = value[:idx]
	}
	return value
}

func attributeRegistryDecoder(entry AttributeRegistryEntry) (string, int) {
	if entry.DictionaryStatus == "missing" || entry.Number == 0 || entry.Number > 255 || entry.PackKey == "" {
		return "", 0
	}
	if !registryDirectionContains(entry.Directions, "inbound") && !registryDirectionContains(entry.Directions, "accounting") {
		return "", 0
	}
	name := strings.ToLower(entry.Attribute)
	switch {
	case entry.PackKey == VendorPackNokia && strings.Contains(name, "service-name"):
		return "nokia_bcd", 0
	case entry.PackKey == VendorPackExtreme && strings.Contains(name, "extended-vlan"):
		return "extended_vlan", 0
	case entry.PackKey == VendorPackTPLink && strings.Contains(name, "portal-access-status"):
		return "mapped_portal_status", 0
	case entry.Semantic == VendorSemanticSessionAction:
		return "mapped_session_action", 0
	case entry.Semantic == VendorSemanticDataQuota:
		return "data_quota", 0
	case entry.Semantic == VendorSemanticDynamicACL && (strings.Contains(name, "avpair") || strings.Contains(name, "av-pair")):
		return "avpairs", 0
	case entry.Semantic == VendorSemanticVLAN:
		return "vlan", 0
	case entry.Semantic == VendorSemanticUploadBandwidth || entry.Semantic == VendorSemanticDownloadBandwidth:
		if entry.PackKey == VendorPackUBNT {
			return "rate_bps", 1000
		}
		return "rate_kbps", 1
	case entry.Semantic == VendorSemanticQuarantine:
		return "bool", 0
	case entry.Semantic == VendorSemanticRole && registryIntegerType(entry.WireType):
		return "mapped_role", 0
	case registryIntegerType(entry.WireType):
		if entry.Semantic == VendorSemanticAccountingCounters {
			return "", 0
		}
		return "integer_text", 0
	default:
		return "string", 0
	}
}

func registryIntegerType(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "byte", "short", "signed", "int8", "int16", "int32", "integer", "uint8", "uint16", "uint32":
		return true
	default:
		return false
	}
}

func registryDirectionContains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func attributeRegistryNameKey(vendor, attribute string) string {
	vendor = NormalizeDictionaryVendorName(DefaultDictionaryReleaseProfileID, vendor)
	attribute = NormalizeDictionaryAttributeName(DefaultDictionaryReleaseProfileID, vendor, attribute)
	return strings.ToLower(strings.TrimSpace(vendor)) + "\x00" + strings.ToLower(strings.TrimSpace(attribute))
}

func (r *AttributeRegistry) LookupName(vendor, attribute string) (AttributeRegistryEntry, bool) {
	if r == nil {
		return AttributeRegistryEntry{}, false
	}
	idx, ok := r.byName[attributeRegistryNameKey(vendor, attribute)]
	if !ok {
		return AttributeRegistryEntry{}, false
	}
	return r.Entries[idx], true
}

func (r *AttributeRegistry) LookupWire(pen, number uint32) []AttributeRegistryEntry {
	if r == nil {
		return nil
	}
	indexes := r.byWire[fmt.Sprintf("vsa:%d:%d", pen, number)]
	out := make([]AttributeRegistryEntry, 0, len(indexes))
	for _, idx := range indexes {
		out = append(out, r.Entries[idx])
	}
	return out
}

func (r *AttributeRegistry) ValidateCompatibilityPacks(packs []VendorCompatibilityPack) error {
	if r == nil {
		return fmt.Errorf("attribute registry is nil")
	}
	for _, pack := range packs {
		packKey := NormalizeVendorCompatibilityPackKey(pack.Key)
		if packKey == VendorPackStandard || packKey == VendorPackAegisNAS {
			continue
		}
		for _, mapping := range pack.Attributes {
			if strings.EqualFold(mapping.Direction, "controller_api") || !strings.EqualFold(mapping.CompatibilityState, "implemented") {
				continue
			}
			entry, ok := r.lookupPackAttribute(pack, mapping.Attribute)
			if !ok {
				return fmt.Errorf("pack %s attribute %s is absent from the typed registry", packKey, mapping.Attribute)
			}
			if !registrySemanticContains(entry.Semantic, mapping.Semantic) {
				return fmt.Errorf("pack %s attribute %s semantic %s conflicts with registry semantic %s", packKey, mapping.Attribute, mapping.Semantic, entry.Semantic)
			}
			if !registryDirectionContains(entry.Directions, strings.ToLower(strings.TrimSpace(mapping.Direction))) {
				return fmt.Errorf("pack %s attribute %s direction %s is absent from the typed registry", packKey, mapping.Attribute, mapping.Direction)
			}
		}
	}
	return nil
}

func (r *AttributeRegistry) lookupPackAttribute(pack VendorCompatibilityPack, attribute string) (AttributeRegistryEntry, bool) {
	attribute = strings.ToLower(strings.TrimSpace(NormalizeDictionaryAttributeName(DefaultDictionaryReleaseProfileID, pack.VendorName, attribute)))
	if entry, ok := r.LookupName(pack.VendorName, attribute); ok {
		return entry, true
	}
	for _, entry := range r.Entries {
		if pack.VendorID > 0 && entry.PEN != uint32(pack.VendorID) {
			continue
		}
		if pack.VendorID == 0 && !strings.EqualFold(NormalizeDictionaryVendorName(DefaultDictionaryReleaseProfileID, entry.Vendor), NormalizeDictionaryVendorName(DefaultDictionaryReleaseProfileID, pack.VendorName)) {
			continue
		}
		candidate := strings.ToLower(strings.TrimSpace(NormalizeDictionaryAttributeName(DefaultDictionaryReleaseProfileID, entry.Vendor, entry.Attribute)))
		if candidate == attribute || strings.HasSuffix(candidate, "-"+attribute) {
			return entry, true
		}
	}
	return AttributeRegistryEntry{}, false
}

func (r *AttributeRegistry) RuntimeMappings() []AttributeRuntimeMapping {
	if r == nil {
		return nil
	}
	out := make([]AttributeRuntimeMapping, 0, r.MappedCount)
	seen := map[string]struct{}{}
	for _, entry := range r.Entries {
		if entry.DecodeKind == "" || entry.Number == 0 || entry.Number > 255 {
			continue
		}
		semantic := entry.DecodeSemantic
		if semantic == "" {
			semantic = firstRegistrySemantic(entry.Semantic)
		}
		key := fmt.Sprintf("%s\x00%d\x00%d\x00%s", entry.PackKey, entry.PEN, entry.Number, semantic)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, AttributeRuntimeMapping{
			PackKey: entry.PackKey, VendorID: entry.PEN, Type: byte(entry.Number), Attribute: entry.Attribute,
			Semantic: semantic, Kind: entry.DecodeKind, Scale: entry.DecodeScale,
		})
	}
	packOrder := map[string]int{}
	for idx, pack := range AegisNASVendorCompatibilityPacks() {
		packOrder[NormalizeVendorCompatibilityPackKey(pack.Key)] = idx
	}
	sort.SliceStable(out, func(i, j int) bool {
		left, leftOK := packOrder[out[i].PackKey]
		right, rightOK := packOrder[out[j].PackKey]
		if leftOK != rightOK {
			return leftOK
		}
		if left != right {
			return left < right
		}
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].Attribute < out[j].Attribute
	})
	return out
}
