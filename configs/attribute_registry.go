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
			PackKey: VendorPackHuawei, Semantic: VendorSemanticDynamicACL + "," + VendorSemanticRoute + "," + VendorSemanticVRF + "," + VendorSemanticAddressPool + "," + VendorSemanticDelegatedIPv6Prefix + "," + VendorSemanticDHCPv6 + "," + VendorSemanticRouterAdvertisement + "," + VendorSemanticTranslationPolicy + "," + VendorSemanticTranslationPublicIPv4 + "," + VendorSemanticTranslationPortBlock + "," + VendorSemanticNAT64Prefix + "," + VendorSemanticTranslationLogging, Directions: []string{"inbound", "outbound_reply"}, DecodeKind: "avpairs", DecodeSemantic: VendorSemanticDynamicACL,
		},
		{
			ReleaseProfileID: DefaultDictionaryReleaseProfileID, Vendor: "H3C", PEN: 25506, Attribute: "H3C-Av-Pair", Number: 210, WireType: "string",
			PackKey: VendorPackH3C, Semantic: VendorSemanticDynamicACL + "," + VendorSemanticRoute + "," + VendorSemanticVRF + "," + VendorSemanticAddressPool + "," + VendorSemanticDelegatedIPv6Prefix + "," + VendorSemanticDHCPv6 + "," + VendorSemanticRouterAdvertisement + "," + VendorSemanticTranslationPolicy + "," + VendorSemanticTranslationPublicIPv4 + "," + VendorSemanticTranslationPortBlock + "," + VendorSemanticNAT64Prefix + "," + VendorSemanticTranslationLogging, Directions: []string{"inbound", "outbound_reply"}, DecodeKind: "avpairs", DecodeSemantic: VendorSemanticDynamicACL,
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
	entries = append(entries, juniperExtremeRuntimeAnnotations()...)
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
		withAttributeRegistryDirections(arubaRuntimeAnnotation("Aruba", 14823, "Aruba-Device-Type", 12, "string", VendorPackAruba, VendorSemanticDevicePosture, "string", VendorSemanticDevicePosture), "accounting", "inbound"),
		arubaRuntimeAnnotation("Aruba", 14823, "Aruba-Mdps-Device-Udid", 15, "string", VendorPackAruba, VendorSemanticAccountingIdentity, "string", VendorSemanticAccountingIdentity),
		withAttributeRegistryDirections(arubaRuntimeAnnotation("Aruba", 14823, "Aruba-Mdps-Device-Name", 19, "string", VendorPackAruba, VendorSemanticAccountingIdentity, "string", VendorSemanticAccountingIdentity), "accounting", "inbound"),
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
		withAttributeRegistryDirections(arubaRuntimeAnnotation("Aerohive", 26928, "Extreme-Client-Monitor-Problem", 210, "integer", VendorPackAerohive, VendorSemanticDevicePosture, "integer_text", VendorSemanticDevicePosture), "accounting", "inbound"),
		arubaRuntimeAnnotation("Aerohive", 26928, "Extreme-IDM-Redirect-URL", 211, "string", VendorPackAerohive, VendorSemanticPortalProfile, "string", VendorSemanticPortalProfile),
		arubaRuntimeAnnotation("Aerohive", 26928, "Extreme-Auth-Source", 213, "integer", VendorPackAerohive, VendorSemanticCertificateOnboarding, "integer_text", VendorSemanticCertificateOnboarding),
		arubaRuntimeAnnotation("Colubris", 8744, "Colubris-Intercept", 1, "integer", VendorPackColubris, VendorSemanticQuarantine, "bool", VendorSemanticQuarantine),
		{
			Source:             "aegisnas-runtime",
			ReleaseProfileID:   DefaultDictionaryReleaseProfileID,
			Vendor:             "Colubris",
			PEN:                8744,
			Attribute:          "Colubris-AVPair",
			WireType:           "string",
			CapabilityFamily:   "Authorization/policy",
			DictionaryStatus:   "missing",
			PackKey:            VendorPackColubris,
			Semantic:           VendorSemanticPolicyTag,
			SemanticProvenance: "aegisnas-runtime:nas-0062",
			Directions:         []string{"outbound_reply"},
			Functionality:      "AegisNAS Colubris/MSM profile export template for vendor-scoped AVPair-style policy evidence; not present as a pinned FreeRADIUS dictionary row.",
		},
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

func withAttributeRegistryDirections(entry AttributeRegistryEntry, directions ...string) AttributeRegistryEntry {
	entry.Directions = append([]string(nil), directions...)
	return entry
}

func juniperExtremeRuntimeAnnotations() []AttributeRegistryEntry {
	return []AttributeRegistryEntry{
		juniperExtremeRuntimeAnnotation("Juniper", 2636, "Juniper-Local-User-Name", 1, "string", VendorPackJuniper, VendorSemanticRole, "string", VendorSemanticRole),
		juniperExtremeRuntimeAnnotation("Juniper", 2636, "Juniper-Allow-Commands", 2, "string", VendorPackJuniper, VendorSemanticRole, "string", VendorSemanticRole),
		juniperExtremeRuntimeAnnotation("Juniper", 2636, "Juniper-Deny-Commands", 3, "string", VendorPackJuniper, VendorSemanticRole, "string", VendorSemanticRole),
		juniperExtremeRuntimeAnnotation("Juniper", 2636, "Juniper-Allow-Configuration", 4, "string", VendorPackJuniper, VendorSemanticRole, "string", VendorSemanticRole),
		juniperExtremeRuntimeAnnotation("Juniper", 2636, "Juniper-Deny-Configuration", 5, "string", VendorPackJuniper, VendorSemanticRole, "string", VendorSemanticRole),
		juniperExtremeRuntimeAnnotation("Juniper", 2636, "Juniper-Interactive-Command", 8, "string", VendorPackJuniper, VendorSemanticRole, "string", VendorSemanticRole),
		juniperExtremeRuntimeAnnotation("Juniper", 2636, "Juniper-Configuration-Change", 9, "string", VendorPackJuniper, VendorSemanticPolicyTag, "string", VendorSemanticPolicyTag),
		juniperExtremeRuntimeAnnotation("Juniper", 2636, "Juniper-User-Permissions", 10, "string", VendorPackJuniper, VendorSemanticRole, "string", VendorSemanticRole),
		juniperExtremeRuntimeAnnotation("Juniper", 2636, "Juniper-Junosspace-Profile", 11, "string", VendorPackJuniper, VendorSemanticDeviceGroup, "string", VendorSemanticDeviceGroup),
		juniperExtremeRuntimeAnnotation("Juniper", 2636, "Juniper-CTP-Group", 21, "integer", VendorPackJuniper, VendorSemanticDeviceGroup, "integer_text", VendorSemanticDeviceGroup),
		juniperExtremeRuntimeAnnotation("Juniper", 2636, "Juniper-CTPView-APP-Group", 22, "integer", VendorPackJuniper, VendorSemanticDeviceGroup, "integer_text", VendorSemanticDeviceGroup),
		juniperExtremeRuntimeAnnotation("Juniper", 2636, "Juniper-CTPView-OS-Group", 23, "integer", VendorPackJuniper, VendorSemanticDeviceGroup, "integer_text", VendorSemanticDeviceGroup),
		juniperExtremeRuntimeAnnotation("Juniper", 2636, "Juniper-Primary-Dns", 31, "ipaddr", VendorPackJuniper, VendorSemanticIPv4Address, "string", VendorSemanticIPv4Address),
		juniperExtremeRuntimeAnnotation("Juniper", 2636, "Juniper-Secondary-Dns", 33, "ipaddr", VendorPackJuniper, VendorSemanticIPv4Address, "string", VendorSemanticIPv4Address),
		juniperExtremeRuntimeAnnotation("Juniper", 2636, "Juniper-Interface-id", 35, "string", VendorPackJuniper, VendorSemanticAccountingIdentity, "string", VendorSemanticAccountingIdentity),
		juniperExtremeRuntimeAnnotation("Juniper", 2636, "Juniper-Ip-Pool-Name", 36, "string", VendorPackJuniper, VendorSemanticAddressPool, "string", VendorSemanticAddressPool),
		juniperExtremeRuntimeAnnotation("Juniper", 2636, "Juniper-Keep-Alive", 37, "integer", VendorPackJuniper, VendorSemanticSessionTimeout, "integer_text", VendorSemanticSessionTimeout),
		juniperExtremeRuntimeAnnotation("Juniper", 2636, "Juniper-CoS-Traffic-Control-Profile", 38, "string", VendorPackJuniper, VendorSemanticBandwidthProfile, "string", VendorSemanticBandwidthProfile),
		juniperExtremeRuntimeAnnotation("Juniper", 2636, "Juniper-CoS-Parameter", 39, "string", VendorPackJuniper, VendorSemanticBandwidthProfile, "string", VendorSemanticBandwidthProfile),
		juniperExtremeRuntimeAnnotation("Juniper", 2636, "Juniper-tx-connect-speed", 42, "integer", VendorPackJuniper, VendorSemanticUploadBandwidth, "rate_kbps", VendorSemanticUploadBandwidth),
		juniperExtremeRuntimeAnnotation("Juniper", 2636, "Juniper-rx-connect-speed", 43, "integer", VendorPackJuniper, VendorSemanticDownloadBandwidth, "rate_kbps", VendorSemanticDownloadBandwidth),
		juniperExtremeRuntimeAnnotation("Juniper", 2636, "Juniper-Firewall-filter-name", 44, "string", VendorPackJuniper, VendorSemanticACL, "string", VendorSemanticACL),
		juniperExtremeRuntimeAnnotation("Juniper", 2636, "Juniper-Policer-Parameter", 45, "string", VendorPackJuniper, VendorSemanticBandwidthProfile, "string", VendorSemanticBandwidthProfile),
		juniperExtremeRuntimeAnnotation("Juniper", 2636, "Juniper-Local-Group-Name", 46, "string", VendorPackJuniper, VendorSemanticDeviceGroup, "string", VendorSemanticDeviceGroup),
		juniperExtremeRuntimeAnnotation("Juniper", 2636, "Juniper-Local-Interface", 47, "string", VendorPackJuniper, VendorSemanticAccountingIdentity, "string", VendorSemanticAccountingIdentity),
		juniperExtremeRuntimeAnnotation("Juniper", 2636, "Juniper-Switching-Filter", 48, "string", VendorPackJuniper, VendorSemanticACL, "string", VendorSemanticACL),
		juniperExtremeRuntimeAnnotation("Juniper", 2636, "Juniper-VoIP-Vlan", 49, "string", VendorPackJuniper, VendorSemanticVLAN, "string", VendorSemanticVLAN),
		juniperExtremeRuntimeAnnotation("Juniper", 2636, "Juniper-CWA-Redirect", 50, "string", VendorPackJuniper, VendorSemanticPortalProfile, "string", VendorSemanticPortalProfile),
		juniperExtremeRuntimeAnnotation("Juniper", 2636, "Juniper-AV-Pair", 52, "string", VendorPackJuniper, VendorSemanticDynamicACL+","+VendorSemanticRoute+","+VendorSemanticVRF+","+VendorSemanticAddressPool+","+VendorSemanticDelegatedIPv6Prefix+","+VendorSemanticTranslationPolicy+","+VendorSemanticTranslationPublicIPv4+","+VendorSemanticTranslationPortBlock+","+VendorSemanticNAT64Prefix, "avpairs", VendorSemanticDynamicACL),
		juniperExtremeRuntimeAnnotation("Juniper", 2636, "Juniper-DHCPv4-Options", 55, "octets", VendorPackJuniper, VendorSemanticAccountingIdentity, "string", VendorSemanticAccountingIdentity),
		juniperExtremeRuntimeAnnotation("Juniper", 2636, "Juniper-DHCPv6-Options", 207, "octets", VendorPackJuniper, VendorSemanticDHCPv6, "string", VendorSemanticDHCPv6),
		juniperExtremeRuntimeAnnotation("Juniper", 2636, "Juniper-DHCPv4-Packet-Header", 208, "octets", VendorPackJuniper, VendorSemanticAccountingIdentity, "string", VendorSemanticAccountingIdentity),
		juniperExtremeRuntimeAnnotation("Juniper", 2636, "Juniper-DHCPv6-Packet-Header", 209, "octets", VendorPackJuniper, VendorSemanticDHCPv6, "string", VendorSemanticDHCPv6),
		withAttributeRegistryDirections(juniperExtremeRuntimeAnnotation("Juniper", 2636, "Juniper-Acct-Request-Reason", 210, "uint32", VendorPackJuniper, VendorSemanticAccountingCounters, "integer_text", VendorSemanticAccountingCounters), "accounting", "inbound"),

		juniperExtremeRuntimeAnnotation("Extreme", 1916, "Extreme-CLI-Authorization", 201, "integer", VendorPackExtreme, VendorSemanticRole, "integer_text", VendorSemanticRole),
		juniperExtremeRuntimeAnnotation("Extreme", 1916, "Extreme-Shell-Command", 202, "string", VendorPackExtreme, VendorSemanticRole, "string", VendorSemanticRole),
		juniperExtremeRuntimeAnnotation("Extreme", 1916, "Extreme-Netlogin-Vlan", 203, "string", VendorPackExtreme, VendorSemanticVLAN, "vlan", VendorSemanticVLAN),
		juniperExtremeRuntimeAnnotation("Extreme", 1916, "Extreme-Netlogin-Url", 204, "string", VendorPackExtreme, VendorSemanticPortalProfile, "string", VendorSemanticPortalProfile),
		juniperExtremeRuntimeAnnotation("Extreme", 1916, "Extreme-Netlogin-Url-Desc", 205, "string", VendorPackExtreme, VendorSemanticPortalProfile, "string", VendorSemanticPortalProfile),
		juniperExtremeRuntimeAnnotation("Extreme", 1916, "Extreme-Netlogin-Only", 206, "integer", VendorPackExtreme, VendorSemanticSessionAction, "integer_text", VendorSemanticSessionAction),
		juniperExtremeRuntimeAnnotation("Extreme", 1916, "Extreme-User-Location", 208, "string", VendorPackExtreme, VendorSemanticTenant, "string", VendorSemanticTenant),
		juniperExtremeRuntimeAnnotation("Extreme", 1916, "Extreme-Netlogin-Vlan-Tag", 209, "integer", VendorPackExtreme, VendorSemanticVLAN, "vlan", VendorSemanticVLAN),
		juniperExtremeRuntimeAnnotation("Extreme", 1916, "Extreme-Netlogin-Extended-Vlan", 211, "string", VendorPackExtreme, VendorSemanticVLAN, "extended_vlan", VendorSemanticVLAN),
		juniperExtremeRuntimeAnnotation("Extreme", 1916, "Extreme-Security-Profile", 212, "string", VendorPackExtreme, VendorSemanticRole, "string", VendorSemanticRole),
		juniperExtremeRuntimeAnnotation("Extreme", 1916, "Extreme-VM-Name", 213, "string", VendorPackExtreme, VendorSemanticAccountingIdentity, "string", VendorSemanticAccountingIdentity),
		juniperExtremeRuntimeAnnotation("Extreme", 1916, "Extreme-VM-VPP-Name", 214, "string", VendorPackExtreme, VendorSemanticPolicyTag, "string", VendorSemanticPolicyTag),
		juniperExtremeRuntimeAnnotation("Extreme", 1916, "Extreme-VM-IP-Addr", 215, "ipaddr", VendorPackExtreme, VendorSemanticIPv4Address, "string", VendorSemanticIPv4Address),
		juniperExtremeRuntimeAnnotation("Extreme", 1916, "Extreme-VM-VLAN-ID", 216, "integer", VendorPackExtreme, VendorSemanticVLAN, "vlan", VendorSemanticVLAN),
		juniperExtremeRuntimeAnnotation("Extreme", 1916, "Extreme-VM-VR-Name", 217, "string", VendorPackExtreme, VendorSemanticVRF, "string", VendorSemanticVRF),

		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Virtual-Router-Name", 1, "string", VendorPackERX, VendorSemanticVRF, "string", VendorSemanticVRF),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Address-Pool-Name", 2, "string", VendorPackERX, VendorSemanticAddressPool+","+VendorSemanticTranslationPublicIPv4, "string", VendorSemanticAddressPool),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Primary-Dns", 4, "ipaddr", VendorPackERX, VendorSemanticIPv4Address, "string", VendorSemanticIPv4Address),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Secondary-Dns", 5, "ipaddr", VendorPackERX, VendorSemanticIPv4Address, "string", VendorSemanticIPv4Address),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Tunnel-Virtual-Router", 8, "string", VendorPackERX, VendorSemanticVRF, "string", VendorSemanticVRF),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Tunnel-Password", 9, "string", VendorPackERX, VendorSemanticPolicyTag, "string", VendorSemanticPolicyTag),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Ingress-Policy-Name", 10, "string", VendorPackERX, VendorSemanticACL, "string", VendorSemanticACL),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Egress-Policy-Name", 11, "string", VendorPackERX, VendorSemanticACL, "string", VendorSemanticACL),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Redirect-VR-Name", 25, "string", VendorPackERX, VendorSemanticPortalProfile, "string", VendorSemanticPortalProfile),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Qos-Profile-Name", 26, "string", VendorPackERX, VendorSemanticBandwidthProfile, "string", VendorSemanticBandwidthProfile),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Pppoe-Max-Sessions", 27, "integer", VendorPackERX, VendorSemanticSessionTimeout, "integer_text", VendorSemanticSessionTimeout),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Pppoe-Url", 28, "string", VendorPackERX, VendorSemanticPortalProfile, "string", VendorSemanticPortalProfile),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Service-Bundle", 31, "string", VendorPackERX, VendorSemanticPolicyTag, "string", VendorSemanticPolicyTag),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Tunnel-Maximum-Sessions", 33, "integer", VendorPackERX, VendorSemanticSessionTimeout, "integer_text", VendorSemanticSessionTimeout),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Framed-Ip-Route-Tag", 34, "string", VendorPackERX, VendorSemanticRoute, "string", VendorSemanticRoute),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-PPP-Username", 36, "string", VendorPackERX, VendorSemanticAccountingIdentity, "string", VendorSemanticAccountingIdentity),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-PPP-Password", 37, "string", VendorPackERX, VendorSemanticPolicyTag, "string", VendorSemanticPolicyTag),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-PPP-Auth-Protocol", 38, "integer", VendorPackERX, VendorSemanticPolicyTag, "integer_text", VendorSemanticPolicyTag),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-IpV6-Virtual-Router", 45, "string", VendorPackERX, VendorSemanticVRF, "string", VendorSemanticVRF),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-IpV6-Local-Interface", 46, "string", VendorPackERX, VendorSemanticAccountingIdentity, "string", VendorSemanticAccountingIdentity),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Ipv6-Primary-Dns", 47, "ipv6addr", VendorPackERX, VendorSemanticIPv6Address, "string", VendorSemanticIPv6Address),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Ipv6-Secondary-Dns", 48, "ipv6addr", VendorPackERX, VendorSemanticIPv6Address, "string", VendorSemanticIPv6Address),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "Sdx-Service-Name", 49, "string", VendorPackERX, VendorSemanticPolicyTag, "string", VendorSemanticPolicyTag),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "Sdx-Tunnel-Disconnect-Cause-Info", 51, "string", VendorPackERX, VendorSemanticCoADisconnect, "string", VendorSemanticCoADisconnect),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Radius-Client-Address", 52, "ipaddr", VendorPackERX, VendorSemanticAccountingIdentity, "string", VendorSemanticAccountingIdentity),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Service-Description", 53, "string", VendorPackERX, VendorSemanticPolicyTag, "string", VendorSemanticPolicyTag),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Dhcp-Mac-Addr", 56, "string", VendorPackERX, VendorSemanticAccountingIdentity, "string", VendorSemanticAccountingIdentity),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Dhcp-Gi-Address", 57, "ipaddr", VendorPackERX, VendorSemanticAccountingIdentity, "string", VendorSemanticAccountingIdentity),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-MLPPP-Bundle-Name", 62, "string", VendorPackERX, VendorSemanticAccountingIdentity, "string", VendorSemanticAccountingIdentity),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Tunnel-Group", 64, "string", VendorPackERX, VendorSemanticPolicyTag, "string", VendorSemanticPolicyTag),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Service-Activate", 65, "string", VendorPackERX, VendorSemanticSessionAction, "string", VendorSemanticSessionAction),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Service-Deactivate", 66, "string", VendorPackERX, VendorSemanticSessionAction, "string", VendorSemanticSessionAction),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Service-Volume", 67, "integer", VendorPackERX, VendorSemanticDataQuota, "data_quota", VendorSemanticDataQuota),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Service-Timeout", 68, "integer", VendorPackERX, VendorSemanticSessionTimeout, "integer_text", VendorSemanticSessionTimeout),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Qos-Parameters", 82, "string", VendorPackERX, VendorSemanticBandwidthProfile, "string", VendorSemanticBandwidthProfile),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Service-Session", 83, "string", VendorPackERX, VendorSemanticAccountingIdentity, "string", VendorSemanticAccountingIdentity),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Mobile-IP-Key", 86, "string", VendorPackERX, VendorSemanticPolicyTag, "string", VendorSemanticPolicyTag),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-IPv6-Ingress-Policy-Name", 106, "string", VendorPackERX, VendorSemanticACL, "string", VendorSemanticACL),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-IPv6-Egress-Policy-Name", 107, "string", VendorPackERX, VendorSemanticACL, "string", VendorSemanticACL),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Act-Data-Rate-Up", 113, "integer", VendorPackERX, VendorSemanticUploadBandwidth, "rate_kbps", VendorSemanticUploadBandwidth),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Act-Data-Rate-Dn", 114, "integer", VendorPackERX, VendorSemanticDownloadBandwidth, "rate_kbps", VendorSemanticDownloadBandwidth),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Max-Data-Rate-Up", 119, "integer", VendorPackERX, VendorSemanticUploadBandwidth, "rate_kbps", VendorSemanticUploadBandwidth),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Max-Data-Rate-Dn", 120, "integer", VendorPackERX, VendorSemanticDownloadBandwidth, "rate_kbps", VendorSemanticDownloadBandwidth),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-IPv6-NdRa-Prefix", 129, "ipv6prefix", VendorPackERX, VendorSemanticRouterAdvertisement, "string", VendorSemanticRouterAdvertisement),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Qos-Set-Name", 130, "string", VendorPackERX, VendorSemanticBandwidthProfile, "string", VendorSemanticBandwidthProfile),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Service-Acct-Interval", 140, "integer", VendorPackERX, VendorSemanticAccountingCounters, "integer_text", VendorSemanticAccountingCounters),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-DownStream-Calc-Rate", 141, "integer", VendorPackERX, VendorSemanticDownloadBandwidth, "rate_kbps", VendorSemanticDownloadBandwidth),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-UpStream-Calc-Rate", 142, "integer", VendorPackERX, VendorSemanticUploadBandwidth, "rate_kbps", VendorSemanticUploadBandwidth),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Max-Clients-Per-Interface", 143, "integer", VendorPackERX, VendorSemanticPolicyTag, "integer_text", VendorSemanticPolicyTag),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-IPv6-Delegated-Pool-Name", 161, "string", VendorPackERX, VendorSemanticDelegatedIPv6Prefix, "string", VendorSemanticDelegatedIPv6Prefix),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Client-Profile-Name", 174, "string", VendorPackERX, VendorSemanticDeviceGroup, "string", VendorSemanticDeviceGroup),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Redirect-GW-Address", 175, "ipaddr", VendorPackERX, VendorSemanticPortalProfile, "string", VendorSemanticPortalProfile),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-APN-Name", 176, "string", VendorPackERX, VendorSemanticTenant, "string", VendorSemanticTenant),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Cos-Shaping-Rate", 177, "string", VendorPackERX, VendorSemanticBandwidthProfile, "string", VendorSemanticBandwidthProfile),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Update-Service", 180, "string", VendorPackERX, VendorSemanticSessionAction, "string", VendorSemanticSessionAction),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-DHCPv6-Guided-Relay-Server", 181, "ipv6addr", VendorPackERX, VendorSemanticDHCPv6, "string", VendorSemanticDHCPv6),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Input-Interface-Filter", 191, "string", VendorPackERX, VendorSemanticACL, "string", VendorSemanticACL),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Output-Interface-Filter", 192, "string", VendorPackERX, VendorSemanticACL, "string", VendorSemanticACL),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Bulk-CoA-Transaction-Id", 194, "integer", VendorPackERX, VendorSemanticCoAReauth, "integer_text", VendorSemanticCoAReauth),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Bulk-CoA-Identifier", 195, "integer", VendorPackERX, VendorSemanticCoAReauth, "integer_text", VendorSemanticCoAReauth),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-IPv4-Input-Service-Set", 196, "string", VendorPackERX, VendorSemanticPolicyTag, "string", VendorSemanticPolicyTag),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-IPv4-Output-Service-Set", 197, "string", VendorPackERX, VendorSemanticPolicyTag, "string", VendorSemanticPolicyTag),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-IPv6-Input-Service-Set", 200, "string", VendorPackERX, VendorSemanticPolicyTag, "string", VendorSemanticPolicyTag),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-IPv6-Output-Service-Set", 201, "string", VendorPackERX, VendorSemanticPolicyTag, "string", VendorSemanticPolicyTag),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Adv-Pcef-Rule-Name", 205, "string", VendorPackERX, VendorSemanticDynamicACL, "string", VendorSemanticDynamicACL),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Acct-Request-Reason", 210, "integer", VendorPackERX, VendorSemanticAccountingCounters, "integer_text", VendorSemanticAccountingCounters),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Routing-Services", 212, "integer", VendorPackERX, VendorSemanticRoute, "integer_text", VendorSemanticRoute),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-ONT-ONU-Average-Data-Rate-Downstream", 220, "integer", VendorPackERX, VendorSemanticDownloadBandwidth, "rate_kbps", VendorSemanticDownloadBandwidth),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-ONT-ONU-Peak-Data-Rate-Downstream", 221, "integer", VendorPackERX, VendorSemanticDownloadBandwidth, "rate_kbps", VendorSemanticDownloadBandwidth),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-ONT-ONU-Maximum-Data-Rate-Upstream", 222, "integer", VendorPackERX, VendorSemanticUploadBandwidth, "rate_kbps", VendorSemanticUploadBandwidth),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-ONT-ONU-Assured-Data-Rate-Upstream", 223, "integer", VendorPackERX, VendorSemanticUploadBandwidth, "rate_kbps", VendorSemanticUploadBandwidth),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Gamma-Data-Rate-Upstream", 230, "integer", VendorPackERX, VendorSemanticUploadBandwidth, "rate_kbps", VendorSemanticUploadBandwidth),
		juniperExtremeRuntimeAnnotation("ERX", 4874, "ERX-Gamma-Data-Rate-Downstream", 231, "integer", VendorPackERX, VendorSemanticDownloadBandwidth, "rate_kbps", VendorSemanticDownloadBandwidth),
	}
}

func juniperExtremeRuntimeAnnotation(vendor string, pen uint32, attribute string, number uint32, wireType, packKey, semantic, decodeKind, decodeSemantic string) AttributeRegistryEntry {
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
		if annotation.DictionaryStatus == "" {
			annotation.DictionaryStatus = "partial"
		}
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
	r.applyRuckusICXRuntimeProfile()
	r.applyFortinetPaloAltoRuntimeProfile()
	r.applyAccessVendorRuntimeProfile()
	r.applyBroadbandVendorRuntimeProfile()
	r.applyNokiaALURuntimeProfile()
	r.applyMikroTikRuntimeProfile()
	r.applySwitchingVendorRuntimeProfile()
	r.applyLongTailNamespaceRuntimeProfile()
}

func (r *AttributeRegistry) applyRuckusICXRuntimeProfile() {
	if r == nil {
		return
	}
	for idx := range r.Entries {
		entry := &r.Entries[idx]
		if !isRuckusICXRegistryVendor(entry.Vendor) {
			continue
		}
		wasMissing := entry.DictionaryStatus == "missing"
		semantic := ruckusICXRegistrySemantic(*entry)
		entry.PackKey = ruckusICXRegistryPack(entry.Vendor)
		entry.Semantic = mergeRegistrySemantics(entry.Semantic, semantic)
		entry.SemanticProvenance = mergeRegistrySemantics(entry.SemanticProvenance, "aegisnas-runtime:nas-0064")
		entry.Directions = ruckusICXRegistryDirections(*entry, semantic)
		entry.Functionality = ruckusICXRegistryFunctionality(*entry, semantic)
		entry.DecodeKind, entry.DecodeSemantic, entry.DecodeScale = ruckusICXRegistryDecoder(*entry, semantic)
		if wasMissing {
			entry.DictionaryStatus = "partial"
			r.MappedCount++
		}
	}
}

func isRuckusICXRegistryVendor(vendor string) bool {
	switch strings.ToLower(strings.TrimSpace(vendor)) {
	case "ruckus", "foundry":
		return true
	default:
		return false
	}
}

func ruckusICXRegistryPack(vendor string) string {
	switch strings.ToLower(strings.TrimSpace(vendor)) {
	case "foundry":
		return VendorPackFoundry
	default:
		return VendorPackRuckus
	}
}

func ruckusICXRegistrySemantic(entry AttributeRegistryEntry) string {
	name := strings.ToLower(entry.Attribute)
	vendor := strings.ToLower(entry.Vendor)
	if vendor == "foundry" {
		switch {
		case containsAnyRuckusICXRegistryToken(name, "coa"):
			return VendorSemanticCoAReauth
		case containsAnyRuckusICXRegistryToken(name, "access-list"):
			return VendorSemanticACL
		case containsAnyRuckusICXRegistryToken(name, "vlan-qos"):
			return VendorSemanticVLAN + "," + VendorSemanticBandwidthProfile
		case containsAnyRuckusICXRegistryToken(name, "802.1x", "mac-authent"):
			return VendorSemanticDevicePosture
		case containsAnyRuckusICXRegistryToken(name, "voice"):
			return VendorSemanticPolicyTag
		case containsAnyRuckusICXRegistryToken(name, "command", "privilege", "role"):
			return VendorSemanticRole
		default:
			return VendorSemanticPolicyTag
		}
	}
	switch {
	case containsAnyRuckusICXRegistryToken(name, "gn-user-name", "imsi", "msisdn", "apn", "sgsn", "pdp", "charging", "cdr", "cell", "area"):
		return VendorSemanticAccountingIdentity
	case containsAnyRuckusICXRegistryToken(name, "dpsk", "triplets", "flexauth", "auth-type", "auth-server"):
		return VendorSemanticPolicyTag
	case containsAnyRuckusICXRegistryToken(name, "acct-ctrs", "accounting-status", "session-type", "start-time"):
		return VendorSemanticAccountingCounters
	case containsAnyRuckusICXRegistryToken(name, "ssid", "wlan", "bssid", "roamed", "eth-profile", "sta-rssi", "sta-uuid", "sta-inner"):
		return VendorSemanticDeviceGroup
	case containsAnyRuckusICXRegistryToken(name, "location", "domain"):
		return VendorSemanticTenant
	case containsAnyRuckusICXRegistryToken(name, "wispr", "cp-token"):
		return VendorSemanticPortalProfile + "," + VendorSemanticGuestLifecycle
	case containsAnyRuckusICXRegistryToken(name, "vlan"):
		return VendorSemanticVLAN
	case containsAnyRuckusICXRegistryToken(name, "quota"):
		return VendorSemanticDataQuota
	case containsAnyRuckusICXRegistryToken(name, "qos", "traffic-class", "tc-"):
		return VendorSemanticBandwidthProfile
	case containsAnyRuckusICXRegistryToken(name, "nat-pool"):
		return VendorSemanticAddressPool + "," + VendorSemanticTranslationPublicIPv4
	case containsAnyRuckusICXRegistryToken(name, "client-local-ip", "aaa-ip"):
		return VendorSemanticIPv4Address
	case containsAnyRuckusICXRegistryToken(name, "zone", "cluster", "blade", "nas-type", "aaa-id", "utp", "sci-resource"):
		return VendorSemanticDeviceGroup
	case containsAnyRuckusICXRegistryToken(name, "client-host"):
		return VendorSemanticAccountingIdentity
	case containsAnyRuckusICXRegistryToken(name, "client-os", "client-device"):
		return VendorSemanticDevicePosture
	case containsAnyRuckusICXRegistryToken(name, "user-groups", "policy-name", "sci-role"):
		return VendorSemanticRole
	case containsAnyRuckusICXRegistryToken(name, "grace-period", "expiration"):
		return VendorSemanticSessionTimeout
	default:
		return VendorSemanticPolicyTag
	}
}

func ruckusICXRegistryDirections(entry AttributeRegistryEntry, semantic string) []string {
	name := strings.ToLower(entry.Attribute)
	switch {
	case containsAnyRuckusICXRegistryToken(name, "acct-ctrs", "accounting-status", "client-host", "client-os", "client-device", "client-local-ip", "client-remote-ip", "imsi", "msisdn", "apn", "sgsn", "cdr", "cell", "area", "start-time"):
		return []string{"accounting", "inbound"}
	case containsAnyRuckusICXRegistryToken(name, "coa"):
		return []string{"coa", "inbound", "outbound_reply"}
	case registrySemanticContains(semantic, VendorSemanticControllerHealth):
		return []string{"controller_api", "inbound"}
	case containsAnyRuckusICXRegistryToken(name, "zone"):
		return []string{"accounting", "controller_api", "inbound", "outbound_reply"}
	case containsAnyRuckusICXRegistryToken(name, "cluster", "domain", "blade", "aaa-id", "auth-server", "utp"):
		return []string{"accounting", "controller_api", "inbound"}
	default:
		return []string{"accounting", "inbound", "outbound_reply"}
	}
}

func ruckusICXRegistryDecoder(entry AttributeRegistryEntry, semantic string) (string, string, int) {
	if entry.Number == 0 || entry.Number > 255 {
		return "", "", 0
	}
	baseType := baseDictionaryWireType(entry.WireType)
	switch baseType {
	case "tlv", "group", "struct":
		return "", "", 0
	}
	decodeSemantic := firstRegistrySemantic(semantic)
	if isRuckusICXRegistrySensitiveAttribute(entry.Attribute) {
		return "string", decodeSemantic, 0
	}
	if baseType == "ipaddr" {
		return "ipaddr", decodeSemantic, 0
	}
	if registrySemanticContains(semantic, VendorSemanticDataQuota) && registryIntegerType(entry.WireType) {
		return "data_quota", VendorSemanticDataQuota, 0
	}
	if registrySemanticContains(semantic, VendorSemanticVLAN) {
		if registryIntegerType(entry.WireType) {
			return "vlan", VendorSemanticVLAN, 0
		}
		return "string", VendorSemanticVLAN, 0
	}
	if registrySemanticContains(semantic, VendorSemanticUploadBandwidth) || registrySemanticContains(semantic, VendorSemanticDownloadBandwidth) {
		if registryIntegerType(entry.WireType) {
			return "rate_kbps", decodeSemantic, 1
		}
		return "string", decodeSemantic, 0
	}
	if registryIntegerType(entry.WireType) {
		return "integer_text", decodeSemantic, 0
	}
	return "string", decodeSemantic, 0
}

func ruckusICXRegistryFunctionality(entry AttributeRegistryEntry, semantic string) string {
	scope := "Ruckus SmartZone, ZoneDirector, Unleashed, and ICX/Foundry policy"
	if strings.EqualFold(entry.Vendor, "Foundry") {
		scope = "Ruckus ICX and Foundry switch policy"
	}
	return fmt.Sprintf("%s carries %s for %s; AegisNAS normalizes known semantics, redacts secret or subscriber identifiers, and stores bounded evidence until hardware certification is attached.", entry.Attribute, strings.ReplaceAll(semantic, ",", "/"), scope)
}

func isRuckusICXRegistrySensitiveAttribute(attribute string) bool {
	name := strings.ToLower(strings.TrimSpace(attribute))
	return containsAnyRuckusICXRegistryToken(name,
		"dpsk", "eapol-key-frame", "triplets", "imsi", "msisdn",
		"charging-charac", "pdp-type", "dynamic-address-flag",
		"chch-selection-mode", "sgsn-number", "area-code", "cell-identifier",
		"read-preference",
	)
}

func containsAnyRuckusICXRegistryToken(value string, tokens ...string) bool {
	value = strings.ToLower(value)
	for _, token := range tokens {
		if strings.Contains(value, token) {
			return true
		}
	}
	return false
}

func (r *AttributeRegistry) applyFortinetPaloAltoRuntimeProfile() {
	if r == nil {
		return
	}
	for idx := range r.Entries {
		entry := &r.Entries[idx]
		if !isFortinetPaloAltoRegistryVendor(entry.Vendor) {
			continue
		}
		wasMissing := entry.DictionaryStatus == "missing"
		semantic := fortinetPaloAltoRegistrySemantic(*entry)
		entry.PackKey = fortinetPaloAltoRegistryPack(entry.Vendor)
		entry.Semantic = mergeRegistrySemantics(entry.Semantic, semantic)
		entry.SemanticProvenance = mergeRegistrySemantics(entry.SemanticProvenance, "aegisnas-runtime:nas-0065")
		entry.Directions = fortinetPaloAltoRegistryDirections(*entry, semantic)
		entry.Functionality = fortinetPaloAltoRegistryFunctionality(*entry, semantic)
		entry.DecodeKind, entry.DecodeSemantic, entry.DecodeScale = fortinetPaloAltoRegistryDecoder(*entry, semantic)
		if wasMissing {
			entry.DictionaryStatus = "partial"
			r.MappedCount++
		}
	}
}

func isFortinetPaloAltoRegistryVendor(vendor string) bool {
	switch strings.ToLower(strings.TrimSpace(vendor)) {
	case "fortinet", "paloalto":
		return true
	default:
		return false
	}
}

func fortinetPaloAltoRegistryPack(vendor string) string {
	if strings.EqualFold(strings.TrimSpace(vendor), "PaloAlto") {
		return VendorPackPaloAlto
	}
	return VendorPackFortinet
}

func fortinetPaloAltoRegistrySemantic(entry AttributeRegistryEntry) string {
	name := strings.ToLower(entry.Attribute)
	vendor := strings.ToLower(entry.Vendor)
	if vendor == "paloalto" {
		switch {
		case containsAnyFortinetPaloAltoRegistryToken(name, "admin-role", "panorama-admin-role"):
			return VendorSemanticRole
		case containsAnyFortinetPaloAltoRegistryToken(name, "access-domain", "user-domain"):
			return VendorSemanticTenant
		case containsAnyFortinetPaloAltoRegistryToken(name, "user-group"):
			return VendorSemanticDeviceGroup
		case containsAnyFortinetPaloAltoRegistryToken(name, "source-ip"):
			return VendorSemanticIPv4Address
		case containsAnyFortinetPaloAltoRegistryToken(name, "client-os", "globalprotect"):
			return VendorSemanticDevicePosture
		case containsAnyFortinetPaloAltoRegistryToken(name, "hostname"):
			return VendorSemanticAccountingIdentity
		default:
			return VendorSemanticPolicyTag
		}
	}
	switch {
	case containsAnyFortinetPaloAltoRegistryToken(name, "group-name", "user-role", "is-system-admin", "is-spp-admin"):
		return VendorSemanticRole
	case containsAnyFortinetPaloAltoRegistryToken(name, "vdom"):
		return VendorSemanticTenant + "," + VendorSemanticVRF
	case containsAnyFortinetPaloAltoRegistryToken(name, "tenant"):
		return VendorSemanticTenant
	case containsAnyFortinetPaloAltoRegistryToken(name, "client-ip-address"):
		return VendorSemanticIPv4Address
	case containsAnyFortinetPaloAltoRegistryToken(name, "client-ipv6-address"):
		return VendorSemanticIPv6Address
	case containsAnyFortinetPaloAltoRegistryToken(name, "interface", "ap-name", "ssid"):
		return VendorSemanticDeviceGroup
	case containsAnyFortinetPaloAltoRegistryToken(name, "wirelesscontroller-device-mac", "wirelesscontroller-wtp-id", "assoc-time"):
		return VendorSemanticAccountingIdentity
	case containsAnyFortinetPaloAltoRegistryToken(name, "fac-auth-status"):
		return VendorSemanticDevicePosture
	case containsAnyFortinetPaloAltoRegistryToken(name, "fac-token", "fac-challenge"):
		return VendorSemanticCertificateOnboarding
	case containsAnyFortinetPaloAltoRegistryToken(name, "trusted-hosts", "fortiwan-avpair", "host-port-avpair"):
		return VendorSemanticDynamicACL + "," + VendorSemanticRoute + "," + VendorSemanticPolicyTag
	case containsAnyFortinetPaloAltoRegistryToken(name, "appctrl-risk"):
		return VendorSemanticDevicePosture + "," + VendorSemanticPolicyTag
	case containsAnyFortinetPaloAltoRegistryToken(name, "webfilter", "appctrl", "access-profile", "fdd-access-profile", "fdd-spp-name", "fdd-spp-policy-group", "allow-api-access"):
		return VendorSemanticPolicyTag
	default:
		return VendorSemanticPolicyTag
	}
}

func fortinetPaloAltoRegistryDirections(entry AttributeRegistryEntry, semantic string) []string {
	name := strings.ToLower(entry.Attribute)
	switch {
	case containsAnyFortinetPaloAltoRegistryToken(name, "interface-name", "ap-name"):
		return []string{"accounting", "inbound", "outbound_reply"}
	case containsAnyFortinetPaloAltoRegistryToken(name, "client-os", "client-hostname", "client-source-ip", "wirelesscontroller", "assoc-time", "device-mac"):
		return []string{"accounting", "inbound"}
	case containsAnyFortinetPaloAltoRegistryToken(name, "fac-token", "fac-challenge", "fac-auth"):
		return []string{"inbound", "outbound_reply"}
	case registrySemanticContains(semantic, VendorSemanticDynamicACL):
		return []string{"accounting", "inbound", "outbound_reply"}
	default:
		return []string{"accounting", "inbound", "outbound_reply"}
	}
}

func fortinetPaloAltoRegistryDecoder(entry AttributeRegistryEntry, semantic string) (string, string, int) {
	if entry.Number == 0 || entry.Number > 255 {
		return "", "", 0
	}
	baseType := baseDictionaryWireType(entry.WireType)
	decodeSemantic := firstRegistrySemantic(semantic)
	if isFortinetPaloAltoRegistrySensitiveAttribute(entry.Attribute) {
		return "string", decodeSemantic, 0
	}
	if strings.EqualFold(entry.Attribute, "Fortinet-Client-IPv6-Address") {
		return "ipv6addr", VendorSemanticIPv6Address, 0
	}
	if strings.EqualFold(entry.Attribute, "PaloAlto-Client-Source-IP") {
		return "ipaddr", VendorSemanticIPv4Address, 0
	}
	if baseType == "ipaddr" {
		return "ipaddr", decodeSemantic, 0
	}
	if baseType == "ether" {
		return "ether", decodeSemantic, 0
	}
	if baseType == "date" {
		return "integer_text", decodeSemantic, 0
	}
	if baseType == "octets" {
		return "octets_hex", decodeSemantic, 0
	}
	if registrySemanticContains(semantic, VendorSemanticDynamicACL) && strings.Contains(strings.ToLower(entry.Attribute), "avpair") {
		return "avpairs", VendorSemanticDynamicACL, 0
	}
	if registryIntegerType(entry.WireType) {
		return "integer_text", decodeSemantic, 0
	}
	return "string", decodeSemantic, 0
}

func fortinetPaloAltoRegistryFunctionality(entry AttributeRegistryEntry, semantic string) string {
	scope := "Fortinet FortiGate, FortiAuthenticator, FortiNAC, FortiDeceptor, FortiWAN, FortiAP, and FortiSwitch policy"
	if strings.EqualFold(entry.Vendor, "PaloAlto") {
		scope = "Palo Alto PAN-OS, GlobalProtect, User-ID, and Panorama policy"
	}
	return fmt.Sprintf("%s carries %s for %s; AegisNAS normalizes known semantics, redacts challenge secrets, and stores bounded evidence until hardware certification is attached.", entry.Attribute, strings.ReplaceAll(semantic, ",", "/"), scope)
}

func isFortinetPaloAltoRegistrySensitiveAttribute(attribute string) bool {
	name := strings.ToLower(strings.TrimSpace(attribute))
	return containsAnyFortinetPaloAltoRegistryToken(name, "fac-token", "fac-challenge")
}

func containsAnyFortinetPaloAltoRegistryToken(value string, tokens ...string) bool {
	value = strings.ToLower(value)
	for _, token := range tokens {
		if strings.Contains(value, token) {
			return true
		}
	}
	return false
}

func (r *AttributeRegistry) applyAccessVendorRuntimeProfile() {
	if r == nil {
		return
	}
	for idx := range r.Entries {
		entry := &r.Entries[idx]
		if !isAccessVendorRegistryVendor(entry.Vendor) {
			continue
		}
		wasMissing := entry.DictionaryStatus == "missing"
		semantic := accessVendorRegistrySemantic(*entry)
		entry.PackKey = accessVendorRegistryPack(entry.Vendor)
		entry.Semantic = mergeRegistrySemantics(entry.Semantic, semantic)
		entry.SemanticProvenance = mergeRegistrySemantics(entry.SemanticProvenance, "aegisnas-runtime:nas-0067")
		entry.Directions = accessVendorRegistryDirections(*entry, semantic)
		entry.Functionality = accessVendorRegistryFunctionality(*entry, semantic)
		entry.DecodeKind, entry.DecodeSemantic, entry.DecodeScale = accessVendorRegistryDecoder(*entry, semantic)
		if wasMissing {
			entry.DictionaryStatus = "partial"
			r.MappedCount++
		}
	}
}

func isAccessVendorRegistryVendor(vendor string) bool {
	switch strings.ToLower(strings.TrimSpace(vendor)) {
	case "cambium", "tplink", "dlink":
		return true
	default:
		return false
	}
}

func accessVendorRegistryPack(vendor string) string {
	switch strings.ToLower(strings.TrimSpace(vendor)) {
	case "cambium":
		return VendorPackCambium
	case "tplink":
		return VendorPackTPLink
	default:
		return VendorPackDLink
	}
}

func accessVendorRegistrySemantic(entry AttributeRegistryEntry) string {
	name := strings.ToLower(entry.Attribute)
	switch accessVendorRegistryPack(entry.Vendor) {
	case VendorPackCambium:
		switch {
		case containsAnyAccessVendorRegistryToken(name, "auth-role", "userlevel"):
			return VendorSemanticRole
		case containsAnyAccessVendorRegistryToken(name, "data-vlan-id", "management-vlan-id", "separate-management-vlan-id", "multicast-vlan-id", "vlan-mapping"):
			return VendorSemanticVLAN
		case containsAnyAccessVendorRegistryToken(name, "vlan-pool"):
			return VendorSemanticVLAN + "," + VendorSemanticAddressPool
		case containsAnyAccessVendorRegistryToken(name, "vlan-membersip-set"):
			return VendorSemanticVLAN + "," + VendorSemanticPolicyTag
		case containsAnyAccessVendorRegistryToken(name, "max-burst-uplink"):
			return VendorSemanticUploadBandwidth
		case containsAnyAccessVendorRegistryToken(name, "max-burst-downlink"):
			return VendorSemanticDownloadBandwidth
		case containsAnyAccessVendorRegistryToken(name, "traffic-quota-limit"):
			return VendorSemanticDataQuota
		case containsAnyAccessVendorRegistryToken(name, "sm-priority", "vlan-priority"):
			return VendorSemanticBandwidthProfile
		case containsAnyAccessVendorRegistryToken(name, "authorize-bytes-left"):
			return VendorSemanticDataQuota
		case containsAnyAccessVendorRegistryToken(name, "authorize-class-name"):
			return VendorSemanticBandwidthProfile
		case containsAnyAccessVendorRegistryToken(name, "authorize-classes"):
			return VendorSemanticDataQuota + "," + VendorSemanticBandwidthProfile
		case containsAnyAccessVendorRegistryToken(name, "acct-class-name"):
			return VendorSemanticAccountingIdentity
		case containsAnyAccessVendorRegistryToken(name, "traffic-classes-acct", "acct-input", "acct-output"):
			return VendorSemanticAccountingCounters
		case containsAnyAccessVendorRegistryToken(name, "walled-garden"):
			return VendorSemanticQuarantine + "," + VendorSemanticPortalProfile
		default:
			return VendorSemanticPolicyTag
		}
	case VendorPackTPLink:
		switch {
		case containsAnyAccessVendorRegistryToken(name, "recv-limit"):
			return VendorSemanticUploadBandwidth
		case containsAnyAccessVendorRegistryToken(name, "xmit-limit"):
			return VendorSemanticDownloadBandwidth
		case containsAnyAccessVendorRegistryToken(name, "authentication-findkey", "authentication-foundkey"):
			return VendorSemanticCertificateOnboarding
		case containsAnyAccessVendorRegistryToken(name, "user-command"):
			return VendorSemanticRole
		case containsAnyAccessVendorRegistryToken(name, "site"):
			return VendorSemanticTenant
		case containsAnyAccessVendorRegistryToken(name, "omada"):
			return VendorSemanticDeviceGroup
		case containsAnyAccessVendorRegistryToken(name, "redirect-url", "portal-access-status"):
			return VendorSemanticPortalProfile + "," + VendorSemanticGuestLifecycle
		default:
			return VendorSemanticPolicyTag
		}
	default:
		switch {
		case containsAnyAccessVendorRegistryToken(name, "user-level"):
			return VendorSemanticRole
		case containsAnyAccessVendorRegistryToken(name, "ingress-bandwidth"):
			return VendorSemanticUploadBandwidth
		case containsAnyAccessVendorRegistryToken(name, "egress-bandwidth"):
			return VendorSemanticDownloadBandwidth
		case containsAnyAccessVendorRegistryToken(name, "1p-priority"):
			return VendorSemanticBandwidthProfile
		case containsAnyAccessVendorRegistryToken(name, "vlan-id", "vlan-name"):
			return VendorSemanticVLAN
		case containsAnyAccessVendorRegistryToken(name, "acl-profile"):
			return VendorSemanticACL
		case containsAnyAccessVendorRegistryToken(name, "acl-rule", "acl-script"):
			return VendorSemanticDynamicACL
		default:
			return VendorSemanticPolicyTag
		}
	}
}

func accessVendorRegistryDirections(entry AttributeRegistryEntry, semantic string) []string {
	name := strings.ToLower(entry.Attribute)
	switch {
	case containsAnyAccessVendorRegistryToken(name, "acct-", "traffic-classes-acct"):
		return []string{"accounting", "inbound"}
	case containsAnyAccessVendorRegistryToken(name, "authentication-findkey", "authentication-foundkey"):
		return []string{"inbound"}
	case registrySemanticContains(semantic, VendorSemanticACL) || registrySemanticContains(semantic, VendorSemanticDynamicACL):
		return []string{"inbound", "outbound_reply"}
	case registrySemanticContains(semantic, VendorSemanticDataQuota):
		return []string{"inbound", "outbound_reply", "accounting"}
	default:
		return []string{"inbound", "outbound_reply"}
	}
}

func accessVendorRegistryDecoder(entry AttributeRegistryEntry, semantic string) (string, string, int) {
	if entry.Number == 0 || entry.Number > 255 {
		return "", "", 0
	}
	baseType := baseDictionaryWireType(entry.WireType)
	decodeSemantic := firstRegistrySemantic(semantic)
	if baseType == "tlv" || baseType == "group" || baseType == "struct" {
		return "", "", 0
	}
	if baseType == "octets" {
		return "octets_hex", decodeSemantic, 0
	}
	if registrySemanticContains(semantic, VendorSemanticQuarantine) {
		return "bool", VendorSemanticQuarantine, 0
	}
	if accessVendorRegistryPack(entry.Vendor) == VendorPackDLink && containsAnyAccessVendorRegistryToken(strings.ToLower(entry.Attribute), "vlan-id") {
		return "vlan", VendorSemanticVLAN, 0
	}
	if registrySemanticContains(semantic, VendorSemanticVLAN) {
		if baseType == "string" {
			return "string", semantic, 0
		}
		return "vlan", VendorSemanticVLAN, 0
	}
	if containsAnyAccessVendorRegistryToken(strings.ToLower(entry.Attribute), "portal-access-status") {
		return "mapped_portal_status", VendorSemanticPortalProfile, 0
	}
	if registrySemanticContains(semantic, VendorSemanticUploadBandwidth) || registrySemanticContains(semantic, VendorSemanticDownloadBandwidth) {
		if registryIntegerType(baseType) {
			return "rate_kbps", decodeSemantic, 1
		}
		return "string", decodeSemantic, 0
	}
	if registrySemanticContains(semantic, VendorSemanticDataQuota) {
		if registryIntegerType(baseType) {
			return "data_quota", VendorSemanticDataQuota, 0
		}
		return "string", VendorSemanticDataQuota, 0
	}
	if registrySemanticContains(semantic, VendorSemanticRole) && registryIntegerType(baseType) {
		return "mapped_role", VendorSemanticRole, 0
	}
	if registryIntegerType(baseType) {
		return "integer_text", decodeSemantic, 0
	}
	return "string", decodeSemantic, 0
}

func accessVendorRegistryFunctionality(entry AttributeRegistryEntry, semantic string) string {
	scope := "Cambium cnMaestro/ePMP/PMP access policy"
	switch accessVendorRegistryPack(entry.Vendor) {
	case VendorPackTPLink:
		scope = "TP-Link Omada controller, AP, switch, and portal policy"
	case VendorPackDLink:
		scope = "D-Link access switch, AP, bandwidth, VLAN, and ACL policy"
	}
	return fmt.Sprintf("%s carries %s for %s; AegisNAS normalizes stable semantics, safely decodes typed wire values, redacts credential-like evidence, and keeps real device behavior in release certification.", entry.Attribute, strings.ReplaceAll(semantic, ",", "/"), scope)
}

func containsAnyAccessVendorRegistryToken(value string, tokens ...string) bool {
	value = strings.ToLower(value)
	for _, token := range tokens {
		if strings.Contains(value, token) {
			return true
		}
	}
	return false
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
	case registrySemanticContains(entry.Semantic, VendorSemanticDynamicACL) && (strings.Contains(name, "avpair") || strings.Contains(name, "av-pair")):
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
			for _, direction := range strings.Split(mapping.Direction, ",") {
				direction = strings.ToLower(strings.TrimSpace(direction))
				if direction == "" {
					continue
				}
				if !registryDirectionContains(entry.Directions, direction) {
					return fmt.Errorf("pack %s attribute %s direction %s is absent from the typed registry", packKey, mapping.Attribute, direction)
				}
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
