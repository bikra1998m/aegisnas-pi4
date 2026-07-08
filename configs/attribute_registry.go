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
	Source           string   `json:"source"`
	Key              string   `json:"key"`
	WireKey          string   `json:"wire_key"`
	Vendor           string   `json:"vendor"`
	PEN              uint32   `json:"pen"`
	Attribute        string   `json:"attribute"`
	Number           uint32   `json:"number,omitempty"`
	OID              string   `json:"oid,omitempty"`
	WireType         string   `json:"wire_type"`
	EnumeratedValues int      `json:"enumerated_values,omitempty"`
	CapabilityFamily string   `json:"capability_family"`
	DictionaryStatus string   `json:"dictionary_status"`
	PackKey          string   `json:"pack_key,omitempty"`
	Semantic         string   `json:"semantic,omitempty"`
	Directions       []string `json:"directions,omitempty"`
	Functionality    string   `json:"functionality,omitempty"`
	DecodeKind       string   `json:"decode_kind,omitempty"`
	DecodeSemantic   string   `json:"decode_semantic,omitempty"`
	DecodeScale      int      `json:"decode_scale,omitempty"`
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
		SchemaVersion:   AttributeRegistrySchemaVersion,
		SourceRelease:   FreeRADIUSRegistryRelease,
		SourceFileCount: FreeRADIUSRegistryFileCount,
		SourceSHA256:    hex.EncodeToString(digest[:]),
		byName:          map[string]int{},
		byWire:          map[string][]int{},
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
	vendor := strings.TrimSpace(record[0])
	attribute := strings.TrimSpace(record[2])
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
		Source: "freeradius-" + FreeRADIUSRegistryRelease,
		Vendor: vendor, PEN: uint32(pen), Attribute: attribute, Number: number, OID: oid,
		WireType: wireType, EnumeratedValues: enums, CapabilityFamily: strings.TrimSpace(record[7]),
		DictionaryStatus: status, PackKey: NormalizeVendorCompatibilityPackKey(record[9]),
		Semantic: strings.TrimSpace(record[10]), Directions: parseRegistryDirections(record[11]),
		Functionality: strings.TrimSpace(record[12]),
	}
	entry.Key = fmt.Sprintf("freeradius:%s:%d:%s", FreeRADIUSRegistryRelease, entry.PEN, strings.ToLower(entry.Attribute))
	if entry.Number > 0 {
		entry.WireKey = fmt.Sprintf("vsa:%d:%d", entry.PEN, entry.Number)
	} else {
		entry.WireKey = fmt.Sprintf("vsa:%d:%s", entry.PEN, entry.OID)
	}
	entry.DecodeKind, entry.DecodeScale = attributeRegistryDecoder(entry)
	if entry.DecodeKind != "" {
		entry.DecodeSemantic = firstRegistrySemantic(entry.Semantic)
	}
	return entry, nil
}

func (r *AttributeRegistry) addEntry(entry AttributeRegistryEntry) {
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
			Vendor: "Cisco", PEN: 9, Attribute: "Cisco-AVPair", Number: 1, WireType: "string",
			PackKey: VendorPackCisco, Semantic: VendorSemanticDynamicACL, Directions: []string{"inbound", "outbound_reply"}, DecodeKind: "string", DecodeSemantic: VendorSemanticDynamicACL,
		},
		{
			Vendor: "Nomadix", PEN: 3309, Attribute: "Nomadix-Bw-Class-Name", Number: 27, WireType: "string",
			PackKey: VendorPackNomadix, Semantic: VendorSemanticBandwidthProfile, Directions: []string{"inbound"}, DecodeKind: "string", DecodeSemantic: VendorSemanticBandwidthProfile,
		},
		{
			Vendor: "Meraki", PEN: 29671, Attribute: "Meraki-Ap-Name", Number: 3, WireType: "string",
			PackKey: VendorPackMeraki, Semantic: VendorSemanticAccountingIdentity, Directions: []string{"accounting", "inbound"}, DecodeKind: "string", DecodeSemantic: VendorSemanticAccountingIdentity,
		},
		{
			Vendor: "Arista", PEN: 30065, Attribute: "Arista-Segment-Id", Number: 11, WireType: "string",
			PackKey: VendorPackArista, Semantic: VendorSemanticVLAN, Directions: []string{"inbound", "outbound_reply"}, DecodeKind: "vlan", DecodeSemantic: VendorSemanticVLAN,
		},
		{
			Vendor: "Arista", PEN: 30065, Attribute: "Arista-Device-Profiling", Number: 17, WireType: "string",
			PackKey: VendorPackArista, Semantic: VendorSemanticDevicePosture, Directions: []string{"accounting", "inbound"}, DecodeKind: "string", DecodeSemantic: VendorSemanticDevicePosture,
		},
		{
			Vendor: "Arista", PEN: 30065, Attribute: "Arista-Tenant-Id", Number: 20, WireType: "integer",
			PackKey: VendorPackArista, Semantic: VendorSemanticTenant, Directions: []string{"inbound"}, DecodeKind: "integer_text", DecodeSemantic: VendorSemanticTenant,
		},
		{
			Vendor: "Arista", PEN: 30065, Attribute: "Arista-Interface-Profile", Number: 21, WireType: "string",
			PackKey: VendorPackArista, Semantic: VendorSemanticDeviceGroup, Directions: []string{"inbound", "outbound_reply"}, DecodeKind: "string", DecodeSemantic: VendorSemanticDeviceGroup,
		},
		{
			Source: "aegisnas-runtime", Vendor: "Ubiquiti", PEN: 41112, Attribute: "UBNT-Data-Rate-DL", Number: 1,
			WireType: "integer", CapabilityFamily: "Bandwidth/QoS", DictionaryStatus: "partial", PackKey: VendorPackUBNT,
			Semantic: VendorSemanticDownloadBandwidth, Directions: []string{"inbound", "outbound_reply"},
			Functionality: "Ubiquiti downstream data-rate assignment and accounting context.", DecodeKind: "rate_bps", DecodeSemantic: VendorSemanticDownloadBandwidth, DecodeScale: 1000,
		},
		{
			Source: "aegisnas-runtime", Vendor: "Ubiquiti", PEN: 41112, Attribute: "UBNT-Data-Rate-UL", Number: 3,
			WireType: "integer", CapabilityFamily: "Bandwidth/QoS", DictionaryStatus: "partial", PackKey: VendorPackUBNT,
			Semantic: VendorSemanticUploadBandwidth, Directions: []string{"inbound", "outbound_reply"},
			Functionality: "Ubiquiti upstream data-rate assignment and accounting context.", DecodeKind: "rate_bps", DecodeSemantic: VendorSemanticUploadBandwidth, DecodeScale: 1000,
		},
	}
	return entries
}

func (r *AttributeRegistry) applyRuntimeAnnotations(vendors map[string]struct{}) {
	for _, annotation := range runtimeAttributeRegistryAnnotations() {
		nameKey := attributeRegistryNameKey(annotation.Vendor, annotation.Attribute)
		if idx, exists := r.byName[nameKey]; exists {
			wasMissing := r.Entries[idx].DictionaryStatus == "missing"
			r.Entries[idx].PackKey = annotation.PackKey
			r.Entries[idx].Semantic = mergeRegistrySemantics(r.Entries[idx].Semantic, annotation.Semantic)
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
		annotation.DictionaryStatus = "partial"
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
	attribute = strings.ToLower(strings.TrimSpace(attribute))
	for _, entry := range r.Entries {
		if pack.VendorID > 0 && entry.PEN != uint32(pack.VendorID) {
			continue
		}
		if pack.VendorID == 0 && !strings.EqualFold(entry.Vendor, pack.VendorName) {
			continue
		}
		candidate := strings.ToLower(strings.TrimSpace(entry.Attribute))
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
