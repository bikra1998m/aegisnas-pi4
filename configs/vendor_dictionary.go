package configs

import (
	_ "embed"
	"strconv"
	"strings"
)

//go:embed dictionary.aegisnas
var aegisNASVendorDictionaryTemplate string

type VendorDictionary struct {
	Name       string                      `json:"name"`
	ID         int                         `json:"id"`
	Options    []string                    `json:"options,omitempty"`
	Attributes []VendorDictionaryAttribute `json:"attributes"`
}

type VendorDictionaryAttribute struct {
	Name    string                  `json:"name"`
	Number  int                     `json:"number"`
	OID     string                  `json:"oid,omitempty"`
	Type    string                  `json:"type"`
	Options []string                `json:"options,omitempty"`
	Values  []VendorDictionaryValue `json:"values,omitempty"`
}

type VendorDictionaryValue struct {
	Attribute string `json:"attribute"`
	Name      string `json:"name"`
	Value     string `json:"value"`
}

type VendorDictionaryWarning struct {
	Line    int    `json:"line"`
	Message string `json:"message"`
}

type VendorDictionaryCatalog struct {
	Source   string                    `json:"source,omitempty"`
	Vendors  []VendorDictionary        `json:"vendors"`
	Values   []VendorDictionaryValue   `json:"unresolved_values,omitempty"`
	Warnings []VendorDictionaryWarning `json:"warnings,omitempty"`
}

func AegisNASVendorDictionary() VendorDictionary {
	dict, ok := ParseVendorDictionary(AegisNASVendorDictionaryText())
	if ok {
		return dict
	}
	identity := AegisNASVendorIdentity()
	return VendorDictionary{Name: identity.Name, ID: identity.ID}
}

func AegisNASVendorDictionaryCatalog() VendorDictionaryCatalog {
	identity := AegisNASVendorIdentity()
	return AegisNASVendorDictionaryCatalogFor(identity.Name, identity.ID)
}

func AegisNASVendorDictionaryText() string {
	identity := AegisNASVendorIdentity()
	return AegisNASVendorDictionaryTextFor(identity.Name, identity.ID)
}

func AegisNASVendorDictionaryCatalogFor(name string, id int) VendorDictionaryCatalog {
	return ParseVendorDictionaryCatalog("configs/"+AegisNASVendorDictionaryFilename, AegisNASVendorDictionaryTextFor(name, id))
}

func AegisNASVendorDictionaryTextFor(name string, id int) string {
	name = strings.TrimSpace(name)
	if name == "" {
		name = AegisNASVendorName
	}
	if id < 1 {
		id = AegisNASPlaceholderVendorID
	}
	return strings.Replace(aegisNASVendorDictionaryTemplate, "VENDOR AegisNAS 55555", "VENDOR "+name+" "+strconv.Itoa(id), 1)
}

func ParseVendorDictionary(text string) (VendorDictionary, bool) {
	catalog := ParseVendorDictionaryCatalog("", text)
	for _, vendor := range catalog.Vendors {
		if vendor.Name != "" && vendor.ID > 0 && len(vendor.Attributes) > 0 {
			return vendor, true
		}
	}
	return VendorDictionary{}, false
}

func ParseVendorDictionaryCatalog(source, text string) VendorDictionaryCatalog {
	out := VendorDictionaryCatalog{Source: strings.TrimSpace(source)}
	vendorIndexes := map[string]int{}
	attributeIndexes := map[string][]attributeLocation{}
	activeVendor := ""

	for lineNumber, line := range strings.Split(text, "\n") {
		fields := strings.Fields(stripDictionaryComment(line))
		if len(fields) == 0 {
			continue
		}
		switch strings.ToUpper(fields[0]) {
		case "VENDOR":
			if len(fields) < 3 {
				out.Warnings = append(out.Warnings, VendorDictionaryWarning{Line: lineNumber + 1, Message: "VENDOR directive requires a name and numeric ID"})
				continue
			}
			id, ok := parseDictionaryNumber(fields[2])
			if !ok || id < 1 {
				out.Warnings = append(out.Warnings, VendorDictionaryWarning{Line: lineNumber + 1, Message: "VENDOR directive has an invalid numeric ID"})
				continue
			}
			upsertVendor(&out, vendorIndexes, fields[1], id, fields[3:])
		case "BEGIN-VENDOR":
			if len(fields) < 2 {
				out.Warnings = append(out.Warnings, VendorDictionaryWarning{Line: lineNumber + 1, Message: "BEGIN-VENDOR directive requires a vendor name"})
				continue
			}
			activeVendor = fields[1]
			upsertVendor(&out, vendorIndexes, activeVendor, 0, fields[2:])
		case "END-VENDOR":
			activeVendor = ""
		case "ATTRIBUTE":
			if len(fields) < 4 {
				out.Warnings = append(out.Warnings, VendorDictionaryWarning{Line: lineNumber + 1, Message: "ATTRIBUTE directive requires a name, number, and type"})
				continue
			}
			number, oid, ok := parseAttributeNumber(fields[2])
			if !ok {
				out.Warnings = append(out.Warnings, VendorDictionaryWarning{Line: lineNumber + 1, Message: "ATTRIBUTE directive has an invalid number or OID"})
				continue
			}
			vendorName, options := resolveAttributeVendor(fields[1], activeVendor, fields[4:], &out, vendorIndexes)
			if vendorName == "" {
				continue
			}
			vendorIdx := upsertVendor(&out, vendorIndexes, vendorName, 0, nil)
			attr := VendorDictionaryAttribute{
				Name:    fields[1],
				Number:  number,
				OID:     oid,
				Type:    strings.ToLower(fields[3]),
				Options: normalizedDictionaryOptions(options),
			}
			out.Vendors[vendorIdx].Attributes = append(out.Vendors[vendorIdx].Attributes, attr)
			attrIdx := len(out.Vendors[vendorIdx].Attributes) - 1
			key := strings.ToLower(attr.Name)
			attributeIndexes[key] = append(attributeIndexes[key], attributeLocation{VendorIndex: vendorIdx, AttributeIndex: attrIdx})
		case "VALUE":
			if len(fields) < 4 {
				out.Warnings = append(out.Warnings, VendorDictionaryWarning{Line: lineNumber + 1, Message: "VALUE directive requires an attribute, name, and value"})
				continue
			}
			value := VendorDictionaryValue{
				Attribute: fields[1],
				Name:      fields[2],
				Value:     fields[3],
			}
			if !appendValueToAttributes(&out, attributeIndexes, value) {
				out.Values = append(out.Values, value)
			}
		}
	}
	return out
}

func stripDictionaryComment(line string) string {
	if idx := strings.Index(line, "#"); idx >= 0 {
		return line[:idx]
	}
	return line
}

type attributeLocation struct {
	VendorIndex    int
	AttributeIndex int
}

func parseDictionaryNumber(value string) (int, bool) {
	parsed, err := strconv.ParseInt(strings.TrimSpace(value), 0, 64)
	if err != nil {
		return 0, false
	}
	return int(parsed), true
}

func parseAttributeNumber(value string) (int, string, bool) {
	number, ok := parseDictionaryNumber(value)
	if ok && number > 0 {
		return number, "", true
	}
	value = strings.TrimSpace(value)
	if validDictionaryOID(value) {
		return 0, value, true
	}
	return 0, "", false
}

func validDictionaryOID(value string) bool {
	value = strings.TrimSpace(value)
	partial := strings.HasPrefix(value, ".")
	if strings.HasPrefix(value, ".") {
		value = strings.TrimPrefix(value, ".")
	}
	parts := strings.Split(value, ".")
	if !partial && len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

func upsertVendor(catalog *VendorDictionaryCatalog, indexes map[string]int, name string, id int, options []string) int {
	name = strings.TrimSpace(name)
	if name == "" {
		return -1
	}
	key := strings.ToLower(name)
	if idx, exists := indexes[key]; exists {
		if id > 0 {
			catalog.Vendors[idx].ID = id
		}
		catalog.Vendors[idx].Options = mergeDictionaryOptions(catalog.Vendors[idx].Options, options)
		return idx
	}
	catalog.Vendors = append(catalog.Vendors, VendorDictionary{
		Name:    name,
		ID:      id,
		Options: normalizedDictionaryOptions(options),
	})
	idx := len(catalog.Vendors) - 1
	indexes[key] = idx
	return idx
}

func resolveAttributeVendor(attributeName, activeVendor string, fields []string, catalog *VendorDictionaryCatalog, vendorIndexes map[string]int) (string, []string) {
	if strings.TrimSpace(activeVendor) != "" {
		return strings.TrimSpace(activeVendor), fields
	}
	if prefix, _, ok := strings.Cut(strings.TrimSpace(attributeName), "."); ok {
		if idx, exists := vendorIndexes[strings.ToLower(prefix)]; exists {
			return catalog.Vendors[idx].Name, fields
		}
	}
	options := make([]string, 0, len(fields))
	for _, field := range fields {
		trimmed := strings.TrimSpace(strings.TrimSuffix(field, ","))
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(trimmed), "vendor=") {
			options = append(options, fieldsAfter(fields, field)...)
			return strings.TrimSpace(trimmed[len("vendor="):]), options
		}
		if idx, exists := vendorIndexes[strings.ToLower(trimmed)]; exists {
			options = append(options, fieldsAfter(fields, field)...)
			return catalog.Vendors[idx].Name, options
		}
		options = append(options, trimmed)
	}
	return "", options
}

func appendValueToAttributes(catalog *VendorDictionaryCatalog, indexes map[string][]attributeLocation, value VendorDictionaryValue) bool {
	locations := indexes[strings.ToLower(strings.TrimSpace(value.Attribute))]
	if len(locations) == 0 {
		return false
	}
	for _, location := range locations {
		if location.VendorIndex < 0 || location.VendorIndex >= len(catalog.Vendors) {
			continue
		}
		attrs := catalog.Vendors[location.VendorIndex].Attributes
		if location.AttributeIndex < 0 || location.AttributeIndex >= len(attrs) {
			continue
		}
		catalog.Vendors[location.VendorIndex].Attributes[location.AttributeIndex].Values = append(catalog.Vendors[location.VendorIndex].Attributes[location.AttributeIndex].Values, value)
	}
	return true
}

func mergeDictionaryOptions(existing, additions []string) []string {
	out := append([]string(nil), existing...)
	seen := map[string]struct{}{}
	for _, option := range out {
		seen[strings.ToLower(option)] = struct{}{}
	}
	for _, option := range normalizedDictionaryOptions(additions) {
		key := strings.ToLower(option)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, option)
	}
	return out
}

func normalizedDictionaryOptions(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(strings.TrimSuffix(value, ","))
		if value == "" {
			continue
		}
		out = append(out, value)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func fieldsAfter(fields []string, needle string) []string {
	for i, field := range fields {
		if field == needle && i+1 < len(fields) {
			return fields[i+1:]
		}
	}
	return nil
}

func (c VendorDictionaryCatalog) VendorByName(name string) (VendorDictionary, bool) {
	name = strings.ToLower(strings.TrimSpace(NormalizeDictionaryVendorName(DefaultDictionaryReleaseProfileID, name)))
	for _, vendor := range c.Vendors {
		if strings.ToLower(NormalizeDictionaryVendorName(DefaultDictionaryReleaseProfileID, vendor.Name)) == name {
			return vendor, true
		}
	}
	return VendorDictionary{}, false
}

func (c VendorDictionaryCatalog) Attribute(vendorName, attributeName string) (VendorDictionaryAttribute, bool) {
	vendor, ok := c.VendorByName(vendorName)
	if !ok {
		return VendorDictionaryAttribute{}, false
	}
	attributeName = strings.ToLower(strings.TrimSpace(NormalizeDictionaryAttributeName(DefaultDictionaryReleaseProfileID, vendor.Name, attributeName)))
	for _, attr := range vendor.Attributes {
		attrName := strings.ToLower(NormalizeDictionaryAttributeName(DefaultDictionaryReleaseProfileID, vendor.Name, attr.Name))
		if attrName == attributeName || attrName == strings.ToLower(vendor.Name)+"."+attributeName {
			return attr, true
		}
	}
	return VendorDictionaryAttribute{}, false
}

func ValidVendorDictionaryAttributeType(value string) bool {
	base := strings.ToLower(strings.TrimSpace(value))
	if base == "" {
		return false
	}
	if idx := strings.Index(base, "["); idx >= 0 {
		if !strings.HasSuffix(base, "]") {
			return false
		}
		base = base[:idx]
	}
	switch base {
	case "abinary", "bool", "byte", "combo-ip", "date", "ether", "ethernet", "extended", "float32", "float64", "group", "ifid", "int8", "int16", "int32", "int64", "integer", "integer64", "ipaddr", "ipv4addr", "ipv4prefix", "ipv6addr", "ipv6prefix", "octet", "octets", "short", "signed", "string", "struct", "text", "time_delta", "tlv", "uint8", "uint16", "uint32", "uint64", "union", "vendor", "vsa":
		return true
	default:
		return false
	}
}
