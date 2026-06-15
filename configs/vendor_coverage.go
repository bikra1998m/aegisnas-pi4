package configs

import "strings"

type VendorDictionaryCoverageReport struct {
	Source                          string                        `json:"source,omitempty"`
	CatalogVendorCount              int                           `json:"catalog_vendor_count"`
	CatalogAttributeCount           int                           `json:"catalog_attribute_count"`
	PackCount                       int                           `json:"pack_count"`
	ActivePackCount                 int                           `json:"active_pack_count"`
	DictionaryBackedPackCount       int                           `json:"dictionary_backed_pack_count"`
	PartialDictionaryPackCount      int                           `json:"partial_dictionary_pack_count"`
	MissingDictionaryVendorCount    int                           `json:"missing_dictionary_vendor_count"`
	ImplementedAttributeCount       int                           `json:"implemented_attribute_count"`
	PlannedAttributeCount           int                           `json:"planned_attribute_count"`
	DictionaryMatchedAttributeCount int                           `json:"dictionary_matched_attribute_count"`
	MissingDictionaryAttributeCount int                           `json:"missing_dictionary_attribute_count"`
	Rows                            []VendorDictionaryCoverageRow `json:"rows"`
	Notes                           []string                      `json:"notes,omitempty"`
}

type VendorDictionaryCoverageRow struct {
	PackKey                         string                              `json:"pack_key"`
	PackLabel                       string                              `json:"pack_label"`
	Active                          bool                                `json:"active"`
	VendorName                      string                              `json:"vendor_name,omitempty"`
	VendorID                        int                                 `json:"vendor_id,omitempty"`
	DictionaryVendorFound           bool                                `json:"dictionary_vendor_found"`
	DictionaryVendorID              int                                 `json:"dictionary_vendor_id,omitempty"`
	DictionaryAttributeCount        int                                 `json:"dictionary_attribute_count"`
	PackAttributeCount              int                                 `json:"pack_attribute_count"`
	RadiusAttributeCount            int                                 `json:"radius_attribute_count"`
	ImplementedAttributeCount       int                                 `json:"implemented_attribute_count"`
	PlannedAttributeCount           int                                 `json:"planned_attribute_count"`
	DictionaryMatchedAttributeCount int                                 `json:"dictionary_matched_attribute_count"`
	MissingDictionaryAttributeCount int                                 `json:"missing_dictionary_attribute_count"`
	CoverageState                   string                              `json:"coverage_state"`
	HardwareProfiles                []string                            `json:"hardware_profiles"`
	Attributes                      []VendorDictionaryAttributeCoverage `json:"attributes"`
	Notes                           []string                            `json:"notes,omitempty"`
}

type VendorDictionaryAttributeCoverage struct {
	Semantic                 string `json:"semantic"`
	Attribute                string `json:"attribute"`
	Direction                string `json:"direction"`
	ValueType                string `json:"value_type"`
	CompatibilityState       string `json:"compatibility_state"`
	DictionaryAttributeFound bool   `json:"dictionary_attribute_found"`
	DictionaryNumber         int    `json:"dictionary_number,omitempty"`
	DictionaryOID            string `json:"dictionary_oid,omitempty"`
	DictionaryType           string `json:"dictionary_type,omitempty"`
	DictionaryValueCount     int    `json:"dictionary_value_count,omitempty"`
	Warning                  string `json:"warning,omitempty"`
}

func BuildVendorDictionaryCoverageReport(catalog VendorDictionaryCatalog, packs []VendorCompatibilityPack, activeKeys []string) VendorDictionaryCoverageReport {
	active := normalizedPackSet(activeKeys)
	report := VendorDictionaryCoverageReport{
		Source:                strings.TrimSpace(catalog.Source),
		CatalogVendorCount:    len(catalog.Vendors),
		CatalogAttributeCount: countCatalogAttributes(catalog),
		PackCount:             len(packs),
		Rows:                  make([]VendorDictionaryCoverageRow, 0, len(packs)),
		Notes: []string{
			"Dictionary coverage means the parsed FreeRADIUS catalog contains the attribute name; hardware enforcement still requires AP, switch, or controller validation.",
			"Standard RADIUS attributes are treated as dictionary-backed without a vendor namespace.",
			"Controller API capabilities are tracked in the same matrix but do not require a RADIUS dictionary attribute.",
		},
	}

	for _, pack := range packs {
		row := buildVendorDictionaryCoverageRow(catalog, pack, active)
		report.Rows = append(report.Rows, row)
		if row.Active {
			report.ActivePackCount++
		}
		switch row.CoverageState {
		case "dictionary-backed", "standard-radius":
			report.DictionaryBackedPackCount++
		case "partial-dictionary":
			report.PartialDictionaryPackCount++
		}
		if row.VendorName != "" && !row.DictionaryVendorFound && row.RadiusAttributeCount > 0 {
			report.MissingDictionaryVendorCount++
		}
		report.ImplementedAttributeCount += row.ImplementedAttributeCount
		report.PlannedAttributeCount += row.PlannedAttributeCount
		report.DictionaryMatchedAttributeCount += row.DictionaryMatchedAttributeCount
		report.MissingDictionaryAttributeCount += row.MissingDictionaryAttributeCount
	}

	return report
}

func buildVendorDictionaryCoverageRow(catalog VendorDictionaryCatalog, pack VendorCompatibilityPack, active map[string]struct{}) VendorDictionaryCoverageRow {
	packKey := NormalizeVendorCompatibilityPackKey(pack.Key)
	row := VendorDictionaryCoverageRow{
		PackKey:            packKey,
		PackLabel:          strings.TrimSpace(pack.Label),
		VendorName:         strings.TrimSpace(pack.VendorName),
		VendorID:           pack.VendorID,
		HardwareProfiles:   append([]string(nil), pack.HardwareProfiles...),
		PackAttributeCount: len(pack.Attributes),
		Attributes:         make([]VendorDictionaryAttributeCoverage, 0, len(pack.Attributes)),
		Notes:              append([]string(nil), pack.Notes...),
	}
	if _, ok := active[packKey]; ok {
		row.Active = true
	}

	var vendor VendorDictionary
	if row.VendorName != "" {
		if found, ok := catalog.VendorByName(row.VendorName); ok {
			vendor = found
			row.DictionaryVendorFound = true
			row.DictionaryVendorID = found.ID
			row.DictionaryAttributeCount = len(found.Attributes)
		}
	}

	for _, mapping := range pack.Attributes {
		coverage := buildVendorAttributeCoverage(catalog, vendor, row.DictionaryVendorFound, packKey, row.VendorName, mapping)
		row.Attributes = append(row.Attributes, coverage)
		if mapping.Direction != "controller_api" {
			row.RadiusAttributeCount++
			if coverage.DictionaryAttributeFound {
				row.DictionaryMatchedAttributeCount++
			} else {
				row.MissingDictionaryAttributeCount++
			}
		}
		switch strings.ToLower(strings.TrimSpace(mapping.CompatibilityState)) {
		case "implemented":
			row.ImplementedAttributeCount++
		default:
			row.PlannedAttributeCount++
		}
	}

	row.CoverageState = vendorCoverageState(row)
	return row
}

func buildVendorAttributeCoverage(catalog VendorDictionaryCatalog, vendor VendorDictionary, vendorFound bool, packKey, vendorName string, mapping VendorPackAttributeMapping) VendorDictionaryAttributeCoverage {
	coverage := VendorDictionaryAttributeCoverage{
		Semantic:           strings.TrimSpace(mapping.Semantic),
		Attribute:          strings.TrimSpace(mapping.Attribute),
		Direction:          strings.TrimSpace(mapping.Direction),
		ValueType:          strings.TrimSpace(mapping.ValueType),
		CompatibilityState: strings.TrimSpace(mapping.CompatibilityState),
	}

	switch {
	case coverage.Direction == "controller_api":
		coverage.Warning = "controller API capability; no RADIUS dictionary attribute expected"
		return coverage
	case packKey == VendorPackStandard:
		coverage.DictionaryAttributeFound = true
		coverage.DictionaryType = coverage.ValueType
		return coverage
	case vendorName == "":
		coverage.Warning = "pack has no vendor namespace"
		return coverage
	case !vendorFound:
		coverage.Warning = "vendor dictionary is not present in parsed catalog"
		return coverage
	}

	attr, ok := catalog.Attribute(vendor.Name, coverage.Attribute)
	if !ok {
		coverage.Warning = "attribute is not present in parsed vendor dictionary"
		return coverage
	}
	coverage.DictionaryAttributeFound = true
	coverage.DictionaryNumber = attr.Number
	coverage.DictionaryOID = attr.OID
	coverage.DictionaryType = attr.Type
	coverage.DictionaryValueCount = len(attr.Values)
	return coverage
}

func vendorCoverageState(row VendorDictionaryCoverageRow) string {
	switch {
	case row.RadiusAttributeCount == 0:
		return "controller-api"
	case row.PackKey == VendorPackStandard:
		return "standard-radius"
	case row.DictionaryMatchedAttributeCount == row.RadiusAttributeCount:
		return "dictionary-backed"
	case row.DictionaryMatchedAttributeCount > 0:
		return "partial-dictionary"
	case row.VendorName != "":
		return "dictionary-missing"
	default:
		return "metadata-only"
	}
}

func normalizedPackSet(keys []string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, key := range keys {
		normalized := NormalizeVendorCompatibilityPackKey(key)
		if normalized == "" {
			continue
		}
		out[normalized] = struct{}{}
	}
	return out
}

func countCatalogAttributes(catalog VendorDictionaryCatalog) int {
	var total int
	for _, vendor := range catalog.Vendors {
		total += len(vendor.Attributes)
	}
	return total
}
