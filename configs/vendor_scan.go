package configs

import (
	"strings"
)

type VendorDictionaryScanReport struct {
	Source                string                             `json:"source,omitempty"`
	ImportPaths           []string                           `json:"import_paths,omitempty"`
	IncludeBuiltIn        bool                               `json:"include_built_in"`
	CatalogVendorCount    int                                `json:"catalog_vendor_count"`
	CatalogAttributeCount int                                `json:"catalog_attribute_count"`
	Coverage              VendorDictionaryCoverageReport     `json:"coverage"`
	SupportedAttributes   []VendorDictionaryScannedMapping   `json:"supported_attributes"`
	PlannedAttributes     []VendorDictionaryScannedMapping   `json:"planned_attributes"`
	IgnoredAttributes     []VendorDictionaryIgnoredAttribute `json:"ignored_attributes"`
	Summary               VendorDictionaryScanSummary        `json:"summary"`
	Warnings              []VendorDictionaryWarning          `json:"warnings,omitempty"`
	Notes                 []string                           `json:"notes,omitempty"`
}

type VendorDictionaryScanSummary struct {
	SupportedAttributeCount int `json:"supported_attribute_count"`
	PlannedAttributeCount   int `json:"planned_attribute_count"`
	IgnoredAttributeCount   int `json:"ignored_attribute_count"`
	IgnoredVendorCount      int `json:"ignored_vendor_count"`
	RegistryMappedCount     int `json:"registry_mapped_count"`
	RegistryDecoderCount    int `json:"registry_decoder_count"`
}

type VendorDictionaryScannedMapping struct {
	PackKey                  string `json:"pack_key"`
	PackLabel                string `json:"pack_label"`
	VendorName               string `json:"vendor_name,omitempty"`
	Semantic                 string `json:"semantic"`
	Attribute                string `json:"attribute"`
	Direction                string `json:"direction"`
	ValueType                string `json:"value_type"`
	CompatibilityState       string `json:"compatibility_state"`
	DictionaryAttributeFound bool   `json:"dictionary_attribute_found"`
	Warning                  string `json:"warning,omitempty"`
}

type VendorDictionaryIgnoredAttribute struct {
	VendorName string `json:"vendor_name"`
	VendorID   int    `json:"vendor_id,omitempty"`
	Attribute  string `json:"attribute"`
	Number     int    `json:"number,omitempty"`
	OID        string `json:"oid,omitempty"`
	Type       string `json:"type"`
	ValueCount int    `json:"value_count,omitempty"`
	Reason     string `json:"reason"`
}

func ScanVendorDictionaries(paths []string, activeKeys []string, includeBuiltIn bool) VendorDictionaryScanReport {
	paths = normalizeVendorDictionaryImportPaths(paths)
	var catalogs []VendorDictionaryCatalog
	var sources []string
	if includeBuiltIn {
		builtIn := AegisNASVendorDictionaryCatalog()
		catalogs = append(catalogs, builtIn)
		sources = append(sources, "built-in AegisNAS")
	}
	if len(paths) > 0 {
		imported := LoadVendorDictionaryCatalog(paths)
		catalogs = append(catalogs, imported)
		if strings.TrimSpace(imported.Source) != "" {
			sources = append(sources, imported.Source)
		}
	}
	catalog := MergeVendorDictionaryCatalogs(strings.Join(sources, ", "), catalogs...)
	report := BuildVendorDictionaryScanReport(catalog, AegisNASVendorCompatibilityPacks(), activeKeys)
	report.ImportPaths = paths
	report.IncludeBuiltIn = includeBuiltIn
	return report
}

func BuildVendorDictionaryScanReport(catalog VendorDictionaryCatalog, packs []VendorCompatibilityPack, activeKeys []string) VendorDictionaryScanReport {
	coverage := BuildVendorDictionaryCoverageReport(catalog, packs, activeKeys)
	report := VendorDictionaryScanReport{
		Source:                strings.TrimSpace(catalog.Source),
		CatalogVendorCount:    len(catalog.Vendors),
		CatalogAttributeCount: countCatalogAttributes(catalog),
		Coverage:              coverage,
		Warnings:              append([]VendorDictionaryWarning(nil), catalog.Warnings...),
		Notes: []string{
			"supported_attributes are typed-registry semantic mappings marked implemented; dictionary_attribute_found shows whether the parsed deployment catalog contains that exact attribute.",
			"planned_attributes include partial typed-registry mappings that still need policy, enforcement, UI, packet, or hardware-certification evidence.",
			"ignored_attributes are parsed dictionary attributes that are not yet mapped into AegisNAS vendor-neutral semantics.",
			"registry mapping is distinct from device certification and does not prove end-to-end feature behavior.",
		},
	}

	registry := MustBuiltInAttributeRegistry()
	mappedAttributes := mappedVendorDictionaryAttributes(packs)
	for _, entry := range registry.Entries {
		if entry.DictionaryStatus == "missing" || entry.PackKey == "" {
			continue
		}
		mappedAttributes[vendorDictionaryAttributeKey(entry.Vendor, entry.Attribute)] = struct{}{}
	}
	appendRegistryScanMappings(&report, catalog, registry)
	ignoredVendors := map[string]struct{}{}
	for _, row := range coverage.Rows {
		for _, attr := range row.Attributes {
			mapping := VendorDictionaryScannedMapping{
				PackKey:                  row.PackKey,
				PackLabel:                row.PackLabel,
				VendorName:               row.VendorName,
				Semantic:                 attr.Semantic,
				Attribute:                attr.Attribute,
				Direction:                attr.Direction,
				ValueType:                attr.ValueType,
				CompatibilityState:       attr.CompatibilityState,
				DictionaryAttributeFound: attr.DictionaryAttributeFound,
				Warning:                  attr.Warning,
			}
			if strings.EqualFold(attr.CompatibilityState, "implemented") {
				report.SupportedAttributes = append(report.SupportedAttributes, mapping)
				continue
			}
			report.PlannedAttributes = append(report.PlannedAttributes, mapping)
		}
	}

	for _, vendor := range catalog.Vendors {
		for _, attr := range vendor.Attributes {
			if _, ok := mappedAttributes[vendorDictionaryAttributeKey(vendor.Name, attr.Name)]; ok {
				continue
			}
			reason := "no compatibility mapping for this vendor attribute"
			if !hasVendorPack(packs, vendor.Name) {
				reason = "vendor has no compatibility pack"
			}
			report.IgnoredAttributes = append(report.IgnoredAttributes, VendorDictionaryIgnoredAttribute{
				VendorName: vendor.Name,
				VendorID:   vendor.ID,
				Attribute:  attr.Name,
				Number:     attr.Number,
				OID:        attr.OID,
				Type:       attr.Type,
				ValueCount: len(attr.Values),
				Reason:     reason,
			})
			ignoredVendors[strings.ToLower(strings.TrimSpace(vendor.Name))] = struct{}{}
		}
	}

	report.Summary = VendorDictionaryScanSummary{
		SupportedAttributeCount: len(report.SupportedAttributes),
		PlannedAttributeCount:   len(report.PlannedAttributes),
		IgnoredAttributeCount:   len(report.IgnoredAttributes),
		IgnoredVendorCount:      len(ignoredVendors),
		RegistryMappedCount:     registry.MappedCount,
		RegistryDecoderCount:    len(registry.RuntimeMappings()),
	}
	return report
}

func appendRegistryScanMappings(report *VendorDictionaryScanReport, catalog VendorDictionaryCatalog, registry *AttributeRegistry) {
	seen := map[string]struct{}{}
	for _, mapping := range report.SupportedAttributes {
		seen[vendorDictionaryAttributeKey(mapping.VendorName, mapping.Attribute)] = struct{}{}
	}
	for _, mapping := range report.PlannedAttributes {
		seen[vendorDictionaryAttributeKey(mapping.VendorName, mapping.Attribute)] = struct{}{}
	}
	for _, entry := range registry.Entries {
		if entry.DictionaryStatus == "missing" || entry.PackKey == "" {
			continue
		}
		key := vendorDictionaryAttributeKey(entry.Vendor, entry.Attribute)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		_, found := catalog.Attribute(entry.Vendor, entry.Attribute)
		mapping := VendorDictionaryScannedMapping{
			PackKey: entry.PackKey, PackLabel: entry.Vendor, VendorName: entry.Vendor,
			Semantic: entry.Semantic, Attribute: entry.Attribute,
			Direction: strings.Join(entry.Directions, ","), ValueType: entry.WireType,
			CompatibilityState: entry.DictionaryStatus, DictionaryAttributeFound: found,
		}
		if !found {
			mapping.Warning = "attribute is mapped in the typed registry but absent from the parsed deployment catalog"
		}
		if entry.DictionaryStatus == "implemented" {
			report.SupportedAttributes = append(report.SupportedAttributes, mapping)
		} else {
			report.PlannedAttributes = append(report.PlannedAttributes, mapping)
		}
	}
}

func mappedVendorDictionaryAttributes(packs []VendorCompatibilityPack) map[string]struct{} {
	out := map[string]struct{}{}
	for _, pack := range packs {
		vendorName := strings.TrimSpace(pack.VendorName)
		if vendorName == "" {
			continue
		}
		for _, attr := range pack.Attributes {
			if strings.EqualFold(attr.Direction, "controller_api") {
				continue
			}
			out[vendorDictionaryAttributeKey(vendorName, attr.Attribute)] = struct{}{}
		}
	}
	return out
}

func hasVendorPack(packs []VendorCompatibilityPack, vendorName string) bool {
	vendorName = strings.ToLower(strings.TrimSpace(NormalizeDictionaryVendorName(DefaultDictionaryReleaseProfileID, vendorName)))
	if vendorName == "" {
		return false
	}
	for _, pack := range packs {
		if strings.ToLower(strings.TrimSpace(NormalizeDictionaryVendorName(DefaultDictionaryReleaseProfileID, pack.VendorName))) == vendorName {
			return true
		}
	}
	return false
}

func vendorDictionaryAttributeKey(vendorName, attrName string) string {
	vendorName = strings.ToLower(strings.TrimSpace(NormalizeDictionaryVendorName(DefaultDictionaryReleaseProfileID, vendorName)))
	attrName = strings.ToLower(strings.TrimSpace(NormalizeDictionaryAttributeName(DefaultDictionaryReleaseProfileID, vendorName, attrName)))
	prefix := vendorName + "."
	if strings.HasPrefix(attrName, prefix) {
		attrName = strings.TrimPrefix(attrName, prefix)
	}
	return vendorName + "\x00" + attrName
}
