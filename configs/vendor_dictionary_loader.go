package configs

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func DefaultVendorDictionaryImportPaths() []string {
	return []string{
		"/etc/freeradius/3.0/dictionary",
		"/etc/freeradius/dictionary",
		"/usr/share/freeradius",
	}
}

func ExistingDefaultVendorDictionaryImportPaths() []string {
	var out []string
	for _, path := range DefaultVendorDictionaryImportPaths() {
		if _, err := os.Stat(path); err == nil {
			out = append(out, path)
		}
	}
	return out
}

func LoadVendorDictionaryCatalog(paths []string) VendorDictionaryCatalog {
	paths = normalizeVendorDictionaryImportPaths(paths)
	out := VendorDictionaryCatalog{Source: strings.Join(paths, ", ")}
	if len(paths) == 0 {
		return out
	}

	seenFiles := map[string]struct{}{}
	var catalogs []VendorDictionaryCatalog
	for _, path := range paths {
		loaded, warnings := loadVendorDictionaryPath(path, seenFiles)
		out.Warnings = append(out.Warnings, warnings...)
		catalogs = append(catalogs, loaded...)
	}

	merged := MergeVendorDictionaryCatalogs(out.Source, catalogs...)
	merged.Warnings = append(merged.Warnings, out.Warnings...)
	return merged
}

func MergeVendorDictionaryCatalogs(source string, catalogs ...VendorDictionaryCatalog) VendorDictionaryCatalog {
	out := VendorDictionaryCatalog{Source: strings.TrimSpace(source)}
	vendorIndexes := map[string]int{}

	for _, catalog := range catalogs {
		for _, vendor := range catalog.Vendors {
			idx := upsertVendor(&out, vendorIndexes, vendor.Name, vendor.ID, vendor.Options)
			if idx < 0 {
				continue
			}
			for _, attr := range vendor.Attributes {
				mergeVendorDictionaryAttribute(&out.Vendors[idx], attr)
			}
		}
		out.Values = append(out.Values, catalog.Values...)
		out.Warnings = append(out.Warnings, catalog.Warnings...)
	}

	return out
}

func loadVendorDictionaryPath(path string, seenFiles map[string]struct{}) ([]VendorDictionaryCatalog, []VendorDictionaryWarning) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, []VendorDictionaryWarning{{Message: fmt.Sprintf("dictionary path %q is unavailable: %v", path, err)}}
	}
	if info.IsDir() {
		return loadVendorDictionaryDir(path, seenFiles)
	}
	catalog, warnings := loadVendorDictionaryFile(path, seenFiles)
	if catalog.Source == "" && len(catalog.Vendors) == 0 && len(catalog.Warnings) == 0 {
		return nil, warnings
	}
	return []VendorDictionaryCatalog{catalog}, warnings
}

func loadVendorDictionaryDir(root string, seenFiles map[string]struct{}) ([]VendorDictionaryCatalog, []VendorDictionaryWarning) {
	var files []string
	var warnings []VendorDictionaryWarning
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			warnings = append(warnings, VendorDictionaryWarning{Message: fmt.Sprintf("dictionary path %q is unavailable: %v", path, err)})
			return nil
		}
		if entry.IsDir() {
			if path != root && strings.HasPrefix(entry.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if dictionaryFileName(entry.Name()) {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		warnings = append(warnings, VendorDictionaryWarning{Message: fmt.Sprintf("dictionary directory %q scan failed: %v", root, err)})
	}
	sort.Strings(files)

	var catalogs []VendorDictionaryCatalog
	for _, path := range files {
		catalog, fileWarnings := loadVendorDictionaryFile(path, seenFiles)
		warnings = append(warnings, fileWarnings...)
		if catalog.Source != "" || len(catalog.Vendors) > 0 || len(catalog.Warnings) > 0 {
			catalogs = append(catalogs, catalog)
		}
	}
	return catalogs, warnings
}

func loadVendorDictionaryFile(path string, seenFiles map[string]struct{}) (VendorDictionaryCatalog, []VendorDictionaryWarning) {
	resolved, err := filepath.Abs(path)
	if err != nil {
		resolved = path
	}
	if _, exists := seenFiles[resolved]; exists {
		return VendorDictionaryCatalog{}, nil
	}
	seenFiles[resolved] = struct{}{}

	content, err := os.ReadFile(path)
	if err != nil {
		return VendorDictionaryCatalog{}, []VendorDictionaryWarning{{Message: fmt.Sprintf("dictionary file %q could not be read: %v", path, err)}}
	}

	text, warnings := expandVendorDictionaryIncludes(path, string(content), seenFiles)
	catalog := ParseVendorDictionaryCatalog(path, text)
	catalog.Warnings = append(catalog.Warnings, warnings...)
	return catalog, nil
}

func expandVendorDictionaryIncludes(path, text string, seenFiles map[string]struct{}) (string, []VendorDictionaryWarning) {
	var warnings []VendorDictionaryWarning
	var expanded strings.Builder
	baseDir := filepath.Dir(path)
	for lineNumber, line := range strings.Split(text, "\n") {
		fields := strings.Fields(stripDictionaryComment(line))
		if len(fields) >= 2 && strings.EqualFold(fields[0], "$INCLUDE") {
			includePath := resolveVendorDictionaryIncludePath(baseDir, fields[1])
			matches, err := filepath.Glob(includePath)
			if err != nil || len(matches) == 0 {
				warnings = append(warnings, VendorDictionaryWarning{Line: lineNumber + 1, Message: fmt.Sprintf("include %q could not be resolved from %q", fields[1], path)})
				continue
			}
			sort.Strings(matches)
			for _, match := range matches {
				content, err := os.ReadFile(match)
				if err != nil {
					warnings = append(warnings, VendorDictionaryWarning{Line: lineNumber + 1, Message: fmt.Sprintf("include %q could not be read: %v", match, err)})
					continue
				}
				resolved, err := filepath.Abs(match)
				if err != nil {
					resolved = match
				}
				if _, exists := seenFiles[resolved]; exists {
					continue
				}
				seenFiles[resolved] = struct{}{}
				nested, nestedWarnings := expandVendorDictionaryIncludes(match, string(content), seenFiles)
				warnings = append(warnings, nestedWarnings...)
				expanded.WriteString(nested)
				expanded.WriteByte('\n')
			}
			continue
		}
		expanded.WriteString(line)
		expanded.WriteByte('\n')
	}
	return expanded.String(), warnings
}

func resolveVendorDictionaryIncludePath(baseDir, includePath string) string {
	includePath = strings.TrimSpace(strings.Trim(includePath, `"'`))
	if filepath.IsAbs(includePath) {
		return includePath
	}
	return filepath.Join(baseDir, includePath)
}

func mergeVendorDictionaryAttribute(vendor *VendorDictionary, attr VendorDictionaryAttribute) {
	key := strings.ToLower(strings.TrimSpace(attr.Name))
	if key == "" {
		return
	}
	for i, existing := range vendor.Attributes {
		if strings.ToLower(strings.TrimSpace(existing.Name)) != key {
			continue
		}
		if vendor.Attributes[i].Number == 0 {
			vendor.Attributes[i].Number = attr.Number
		}
		if vendor.Attributes[i].OID == "" {
			vendor.Attributes[i].OID = attr.OID
		}
		if vendor.Attributes[i].Type == "" {
			vendor.Attributes[i].Type = attr.Type
		}
		vendor.Attributes[i].Options = mergeDictionaryOptions(vendor.Attributes[i].Options, attr.Options)
		vendor.Attributes[i].Values = mergeDictionaryValues(vendor.Attributes[i].Values, attr.Values)
		return
	}
	vendor.Attributes = append(vendor.Attributes, attr)
}

func mergeDictionaryValues(existing, additions []VendorDictionaryValue) []VendorDictionaryValue {
	out := append([]VendorDictionaryValue(nil), existing...)
	seen := map[string]struct{}{}
	for _, value := range out {
		seen[strings.ToLower(value.Attribute+"\x00"+value.Name+"\x00"+value.Value)] = struct{}{}
	}
	for _, value := range additions {
		key := strings.ToLower(value.Attribute + "\x00" + value.Name + "\x00" + value.Value)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	return out
}

func normalizeVendorDictionaryImportPaths(paths []string) []string {
	out := make([]string, 0, len(paths))
	seen := map[string]struct{}{}
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		if cleaned := filepath.Clean(path); cleaned != "." {
			path = cleaned
		}
		key := strings.ToLower(path)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, path)
	}
	return out
}

func dictionaryFileName(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	return name == "dictionary" ||
		strings.HasPrefix(name, "dictionary.") ||
		strings.HasSuffix(name, ".dictionary") ||
		strings.HasSuffix(name, ".dictionery")
}
