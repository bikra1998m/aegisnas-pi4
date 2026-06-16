package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
)

var (
	dictionaryScanPaths     []string
	dictionaryScanPacks     []string
	dictionaryScanJSON      bool
	dictionaryScanMatrixCSV bool
	dictionaryScanNoBuiltIn bool
)

var scanRadiusDictionariesCmd = &cobra.Command{
	Use:   "scan-radius-dictionaries",
	Short: "Scan FreeRADIUS dictionaries and report vendor compatibility coverage",
	RunE: func(cmd *cobra.Command, args []string) error {
		activePacks, err := normalizeDictionaryScanPacks(dictionaryScanPacks)
		if err != nil {
			return err
		}
		paths := append([]string(nil), dictionaryScanPaths...)
		if len(paths) == 0 {
			paths = productconfigs.ExistingDefaultVendorDictionaryImportPaths()
		}

		report := productconfigs.ScanVendorDictionaries(paths, activePacks, !dictionaryScanNoBuiltIn)
		switch {
		case dictionaryScanJSON && dictionaryScanMatrixCSV:
			return fmt.Errorf("--json and --matrix-csv are mutually exclusive")
		case dictionaryScanJSON:
			encoder := json.NewEncoder(cmd.OutOrStdout())
			encoder.SetIndent("", "  ")
			return encoder.Encode(report)
		case dictionaryScanMatrixCSV:
			return writeVendorDictionaryMatrixCSV(cmd.OutOrStdout(), report)
		default:
			writeVendorDictionaryScanText(cmd.OutOrStdout(), report)
			return nil
		}
	},
}

func init() {
	scanRadiusDictionariesCmd.Flags().StringArrayVar(&dictionaryScanPaths, "dictionary", nil, "FreeRADIUS dictionary file or directory to scan; repeat for multiple paths")
	scanRadiusDictionariesCmd.Flags().StringArrayVar(&dictionaryScanPacks, "pack", nil, "active compatibility pack key; repeat for multiple packs")
	scanRadiusDictionariesCmd.Flags().BoolVar(&dictionaryScanJSON, "json", false, "print the full scan report as JSON")
	scanRadiusDictionariesCmd.Flags().BoolVar(&dictionaryScanMatrixCSV, "matrix-csv", false, "print the compatibility matrix as CSV")
	scanRadiusDictionariesCmd.Flags().BoolVar(&dictionaryScanNoBuiltIn, "no-built-in", false, "exclude the built-in AegisNAS product dictionary from the scan")
	rootCmd.AddCommand(scanRadiusDictionariesCmd)
}

func normalizeDictionaryScanPacks(keys []string) ([]string, error) {
	if len(keys) == 0 {
		return productconfigs.DefaultVendorCompatibilityPackKeys(), nil
	}
	out := make([]string, 0, len(keys))
	seen := map[string]struct{}{}
	for _, key := range keys {
		normalized := productconfigs.NormalizeVendorCompatibilityPackKey(key)
		if normalized == "" {
			continue
		}
		if !productconfigs.ValidVendorCompatibilityPackKey(normalized) {
			return nil, fmt.Errorf("unknown compatibility pack %q", key)
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	if len(out) == 0 {
		return productconfigs.DefaultVendorCompatibilityPackKeys(), nil
	}
	return out, nil
}

func writeVendorDictionaryScanText(w io.Writer, report productconfigs.VendorDictionaryScanReport) {
	source := report.Source
	if source == "" {
		source = "(no dictionaries found)"
	}
	fmt.Fprintf(w, "Source: %s\n", source)
	if len(report.ImportPaths) > 0 {
		fmt.Fprintf(w, "Import paths: %s\n", strings.Join(report.ImportPaths, ", "))
	}
	fmt.Fprintf(w, "Catalog: %d vendors, %d attributes\n", report.CatalogVendorCount, report.CatalogAttributeCount)
	fmt.Fprintf(w, "Mappings: %d supported, %d planned, %d ignored across %d vendors\n",
		report.Summary.SupportedAttributeCount,
		report.Summary.PlannedAttributeCount,
		report.Summary.IgnoredAttributeCount,
		report.Summary.IgnoredVendorCount,
	)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Compatibility Matrix:")
	fmt.Fprintf(w, "%-12s %-24s %-8s %-20s %7s %7s %7s\n", "PACK", "LABEL", "ACTIVE", "STATE", "RADIUS", "MATCH", "MISS")
	for _, row := range report.Coverage.Rows {
		fmt.Fprintf(w, "%-12s %-24s %-8t %-20s %7d %7d %7d\n",
			row.PackKey,
			truncateScanCell(row.PackLabel, 24),
			row.Active,
			row.CoverageState,
			row.RadiusAttributeCount,
			row.DictionaryMatchedAttributeCount,
			row.MissingDictionaryAttributeCount,
		)
	}
	if len(report.IgnoredAttributes) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Ignored Dictionary Attributes:")
		limit := len(report.IgnoredAttributes)
		if limit > 25 {
			limit = 25
		}
		for _, attr := range report.IgnoredAttributes[:limit] {
			fmt.Fprintf(w, "  - %s %s (%s): %s\n", attr.VendorName, attr.Attribute, attr.Type, attr.Reason)
		}
		if len(report.IgnoredAttributes) > limit {
			fmt.Fprintf(w, "  ... %d more ignored attributes; use --json for the full list\n", len(report.IgnoredAttributes)-limit)
		}
	}
	if len(report.Warnings) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Warnings:")
		for _, warning := range report.Warnings {
			if warning.Line > 0 {
				fmt.Fprintf(w, "  - line %d: %s\n", warning.Line, warning.Message)
				continue
			}
			fmt.Fprintf(w, "  - %s\n", warning.Message)
		}
	}
}

func writeVendorDictionaryMatrixCSV(w io.Writer, report productconfigs.VendorDictionaryScanReport) error {
	writer := csv.NewWriter(w)
	if err := writer.Write([]string{
		"pack_key",
		"pack_label",
		"active",
		"coverage_state",
		"vendor_name",
		"dictionary_vendor_found",
		"radius_attribute_count",
		"dictionary_matched_attribute_count",
		"missing_dictionary_attribute_count",
		"implemented_attribute_count",
		"planned_attribute_count",
	}); err != nil {
		return err
	}
	for _, row := range report.Coverage.Rows {
		if err := writer.Write([]string{
			row.PackKey,
			row.PackLabel,
			strconv.FormatBool(row.Active),
			row.CoverageState,
			row.VendorName,
			strconv.FormatBool(row.DictionaryVendorFound),
			strconv.Itoa(row.RadiusAttributeCount),
			strconv.Itoa(row.DictionaryMatchedAttributeCount),
			strconv.Itoa(row.MissingDictionaryAttributeCount),
			strconv.Itoa(row.ImplementedAttributeCount),
			strconv.Itoa(row.PlannedAttributeCount),
		}); err != nil {
			return err
		}
	}
	writer.Flush()
	return writer.Error()
}

func truncateScanCell(value string, width int) string {
	value = strings.TrimSpace(value)
	if len(value) <= width {
		return value
	}
	if width <= 1 {
		return value[:width]
	}
	return value[:width-1] + "."
}
