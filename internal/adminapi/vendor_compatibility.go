package adminapi

import (
	"database/sql"
	"net/http"
	"sort"
	"strings"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/radius"
)

type vendorCompatibilityResponse struct {
	productconfigs.VendorCompatibilityReport
	ClientProfiles []vendorCompatibilityClientProfile `json:"client_profiles,omitempty"`
	ProfileSummary vendorCompatibilityProfileSummary  `json:"profile_summary"`
}

type vendorCompatibilityClientProfile struct {
	ShortName       string   `json:"shortname"`
	IP              string   `json:"ip"`
	RawNASType      string   `json:"raw_nas_type,omitempty"`
	NASType         string   `json:"nas_type"`
	Enabled         bool     `json:"enabled"`
	KnownPack       bool     `json:"known_pack"`
	UsesGlobalPacks bool     `json:"uses_global_packs"`
	EffectivePacks  []string `json:"effective_packs"`
	Warning         string   `json:"warning,omitempty"`
}

type vendorCompatibilityProfileSummary struct {
	TotalClients              int            `json:"total_clients"`
	EnabledClients            int            `json:"enabled_clients"`
	ProfileCounts             map[string]int `json:"profile_counts"`
	UnknownProfiles           []string       `json:"unknown_profiles,omitempty"`
	GlobalFallbackClientCount int            `json:"global_fallback_client_count"`
	KnownVendorProfileClients int            `json:"known_vendor_profile_clients"`
}

func HandleGetVendorCompatibility(w http.ResponseWriter, r *http.Request) {
	report := productconfigs.AegisNASVendorCompatibilityReport()
	cfg := config.Get()
	if cfg != nil && len(cfg.Radius.Vendor.CompatibilityPacks) > 0 {
		report.ActivePacks = normalizeVendorCompatibilityPackKeys(cfg.Radius.Vendor.CompatibilityPacks)
	}
	if cfg != nil {
		vendor := cfg.Radius.Vendor
		report.Catalog = productconfigs.AegisNASVendorDictionaryCatalogFor(vendor.Name, vendor.ID)
		for index := range report.Packs {
			if report.Packs[index].Key == productconfigs.VendorPackAegisNAS {
				report.Packs[index].VendorName = strings.TrimSpace(vendor.Name)
				report.Packs[index].VendorID = vendor.ID
			}
		}
		report.Summary.ProductVendorID = vendor.ID
		report.Summary.ProductVendorName = strings.TrimSpace(vendor.Name)
		report.Summary.ProductVendorIDPlaceholder = vendor.ID == productconfigs.AegisNASPlaceholderVendorID
		report.Summary.ProductVendorIDSource = "config:radius.vendor.id"
		report.Summary.ProductVendorIdentityMode = strings.ToLower(strings.TrimSpace(vendor.IdentityMode))
		report.Summary.ProductVendorAssignedOrganization = strings.TrimSpace(vendor.AssignedOrganization)
		report.Summary.ProductVendorAssignmentRecordSHA = strings.TrimSpace(vendor.AssignmentRecordSHA)
		report.Summary.ProductVendorLegacyIDs = append([]int(nil), vendor.LegacyIDs...)
		report.Summary.ProductVendorLegacyAcceptUntil = strings.TrimSpace(vendor.LegacyAcceptUntil)
		if evidence, err := config.RadiusVendorAssignmentEvidence(vendor); err == nil && evidence.Validate(vendor.ID, vendor.AssignedOrganization) == nil && db.DB != nil {
			if assignment, assignmentErr := db.ActiveVendorIdentityAssignment(db.DB); assignmentErr == nil && assignment != nil {
				report.Summary.ProductVendorAssignmentVerified = assignment.PEN == uint32(vendor.ID) && assignment.RecordSHA256 == evidence.RecordSHA256
			}
		}
	}
	importPaths := vendorDictionaryImportPaths(cfg)
	if len(importPaths) > 0 {
		imported := productconfigs.LoadVendorDictionaryCatalog(importPaths)
		report.Catalog = productconfigs.MergeVendorDictionaryCatalogs(
			"built-in AegisNAS, "+imported.Source,
			report.Catalog,
			imported,
		)
		report.Notes = append(report.Notes, "FreeRADIUS dictionary import paths: "+strings.Join(importPaths, ", "))
	}
	report.DictionaryCoverage = productconfigs.BuildVendorDictionaryCoverageReport(report.Catalog, report.Packs, report.ActivePacks)
	clientProfiles, profileSummary, err := loadVendorCompatibilityClientProfiles(cfg)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "vendor compatibility client profiles: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, vendorCompatibilityResponse{
		VendorCompatibilityReport: report,
		ClientProfiles:            clientProfiles,
		ProfileSummary:            profileSummary,
	})
}

func vendorDictionaryImportPaths(cfg *config.Config) []string {
	if cfg != nil && len(cfg.Radius.Vendor.DictionaryPaths) > 0 {
		return normalizeVendorDictionaryImportPaths(cfg.Radius.Vendor.DictionaryPaths)
	}
	return normalizeVendorDictionaryImportPaths(productconfigs.ExistingDefaultVendorDictionaryImportPaths())
}

func normalizeVendorDictionaryImportPaths(paths []string) []string {
	out := make([]string, 0, len(paths))
	seen := map[string]struct{}{}
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
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

func normalizeVendorCompatibilityPackKeys(keys []string) []string {
	out := make([]string, 0, len(keys))
	seen := map[string]struct{}{}
	for _, key := range keys {
		normalized := productconfigs.NormalizeVendorCompatibilityPackKey(key)
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out
}

func loadVendorCompatibilityClientProfiles(cfg *config.Config) ([]vendorCompatibilityClientProfile, vendorCompatibilityProfileSummary, error) {
	summary := vendorCompatibilityProfileSummary{ProfileCounts: map[string]int{}}
	if db.DB == nil {
		return nil, summary, nil
	}

	rows, err := queryRadiusClientsForVendorCompatibility()
	if err != nil {
		if isMissingRadiusClientsForVendorCompatibility(err) || isUnavailableRadiusClientDBForVendorCompatibility(err) {
			return nil, summary, nil
		}
		return nil, summary, err
	}
	defer rows.Close()

	vendor := config.RadiusVendorConfig{}
	if cfg != nil {
		vendor = cfg.Radius.Vendor
	}

	var profiles []vendorCompatibilityClientProfile
	unknownSet := map[string]struct{}{}
	for rows.Next() {
		var (
			shortName string
			ip        string
			rawType   string
			enabled   bool
		)
		if err := rows.Scan(&shortName, &ip, &rawType, &enabled); err != nil {
			return nil, summary, err
		}

		normalized := radius.NormalizeClientNASType(rawType)
		knownPack := productconfigs.ValidVendorCompatibilityPackKey(normalized)
		usesGlobal := normalized == "other" || !knownPack
		profile := vendorCompatibilityClientProfile{
			ShortName:       shortName,
			IP:              ip,
			RawNASType:      strings.TrimSpace(rawType),
			NASType:         normalized,
			Enabled:         enabled,
			KnownPack:       knownPack,
			UsesGlobalPacks: usesGlobal,
			EffectivePacks:  radius.ReplyCompatibilityPacksForNASType(vendor, normalized),
		}
		if profile.RawNASType == profile.NASType {
			profile.RawNASType = ""
		}
		if usesGlobal && normalized != "other" {
			profile.Warning = "unknown NAS type uses global compatibility packs"
			unknownSet[normalized] = struct{}{}
		}

		profiles = append(profiles, profile)
		summary.TotalClients++
		if enabled {
			summary.EnabledClients++
		}
		summary.ProfileCounts[normalized]++
		if usesGlobal {
			summary.GlobalFallbackClientCount++
		} else {
			summary.KnownVendorProfileClients++
		}
	}
	if err := rows.Err(); err != nil {
		if isUnavailableRadiusClientDBForVendorCompatibility(err) {
			return nil, summary, nil
		}
		return nil, summary, err
	}

	for profile := range unknownSet {
		summary.UnknownProfiles = append(summary.UnknownProfiles, profile)
	}
	sort.Strings(summary.UnknownProfiles)
	return profiles, summary, nil
}

func queryRadiusClientsForVendorCompatibility() (*sql.Rows, error) {
	rows, err := db.DB.Query(`SELECT shortname, ipaddr, COALESCE(nas_type, ''), enabled FROM radius_clients ORDER BY shortname`)
	if err == nil {
		return rows, nil
	}
	if !isMissingRadiusClientNASTypeForVendorCompatibility(err) {
		return nil, err
	}
	return db.DB.Query(`SELECT shortname, ipaddr, '', enabled FROM radius_clients ORDER BY shortname`)
}

func isMissingRadiusClientsForVendorCompatibility(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "no such table") && strings.Contains(strings.ToLower(err.Error()), "radius_clients")
}

func isMissingRadiusClientNASTypeForVendorCompatibility(err error) bool {
	if err == nil {
		return false
	}
	normalized := strings.ToLower(err.Error())
	return strings.Contains(normalized, "no such column") && strings.Contains(normalized, "nas_type")
}

func isUnavailableRadiusClientDBForVendorCompatibility(err error) bool {
	if err == nil {
		return false
	}
	normalized := strings.ToLower(err.Error())
	return strings.Contains(normalized, "database is closed") ||
		strings.Contains(normalized, "bad connection") ||
		strings.Contains(normalized, "connection is already closed")
}
