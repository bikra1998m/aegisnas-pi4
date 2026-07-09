package adminapi

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

const (
	defaultCompatibilityEvidencePageSize = 100
	maxCompatibilityEvidencePageSize     = 500
)

type compatibilityEvidenceResponse struct {
	SchemaVersion    int                                          `json:"schema_version"`
	ReleaseProfileID string                                       `json:"release_profile_id"`
	SourceSHA256     string                                       `json:"source_sha256"`
	Summary          productconfigs.CompatibilityEvidenceSummary  `json:"summary"`
	FilteredCount    int                                          `json:"filtered_count"`
	Records          []productconfigs.CompatibilityEvidenceRecord `json:"records"`
	NextCursor       string                                       `json:"next_cursor,omitempty"`
	Notes            []string                                     `json:"notes,omitempty"`
}

type compatibilityEvidenceFilter struct {
	Pack               string
	Vendor             string
	Semantic           string
	SoftwareState      string
	CertificationState string
	Claim              string
	Search             string
}

func HandleGetCompatibilityEvidence(w http.ResponseWriter, r *http.Request) {
	report := buildCompatibilityEvidenceForRequest()
	if err := productconfigs.ValidateCompatibilityEvidenceReport(report); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "compatibility evidence is unavailable: " + err.Error()})
		return
	}
	filter, err := parseCompatibilityEvidenceFilter(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	limit, err := parseCompatibilityEvidenceLimit(r.URL.Query().Get("limit"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	fingerprint := compatibilityEvidenceFilterFingerprint(filter)
	offset, err := decodeCompatibilityEvidenceCursor(r.URL.Query().Get("cursor"), report.ReleaseProfileID, report.SourceSHA256, fingerprint)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	filtered := make([]productconfigs.CompatibilityEvidenceRecord, 0, limit)
	matched := 0
	for _, record := range report.Records {
		if !compatibilityEvidenceRecordMatches(record, filter) {
			continue
		}
		if matched >= offset && len(filtered) < limit {
			filtered = append(filtered, record)
		}
		matched++
	}
	if offset > matched {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "compatibility evidence cursor is out of range"})
		return
	}
	next := ""
	if offset+len(filtered) < matched {
		next = encodeCompatibilityEvidenceCursor(report.ReleaseProfileID, report.SourceSHA256, fingerprint, offset+len(filtered))
	}
	writeJSON(w, http.StatusOK, compatibilityEvidenceResponse{
		SchemaVersion: report.SchemaVersion, ReleaseProfileID: report.ReleaseProfileID, SourceSHA256: report.SourceSHA256,
		Summary: report.Summary, FilteredCount: matched, Records: filtered, NextCursor: next, Notes: report.Notes,
	})
}

func buildCompatibilityEvidenceForRequest() productconfigs.CompatibilityEvidenceReport {
	cfg := config.Get()
	report := productconfigs.AegisNASVendorCompatibilityReport()
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
	}
	importPaths := vendorDictionaryImportPaths(cfg)
	if len(importPaths) > 0 {
		imported := productconfigs.LoadVendorDictionaryCatalog(importPaths)
		report.Catalog = productconfigs.MergeVendorDictionaryCatalogs("built-in AegisNAS, "+imported.Source, report.Catalog, imported)
	}
	return productconfigs.BuildCompatibilityEvidenceReport(report.Catalog, report.Packs, report.ActivePacks)
}

func parseCompatibilityEvidenceFilter(r *http.Request) (compatibilityEvidenceFilter, error) {
	query := r.URL.Query()
	filter := compatibilityEvidenceFilter{
		Pack:               productconfigs.NormalizeVendorCompatibilityPackKey(query.Get("pack")),
		Vendor:             strings.ToLower(strings.TrimSpace(query.Get("vendor"))),
		Semantic:           strings.ToLower(strings.TrimSpace(query.Get("semantic"))),
		SoftwareState:      strings.ToLower(strings.TrimSpace(query.Get("software_state"))),
		CertificationState: strings.ToLower(strings.TrimSpace(query.Get("certification_state"))),
		Claim:              strings.ToLower(strings.TrimSpace(query.Get("claim"))),
		Search:             strings.ToLower(strings.TrimSpace(query.Get("search"))),
	}
	if filter.SoftwareState != "" {
		switch filter.SoftwareState {
		case productconfigs.EvidenceSoftwareStateReady, productconfigs.EvidenceSoftwareStatePlanned, productconfigs.EvidenceSoftwareStateBlocked, productconfigs.EvidenceSoftwareStateMetadata:
		default:
			return compatibilityEvidenceFilter{}, fmt.Errorf("software_state is invalid")
		}
	}
	if filter.CertificationState != "" {
		switch filter.CertificationState {
		case productconfigs.EvidenceCertificationNotRequired, productconfigs.EvidenceCertificationRequired, productconfigs.EvidenceCertificationCertified:
		default:
			return compatibilityEvidenceFilter{}, fmt.Errorf("certification_state is invalid")
		}
	}
	if filter.Claim != "" {
		switch filter.Claim {
		case productconfigs.EvidenceClaimSoftwareReady, productconfigs.EvidenceClaimSoftwareReadyExternalNeeded, productconfigs.EvidenceClaimPlanned, productconfigs.EvidenceClaimBlocked, productconfigs.EvidenceClaimMetadataOnly:
		default:
			return compatibilityEvidenceFilter{}, fmt.Errorf("claim is invalid")
		}
	}
	if len(filter.Search) > 200 || len(filter.Vendor) > 200 || len(filter.Semantic) > 200 || len(filter.Pack) > 200 {
		return compatibilityEvidenceFilter{}, fmt.Errorf("compatibility evidence filter exceeds 200 characters")
	}
	return filter, nil
}

func parseCompatibilityEvidenceLimit(value string) (int, error) {
	if strings.TrimSpace(value) == "" {
		return defaultCompatibilityEvidencePageSize, nil
	}
	limit, err := strconv.Atoi(value)
	if err != nil || limit < 1 || limit > maxCompatibilityEvidencePageSize {
		return 0, fmt.Errorf("limit must be between 1 and %d", maxCompatibilityEvidencePageSize)
	}
	return limit, nil
}

func compatibilityEvidenceRecordMatches(record productconfigs.CompatibilityEvidenceRecord, filter compatibilityEvidenceFilter) bool {
	if filter.Pack != "" && !strings.EqualFold(record.PackKey, filter.Pack) {
		return false
	}
	if filter.Vendor != "" && !strings.Contains(strings.ToLower(record.VendorName), filter.Vendor) {
		return false
	}
	if filter.Semantic != "" && !strings.EqualFold(record.Semantic, filter.Semantic) {
		return false
	}
	if filter.SoftwareState != "" && !strings.EqualFold(record.SoftwareState, filter.SoftwareState) {
		return false
	}
	if filter.CertificationState != "" && !strings.EqualFold(record.CertificationState, filter.CertificationState) {
		return false
	}
	if filter.Claim != "" && !strings.EqualFold(record.ClaimState, filter.Claim) {
		return false
	}
	if filter.Search != "" {
		haystack := strings.ToLower(strings.Join([]string{record.PackKey, record.PackLabel, record.VendorName, record.Attribute, record.Semantic, record.Direction, record.SoftwareState, record.CertificationState, record.ClaimState}, "\n"))
		if !strings.Contains(haystack, filter.Search) {
			return false
		}
	}
	return true
}

func compatibilityEvidenceFilterFingerprint(filter compatibilityEvidenceFilter) string {
	digest := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s", filter.Pack, filter.Vendor, filter.Semantic, filter.SoftwareState, filter.CertificationState, filter.Claim, filter.Search)))
	return fmt.Sprintf("%x", digest[:8])
}

func encodeCompatibilityEvidenceCursor(releaseProfileID, sourceSHA, fingerprint string, offset int) string {
	payload := fmt.Sprintf("v1:%s:%s:%s:%d", releaseProfileID, sourceSHA[:16], fingerprint, offset)
	return base64.RawURLEncoding.EncodeToString([]byte(payload))
}

func decodeCompatibilityEvidenceCursor(cursor, releaseProfileID, sourceSHA, fingerprint string) (int, error) {
	if strings.TrimSpace(cursor) == "" {
		return 0, nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return 0, fmt.Errorf("compatibility evidence cursor is invalid")
	}
	parts := strings.Split(string(payload), ":")
	if len(parts) != 5 || parts[0] != "v1" || parts[1] != releaseProfileID || parts[2] != sourceSHA[:16] || parts[3] != fingerprint {
		return 0, fmt.Errorf("compatibility evidence cursor is stale or does not match the filters")
	}
	offset, err := strconv.Atoi(parts[4])
	if err != nil || offset < 0 {
		return 0, fmt.Errorf("compatibility evidence cursor is invalid")
	}
	return offset, nil
}
