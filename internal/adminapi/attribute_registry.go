package adminapi

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
)

const (
	defaultAttributeRegistryPageSize = 100
	maxAttributeRegistryPageSize     = 500
)

type attributeRegistryResponse struct {
	SchemaVersion        int                                     `json:"schema_version"`
	SourceRelease        string                                  `json:"source_release"`
	SourceFileCount      int                                     `json:"source_file_count"`
	SourceAttributeCount int                                     `json:"source_attribute_count"`
	SourceSHA256         string                                  `json:"source_sha256"`
	VendorCount          int                                     `json:"vendor_count"`
	AttributeCount       int                                     `json:"attribute_count"`
	MappedCount          int                                     `json:"mapped_count"`
	FilteredCount        int                                     `json:"filtered_count"`
	Entries              []productconfigs.AttributeRegistryEntry `json:"entries"`
	NextCursor           string                                  `json:"next_cursor,omitempty"`
}

type attributeRegistryFilter struct {
	Vendor   string
	PEN      uint32
	Pack     string
	Semantic string
	Status   string
	Search   string
}

func HandleGetAttributeRegistry(w http.ResponseWriter, r *http.Request) {
	registry, err := productconfigs.BuiltInAttributeRegistry()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "attribute registry is unavailable"})
		return
	}
	filter, err := parseAttributeRegistryFilter(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	limit, err := parseAttributeRegistryLimit(r.URL.Query().Get("limit"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	fingerprint := attributeRegistryFilterFingerprint(filter)
	offset, err := decodeAttributeRegistryCursor(r.URL.Query().Get("cursor"), registry.SourceSHA256, fingerprint)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	filtered := make([]productconfigs.AttributeRegistryEntry, 0, limit)
	matched := 0
	for _, entry := range registry.Entries {
		if !attributeRegistryEntryMatches(entry, filter) {
			continue
		}
		if matched >= offset && len(filtered) < limit {
			filtered = append(filtered, entry)
		}
		matched++
	}
	if offset > matched {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "attribute registry cursor is out of range"})
		return
	}
	next := ""
	if offset+len(filtered) < matched {
		next = encodeAttributeRegistryCursor(registry.SourceSHA256, fingerprint, offset+len(filtered))
	}
	writeJSON(w, http.StatusOK, attributeRegistryResponse{
		SchemaVersion: registry.SchemaVersion, SourceRelease: registry.SourceRelease,
		SourceFileCount: registry.SourceFileCount, SourceAttributeCount: registry.SourceAttributeCount,
		SourceSHA256: registry.SourceSHA256, VendorCount: registry.VendorCount,
		AttributeCount: registry.AttributeCount, MappedCount: registry.MappedCount,
		FilteredCount: matched, Entries: filtered, NextCursor: next,
	})
}

func parseAttributeRegistryFilter(r *http.Request) (attributeRegistryFilter, error) {
	query := r.URL.Query()
	filter := attributeRegistryFilter{
		Vendor:   strings.ToLower(strings.TrimSpace(query.Get("vendor"))),
		Pack:     productconfigs.NormalizeVendorCompatibilityPackKey(query.Get("pack")),
		Semantic: strings.ToLower(strings.TrimSpace(query.Get("semantic"))),
		Status:   strings.ToLower(strings.TrimSpace(query.Get("status"))),
		Search:   strings.ToLower(strings.TrimSpace(query.Get("search"))),
	}
	if value := strings.TrimSpace(query.Get("pen")); value != "" {
		parsed, err := strconv.ParseUint(value, 10, 32)
		if err != nil || parsed == 0 {
			return attributeRegistryFilter{}, fmt.Errorf("pen must be an unsigned non-zero 32-bit integer")
		}
		filter.PEN = uint32(parsed)
	}
	if filter.Status != "" && filter.Status != "missing" && filter.Status != "partial" && filter.Status != "implemented" {
		return attributeRegistryFilter{}, fmt.Errorf("status must be missing, partial, or implemented")
	}
	if len(filter.Search) > 200 || len(filter.Vendor) > 200 || len(filter.Semantic) > 200 || len(filter.Pack) > 200 {
		return attributeRegistryFilter{}, fmt.Errorf("attribute registry filter exceeds 200 characters")
	}
	return filter, nil
}

func parseAttributeRegistryLimit(value string) (int, error) {
	if strings.TrimSpace(value) == "" {
		return defaultAttributeRegistryPageSize, nil
	}
	limit, err := strconv.Atoi(value)
	if err != nil || limit < 1 || limit > maxAttributeRegistryPageSize {
		return 0, fmt.Errorf("limit must be between 1 and %d", maxAttributeRegistryPageSize)
	}
	return limit, nil
}

func attributeRegistryEntryMatches(entry productconfigs.AttributeRegistryEntry, filter attributeRegistryFilter) bool {
	if filter.Vendor != "" && !strings.EqualFold(entry.Vendor, filter.Vendor) {
		return false
	}
	if filter.PEN != 0 && entry.PEN != filter.PEN {
		return false
	}
	if filter.Pack != "" && !strings.EqualFold(entry.PackKey, filter.Pack) {
		return false
	}
	if filter.Semantic != "" && !attributeRegistrySemanticContains(entry.Semantic, filter.Semantic) {
		return false
	}
	if filter.Status != "" && !strings.EqualFold(entry.DictionaryStatus, filter.Status) {
		return false
	}
	if filter.Search != "" {
		haystack := strings.ToLower(strings.Join([]string{entry.Vendor, entry.Attribute, entry.Semantic, entry.CapabilityFamily, entry.Functionality}, "\n"))
		if !strings.Contains(haystack, filter.Search) {
			return false
		}
	}
	return true
}

func attributeRegistrySemanticContains(value, target string) bool {
	for _, semantic := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(semantic), target) {
			return true
		}
	}
	return false
}

func attributeRegistryFilterFingerprint(filter attributeRegistryFilter) string {
	digest := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d\x00%s\x00%s\x00%s\x00%s", filter.Vendor, filter.PEN, filter.Pack, filter.Semantic, filter.Status, filter.Search)))
	return fmt.Sprintf("%x", digest[:8])
}

func encodeAttributeRegistryCursor(sourceSHA, fingerprint string, offset int) string {
	payload := fmt.Sprintf("v1:%s:%s:%d", sourceSHA[:16], fingerprint, offset)
	return base64.RawURLEncoding.EncodeToString([]byte(payload))
}

func decodeAttributeRegistryCursor(cursor, sourceSHA, fingerprint string) (int, error) {
	if strings.TrimSpace(cursor) == "" {
		return 0, nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return 0, fmt.Errorf("attribute registry cursor is invalid")
	}
	parts := strings.Split(string(payload), ":")
	if len(parts) != 4 || parts[0] != "v1" || parts[1] != sourceSHA[:16] || parts[2] != fingerprint {
		return 0, fmt.Errorf("attribute registry cursor is stale or does not match the filters")
	}
	offset, err := strconv.Atoi(parts[3])
	if err != nil || offset < 0 {
		return 0, fmt.Errorf("attribute registry cursor is invalid")
	}
	return offset, nil
}
