package adminapi

import (
	"net/http"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

func HandleGetVendorCompatibility(w http.ResponseWriter, r *http.Request) {
	report := productconfigs.AegisNASVendorCompatibilityReport()
	if cfg := config.Get(); cfg != nil && len(cfg.Radius.Vendor.CompatibilityPacks) > 0 {
		report.ActivePacks = normalizeVendorCompatibilityPackKeys(cfg.Radius.Vendor.CompatibilityPacks)
	}
	writeJSON(w, http.StatusOK, report)
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
