package adminapi

import (
	"net/http"
	"strings"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/radius"
)

func HandleGetVSACodec(w http.ResponseWriter, r *http.Request) {
	registry, err := productconfigs.BuiltInAttributeRegistry()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "vsa codec registry is unavailable: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, radius.BuildVSACodecReport(registry, buildVSACodecCatalogForRequest()))
}

func buildVSACodecCatalogForRequest() productconfigs.VendorDictionaryCatalog {
	cfg := config.Get()
	catalog := productconfigs.AegisNASVendorDictionaryCatalog()
	if cfg != nil {
		vendor := cfg.Radius.Vendor
		catalog = productconfigs.AegisNASVendorDictionaryCatalogFor(vendor.Name, vendor.ID)
	}
	importPaths := vendorDictionaryImportPaths(cfg)
	if len(importPaths) == 0 {
		return catalog
	}
	imported := productconfigs.LoadVendorDictionaryCatalog(importPaths)
	return productconfigs.MergeVendorDictionaryCatalogs("built-in AegisNAS, "+strings.Join(importPaths, ", "), catalog, imported)
}
