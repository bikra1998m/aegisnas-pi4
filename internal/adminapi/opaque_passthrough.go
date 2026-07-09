package adminapi

import (
	"net/http"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/radius"
)

func HandleGetOpaquePassThrough(w http.ResponseWriter, r *http.Request) {
	registry, err := productconfigs.BuiltInAttributeRegistry()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "opaque pass-through registry is unavailable: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, radius.BuildOpaquePassThroughReport(registry, config.Get()))
}
