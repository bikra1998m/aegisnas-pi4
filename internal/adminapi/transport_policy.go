package adminapi

import (
	"net/http"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/radius"
)

func HandleGetTransportPolicy(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, radius.BuildTransportPolicyReport(cfg))
}
