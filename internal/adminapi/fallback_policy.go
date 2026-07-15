package adminapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/radius"
)

func HandleGetFallbackPolicy(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	report := radius.BuildFallbackPolicyReport(cfg)
	decision := strings.TrimSpace(r.URL.Query().Get("decision"))
	source := strings.TrimSpace(r.URL.Query().Get("source"))
	limit := parseUpstreamAAAHistoryLimit(r.URL.Query().Get("limit"), 100)

	var events []db.RadiusFallbackEvent
	var err error
	if decision != "" || source != "" || limit != 100 {
		events, err = db.ListRadiusFallbackEvents(decision, source, limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"report":       report,
		"events":       events,
	})
}
