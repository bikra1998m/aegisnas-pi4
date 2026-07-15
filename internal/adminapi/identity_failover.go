package adminapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/identity"
)

func HandleGetIdentityFailover(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	report := identity.BuildFailoverReport(cfg)
	source := strings.TrimSpace(r.URL.Query().Get("source"))
	decision := strings.TrimSpace(r.URL.Query().Get("decision"))
	limit := parseUpstreamAAAHistoryLimit(r.URL.Query().Get("limit"), 100)

	var events []db.IdentitySourceEvent
	var err error
	if source != "" || decision != "" || limit != 100 {
		events, err = db.ListIdentitySourceEvents(source, decision, limit)
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
