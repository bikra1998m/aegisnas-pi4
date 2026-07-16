package adminapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/activedirectory"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func HandleGetActiveDirectory(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	report := activedirectory.BuildReport(cfg)
	source := strings.TrimSpace(r.URL.Query().Get("source"))
	decision := strings.TrimSpace(r.URL.Query().Get("decision"))
	component := strings.TrimSpace(r.URL.Query().Get("component"))
	limit := parseUpstreamAAAHistoryLimit(r.URL.Query().Get("limit"), 100)

	var events []db.ActiveDirectoryEvent
	var health []db.ActiveDirectoryHealthCheck
	var err error
	if source != "" || decision != "" || limit != 100 {
		events, err = db.ListActiveDirectoryEvents(source, decision, limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if component != "" || limit != 100 {
		health, err = db.ListActiveDirectoryHealthChecks(component, limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"report":       report,
		"events":       events,
		"health":       health,
	})
}

func HandleCheckActiveDirectory(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	checks, err := activedirectory.CheckHealth(r.Context(), cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	audit(r, "check_active_directory", "active_directory", "checked")
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"checks":       checks,
		"report":       activedirectory.BuildReport(cfg),
	})
}
