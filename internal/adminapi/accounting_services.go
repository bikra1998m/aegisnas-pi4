package adminapi

import (
	"net/http"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/radius"
)

func HandleGetAccountingServices(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	status := r.URL.Query().Get("status")
	parentSessionKey := r.URL.Query().Get("parent_session_key")
	limit := parseAccountingSpoolLimit(r.URL.Query().Get("limit"), 100)
	var records []db.AccountingServiceCorrelationRecord
	if status != "" || parentSessionKey != "" || limit != 100 {
		var err error
		records, err = db.ListAccountingServiceCorrelations(limit, status, parentSessionKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"report":       radius.BuildAccountingServicesReport(cfg),
		"records":      records,
	})
}
