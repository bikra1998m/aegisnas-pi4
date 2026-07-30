package adminapi

import (
	"net/http"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/radius"
)

func HandleGetAccountingIP(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	validationStatus := r.URL.Query().Get("validation_status")
	sessionKey := r.URL.Query().Get("session_key")
	limit := parseAccountingSpoolLimit(r.URL.Query().Get("limit"), 100)
	var records []db.AccountingIPAssignmentRecord
	if validationStatus != "" || sessionKey != "" || limit != 100 {
		var err error
		records, err = db.ListAccountingIPAssignments(limit, validationStatus, sessionKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"report":       radius.BuildAccountingIPReport(cfg),
		"records":      records,
	})
}
