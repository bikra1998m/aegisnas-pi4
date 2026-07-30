package adminapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/radius"
)

type accountingOrderingReplayRequest struct {
	Limit      int    `json:"limit"`
	SessionKey string `json:"session_key"`
}

func HandleGetAccountingOrdering(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	report := radius.BuildAccountingOrderingReport(cfg)
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	sessionKey := strings.TrimSpace(r.URL.Query().Get("session_key"))
	limit := parseAccountingSpoolLimit(r.URL.Query().Get("limit"), 100)

	var events []db.AccountingEventRecord
	if status != "" || sessionKey != "" || limit != 100 {
		var err error
		events, err = db.ListAccountingEvents(limit, status, sessionKey)
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

func HandleReplayAccountingOrdering(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	var request accountingOrderingReplayRequest
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
			http.Error(w, "invalid accounting replay request", http.StatusBadRequest)
			return
		}
	}
	report, err := radius.ReplayAccountingOrdering(r.Context(), cfg, request.Limit, request.SessionKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, report)
}
