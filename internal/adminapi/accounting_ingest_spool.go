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

func HandleGetAccountingIngestSpool(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	report := radius.BuildAccountingIngestSpoolReport(cfg)
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	limit := parseAccountingSpoolLimit(r.URL.Query().Get("limit"), 100)
	recordID := strings.TrimSpace(r.URL.Query().Get("record_id"))

	var records []db.AccountingIngestSpoolRecord
	var attempts []db.AccountingIngestSpoolAttempt
	var err error
	if status != "" || limit != 100 {
		records, err = db.ListAccountingIngestSpool(status, limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if recordID != "" {
		attempts, err = db.ListAccountingIngestSpoolAttempts(recordID, limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"report":       report,
		"records":      records,
		"attempts":     attempts,
	})
}

func HandleReplayAccountingIngestSpool(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	var request accountingSpoolReplayRequest
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
			http.Error(w, "invalid replay request", http.StatusBadRequest)
			return
		}
	}
	report, err := radius.ReplayAccountingIngestSpool(r.Context(), cfg, request.BatchSize)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, report)
}
