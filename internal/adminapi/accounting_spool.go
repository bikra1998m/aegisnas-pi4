package adminapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/radius"
)

type accountingSpoolReplayRequest struct {
	BatchSize int `json:"batch_size"`
}

func HandleGetAccountingSpool(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	report := radius.BuildAccountingSpoolReport(cfg)
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	limit := parseAccountingSpoolLimit(r.URL.Query().Get("limit"), 100)
	recordID := strings.TrimSpace(r.URL.Query().Get("record_id"))

	var records []db.RadiusAccountingSpoolRecord
	var attempts []db.RadiusAccountingSpoolAttempt
	var err error
	if status != "" || limit != 100 {
		records, err = db.ListRadiusAccountingSpool(status, limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if recordID != "" {
		attempts, err = db.ListRadiusAccountingSpoolAttempts(recordID, limit)
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

func HandleReplayAccountingSpool(w http.ResponseWriter, r *http.Request) {
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
	report, err := radius.ReplayAccountingSpool(r.Context(), cfg, request.BatchSize)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func parseAccountingSpoolLimit(raw string, fallback int) int {
	if fallback <= 0 {
		fallback = 100
	}
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value <= 0 {
		return fallback
	}
	if value > 1000 {
		return 1000
	}
	return value
}
