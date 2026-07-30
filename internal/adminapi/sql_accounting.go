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

type sqlAccountingReconcileRequest struct {
	BatchSize int `json:"batch_size"`
}

func HandleGetSQLAccounting(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	report := radius.BuildSQLAccountingReport(cfg)
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	limit := parseAccountingSpoolLimit(r.URL.Query().Get("limit"), 100)

	var records []db.FreeRADIUSAccountingRecord
	if status != "" || limit != 100 {
		var err error
		records, err = db.ListFreeRADIUSAccounting(limit, status)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"report":       report,
		"records":      records,
	})
}

func HandleReconcileSQLAccounting(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	var request sqlAccountingReconcileRequest
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
			http.Error(w, "invalid reconcile request", http.StatusBadRequest)
			return
		}
	}
	report, err := radius.ReconcileSQLAccounting(r.Context(), cfg, request.BatchSize)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, report)
}
