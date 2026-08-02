package adminapi

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/radius"
)

type accountingChargingReconcileRequest struct {
	BatchSize int `json:"batch_size"`
}

type accountingChargingExportRequest struct {
	Format string `json:"format"`
	Limit  int    `json:"limit"`
}

func HandleGetAccountingCharging(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	report := radius.BuildAccountingChargingReport(cfg)
	limit := parseAccountingSpoolLimit(r.URL.Query().Get("limit"), 100)
	query := db.AccountingChargingRecordQuery{
		CDRID:        strings.TrimSpace(r.URL.Query().Get("cdr_id")),
		Status:       strings.TrimSpace(r.URL.Query().Get("status")),
		RatingStatus: strings.TrimSpace(r.URL.Query().Get("rating_status")),
		ExportStatus: strings.TrimSpace(r.URL.Query().Get("export_status")),
		SessionKey:   strings.TrimSpace(r.URL.Query().Get("session_key")),
		ExportID:     strings.TrimSpace(r.URL.Query().Get("export_id")),
		Limit:        limit,
	}
	var records []db.AccountingChargingRecord
	if query.CDRID != "" || query.Status != "" || query.RatingStatus != "" || query.ExportStatus != "" || query.SessionKey != "" || query.ExportID != "" || limit != 100 {
		var err error
		records, err = db.ListAccountingChargingRecords(query)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	exports, err := db.ListAccountingChargingExports(25)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"report":       report,
		"records":      records,
		"exports":      exports,
	})
}

func HandleReconcileAccountingCharging(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	var request accountingChargingReconcileRequest
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
			http.Error(w, "invalid charging reconcile request", http.StatusBadRequest)
			return
		}
	}
	report, err := radius.ReconcileAccountingCharging(r.Context(), cfg, request.BatchSize)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	audit(r, "reconcile_accounting_charging", "radius_accounting_charging", report.Status)
	writeJSON(w, http.StatusOK, report)
}

func HandleExportAccountingCharging(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	var request accountingChargingExportRequest
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
			http.Error(w, "invalid charging export request", http.StatusBadRequest)
			return
		}
	}
	identity := adminIdentityFromRequest(r)
	createdBy := firstNonEmptyAdminString(identity.Subject, identity.Role, "admin")
	result, err := radius.ExportAccountingCharging(r.Context(), cfg, request.Format, request.Limit, createdBy)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	audit(r, "export_accounting_charging", result.ExportID, result.Status)
	writeJSON(w, http.StatusOK, result)
}

func HandleDownloadAccountingChargingExport(w http.ResponseWriter, r *http.Request) {
	exportID := strings.TrimSpace(r.URL.Query().Get("export_id"))
	if exportID == "" {
		http.Error(w, "export_id is required", http.StatusBadRequest)
		return
	}
	export, err := db.GetAccountingChargingExport(exportID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "charging export not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	contentType := "application/x-ndjson"
	extension := "jsonl"
	switch export.Format {
	case "json":
		contentType = "application/json"
		extension = "json"
	case "csv":
		contentType = "text/csv; charset=utf-8"
		extension = "csv"
	}
	filename := fmt.Sprintf("aegisnas-charging-%s.%s", sanitizeDownloadName(export.ExportID), extension)
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(export.Payload))
	audit(r, "download_accounting_charging_export", export.ExportID, "downloaded")
}

func firstNonEmptyAdminString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
