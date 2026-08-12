package adminapi

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/radius"
)

func HandleGetRateCompiler(w http.ResponseWriter, r *http.Request) {
	report := radius.BuildRateCompilerReport()
	summary, events, err := rateCompilerEvidenceWithLimit(20)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"report":       report,
		"evidence": map[string]any{
			"summary":       summary,
			"recent_events": events,
		},
	})
}

func HandleCompileRate(w http.ResponseWriter, r *http.Request) {
	var req radius.RateCompilerRequest
	if err := decodeBody(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	result := radius.CompileVendorRates(req)
	status := result.Status
	if status == "ready" {
		status = "compiled"
	}
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	eventID, err := db.RecordRateCompilerEvent(db.RateCompilerEventInput{
		Operation:        "compile",
		Status:           status,
		PackKeysJSON:     rateCompilerJSON(req.PackKeys, "[]"),
		DownloadRateKbps: req.DownloadRateKbps,
		UploadRateKbps:   req.UploadRateKbps,
		AttributeCount:   result.AttributeCount,
		DiagnosticCount:  len(result.Diagnostics),
		RequestJSON:      rateCompilerJSON(req, "{}"),
		ResponseJSON:     rateCompilerJSON(result, "{}"),
		DiagnosticsJSON:  rateCompilerJSON(result.Diagnostics, "[]"),
		Actor:            actor,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"event_id":     eventID,
		"result":       result,
	})
}

func HandleDecompileRate(w http.ResponseWriter, r *http.Request) {
	var req radius.RateDecompilerRequest
	if err := decodeBody(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	result := radius.DecompileVendorRates(req)
	status := result.Status
	if status == "ready" {
		status = "decompiled"
	}
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	packKeys := []string{}
	if result.PackKey != "" {
		packKeys = []string{result.PackKey}
	}
	eventID, err := db.RecordRateCompilerEvent(db.RateCompilerEventInput{
		Operation:        "decompile",
		Status:           status,
		PackKeysJSON:     rateCompilerJSON(packKeys, "[]"),
		DownloadRateKbps: result.Intent.DownloadRateKbps,
		UploadRateKbps:   result.Intent.UploadRateKbps,
		AttributeCount:   result.AttributeCount,
		DiagnosticCount:  len(result.Diagnostics),
		RequestJSON:      rateCompilerJSON(req, "{}"),
		ResponseJSON:     rateCompilerJSON(result, "{}"),
		DiagnosticsJSON:  rateCompilerJSON(result.Diagnostics, "[]"),
		Actor:            actor,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"event_id":     eventID,
		"result":       result,
	})
}

func rateCompilerEvidenceWithLimit(limit int) (db.RateCompilerEventSummary, []db.RateCompilerEvent, error) {
	if db.DB == nil {
		return db.RateCompilerEventSummary{}, nil, nil
	}
	summary, err := db.GetRateCompilerEventSummary()
	if err != nil {
		return db.RateCompilerEventSummary{}, nil, err
	}
	events, err := db.ListRateCompilerEvents(limit)
	if err != nil {
		return db.RateCompilerEventSummary{}, nil, err
	}
	return summary, events, nil
}

func rateCompilerJSON(value any, fallback string) string {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) == 0 {
		return fallback
	}
	return string(encoded)
}
