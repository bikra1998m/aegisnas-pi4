package adminapi

import (
	"context"
	"net/http"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/enforcement"
)

func HandleGetBroadbandServiceActivation(w http.ResponseWriter, r *http.Request) {
	report, err := enforcement.PreviewBroadbandServiceActivation(config.Get())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	summary, events, transactions, err := broadbandServiceActivationEvidenceWithLimit(20)
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
			"transactions":  transactions,
		},
	})
}

func HandlePreviewBroadbandServiceActivation(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	report, eventID, err := enforcement.PreviewAndRecordBroadbandServiceActivation(config.Get(), actor)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"event_id":     eventID,
		"result": map[string]any{
			"status":   report.Status,
			"event_id": eventID,
		},
		"report": report,
	})
}

func HandleApplyBroadbandServiceActivation(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	report, eventID, err := enforcement.ApplyBroadbandServiceActivation(context.Background(), config.Get(), actor)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{
			"generated_at": time.Now().UTC().Format(time.RFC3339),
			"event_id":     eventID,
			"report":       report,
			"error":        err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"event_id":     eventID,
		"result": map[string]any{
			"status":   report.Status,
			"event_id": eventID,
		},
		"report": report,
	})
}

func HandleListBroadbandServiceActivationHistory(w http.ResponseWriter, r *http.Request) {
	limit := parseVLANLifecycleLimit(r.URL.Query().Get("limit"), 100)
	summary, events, transactions, err := broadbandServiceActivationEvidenceWithLimit(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"feature_id":   enforcement.BroadbandServiceActivationFeatureID,
		"summary":      summary,
		"events":       events,
		"transactions": transactions,
	})
}

func broadbandServiceActivationEvidenceWithLimit(limit int) (db.BroadbandServiceActivationSummary, []db.BroadbandServiceActivationEvent, []db.BroadbandServiceActivationTransactionRecord, error) {
	summary, err := db.GetBroadbandServiceActivationSummary()
	if err != nil {
		return db.BroadbandServiceActivationSummary{}, nil, nil, err
	}
	events, err := db.ListBroadbandServiceActivationEvents(limit)
	if err != nil {
		return db.BroadbandServiceActivationSummary{}, nil, nil, err
	}
	transactions, err := db.ListBroadbandServiceActivationTransactions(limit, "")
	if err != nil {
		return db.BroadbandServiceActivationSummary{}, nil, nil, err
	}
	return summary, events, transactions, nil
}
