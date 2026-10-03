package adminapi

import (
	"context"
	"net/http"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/enforcement"
)

func HandleGetBroadbandL2TPWholesale(w http.ResponseWriter, r *http.Request) {
	report, err := enforcement.PreviewBroadbandL2TPWholesale(config.Get())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	summary, events, bindings, err := broadbandL2TPWholesaleEvidenceWithLimit(20)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"report":       report,
		"evidence": map[string]any{
			"summary":        summary,
			"recent_events":  events,
			"realm_bindings": bindings,
		},
	})
}

func HandlePreviewBroadbandL2TPWholesale(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	report, eventID, err := enforcement.PreviewAndRecordBroadbandL2TPWholesale(config.Get(), actor)
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

func HandleApplyBroadbandL2TPWholesale(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	report, eventID, err := enforcement.ApplyBroadbandL2TPWholesale(context.Background(), config.Get(), actor)
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

func HandleListBroadbandL2TPWholesaleHistory(w http.ResponseWriter, r *http.Request) {
	limit := parseVLANLifecycleLimit(r.URL.Query().Get("limit"), 100)
	summary, events, bindings, err := broadbandL2TPWholesaleEvidenceWithLimit(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at":   time.Now().UTC().Format(time.RFC3339),
		"feature_id":     enforcement.BroadbandL2TPWholesaleFeatureID,
		"summary":        summary,
		"events":         events,
		"realm_bindings": bindings,
	})
}

func broadbandL2TPWholesaleEvidenceWithLimit(limit int) (db.BroadbandL2TPWholesaleSummary, []db.BroadbandL2TPWholesaleEvent, []db.BroadbandL2TPWholesaleBindingRecord, error) {
	summary, err := db.GetBroadbandL2TPWholesaleSummary()
	if err != nil {
		return db.BroadbandL2TPWholesaleSummary{}, nil, nil, err
	}
	events, err := db.ListBroadbandL2TPWholesaleEvents(limit)
	if err != nil {
		return db.BroadbandL2TPWholesaleSummary{}, nil, nil, err
	}
	bindings, err := db.ListBroadbandL2TPWholesaleBindings(limit, "")
	if err != nil {
		return db.BroadbandL2TPWholesaleSummary{}, nil, nil, err
	}
	return summary, events, bindings, nil
}
