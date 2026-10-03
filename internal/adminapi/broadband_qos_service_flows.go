package adminapi

import (
	"context"
	"net/http"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/enforcement"
)

func HandleGetBroadbandQoSServiceFlows(w http.ResponseWriter, r *http.Request) {
	report, err := enforcement.PreviewBroadbandQoSServiceFlows(config.Get())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	summary, events, flows, err := broadbandQoSServiceFlowEvidenceWithLimit(20)
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
			"flows":         flows,
		},
	})
}

func HandlePreviewBroadbandQoSServiceFlows(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	report, eventID, err := enforcement.PreviewAndRecordBroadbandQoSServiceFlows(config.Get(), actor)
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

func HandleApplyBroadbandQoSServiceFlows(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	report, eventID, err := enforcement.ApplyBroadbandQoSServiceFlows(context.Background(), config.Get(), actor)
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

func HandleListBroadbandQoSServiceFlowHistory(w http.ResponseWriter, r *http.Request) {
	limit := parseVLANLifecycleLimit(r.URL.Query().Get("limit"), 100)
	summary, events, flows, err := broadbandQoSServiceFlowEvidenceWithLimit(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"feature_id":   enforcement.BroadbandQoSServiceFlowFeatureID,
		"summary":      summary,
		"events":       events,
		"flows":        flows,
	})
}

func broadbandQoSServiceFlowEvidenceWithLimit(limit int) (db.BroadbandQoSServiceFlowSummary, []db.BroadbandQoSServiceFlowEvent, []db.BroadbandQoSServiceFlowRecord, error) {
	summary, err := db.GetBroadbandQoSServiceFlowSummary()
	if err != nil {
		return db.BroadbandQoSServiceFlowSummary{}, nil, nil, err
	}
	events, err := db.ListBroadbandQoSServiceFlowEvents(limit)
	if err != nil {
		return db.BroadbandQoSServiceFlowSummary{}, nil, nil, err
	}
	flows, err := db.ListBroadbandQoSServiceFlows(limit, "")
	if err != nil {
		return db.BroadbandQoSServiceFlowSummary{}, nil, nil, err
	}
	return summary, events, flows, nil
}
