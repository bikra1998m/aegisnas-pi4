package adminapi

import (
	"context"
	"net/http"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/enforcement"
)

func HandleGetWiMAXServiceFlows(w http.ResponseWriter, r *http.Request) {
	report, err := enforcement.PreviewWiMAXServiceFlows(config.Get())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	summary, events, profiles, err := wimaxServiceFlowEvidenceWithLimit(20)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"report":       report,
		"evidence": map[string]any{
			"summary":         summary,
			"recent_events":   events,
			"effective_state": profiles,
		},
	})
}

func HandlePreviewWiMAXServiceFlows(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	report, eventID, err := enforcement.PreviewAndRecordWiMAXServiceFlows(config.Get(), actor)
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

func HandleApplyWiMAXServiceFlows(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	report, eventID, err := enforcement.ApplyWiMAXServiceFlows(context.Background(), config.Get(), actor)
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

func HandleListWiMAXServiceFlowHistory(w http.ResponseWriter, r *http.Request) {
	limit := parseVLANLifecycleLimit(r.URL.Query().Get("limit"), 100)
	summary, events, profiles, err := wimaxServiceFlowEvidenceWithLimit(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at":    time.Now().UTC().Format(time.RFC3339),
		"feature_id":      enforcement.WiMAXServiceFlowFeatureID,
		"summary":         summary,
		"events":          events,
		"effective_state": profiles,
	})
}

func wimaxServiceFlowEvidenceWithLimit(limit int) (db.WiMAXServiceFlowSummary, []db.WiMAXServiceFlowEvent, []db.WiMAXServiceFlowProfileRecord, error) {
	summary, err := db.GetWiMAXServiceFlowSummary()
	if err != nil {
		return db.WiMAXServiceFlowSummary{}, nil, nil, err
	}
	events, err := db.ListWiMAXServiceFlowEvents(limit)
	if err != nil {
		return db.WiMAXServiceFlowSummary{}, nil, nil, err
	}
	profiles, err := db.ListWiMAXServiceFlowProfiles(limit, "")
	if err != nil {
		return db.WiMAXServiceFlowSummary{}, nil, nil, err
	}
	return summary, events, profiles, nil
}
