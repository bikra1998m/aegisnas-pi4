package adminapi

import (
	"net/http"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/integrations"
)

func HandleGetControllerEstateLifecycle(w http.ResponseWriter, r *http.Request) {
	report, err := integrations.PreviewControllerEstateLifecycle(config.Get())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	summary, events, err := controllerEstateLifecycleEvidenceWithLimit(20)
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

func HandlePreviewControllerEstateLifecycle(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	report, eventID, err := integrations.PreviewAndRecordControllerEstateLifecycle(config.Get(), actor)
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

func HandleApplyControllerEstateLifecycle(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	report, eventID, err := integrations.ApplyControllerEstateLifecycle(r.Context(), config.Get(), actor)
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

func HandleListControllerEstateLifecycleHistory(w http.ResponseWriter, r *http.Request) {
	limit := parseVLANLifecycleLimit(r.URL.Query().Get("limit"), 100)
	summary, events, err := controllerEstateLifecycleEvidenceWithLimit(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"feature_id":   integrations.ControllerEstateLifecycleFeatureID,
		"summary":      summary,
		"events":       events,
	})
}

func controllerEstateLifecycleEvidenceWithLimit(limit int) (db.ControllerEstateLifecycleSummary, []db.ControllerEstateLifecycleEvent, error) {
	summary, err := db.GetControllerEstateLifecycleSummary()
	if err != nil {
		return db.ControllerEstateLifecycleSummary{}, nil, err
	}
	events, err := db.ListControllerEstateLifecycleEvents(limit)
	if err != nil {
		return db.ControllerEstateLifecycleSummary{}, nil, err
	}
	return summary, events, nil
}
