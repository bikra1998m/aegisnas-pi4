package adminapi

import (
	"context"
	"net/http"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/enforcement"
)

func HandleGetCWAPortalLifecycle(w http.ResponseWriter, r *http.Request) {
	report, err := enforcement.PreviewCWAPortalLifecycle(config.Get())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	summary, events, err := cwaPortalLifecycleEvidenceWithLimit(20)
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

func HandlePreviewCWAPortalLifecycle(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	report, eventID, err := enforcement.PreviewAndRecordCWAPortalLifecycle(config.Get(), actor)
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

func HandleApplyCWAPortalLifecycle(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	report, eventID, err := enforcement.ApplyCWAPortalLifecycle(context.Background(), config.Get(), actor)
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

func HandleListCWAPortalLifecycleHistory(w http.ResponseWriter, r *http.Request) {
	limit := parseVLANLifecycleLimit(r.URL.Query().Get("limit"), 100)
	summary, events, err := cwaPortalLifecycleEvidenceWithLimit(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"feature_id":   enforcement.CWAPortalLifecycleFeatureID,
		"summary":      summary,
		"events":       events,
	})
}

func cwaPortalLifecycleEvidenceWithLimit(limit int) (db.CWAPortalLifecycleSummary, []db.CWAPortalLifecycleEvent, error) {
	summary, err := db.GetCWAPortalLifecycleSummary()
	if err != nil {
		return db.CWAPortalLifecycleSummary{}, nil, err
	}
	events, err := db.ListCWAPortalLifecycleEvents(limit)
	if err != nil {
		return db.CWAPortalLifecycleSummary{}, nil, err
	}
	return summary, events, nil
}
