package adminapi

import (
	"context"
	"net/http"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/enforcement"
)

func HandleGetMobileSessions(w http.ResponseWriter, r *http.Request) {
	report, err := enforcement.PreviewMobileSessions(config.Get())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	summary, events, profiles, err := mobileSessionEvidenceWithLimit(20)
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

func HandlePreviewMobileSessions(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	report, eventID, err := enforcement.PreviewAndRecordMobileSessions(config.Get(), actor)
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

func HandleApplyMobileSessions(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	report, eventID, err := enforcement.ApplyMobileSessions(context.Background(), config.Get(), actor)
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

func HandleListMobileSessionHistory(w http.ResponseWriter, r *http.Request) {
	limit := parseVLANLifecycleLimit(r.URL.Query().Get("limit"), 100)
	summary, events, profiles, err := mobileSessionEvidenceWithLimit(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at":    time.Now().UTC().Format(time.RFC3339),
		"feature_id":      enforcement.MobileSessionFeatureID,
		"summary":         summary,
		"events":          events,
		"effective_state": profiles,
	})
}

func mobileSessionEvidenceWithLimit(limit int) (db.MobileSessionSummary, []db.MobileSessionEvent, []db.MobileSessionProfileRecord, error) {
	summary, err := db.GetMobileSessionSummary()
	if err != nil {
		return db.MobileSessionSummary{}, nil, nil, err
	}
	events, err := db.ListMobileSessionEvents(limit)
	if err != nil {
		return db.MobileSessionSummary{}, nil, nil, err
	}
	profiles, err := db.ListMobileSessionProfiles(limit, "")
	if err != nil {
		return db.MobileSessionSummary{}, nil, nil, err
	}
	return summary, events, profiles, nil
}
