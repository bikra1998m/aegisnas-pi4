package adminapi

import (
	"context"
	"net/http"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/enforcement"
)

func HandleGetMobilePolicyControl(w http.ResponseWriter, r *http.Request) {
	report, err := enforcement.PreviewMobilePolicyControl(config.Get())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	summary, events, profiles, err := mobilePolicyControlEvidenceWithLimit(20)
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

func HandlePreviewMobilePolicyControl(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	report, eventID, err := enforcement.PreviewAndRecordMobilePolicyControl(config.Get(), actor)
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

func HandleApplyMobilePolicyControl(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	report, eventID, err := enforcement.ApplyMobilePolicyControl(context.Background(), config.Get(), actor)
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

func HandleListMobilePolicyControlHistory(w http.ResponseWriter, r *http.Request) {
	limit := parseVLANLifecycleLimit(r.URL.Query().Get("limit"), 100)
	summary, events, profiles, err := mobilePolicyControlEvidenceWithLimit(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at":    time.Now().UTC().Format(time.RFC3339),
		"feature_id":      enforcement.MobilePolicyControlFeatureID,
		"summary":         summary,
		"events":          events,
		"effective_state": profiles,
	})
}

func mobilePolicyControlEvidenceWithLimit(limit int) (db.MobilePolicyControlSummary, []db.MobilePolicyControlEvent, []db.MobilePolicyControlProfileRecord, error) {
	summary, err := db.GetMobilePolicyControlSummary()
	if err != nil {
		return db.MobilePolicyControlSummary{}, nil, nil, err
	}
	events, err := db.ListMobilePolicyControlEvents(limit)
	if err != nil {
		return db.MobilePolicyControlSummary{}, nil, nil, err
	}
	profiles, err := db.ListMobilePolicyControlProfiles(limit, "")
	if err != nil {
		return db.MobilePolicyControlSummary{}, nil, nil, err
	}
	return summary, events, profiles, nil
}
