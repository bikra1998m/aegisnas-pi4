package adminapi

import (
	"context"
	"net/http"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/enforcement"
)

func HandleGetDOCSISPolicy(w http.ResponseWriter, r *http.Request) {
	report, err := enforcement.PreviewDOCSISPolicy(config.Get())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	summary, events, profiles, err := docsisPolicyEvidenceWithLimit(20)
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

func HandlePreviewDOCSISPolicy(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	report, eventID, err := enforcement.PreviewAndRecordDOCSISPolicy(config.Get(), actor)
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

func HandleApplyDOCSISPolicy(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	report, eventID, err := enforcement.ApplyDOCSISPolicy(context.Background(), config.Get(), actor)
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

func HandleListDOCSISPolicyHistory(w http.ResponseWriter, r *http.Request) {
	limit := parseVLANLifecycleLimit(r.URL.Query().Get("limit"), 100)
	summary, events, profiles, err := docsisPolicyEvidenceWithLimit(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at":    time.Now().UTC().Format(time.RFC3339),
		"feature_id":      enforcement.DOCSISPolicyFeatureID,
		"summary":         summary,
		"events":          events,
		"effective_state": profiles,
	})
}

func docsisPolicyEvidenceWithLimit(limit int) (db.DOCSISPolicySummary, []db.DOCSISPolicyEvent, []db.DOCSISPolicyProfileRecord, error) {
	summary, err := db.GetDOCSISPolicySummary()
	if err != nil {
		return db.DOCSISPolicySummary{}, nil, nil, err
	}
	events, err := db.ListDOCSISPolicyEvents(limit)
	if err != nil {
		return db.DOCSISPolicySummary{}, nil, nil, err
	}
	profiles, err := db.ListDOCSISPolicyProfiles(limit, "")
	if err != nil {
		return db.DOCSISPolicySummary{}, nil, nil, err
	}
	return summary, events, profiles, nil
}
