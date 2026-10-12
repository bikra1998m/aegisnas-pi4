package adminapi

import (
	"context"
	"net/http"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/enforcement"
)

func HandleGetMobileGroupedAVPs(w http.ResponseWriter, r *http.Request) {
	report, err := enforcement.PreviewMobileGroupedAVPs(config.Get())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	summary, events, scopes, err := mobileGroupedAVPEvidenceWithLimit(20)
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
			"scopes":        scopes,
		},
	})
}

func HandlePreviewMobileGroupedAVPs(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	report, eventID, err := enforcement.PreviewAndRecordMobileGroupedAVPs(config.Get(), actor)
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

func HandleApplyMobileGroupedAVPs(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	report, eventID, err := enforcement.ApplyMobileGroupedAVPs(context.Background(), config.Get(), actor)
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

func HandleListMobileGroupedAVPHistory(w http.ResponseWriter, r *http.Request) {
	limit := parseVLANLifecycleLimit(r.URL.Query().Get("limit"), 100)
	summary, events, scopes, err := mobileGroupedAVPEvidenceWithLimit(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"feature_id":   enforcement.MobileGroupedAVPFeatureID,
		"summary":      summary,
		"events":       events,
		"scopes":       scopes,
	})
}

func mobileGroupedAVPEvidenceWithLimit(limit int) (db.MobileGroupedAVPSummary, []db.MobileGroupedAVPEvent, []db.MobileGroupedAVPScopeRecord, error) {
	summary, err := db.GetMobileGroupedAVPSummary()
	if err != nil {
		return db.MobileGroupedAVPSummary{}, nil, nil, err
	}
	events, err := db.ListMobileGroupedAVPEvents(limit)
	if err != nil {
		return db.MobileGroupedAVPSummary{}, nil, nil, err
	}
	scopes, err := db.ListMobileGroupedAVPScopes(limit, "")
	if err != nil {
		return db.MobileGroupedAVPSummary{}, nil, nil, err
	}
	return summary, events, scopes, nil
}
