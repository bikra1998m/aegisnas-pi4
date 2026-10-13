package adminapi

import (
	"context"
	"net/http"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/enforcement"
)

func HandleGetMobileCharging(w http.ResponseWriter, r *http.Request) {
	report, err := enforcement.PreviewMobileCharging(config.Get())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	summary, events, profiles, err := mobileChargingEvidenceWithLimit(20)
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

func HandlePreviewMobileCharging(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	report, eventID, err := enforcement.PreviewAndRecordMobileCharging(config.Get(), actor)
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

func HandleApplyMobileCharging(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	report, eventID, err := enforcement.ApplyMobileCharging(context.Background(), config.Get(), actor)
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

func HandleListMobileChargingHistory(w http.ResponseWriter, r *http.Request) {
	limit := parseVLANLifecycleLimit(r.URL.Query().Get("limit"), 100)
	summary, events, profiles, err := mobileChargingEvidenceWithLimit(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at":    time.Now().UTC().Format(time.RFC3339),
		"feature_id":      enforcement.MobileChargingFeatureID,
		"summary":         summary,
		"events":          events,
		"effective_state": profiles,
	})
}

func mobileChargingEvidenceWithLimit(limit int) (db.MobileChargingSummary, []db.MobileChargingEvent, []db.MobileChargingProfileRecord, error) {
	summary, err := db.GetMobileChargingSummary()
	if err != nil {
		return db.MobileChargingSummary{}, nil, nil, err
	}
	events, err := db.ListMobileChargingEvents(limit)
	if err != nil {
		return db.MobileChargingSummary{}, nil, nil, err
	}
	profiles, err := db.ListMobileChargingProfiles(limit, "")
	if err != nil {
		return db.MobileChargingSummary{}, nil, nil, err
	}
	return summary, events, profiles, nil
}
