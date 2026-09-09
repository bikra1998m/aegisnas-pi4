package adminapi

import (
	"net/http"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/enforcement"
)

func HandleGetWirelessRoamingLifecycle(w http.ResponseWriter, r *http.Request) {
	report, err := enforcement.PreviewWirelessRoamingLifecycle(config.Get())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	summary, events, err := wirelessRoamingLifecycleEvidenceWithLimit(20)
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

func HandlePreviewWirelessRoamingLifecycle(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	report, eventID, err := enforcement.PreviewAndRecordWirelessRoamingLifecycle(config.Get(), actor)
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

func HandleApplyWirelessRoamingLifecycle(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	report, eventID, err := enforcement.ApplyWirelessRoamingLifecycle(config.Get(), actor)
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
		"report":       report,
	})
}

func HandleListWirelessRoamingLifecycleHistory(w http.ResponseWriter, r *http.Request) {
	limit := parseVLANLifecycleLimit(r.URL.Query().Get("limit"), 100)
	summary, events, err := wirelessRoamingLifecycleEvidenceWithLimit(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"feature_id":   enforcement.WirelessRoamingLifecycleFeatureID,
		"summary":      summary,
		"events":       events,
	})
}

func wirelessRoamingLifecycleEvidenceWithLimit(limit int) (db.WirelessRoamingLifecycleSummary, []db.WirelessRoamingLifecycleEvent, error) {
	summary, err := db.GetWirelessRoamingLifecycleSummary()
	if err != nil {
		return db.WirelessRoamingLifecycleSummary{}, nil, err
	}
	events, err := db.ListWirelessRoamingLifecycleEvents(limit)
	if err != nil {
		return db.WirelessRoamingLifecycleSummary{}, nil, err
	}
	return summary, events, nil
}
