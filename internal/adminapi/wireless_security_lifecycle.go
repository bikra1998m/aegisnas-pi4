package adminapi

import (
	"context"
	"net/http"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/enforcement"
)

func HandleGetWirelessSecurityLifecycle(w http.ResponseWriter, r *http.Request) {
	report, err := enforcement.PreviewWirelessSecurityLifecycle(config.Get())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	summary, events, err := wirelessSecurityLifecycleEvidenceWithLimit(20)
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

func HandlePreviewWirelessSecurityLifecycle(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	report, eventID, err := enforcement.PreviewAndRecordWirelessSecurityLifecycle(config.Get(), actor)
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

func HandleApplyWirelessSecurityLifecycle(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	report, eventID, err := enforcement.ApplyWirelessSecurityLifecycle(context.Background(), config.Get(), actor)
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

func HandleListWirelessSecurityLifecycleHistory(w http.ResponseWriter, r *http.Request) {
	limit := parseVLANLifecycleLimit(r.URL.Query().Get("limit"), 100)
	summary, events, err := wirelessSecurityLifecycleEvidenceWithLimit(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"feature_id":   enforcement.WirelessSecurityLifecycleFeatureID,
		"summary":      summary,
		"events":       events,
	})
}

func wirelessSecurityLifecycleEvidenceWithLimit(limit int) (db.WirelessSecurityLifecycleSummary, []db.WirelessSecurityLifecycleEvent, error) {
	summary, err := db.GetWirelessSecurityLifecycleSummary()
	if err != nil {
		return db.WirelessSecurityLifecycleSummary{}, nil, err
	}
	events, err := db.ListWirelessSecurityLifecycleEvents(limit)
	if err != nil {
		return db.WirelessSecurityLifecycleSummary{}, nil, err
	}
	return summary, events, nil
}
