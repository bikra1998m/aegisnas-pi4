package adminapi

import (
	"context"
	"net/http"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/enforcement"
)

func HandleGetBroadbandDHCPSecurity(w http.ResponseWriter, r *http.Request) {
	report, err := enforcement.PreviewBroadbandDHCPSecurity(config.Get())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	summary, events, bindings, err := broadbandDHCPSecurityEvidenceWithLimit(20)
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
			"bindings":      bindings,
		},
	})
}

func HandlePreviewBroadbandDHCPSecurity(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	report, eventID, err := enforcement.PreviewAndRecordBroadbandDHCPSecurity(config.Get(), actor)
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

func HandleApplyBroadbandDHCPSecurity(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	report, eventID, err := enforcement.ApplyBroadbandDHCPSecurity(context.Background(), config.Get(), actor)
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

func HandleListBroadbandDHCPSecurityHistory(w http.ResponseWriter, r *http.Request) {
	limit := parseVLANLifecycleLimit(r.URL.Query().Get("limit"), 100)
	summary, events, bindings, err := broadbandDHCPSecurityEvidenceWithLimit(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"feature_id":   enforcement.BroadbandDHCPSecurityFeatureID,
		"summary":      summary,
		"events":       events,
		"bindings":     bindings,
	})
}

func broadbandDHCPSecurityEvidenceWithLimit(limit int) (db.BroadbandDHCPSecuritySummary, []db.BroadbandDHCPSecurityEvent, []db.BroadbandDHCPSecurityBindingRecord, error) {
	summary, err := db.GetBroadbandDHCPSecuritySummary()
	if err != nil {
		return db.BroadbandDHCPSecuritySummary{}, nil, nil, err
	}
	events, err := db.ListBroadbandDHCPSecurityEvents(limit)
	if err != nil {
		return db.BroadbandDHCPSecuritySummary{}, nil, nil, err
	}
	bindings, err := db.ListBroadbandDHCPSecurityBindings(limit, "")
	if err != nil {
		return db.BroadbandDHCPSecuritySummary{}, nil, nil, err
	}
	return summary, events, bindings, nil
}
