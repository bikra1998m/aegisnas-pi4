package adminapi

import (
	"context"
	"net/http"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/enforcement"
)

func HandleGetBroadbandAddressLeases(w http.ResponseWriter, r *http.Request) {
	report, err := enforcement.PreviewBroadbandAddressLeases(config.Get())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	summary, events, leases, err := broadbandAddressLeaseEvidenceWithLimit(20)
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
			"leases":        leases,
		},
	})
}

func HandlePreviewBroadbandAddressLeases(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	report, eventID, err := enforcement.PreviewAndRecordBroadbandAddressLeases(config.Get(), actor)
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

func HandleApplyBroadbandAddressLeases(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	report, eventID, err := enforcement.ApplyBroadbandAddressLeases(context.Background(), config.Get(), actor)
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

func HandleListBroadbandAddressLeaseHistory(w http.ResponseWriter, r *http.Request) {
	limit := parseVLANLifecycleLimit(r.URL.Query().Get("limit"), 100)
	summary, events, leases, err := broadbandAddressLeaseEvidenceWithLimit(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"feature_id":   enforcement.BroadbandAddressLeaseFeatureID,
		"summary":      summary,
		"events":       events,
		"leases":       leases,
	})
}

func broadbandAddressLeaseEvidenceWithLimit(limit int) (db.BroadbandAddressLeaseSummary, []db.BroadbandAddressLeaseEvent, []db.BroadbandAddressLeaseRecord, error) {
	summary, err := db.GetBroadbandAddressLeaseSummary()
	if err != nil {
		return db.BroadbandAddressLeaseSummary{}, nil, nil, err
	}
	events, err := db.ListBroadbandAddressLeaseEvents(limit)
	if err != nil {
		return db.BroadbandAddressLeaseSummary{}, nil, nil, err
	}
	leases, err := db.ListBroadbandAddressLeases(limit, "")
	if err != nil {
		return db.BroadbandAddressLeaseSummary{}, nil, nil, err
	}
	return summary, events, leases, nil
}
