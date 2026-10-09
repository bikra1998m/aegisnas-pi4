package adminapi

import (
	"context"
	"net/http"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/enforcement"
)

func HandleGetBroadbandGovernanceSelfService(w http.ResponseWriter, r *http.Request) {
	report, err := enforcement.PreviewBroadbandGovernanceSelfService(config.Get())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	summary, events, cases, requests, err := broadbandGovernanceSelfServiceEvidenceWithLimit(20)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"report":       report,
		"evidence": map[string]any{
			"summary":               summary,
			"recent_events":         events,
			"cases":                 cases,
			"self_service_requests": requests,
		},
	})
}

func HandlePreviewBroadbandGovernanceSelfService(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	report, eventID, err := enforcement.PreviewAndRecordBroadbandGovernanceSelfService(config.Get(), actor)
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

func HandleApplyBroadbandGovernanceSelfService(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	report, eventID, err := enforcement.ApplyBroadbandGovernanceSelfService(context.Background(), config.Get(), actor)
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

func HandleListBroadbandGovernanceSelfServiceHistory(w http.ResponseWriter, r *http.Request) {
	limit := parseVLANLifecycleLimit(r.URL.Query().Get("limit"), 100)
	summary, events, cases, requests, err := broadbandGovernanceSelfServiceEvidenceWithLimit(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at":          time.Now().UTC().Format(time.RFC3339),
		"feature_id":            enforcement.BroadbandGovernanceSelfServiceFeatureID,
		"summary":               summary,
		"events":                events,
		"cases":                 cases,
		"self_service_requests": requests,
	})
}

func broadbandGovernanceSelfServiceEvidenceWithLimit(limit int) (db.BroadbandGovernanceSelfServiceSummary, []db.BroadbandGovernanceSelfServiceEvent, []db.BroadbandGovernanceCaseRecord, []db.BroadbandSelfServiceRequestRecord, error) {
	summary, err := db.GetBroadbandGovernanceSelfServiceSummary()
	if err != nil {
		return db.BroadbandGovernanceSelfServiceSummary{}, nil, nil, nil, err
	}
	events, err := db.ListBroadbandGovernanceSelfServiceEvents(limit)
	if err != nil {
		return db.BroadbandGovernanceSelfServiceSummary{}, nil, nil, nil, err
	}
	cases, err := db.ListBroadbandGovernanceCases(limit, "")
	if err != nil {
		return db.BroadbandGovernanceSelfServiceSummary{}, nil, nil, nil, err
	}
	requests, err := db.ListBroadbandSelfServiceRequests(limit, "")
	if err != nil {
		return db.BroadbandGovernanceSelfServiceSummary{}, nil, nil, nil, err
	}
	return summary, events, cases, requests, nil
}
