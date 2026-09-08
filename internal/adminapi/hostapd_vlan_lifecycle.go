package adminapi

import (
	"net/http"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/enforcement"
)

func HandleGetHostapdVLANLifecycle(w http.ResponseWriter, r *http.Request) {
	report, err := enforcement.PreviewHostapdVLANLifecycle(config.Get())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	summary, snapshots, events, err := vlanLifecycleEvidenceWithLimit(20)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"report":       report,
		"evidence": map[string]any{
			"summary":          summary,
			"recent_snapshots": snapshots,
			"recent_events":    events,
		},
	})
}

func HandlePreviewHostapdVLANLifecycle(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	report, eventID, err := enforcement.PreviewAndRecordHostapdVLANLifecycle(config.Get(), actor)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"event_id":     eventID,
		"report":       report,
	})
}

func HandleApplyHostapdVLANLifecycle(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	result, err := enforcement.ApplyVLANLifecycle(config.Get(), actor, "apply")
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	report, reportErr := enforcement.PreviewHostapdVLANLifecycle(config.Get())
	payload := map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"result":       result,
	}
	if reportErr == nil {
		payload["report"] = report
	}
	writeJSON(w, http.StatusOK, payload)
}

func HandleRollbackHostapdVLANLifecycle(w http.ResponseWriter, r *http.Request) {
	var req vlanLifecycleRollbackRequest
	if r.Body != nil && r.ContentLength > 0 {
		if err := decodeBody(r, &req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
	}
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	result, err := enforcement.RollbackVLANLifecycle(req.SnapshotID, actor)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	report, reportErr := enforcement.PreviewHostapdVLANLifecycle(config.Get())
	payload := map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"result":       result,
	}
	if reportErr == nil {
		payload["report"] = report
	}
	writeJSON(w, http.StatusOK, payload)
}

func HandleListHostapdVLANLifecycleHistory(w http.ResponseWriter, r *http.Request) {
	limit := parseVLANLifecycleLimit(r.URL.Query().Get("limit"), 100)
	summary, snapshots, events, err := vlanLifecycleEvidenceWithLimit(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"feature_id":   enforcement.HostapdVLANLifecycleFeatureID,
		"summary":      summary,
		"snapshots":    snapshots,
		"events":       events,
	})
}
