package adminapi

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/enforcement"
)

type vlanLifecycleRollbackRequest struct {
	SnapshotID string `json:"snapshot_id"`
}

func HandleGetVLANLifecycle(w http.ResponseWriter, r *http.Request) {
	plan, err := enforcement.PreviewVLANLifecycle(config.Get())
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
		"report": map[string]any{
			"schema_version":           enforcement.VLANLifecycleSchemaVersion,
			"status":                   plan.Status,
			"message":                  plan.Message,
			"parent_interface":         plan.ParentInterface,
			"hostapd_vlan_file_path":   plan.HostapdVLANFilePath,
			"hostapd_vlan_file_sha256": plan.HostapdVLANFileSHA256,
			"summary":                  plan.Summary,
			"diagnostics":              plan.Diagnostics,
			"intents":                  plan.Intents,
			"bridges":                  plan.Bridges,
			"subinterfaces":            plan.Subinterfaces,
			"hostapd_vlan_entries":     plan.HostapdVLANEntries,
			"commands":                 plan.CommandPreview,
			"fingerprint":              plan.PlanFingerprint,
			"rfcs":                     plan.RFCs,
			"attributes":               plan.FreeRADIUSAttributes,
			"evidence": map[string]any{
				"summary":          summary,
				"recent_snapshots": snapshots,
				"recent_events":    events,
			},
		},
	})
}

func HandlePreviewVLANLifecycle(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	plan, eventID, err := enforcement.PreviewAndRecordVLANLifecycle(config.Get(), actor)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"event_id":     eventID,
		"plan":         plan,
	})
}

func HandleApplyVLANLifecycle(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	result, err := enforcement.ApplyVLANLifecycle(config.Get(), actor, "apply")
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"result":       result,
	})
}

func HandleRollbackVLANLifecycle(w http.ResponseWriter, r *http.Request) {
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
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"result":       result,
	})
}

func HandleListVLANLifecycleHistory(w http.ResponseWriter, r *http.Request) {
	limit := parseVLANLifecycleLimit(r.URL.Query().Get("limit"), 100)
	summary, snapshots, events, err := vlanLifecycleEvidenceWithLimit(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"summary":      summary,
		"snapshots":    snapshots,
		"events":       events,
	})
}

func vlanLifecycleEvidenceWithLimit(limit int) (db.VLANLifecycleEventSummary, []db.VLANLifecycleSnapshot, []db.VLANLifecycleEvent, error) {
	if db.DB == nil {
		return db.VLANLifecycleEventSummary{}, nil, nil, nil
	}
	summary, err := db.GetVLANLifecycleEventSummary()
	if err != nil {
		return db.VLANLifecycleEventSummary{}, nil, nil, err
	}
	snapshots, err := db.ListVLANLifecycleSnapshots(limit)
	if err != nil {
		return db.VLANLifecycleEventSummary{}, nil, nil, err
	}
	events, err := db.ListVLANLifecycleEvents(limit)
	if err != nil {
		return db.VLANLifecycleEventSummary{}, nil, nil, err
	}
	return summary, snapshots, events, nil
}

func parseVLANLifecycleLimit(value string, fallback int) int {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	limit, err := strconv.Atoi(value)
	if err != nil || limit <= 0 {
		return fallback
	}
	if limit > 500 {
		return 500
	}
	return limit
}
