package adminapi

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/enforcement"
)

type runtimeFirewallRollbackRequest struct {
	SnapshotID string `json:"snapshot_id"`
}

func HandleGetRuntimeFirewall(w http.ResponseWriter, r *http.Request) {
	plan, err := enforcement.PreviewRuntimeFirewall()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	summary, snapshots, events, err := runtimeFirewallEvidence()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"report": map[string]any{
			"schema_version": enforcement.RuntimeFirewallSchemaVersion,
			"status":         plan.Status,
			"message":        plan.Message,
			"summary":        plan.Summary,
			"diagnostics":    plan.Diagnostics,
			"sessions":       plan.Sessions,
			"rules":          plan.Rules,
			"fingerprint":    plan.RulesetFingerprint,
			"table_name":     plan.TableName,
			"rfcs":           plan.RFCs,
			"attributes":     plan.FreeRADIUSAttributes,
			"evidence": map[string]any{
				"summary":          summary,
				"recent_snapshots": snapshots,
				"recent_events":    events,
			},
		},
	})
}

func HandlePreviewRuntimeFirewall(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	plan, eventID, err := enforcement.PreviewAndRecordRuntimeFirewall(actor)
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

func HandleApplyRuntimeFirewall(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	result, err := enforcement.ApplyRuntimeFirewall(actor, "apply")
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"result":       result,
	})
}

func HandleRollbackRuntimeFirewall(w http.ResponseWriter, r *http.Request) {
	var req runtimeFirewallRollbackRequest
	if r.Body != nil && r.ContentLength > 0 {
		if err := decodeBody(r, &req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
	}
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	result, err := enforcement.RollbackRuntimeFirewall(req.SnapshotID, actor)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"result":       result,
	})
}

func HandleListRuntimeFirewallHistory(w http.ResponseWriter, r *http.Request) {
	limit := parseRuntimeFirewallLimit(r.URL.Query().Get("limit"), 100)
	summary, snapshots, events, err := runtimeFirewallEvidenceWithLimit(limit)
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

func runtimeFirewallEvidence() (db.RuntimeFirewallEventSummary, []db.RuntimeFirewallSnapshot, []db.RuntimeFirewallEvent, error) {
	return runtimeFirewallEvidenceWithLimit(20)
}

func runtimeFirewallEvidenceWithLimit(limit int) (db.RuntimeFirewallEventSummary, []db.RuntimeFirewallSnapshot, []db.RuntimeFirewallEvent, error) {
	if db.DB == nil {
		return db.RuntimeFirewallEventSummary{}, nil, nil, nil
	}
	summary, err := db.GetRuntimeFirewallEventSummary()
	if err != nil {
		return db.RuntimeFirewallEventSummary{}, nil, nil, err
	}
	snapshots, err := db.ListRuntimeFirewallSnapshots(limit)
	if err != nil {
		return db.RuntimeFirewallEventSummary{}, nil, nil, err
	}
	events, err := db.ListRuntimeFirewallEvents(limit)
	if err != nil {
		return db.RuntimeFirewallEventSummary{}, nil, nil, err
	}
	return summary, snapshots, events, nil
}

func parseRuntimeFirewallLimit(value string, fallback int) int {
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
