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

type subscriberRouteExportRollbackRequest struct {
	SnapshotID string `json:"snapshot_id"`
}

func HandleGetSubscriberRouteExport(w http.ResponseWriter, r *http.Request) {
	plan, err := enforcement.PreviewSubscriberRouteExport(config.Get())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	summary, snapshots, events, err := subscriberRouteExportEvidenceWithLimit(20)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"report": map[string]any{
			"schema_version":  enforcement.SubscriberRouteExportSchemaVersion,
			"status":          plan.Status,
			"message":         plan.Message,
			"driver":          plan.Driver,
			"apply_enabled":   plan.ApplyEnabled,
			"artifact_path":   plan.ArtifactPath,
			"artifact_sha256": plan.ArtifactSHA256,
			"summary":         plan.Summary,
			"diagnostics":     plan.Diagnostics,
			"protocols":       plan.Protocols,
			"routes":          plan.Routes,
			"withdrawals":     plan.Withdrawals,
			"commands":        plan.CommandPreview,
			"fingerprint":     plan.PlanFingerprint,
			"rfcs":            plan.RFCs,
			"attributes":      plan.FreeRADIUSAttributes,
			"release_scope":   "External BGP/OSPF convergence, route reflection, hardware FIB install, and multi-vendor controller behavior are tracked in the NAS-0059 release certification checklist.",
			"evidence": map[string]any{
				"summary":          summary,
				"recent_snapshots": snapshots,
				"recent_events":    events,
			},
		},
	})
}

func HandlePreviewSubscriberRouteExport(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	plan, eventID, err := enforcement.PreviewAndRecordSubscriberRouteExport(config.Get(), actor)
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

func HandleApplySubscriberRouteExport(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	result, err := enforcement.ApplySubscriberRouteExport(config.Get(), actor, "apply")
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"result":       result,
	})
}

func HandleRollbackSubscriberRouteExport(w http.ResponseWriter, r *http.Request) {
	var req subscriberRouteExportRollbackRequest
	if r.Body != nil && r.ContentLength > 0 {
		if err := decodeBody(r, &req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
	}
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	result, err := enforcement.RollbackSubscriberRouteExport(req.SnapshotID, actor)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"result":       result,
	})
}

func HandleListSubscriberRouteExportHistory(w http.ResponseWriter, r *http.Request) {
	limit := parseSubscriberRouteExportLimit(r.URL.Query().Get("limit"), 100)
	summary, snapshots, events, err := subscriberRouteExportEvidenceWithLimit(limit)
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

func subscriberRouteExportEvidenceWithLimit(limit int) (db.SubscriberRouteExportSummary, []db.SubscriberRouteExportSnapshot, []db.SubscriberRouteExportEvent, error) {
	if db.DB == nil {
		return db.SubscriberRouteExportSummary{}, nil, nil, nil
	}
	summary, err := db.GetSubscriberRouteExportSummary()
	if err != nil {
		return db.SubscriberRouteExportSummary{}, nil, nil, err
	}
	snapshots, err := db.ListSubscriberRouteExportSnapshots(limit)
	if err != nil {
		return db.SubscriberRouteExportSummary{}, nil, nil, err
	}
	events, err := db.ListSubscriberRouteExportEvents(limit)
	if err != nil {
		return db.SubscriberRouteExportSummary{}, nil, nil, err
	}
	return summary, snapshots, events, nil
}

func parseSubscriberRouteExportLimit(value string, fallback int) int {
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
