package adminapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/enforcement"
)

type runtimeQoSRollbackRequest struct {
	SnapshotID string `json:"snapshot_id"`
}

type qosSchedulerProfileRequest struct {
	ProfileName          string         `json:"profile_name"`
	Enabled              *bool          `json:"enabled,omitempty"`
	ParentProfileName    string         `json:"parent_profile_name"`
	Scheduler            string         `json:"scheduler"`
	Priority             *int           `json:"priority,omitempty"`
	DSCPMark             *int           `json:"dscp_mark,omitempty"`
	DownloadMinRateKbps  int            `json:"download_min_rate_kbps"`
	DownloadCeilRateKbps int            `json:"download_ceil_rate_kbps"`
	UploadMinRateKbps    int            `json:"upload_min_rate_kbps"`
	UploadCeilRateKbps   int            `json:"upload_ceil_rate_kbps"`
	BurstKB              int            `json:"burst_kb"`
	CBurstKB             int            `json:"cburst_kb"`
	QuantumBytes         int            `json:"quantum_bytes"`
	Metadata             map[string]any `json:"metadata,omitempty"`
	MetadataJSON         string         `json:"metadata_json,omitempty"`
}

func HandleGetRuntimeQoS(w http.ResponseWriter, r *http.Request) {
	plan, err := enforcement.PreviewRuntimeQoS(config.Get())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	summary, snapshots, events, profiles, err := runtimeQoSEvidenceWithLimit(20)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"report": map[string]any{
			"schema_version": enforcement.RuntimeQoSSchemaVersion,
			"status":         plan.Status,
			"message":        plan.Message,
			"interface_name": plan.InterfaceName,
			"ifb_device":     plan.IFBDevice,
			"summary":        plan.Summary,
			"diagnostics":    plan.Diagnostics,
			"classes":        plan.Classes,
			"sessions":       plan.Sessions,
			"commands":       plan.CommandPreview,
			"fingerprint":    plan.PlanFingerprint,
			"rfcs":           plan.RFCs,
			"attributes":     plan.FreeRADIUSAttributes,
			"profiles":       profiles,
			"evidence": map[string]any{
				"summary":          summary,
				"recent_snapshots": snapshots,
				"recent_events":    events,
			},
		},
	})
}

func HandlePreviewRuntimeQoS(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	plan, eventID, err := enforcement.PreviewAndRecordRuntimeQoS(config.Get(), actor)
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

func HandleApplyRuntimeQoS(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	result, err := enforcement.ApplyRuntimeQoS(config.Get(), actor, "apply")
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"result":       result,
	})
}

func HandleRollbackRuntimeQoS(w http.ResponseWriter, r *http.Request) {
	var req runtimeQoSRollbackRequest
	if r.Body != nil && r.ContentLength > 0 {
		if err := decodeBody(r, &req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
	}
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	result, err := enforcement.RollbackRuntimeQoS(req.SnapshotID, actor)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"result":       result,
	})
}

func HandleListRuntimeQoSHistory(w http.ResponseWriter, r *http.Request) {
	limit := parseRuntimeQoSLimit(r.URL.Query().Get("limit"), 100)
	summary, snapshots, events, _, err := runtimeQoSEvidenceWithLimit(limit)
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

func HandleListQoSSchedulerProfiles(w http.ResponseWriter, r *http.Request) {
	profiles, err := db.ListQoSSchedulerProfiles()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"profiles":     profiles,
	})
}

func HandleUpsertQoSSchedulerProfile(w http.ResponseWriter, r *http.Request) {
	var req qosSchedulerProfileRequest
	if err := decodeBody(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	profileName := firstNonEmptyAdminString(chi.URLParam(r, "name"), req.ProfileName)
	input, err := qosSchedulerProfileInput(profileName, req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := db.UpsertQoSSchedulerProfile(input); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"profile_name": input.ProfileName,
		"status":       "saved",
	})
}

func HandleDeleteQoSSchedulerProfile(w http.ResponseWriter, r *http.Request) {
	profileName := strings.TrimSpace(chi.URLParam(r, "name"))
	if profileName == "" {
		http.Error(w, "profile name is required", http.StatusBadRequest)
		return
	}
	if err := db.DeleteQoSSchedulerProfile(profileName); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"profile_name": profileName,
		"status":       "deleted",
	})
}

func qosSchedulerProfileInput(profileName string, req qosSchedulerProfileRequest) (db.QoSSchedulerProfileInput, error) {
	profileName = strings.TrimSpace(profileName)
	if profileName == "" {
		return db.QoSSchedulerProfileInput{}, fmt.Errorf("profile name is required")
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	priority := 4
	if req.Priority != nil {
		priority = *req.Priority
	}
	if priority < 0 || priority > 7 {
		return db.QoSSchedulerProfileInput{}, fmt.Errorf("priority must be between 0 and 7")
	}
	if req.DSCPMark != nil && (*req.DSCPMark < 0 || *req.DSCPMark > 63) {
		return db.QoSSchedulerProfileInput{}, fmt.Errorf("dscp_mark must be between 0 and 63")
	}
	metadataJSON := strings.TrimSpace(req.MetadataJSON)
	if req.Metadata != nil {
		encoded, err := json.Marshal(req.Metadata)
		if err != nil {
			return db.QoSSchedulerProfileInput{}, fmt.Errorf("metadata must be JSON serializable")
		}
		metadataJSON = string(encoded)
	}
	if metadataJSON == "" {
		metadataJSON = "{}"
	}
	if !json.Valid([]byte(metadataJSON)) {
		return db.QoSSchedulerProfileInput{}, fmt.Errorf("metadata_json must be valid JSON")
	}
	return db.QoSSchedulerProfileInput{
		ProfileName:          profileName,
		Enabled:              enabled,
		ParentProfileName:    strings.TrimSpace(req.ParentProfileName),
		Scheduler:            firstNonEmptyAdminString(req.Scheduler, "htb"),
		Priority:             priority,
		DSCPMark:             req.DSCPMark,
		DownloadMinRateKbps:  req.DownloadMinRateKbps,
		DownloadCeilRateKbps: req.DownloadCeilRateKbps,
		UploadMinRateKbps:    req.UploadMinRateKbps,
		UploadCeilRateKbps:   req.UploadCeilRateKbps,
		BurstKB:              req.BurstKB,
		CBurstKB:             req.CBurstKB,
		QuantumBytes:         req.QuantumBytes,
		MetadataJSON:         metadataJSON,
	}, nil
}

func runtimeQoSEvidenceWithLimit(limit int) (db.RuntimeQoSEventSummary, []db.RuntimeQoSSnapshot, []db.RuntimeQoSEvent, []db.QoSSchedulerProfile, error) {
	if db.DB == nil {
		return db.RuntimeQoSEventSummary{}, nil, nil, nil, nil
	}
	summary, err := db.GetRuntimeQoSEventSummary()
	if err != nil {
		return db.RuntimeQoSEventSummary{}, nil, nil, nil, err
	}
	snapshots, err := db.ListRuntimeQoSSnapshots(limit)
	if err != nil {
		return db.RuntimeQoSEventSummary{}, nil, nil, nil, err
	}
	events, err := db.ListRuntimeQoSEvents(limit)
	if err != nil {
		return db.RuntimeQoSEventSummary{}, nil, nil, nil, err
	}
	profiles, err := db.ListQoSSchedulerProfiles()
	if err != nil {
		return db.RuntimeQoSEventSummary{}, nil, nil, nil, err
	}
	return summary, snapshots, events, profiles, nil
}

func parseRuntimeQoSLimit(value string, fallback int) int {
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
