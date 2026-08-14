package adminapi

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/radius"
)

func HandleGetVLANPolicy(w http.ResponseWriter, r *http.Request) {
	report := radius.BuildVLANPolicyReport(config.Get())
	summary, events, err := vlanPolicyEvidenceWithLimit(20)
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

func HandlePreviewVLANPolicy(w http.ResponseWriter, r *http.Request) {
	handleVLANPolicyCompile(w, r, "preview")
}

func HandleCompileVLANPolicy(w http.ResponseWriter, r *http.Request) {
	handleVLANPolicyCompile(w, r, "compile")
}

func handleVLANPolicyCompile(w http.ResponseWriter, r *http.Request, operation string) {
	var req radius.VLANPolicyCompileRequest
	if err := decodeBody(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	result := radius.CompileVLANPolicy(config.Get(), req)
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	eventID, err := recordVLANPolicyResult(operation, req, result, actor)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"event_id":     eventID,
		"result":       result,
	})
}

func HandleDecompileVLANPolicy(w http.ResponseWriter, r *http.Request) {
	var req radius.VLANPolicyDecompileRequest
	if err := decodeBody(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	result := radius.DecompileVLANPolicyAttributes(req)
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	eventID, err := recordVLANPolicyResult("decompile", req, result, actor)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"event_id":     eventID,
		"result":       result,
	})
}

func HandleListVLANPolicyHistory(w http.ResponseWriter, r *http.Request) {
	limit := parseVLANPolicyLimit(r.URL.Query().Get("limit"), 100)
	summary, events, err := vlanPolicyEvidenceWithLimit(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"summary":      summary,
		"events":       events,
	})
}

func recordVLANPolicyResult(operation string, request any, result radius.VLANPolicyCompileResult, actor string) (string, error) {
	status := result.Status
	if operation == "preview" && status == "compiled" {
		status = "previewed"
	}
	if operation == "decompile" && status == "compiled" {
		status = "decompiled"
	}
	return db.RecordVLANPolicyEvent(db.VLANPolicyEventInput{
		Operation:       operation,
		Status:          status,
		Role:            result.Decision.Role,
		PoolName:        result.Decision.PoolName,
		EffectiveVLAN:   result.Decision.EffectiveVLAN,
		DataVLAN:        result.Decision.DataVLAN,
		VoiceVLAN:       result.Decision.VoiceVLAN,
		TaggedVLANCount: len(result.Decision.TaggedVLANs),
		QinQOuterVLAN:   result.Decision.QinQOuterVLAN,
		QinQInnerVLAN:   result.Decision.QinQInnerVLAN,
		FallbackVLAN:    result.Decision.FallbackVLAN,
		AuthFailVLAN:    result.Decision.AuthFailVLAN,
		AttributeCount:  len(result.Attributes),
		DiagnosticCount: len(result.Diagnostics),
		Fingerprint:     result.Fingerprint,
		RequestJSON:     vlanPolicyJSON(request, "{}"),
		ResponseJSON:    vlanPolicyJSON(result, "{}"),
		DiagnosticsJSON: vlanPolicyJSON(result.Diagnostics, "[]"),
		Actor:           actor,
	})
}

func vlanPolicyEvidenceWithLimit(limit int) (db.VLANPolicyEventSummary, []db.VLANPolicyEvent, error) {
	if db.DB == nil {
		return db.VLANPolicyEventSummary{}, nil, nil
	}
	summary, err := db.GetVLANPolicyEventSummary()
	if err != nil {
		return db.VLANPolicyEventSummary{}, nil, err
	}
	events, err := db.ListVLANPolicyEvents(limit)
	if err != nil {
		return db.VLANPolicyEventSummary{}, nil, err
	}
	return summary, events, nil
}

func parseVLANPolicyLimit(value string, fallback int) int {
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

func vlanPolicyJSON(value any, fallback string) string {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) == 0 {
		return fallback
	}
	return string(encoded)
}
