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

func HandleGetTranslationPolicy(w http.ResponseWriter, r *http.Request) {
	report := radius.BuildTranslationPolicyReport(config.Get())
	summary, events, ownership, err := translationPolicyEvidenceWithLimit(20)
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
			"ownership":     ownership,
		},
	})
}

func HandlePreviewTranslationPolicy(w http.ResponseWriter, r *http.Request) {
	handleTranslationPolicyCompile(w, r, "preview")
}

func HandleCompileTranslationPolicy(w http.ResponseWriter, r *http.Request) {
	handleTranslationPolicyCompile(w, r, "compile")
}

func handleTranslationPolicyCompile(w http.ResponseWriter, r *http.Request, operation string) {
	var req radius.TranslationPolicyCompileRequest
	if err := decodeBody(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	result := radius.CompileTranslationPolicy(config.Get(), req)
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	eventID, err := recordTranslationPolicyResult(operation, req, result, actor)
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

func HandleDecompileTranslationPolicy(w http.ResponseWriter, r *http.Request) {
	var req radius.TranslationPolicyDecompileRequest
	if err := decodeBody(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	result := radius.DecompileTranslationPolicyAttributes(req)
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	eventID, err := recordTranslationPolicyResult("decompile", req, result, actor)
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

func HandleListTranslationPolicyHistory(w http.ResponseWriter, r *http.Request) {
	limit := parseTranslationPolicyLimit(r.URL.Query().Get("limit"), 100)
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	summary, events, ownership, err := translationPolicyEvidenceWithLimit(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if status != "" && db.DB != nil {
		filtered, err := db.ListTranslationPolicyOwnership(limit, status)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		ownership = filtered
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"summary":      summary,
		"events":       events,
		"ownership":    ownership,
	})
}

func recordTranslationPolicyResult(operation string, request any, result radius.TranslationPolicyCompileResult, actor string) (string, error) {
	status := result.Status
	if operation == "preview" && (status == "compiled" || status == "degraded") {
		status = "previewed"
	}
	if operation == "decompile" && (status == "compiled" || status == "degraded") {
		status = "decompiled"
	}
	ownershipStatus := "active"
	if result.Decision.Withdraw {
		ownershipStatus = "withdrawn"
	}
	shouldRecordOwnership := operation == "compile"
	ownership := make([]db.TranslationPolicyOwnershipInput, 0, 1)
	if shouldRecordOwnership && (strings.TrimSpace(result.Decision.PublicPool) != "" ||
		strings.TrimSpace(result.Decision.PublicIPv4) != "" ||
		strings.TrimSpace(result.Decision.PrivateIPv4Prefix) != "" ||
		strings.TrimSpace(result.Decision.SubscriberIPv6Prefix) != "" ||
		strings.TrimSpace(result.Decision.NAT64Prefix) != "" ||
		result.Decision.PortBlockStart > 0 ||
		result.Decision.PortBlockEnd > 0) {
		ownership = append(ownership, db.TranslationPolicyOwnershipInput{
			OwnershipKey:         result.Decision.OwnershipKey,
			SessionID:            result.Decision.SessionID,
			AcctSessionID:        result.Decision.AcctSessionID,
			Role:                 result.Decision.Role,
			Owner:                result.Decision.Owner,
			Revision:             result.Decision.Revision,
			TranslationMode:      result.Decision.TranslationMode,
			PublicPool:           result.Decision.PublicPool,
			PublicIPv4:           result.Decision.PublicIPv4,
			PrivateIPv4Prefix:    result.Decision.PrivateIPv4Prefix,
			SubscriberIPv6Prefix: result.Decision.SubscriberIPv6Prefix,
			NAT64Prefix:          result.Decision.NAT64Prefix,
			PortBlockStart:       result.Decision.PortBlockStart,
			PortBlockEnd:         result.Decision.PortBlockEnd,
			PortBlockSize:        result.Decision.PortBlockSize,
			Status:               ownershipStatus,
		})
	}
	return db.RecordTranslationPolicyEvent(db.TranslationPolicyEventInput{
		Operation:            operation,
		Status:               status,
		Role:                 result.Decision.Role,
		SessionID:            result.Decision.SessionID,
		AcctSessionID:        result.Decision.AcctSessionID,
		Owner:                result.Decision.Owner,
		Revision:             result.Decision.Revision,
		TranslationMode:      result.Decision.TranslationMode,
		PublicPool:           result.Decision.PublicPool,
		PublicIPv4:           result.Decision.PublicIPv4,
		PrivateIPv4Prefix:    result.Decision.PrivateIPv4Prefix,
		SubscriberIPv6Prefix: result.Decision.SubscriberIPv6Prefix,
		NAT64Prefix:          result.Decision.NAT64Prefix,
		PortBlockStart:       result.Decision.PortBlockStart,
		PortBlockEnd:         result.Decision.PortBlockEnd,
		PortBlockSize:        result.Decision.PortBlockSize,
		MappingCount:         result.Summary.MappingCount,
		PortBlockCount:       result.Summary.PortBlockCount,
		WithdrawCount:        result.Summary.WithdrawCount,
		AttributeCount:       len(result.Attributes),
		DiagnosticCount:      len(result.Diagnostics),
		Fingerprint:          result.Fingerprint,
		RequestJSON:          translationPolicyJSON(request, "{}"),
		ResponseJSON:         translationPolicyJSON(result, "{}"),
		DiagnosticsJSON:      translationPolicyJSON(result.Diagnostics, "[]"),
		Actor:                actor,
		Ownership:            ownership,
	})
}

func translationPolicyEvidenceWithLimit(limit int) (db.TranslationPolicyEventSummary, []db.TranslationPolicyEvent, []db.TranslationPolicyOwnershipRecord, error) {
	if db.DB == nil {
		return db.TranslationPolicyEventSummary{}, nil, nil, nil
	}
	summary, err := db.GetTranslationPolicyEventSummary()
	if err != nil {
		return db.TranslationPolicyEventSummary{}, nil, nil, err
	}
	events, err := db.ListTranslationPolicyEvents(limit)
	if err != nil {
		return db.TranslationPolicyEventSummary{}, nil, nil, err
	}
	ownership, err := db.ListTranslationPolicyOwnership(limit, "")
	if err != nil {
		return db.TranslationPolicyEventSummary{}, nil, nil, err
	}
	return summary, events, ownership, nil
}

func parseTranslationPolicyLimit(value string, fallback int) int {
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

func translationPolicyJSON(value any, fallback string) string {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) == 0 {
		return fallback
	}
	return string(encoded)
}
