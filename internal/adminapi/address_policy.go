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

func HandleGetAddressPolicy(w http.ResponseWriter, r *http.Request) {
	report := radius.BuildAddressPolicyReport(config.Get())
	summary, events, ownership, err := addressPolicyEvidenceWithLimit(20)
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

func HandlePreviewAddressPolicy(w http.ResponseWriter, r *http.Request) {
	handleAddressPolicyCompile(w, r, "preview")
}

func HandleCompileAddressPolicy(w http.ResponseWriter, r *http.Request) {
	handleAddressPolicyCompile(w, r, "compile")
}

func handleAddressPolicyCompile(w http.ResponseWriter, r *http.Request, operation string) {
	var req radius.AddressPolicyCompileRequest
	if err := decodeBody(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	result := radius.CompileAddressPolicy(config.Get(), req)
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	eventID, err := recordAddressPolicyResult(operation, req, result, actor)
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

func HandleDecompileAddressPolicy(w http.ResponseWriter, r *http.Request) {
	var req radius.AddressPolicyDecompileRequest
	if err := decodeBody(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	result := radius.DecompileAddressPolicyAttributes(req)
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	eventID, err := recordAddressPolicyResult("decompile", req, result, actor)
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

func HandleListAddressPolicyHistory(w http.ResponseWriter, r *http.Request) {
	limit := parseAddressPolicyLimit(r.URL.Query().Get("limit"), 100)
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	summary, events, ownership, err := addressPolicyEvidenceWithLimit(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if status != "" && db.DB != nil {
		filtered, err := db.ListAddressPolicyOwnership(limit, status)
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

func recordAddressPolicyResult(operation string, request any, result radius.AddressPolicyCompileResult, actor string) (string, error) {
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
	ownership := make([]db.AddressPolicyOwnershipInput, 0, 8)
	appendOwnership := func(family, assignmentType, pool, address, prefix string) {
		if !shouldRecordOwnership {
			return
		}
		if strings.TrimSpace(pool) == "" && strings.TrimSpace(address) == "" && strings.TrimSpace(prefix) == "" {
			return
		}
		ownership = append(ownership, db.AddressPolicyOwnershipInput{
			OwnershipKey:   result.Decision.OwnershipKey,
			SessionID:      result.Decision.SessionID,
			AcctSessionID:  result.Decision.AcctSessionID,
			Role:           result.Decision.Role,
			Owner:          result.Decision.Owner,
			Revision:       result.Decision.Revision,
			Family:         family,
			AssignmentType: assignmentType,
			PoolName:       pool,
			Address:        address,
			Prefix:         prefix,
			Status:         ownershipStatus,
		})
	}
	appendOwnership("ipv4", "address", result.Decision.IPv4Pool, result.Decision.IPv4Address, "")
	appendOwnership("ipv6", "address", result.Decision.IPv6Pool, result.Decision.IPv6Address, "")
	if strings.TrimSpace(result.Decision.IPv6Prefix) != "" {
		appendOwnership("ipv6", "prefix", result.Decision.IPv6Pool, "", result.Decision.IPv6Prefix)
	}
	appendOwnership("ipv6", "delegated_prefix", result.Decision.DelegatedIPv6Pool, "", result.Decision.DelegatedIPv6Prefix)
	appendOwnership("ipv6", "ra_prefix", result.Decision.RAPrefixPool, "", result.Decision.RAPrefix)
	return db.RecordAddressPolicyEvent(db.AddressPolicyEventInput{
		Operation:            operation,
		Status:               status,
		Role:                 result.Decision.Role,
		SessionID:            result.Decision.SessionID,
		AcctSessionID:        result.Decision.AcctSessionID,
		Owner:                result.Decision.Owner,
		Revision:             result.Decision.Revision,
		IPv4AssignmentCount:  result.Summary.IPv4AssignmentCount,
		IPv6AssignmentCount:  result.Summary.IPv6AssignmentCount,
		DelegatedPrefixCount: result.Summary.DelegatedPrefixCount,
		RAPrefixCount:        result.Summary.RAPrefixCount,
		WithdrawCount:        result.Summary.WithdrawCount,
		AttributeCount:       len(result.Attributes),
		DiagnosticCount:      len(result.Diagnostics),
		Fingerprint:          result.Fingerprint,
		RequestJSON:          addressPolicyJSON(request, "{}"),
		ResponseJSON:         addressPolicyJSON(result, "{}"),
		DiagnosticsJSON:      addressPolicyJSON(result.Diagnostics, "[]"),
		Actor:                actor,
		Ownership:            ownership,
	})
}

func addressPolicyEvidenceWithLimit(limit int) (db.AddressPolicyEventSummary, []db.AddressPolicyEvent, []db.AddressPolicyOwnershipRecord, error) {
	if db.DB == nil {
		return db.AddressPolicyEventSummary{}, nil, nil, nil
	}
	summary, err := db.GetAddressPolicyEventSummary()
	if err != nil {
		return db.AddressPolicyEventSummary{}, nil, nil, err
	}
	events, err := db.ListAddressPolicyEvents(limit)
	if err != nil {
		return db.AddressPolicyEventSummary{}, nil, nil, err
	}
	ownership, err := db.ListAddressPolicyOwnership(limit, "")
	if err != nil {
		return db.AddressPolicyEventSummary{}, nil, nil, err
	}
	return summary, events, ownership, nil
}

func parseAddressPolicyLimit(value string, fallback int) int {
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

func addressPolicyJSON(value any, fallback string) string {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) == 0 {
		return fallback
	}
	return string(encoded)
}
