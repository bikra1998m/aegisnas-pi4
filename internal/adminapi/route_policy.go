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

func HandleGetRoutePolicy(w http.ResponseWriter, r *http.Request) {
	report := radius.BuildRoutePolicyReport(config.Get())
	summary, events, ownership, err := routePolicyEvidenceWithLimit(20)
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

func HandlePreviewRoutePolicy(w http.ResponseWriter, r *http.Request) {
	handleRoutePolicyCompile(w, r, "preview")
}

func HandleCompileRoutePolicy(w http.ResponseWriter, r *http.Request) {
	handleRoutePolicyCompile(w, r, "compile")
}

func handleRoutePolicyCompile(w http.ResponseWriter, r *http.Request, operation string) {
	var req radius.RoutePolicyCompileRequest
	if err := decodeBody(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	result := radius.CompileRoutePolicy(config.Get(), req)
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	eventID, err := recordRoutePolicyResult(operation, req, result, actor)
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

func HandleDecompileRoutePolicy(w http.ResponseWriter, r *http.Request) {
	var req radius.RoutePolicyDecompileRequest
	if err := decodeBody(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	result := radius.DecompileRoutePolicyAttributes(req)
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	eventID, err := recordRoutePolicyResult("decompile", req, result, actor)
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

func HandleListRoutePolicyHistory(w http.ResponseWriter, r *http.Request) {
	limit := parseRoutePolicyLimit(r.URL.Query().Get("limit"), 100)
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	summary, events, ownership, err := routePolicyEvidenceWithLimit(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if status != "" && db.DB != nil {
		filtered, err := db.ListRoutePolicyOwnership(limit, status)
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

func recordRoutePolicyResult(operation string, request any, result radius.RoutePolicyCompileResult, actor string) (string, error) {
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
	ownership := make([]db.RoutePolicyOwnershipInput, 0, len(result.Decision.IPv4Routes)+len(result.Decision.IPv6Routes))
	appendRoute := func(route radius.RoutePolicyRoute) {
		if !shouldRecordOwnership {
			return
		}
		ownership = append(ownership, db.RoutePolicyOwnershipInput{
			OwnershipKey:  result.Decision.OwnershipKey,
			SessionID:     result.Decision.SessionID,
			AcctSessionID: result.Decision.AcctSessionID,
			Role:          result.Decision.Role,
			VRF:           result.Decision.VRF,
			Owner:         firstNonEmptyAdminString(route.Owner, result.Decision.Owner),
			Revision:      result.Decision.Revision,
			Family:        route.Family,
			Destination:   route.Destination,
			Gateway:       route.Gateway,
			Metric:        route.Metric,
			Preference:    route.Preference,
			Interface:     route.Interface,
			Tag:           route.Tag,
			Source:        route.Source,
			Status:        ownershipStatus,
		})
	}
	for _, route := range result.Decision.IPv4Routes {
		appendRoute(route)
	}
	for _, route := range result.Decision.IPv6Routes {
		appendRoute(route)
	}
	return db.RecordRoutePolicyEvent(db.RoutePolicyEventInput{
		Operation:       operation,
		Status:          status,
		Role:            result.Decision.Role,
		SessionID:       result.Decision.SessionID,
		AcctSessionID:   result.Decision.AcctSessionID,
		VRF:             result.Decision.VRF,
		Owner:           result.Decision.Owner,
		Revision:        result.Decision.Revision,
		IPv4RouteCount:  len(result.Decision.IPv4Routes),
		IPv6RouteCount:  len(result.Decision.IPv6Routes),
		WithdrawCount:   result.Summary.WithdrawCount,
		AttributeCount:  len(result.Attributes),
		DiagnosticCount: len(result.Diagnostics),
		Fingerprint:     result.Fingerprint,
		RequestJSON:     routePolicyJSON(request, "{}"),
		ResponseJSON:    routePolicyJSON(result, "{}"),
		DiagnosticsJSON: routePolicyJSON(result.Diagnostics, "[]"),
		Actor:           actor,
		Ownership:       ownership,
	})
}

func routePolicyEvidenceWithLimit(limit int) (db.RoutePolicyEventSummary, []db.RoutePolicyEvent, []db.RoutePolicyOwnershipRecord, error) {
	if db.DB == nil {
		return db.RoutePolicyEventSummary{}, nil, nil, nil
	}
	summary, err := db.GetRoutePolicyEventSummary()
	if err != nil {
		return db.RoutePolicyEventSummary{}, nil, nil, err
	}
	events, err := db.ListRoutePolicyEvents(limit)
	if err != nil {
		return db.RoutePolicyEventSummary{}, nil, nil, err
	}
	ownership, err := db.ListRoutePolicyOwnership(limit, "")
	if err != nil {
		return db.RoutePolicyEventSummary{}, nil, nil, err
	}
	return summary, events, ownership, nil
}

func parseRoutePolicyLimit(value string, fallback int) int {
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

func routePolicyJSON(value any, fallback string) string {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) == 0 {
		return fallback
	}
	return string(encoded)
}
