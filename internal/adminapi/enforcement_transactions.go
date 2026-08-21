package adminapi

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/enforcement"
)

func HandleGetEnforcementTransactions(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	plan, err := enforcement.BuildAtomicEnforcementPlan(r.Context(), cfg, enforcement.AtomicEnforcementRequest{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	summary, transactions, drifts, err := enforcementTransactionEvidenceWithLimit(20)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"report": map[string]any{
			"schema_version": enforcement.AtomicEnforcementSchemaVersion,
			"status":         plan.Status,
			"message":        plan.Message,
			"summary":        plan.Summary,
			"targets":        plan.Targets,
			"diagnostics":    plan.Diagnostics,
			"fingerprint":    plan.PlanFingerprint,
			"rfcs":           plan.RFCs,
			"capabilities":   plan.Capabilities,
			"policy": map[string]any{
				"enabled":                      cfg.Policy.EnforcementTransactions.Enabled,
				"fail_closed":                  cfg.Policy.EnforcementTransactions.FailClosed,
				"targets":                      cfg.Policy.EnforcementTransactions.Targets,
				"require_preview_before_apply": cfg.Policy.EnforcementTransactions.RequirePreviewBeforeApply,
				"auto_rollback_on_failure":     cfg.Policy.EnforcementTransactions.AutoRollbackOnFailure,
				"auto_rollback_on_drift":       cfg.Policy.EnforcementTransactions.AutoRollbackOnDrift,
				"drift_check_after_apply":      cfg.Policy.EnforcementTransactions.DriftCheckAfterApply,
				"drift_tolerance_seconds":      cfg.Policy.EnforcementTransactions.DriftToleranceSeconds,
				"apply_timeout_seconds":        cfg.Policy.EnforcementTransactions.ApplyTimeoutSeconds,
				"rollback_timeout_seconds":     cfg.Policy.EnforcementTransactions.RollbackTimeoutSeconds,
				"history_retention_limit":      cfg.Policy.EnforcementTransactions.HistoryRetentionLimit,
				"compensation_retention_limit": cfg.Policy.EnforcementTransactions.CompensationRetentionLimit,
			},
			"evidence": map[string]any{
				"summary":             summary,
				"recent_transactions": transactions,
				"recent_drift_events": drifts,
			},
		},
	})
}

func HandlePreviewEnforcementTransaction(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeAtomicEnforcementRequest(w, r)
	if !ok {
		return
	}
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	ctx, cancel := context.WithTimeout(r.Context(), enforcementTransactionTimeout(config.Get().Policy.EnforcementTransactions.ApplyTimeoutSeconds, 120))
	defer cancel()
	result, err := enforcement.PreviewAtomicEnforcement(ctx, config.Get(), req, actor)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"result":       result,
	})
}

func HandleApplyEnforcementTransaction(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeAtomicEnforcementRequest(w, r)
	if !ok {
		return
	}
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	ctx, cancel := context.WithTimeout(r.Context(), enforcementTransactionTimeout(config.Get().Policy.EnforcementTransactions.ApplyTimeoutSeconds, 120))
	defer cancel()
	result, err := enforcement.ApplyAtomicEnforcement(ctx, config.Get(), req, actor)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"result":       result,
	})
}

func HandleDetectEnforcementTransactionDrift(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeAtomicEnforcementRequest(w, r)
	if !ok {
		return
	}
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	ctx, cancel := context.WithTimeout(r.Context(), enforcementTransactionTimeout(config.Get().Policy.EnforcementTransactions.ApplyTimeoutSeconds, 120))
	defer cancel()
	result, err := enforcement.DetectAtomicEnforcementDrift(ctx, config.Get(), req, actor)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"result":       result,
	})
}

func HandleRollbackEnforcementTransaction(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeAtomicEnforcementRequest(w, r)
	if !ok {
		return
	}
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	ctx, cancel := context.WithTimeout(r.Context(), enforcementTransactionTimeout(config.Get().Policy.EnforcementTransactions.RollbackTimeoutSeconds, 120))
	defer cancel()
	result, err := enforcement.RollbackAtomicEnforcement(ctx, config.Get(), req, actor)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"result":       result,
	})
}

func HandleListEnforcementTransactionHistory(w http.ResponseWriter, r *http.Request) {
	limit := parseEnforcementTransactionLimit(r.URL.Query().Get("limit"), 100)
	summary, transactions, drifts, err := enforcementTransactionEvidenceWithLimit(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"summary":      summary,
		"transactions": transactions,
		"drift_events": drifts,
	})
}

func decodeAtomicEnforcementRequest(w http.ResponseWriter, r *http.Request) (enforcement.AtomicEnforcementRequest, bool) {
	var req enforcement.AtomicEnforcementRequest
	if r.Body == nil || r.ContentLength == 0 {
		return req, true
	}
	if err := decodeBody(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return enforcement.AtomicEnforcementRequest{}, false
	}
	return req, true
}

func enforcementTransactionEvidenceWithLimit(limit int) (db.EnforcementTransactionSummary, []db.EnforcementTransactionRecord, []db.EnforcementDriftEventRecord, error) {
	if db.DB == nil {
		return db.EnforcementTransactionSummary{}, nil, nil, nil
	}
	summary, err := db.GetEnforcementTransactionSummary()
	if err != nil {
		return db.EnforcementTransactionSummary{}, nil, nil, err
	}
	transactions, err := db.ListEnforcementTransactions(limit)
	if err != nil {
		return db.EnforcementTransactionSummary{}, nil, nil, err
	}
	drifts, err := db.ListEnforcementDriftEvents(limit)
	if err != nil {
		return db.EnforcementTransactionSummary{}, nil, nil, err
	}
	return summary, transactions, drifts, nil
}

func parseEnforcementTransactionLimit(value string, fallback int) int {
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

func enforcementTransactionTimeout(seconds int, fallback int) time.Duration {
	if seconds <= 0 {
		seconds = fallback
	}
	return time.Duration(seconds) * time.Second
}
