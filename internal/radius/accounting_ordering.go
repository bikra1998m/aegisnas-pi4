package radius

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

const AccountingOrderingSchemaVersion = 1

type AccountingOrderingPolicy struct {
	SchemaVersion          int  `json:"schema_version"`
	Enabled                bool `json:"enabled"`
	ReplayEnabled          bool `json:"replay_enabled"`
	SequenceWindowSeconds  int  `json:"sequence_window_seconds"`
	LateStopWindowSeconds  int  `json:"late_stop_window_seconds"`
	MaxReplayBatch         int  `json:"max_replay_batch"`
	DuplicateRetentionDays int  `json:"duplicate_retention_days"`
}

type AccountingOrderingReport struct {
	SchemaVersion int                        `json:"schema_version"`
	Enabled       bool                       `json:"enabled"`
	Status        string                     `json:"status"`
	Message       string                     `json:"message"`
	Policy        AccountingOrderingPolicy   `json:"policy"`
	Summary       db.AccountingEventSummary  `json:"summary"`
	Recent        []db.AccountingEventRecord `json:"recent,omitempty"`
	RFCs          []string                   `json:"rfcs"`
	Guarantees    []string                   `json:"guarantees"`
	Warnings      []string                   `json:"warnings,omitempty"`
}

type AccountingOrderingReplayReport struct {
	GeneratedAt string                        `json:"generated_at"`
	Status      string                        `json:"status"`
	Message     string                        `json:"message"`
	Result      db.AccountingEventApplyResult `json:"result"`
	Summary     db.AccountingEventSummary     `json:"summary"`
}

func EffectiveAccountingOrderingPolicy(cfg *config.Config) AccountingOrderingPolicy {
	policy := AccountingOrderingPolicy{SchemaVersion: AccountingOrderingSchemaVersion}
	if cfg == nil {
		return policy
	}
	raw := config.EffectiveRadiusAccountingOrderingConfig(cfg.Radius.AccountingOrdering)
	policy.Enabled = raw.Enabled
	policy.ReplayEnabled = raw.ReplayEnabled
	policy.SequenceWindowSeconds = raw.SequenceWindowSeconds
	policy.LateStopWindowSeconds = raw.LateStopWindowSeconds
	policy.MaxReplayBatch = raw.MaxReplayBatch
	policy.DuplicateRetentionDays = raw.DuplicateRetentionDays
	return policy
}

func BuildAccountingOrderingReport(cfg *config.Config) AccountingOrderingReport {
	policy := EffectiveAccountingOrderingPolicy(cfg)
	report := AccountingOrderingReport{
		SchemaVersion: AccountingOrderingSchemaVersion,
		Enabled:       policy.Enabled,
		Status:        "disabled",
		Message:       "Accounting ordering and duplicate protection is disabled.",
		Policy:        policy,
		RFCs:          []string{"RFC 2866", "RFC 5080"},
		Guarantees: []string{
			"deterministic accounting event identity",
			"duplicate packet suppression",
			"ordered Start/Interim-Update/Stop application",
			"late Stop merge without session reopen",
			"operator replay of non-ignored ledger events",
		},
	}
	if cfg == nil {
		report.Status = "blocked"
		report.Message = "Configuration is not loaded."
		return report
	}
	if !policy.Enabled {
		return report
	}
	if db.DB == nil {
		report.Status = "blocked"
		report.Message = "Database is not initialized; accounting event ledger cannot be inspected."
		return report
	}
	summary, err := db.GetAccountingEventSummary(time.Duration(policy.SequenceWindowSeconds) * time.Second)
	if err != nil {
		report.Status = "blocked"
		report.Message = err.Error()
		return report
	}
	recent, err := db.ListAccountingEvents(25, "", "")
	if err != nil {
		report.Status = "blocked"
		report.Message = err.Error()
		return report
	}
	report.Summary = summary
	report.Recent = recent
	switch {
	case summary.ErrorEvents > 0:
		report.Status = "degraded"
		report.Message = fmt.Sprintf("Accounting event ledger has %d event(s) in error state.", summary.ErrorEvents)
	case summary.StalePendingEvents > 0:
		report.Status = "degraded"
		report.Message = fmt.Sprintf("Accounting event ledger has %d stale pending event(s).", summary.StalePendingEvents)
	case summary.PendingEvents > 0:
		report.Status = "ready"
		report.Message = fmt.Sprintf("Accounting event ledger is active with %d pending event(s) inside the apply window.", summary.PendingEvents)
	default:
		report.Status = "ready"
		report.Message = "Accounting event ledger is active and fully applied."
	}
	if summary.DuplicateEvents > 0 {
		report.Warnings = append(report.Warnings, fmt.Sprintf("%d duplicate accounting packet(s) were suppressed.", summary.DuplicateEvents))
	}
	if summary.ReorderedEvents > 0 {
		report.Warnings = append(report.Warnings, fmt.Sprintf("%d out-of-order accounting event(s) were merged deterministically.", summary.ReorderedEvents))
	}
	if summary.LateStopEvents > 0 {
		report.Warnings = append(report.Warnings, fmt.Sprintf("%d late Stop event(s) were merged without reopening sessions.", summary.LateStopEvents))
	}
	return report
}

func ReplayAccountingOrdering(ctx context.Context, cfg *config.Config, limit int, sessionKey string) (AccountingOrderingReplayReport, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	policy := EffectiveAccountingOrderingPolicy(cfg)
	report := AccountingOrderingReplayReport{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Status:      "disabled",
		Message:     "Accounting ordering replay is disabled.",
	}
	if cfg == nil {
		report.Status = "blocked"
		report.Message = "Configuration is required."
		return report, fmt.Errorf("config is required")
	}
	if !policy.Enabled || !policy.ReplayEnabled {
		return report, nil
	}
	if db.DB == nil {
		report.Status = "blocked"
		report.Message = "Database is not initialized."
		return report, fmt.Errorf("database not initialized")
	}
	if limit <= 0 || limit > policy.MaxReplayBatch {
		limit = policy.MaxReplayBatch
	}
	result, err := db.ReplayAccountingEvents(ctx, limit, strings.TrimSpace(sessionKey))
	if err != nil {
		report.Status = "degraded"
		report.Message = err.Error()
		return report, err
	}
	if err := db.PruneAccountingEvents(time.Duration(policy.DuplicateRetentionDays)*24*time.Hour, time.Now().UTC()); err != nil {
		report.Status = "degraded"
		report.Message = err.Error()
		return report, err
	}
	if err := PruneAccountingCounterEvidence(cfg, time.Now().UTC()); err != nil {
		report.Status = "degraded"
		report.Message = err.Error()
		return report, err
	}
	summary, err := db.GetAccountingEventSummary(time.Duration(policy.SequenceWindowSeconds) * time.Second)
	if err != nil {
		return report, err
	}
	report.Result = result
	report.Summary = summary
	report.Status = "ok"
	if result.ErrorCount > 0 {
		report.Status = "degraded"
	}
	report.Message = fmt.Sprintf("Accounting replay scanned %d event(s), applied %d, created %d session(s), updated %d, closed %d, reordered %d, late-stopped %d, and recorded %d error(s).",
		result.Scanned, result.Applied, result.CreatedSessions, result.UpdatedSessions, result.ClosedSessions,
		result.Reordered, result.LateStops, result.ErrorCount)
	_ = db.UpsertRuntimeStatus("radius_accounting_ordering", report.Status, report.Message, map[string]any{
		"scanned":        result.Scanned,
		"applied":        result.Applied,
		"duplicates":     summary.DuplicateEvents,
		"reordered":      summary.ReorderedEvents,
		"late_stops":     summary.LateStopEvents,
		"pending_events": summary.PendingEvents,
		"error_events":   summary.ErrorEvents,
	})
	return report, nil
}
