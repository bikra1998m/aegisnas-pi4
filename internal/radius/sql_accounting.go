package radius

import (
	"context"
	"fmt"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"go.uber.org/zap"
)

const SQLAccountingSchemaVersion = 1

type SQLAccountingPolicy struct {
	SchemaVersion            int  `json:"schema_version"`
	Enabled                  bool `json:"enabled"`
	ReconcileEnabled         bool `json:"reconcile_enabled"`
	ReconcileIntervalSeconds int  `json:"reconcile_interval_seconds"`
	BatchSize                int  `json:"batch_size"`
	StaleAfterSeconds        int  `json:"stale_after_seconds"`
	AccountingRetentionDays  int  `json:"accounting_retention_days"`
	PostAuthRetentionDays    int  `json:"postauth_retention_days"`
}

type SQLAccountingFreeRADIUSSurface struct {
	Tables     []string `json:"tables"`
	Attributes []string `json:"attributes"`
	Modules    []string `json:"modules"`
	Sites      []string `json:"sites"`
}

type SQLAccountingReport struct {
	SchemaVersion int                             `json:"schema_version"`
	Enabled       bool                            `json:"enabled"`
	Status        string                          `json:"status"`
	Message       string                          `json:"message"`
	Policy        SQLAccountingPolicy             `json:"policy"`
	Summary       db.FreeRADIUSAccountingSummary  `json:"summary"`
	Recent        []db.FreeRADIUSAccountingRecord `json:"recent,omitempty"`
	FreeRADIUS    SQLAccountingFreeRADIUSSurface  `json:"freeradius"`
	RFCs          []string                        `json:"rfcs"`
	Warnings      []string                        `json:"warnings,omitempty"`
}

type SQLAccountingReconcileReport struct {
	GeneratedAt string                                 `json:"generated_at"`
	Status      string                                 `json:"status"`
	Message     string                                 `json:"message"`
	Result      db.FreeRADIUSAccountingReconcileResult `json:"result"`
	Summary     db.FreeRADIUSAccountingSummary         `json:"summary"`
}

func EffectiveSQLAccountingPolicy(cfg *config.Config) SQLAccountingPolicy {
	policy := SQLAccountingPolicy{
		SchemaVersion: SQLAccountingSchemaVersion,
	}
	if cfg == nil {
		return policy
	}
	raw := config.EffectiveRadiusSQLAccountingConfig(cfg.Radius.SQLAccounting)
	policy.Enabled = raw.Enabled
	policy.ReconcileEnabled = raw.ReconcileEnabled
	policy.ReconcileIntervalSeconds = raw.ReconcileIntervalSeconds
	policy.BatchSize = raw.BatchSize
	policy.StaleAfterSeconds = raw.StaleAfterSeconds
	policy.AccountingRetentionDays = raw.AccountingRetentionDays
	policy.PostAuthRetentionDays = raw.PostAuthRetentionDays
	return policy
}

func BuildSQLAccountingReport(cfg *config.Config) SQLAccountingReport {
	policy := EffectiveSQLAccountingPolicy(cfg)
	report := SQLAccountingReport{
		SchemaVersion: SQLAccountingSchemaVersion,
		Enabled:       policy.Enabled,
		Status:        "disabled",
		Message:       "FreeRADIUS SQL accounting reconciliation is disabled.",
		Policy:        policy,
		FreeRADIUS: SQLAccountingFreeRADIUSSurface{
			Tables: []string{"radacct", "radpostauth", "radius_sql_accounting_reconcile_events"},
			Attributes: []string{
				"Acct-Session-Id", "Acct-Unique-Session-Id", "Acct-Status-Type", "Acct-Start-Time",
				"Acct-Update-Time", "Acct-Stop-Time", "Acct-Input-Octets", "Acct-Output-Octets",
				"Acct-Session-Time", "Acct-Terminate-Cause", "User-Name", "Calling-Station-Id",
				"Called-Station-Id", "NAS-IP-Address", "NAS-Port", "NAS-Port-Type", "Framed-IP-Address",
				"Framed-IPv6-Address", "Framed-IPv6-Prefix", "Delegated-IPv6-Prefix", "Class",
			},
			Modules: []string{"mods-enabled/sql"},
			Sites:   []string{"sites-enabled/default:accounting", "sites-enabled/default:post-auth"},
		},
		RFCs: []string{"RFC 2865", "RFC 2866", "RFC 3162", "RFC 5080"},
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
		report.Message = "Database is not initialized; FreeRADIUS SQL accounting tables cannot be inspected."
		return report
	}
	summary, err := db.GetFreeRADIUSAccountingSummary(time.Duration(policy.StaleAfterSeconds) * time.Second)
	if err != nil {
		report.Status = "blocked"
		report.Message = err.Error()
		return report
	}
	recent, err := db.ListFreeRADIUSAccounting(25, "")
	if err != nil {
		report.Status = "blocked"
		report.Message = err.Error()
		return report
	}
	report.Summary = summary
	report.Recent = recent
	switch {
	case !policy.ReconcileEnabled:
		report.Status = "degraded"
		report.Message = "FreeRADIUS SQL accounting tables exist, but automatic reconciliation is disabled."
		report.Warnings = append(report.Warnings, "Enable radius.sql_accounting.reconcile_enabled before production accounting.")
	case summary.ErrorRows > 0:
		report.Status = "degraded"
		report.Message = fmt.Sprintf("FreeRADIUS SQL accounting has %d row(s) in reconcile error state.", summary.ErrorRows)
	case summary.StalePendingRows > 0:
		report.Status = "degraded"
		report.Message = fmt.Sprintf("FreeRADIUS SQL accounting has %d stale pending row(s).", summary.StalePendingRows)
	case summary.PendingRows > 0:
		report.Status = "ready"
		report.Message = fmt.Sprintf("FreeRADIUS SQL accounting is active with %d pending row(s) awaiting reconciliation.", summary.PendingRows)
	default:
		report.Status = "ready"
		report.Message = "FreeRADIUS SQL accounting schema is active and reconciled."
	}
	return report
}

func ReconcileSQLAccounting(ctx context.Context, cfg *config.Config, batchSize int) (SQLAccountingReconcileReport, error) {
	_ = ctx
	policy := EffectiveSQLAccountingPolicy(cfg)
	report := SQLAccountingReconcileReport{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Status:      "disabled",
		Message:     "FreeRADIUS SQL accounting reconciliation is disabled.",
	}
	if cfg == nil {
		report.Status = "blocked"
		report.Message = "Configuration is required."
		return report, fmt.Errorf("config is required")
	}
	if !policy.Enabled || !policy.ReconcileEnabled {
		return report, nil
	}
	if db.DB == nil {
		report.Status = "blocked"
		report.Message = "Database is not initialized."
		return report, fmt.Errorf("database not initialized")
	}
	if batchSize <= 0 || batchSize > policy.BatchSize {
		batchSize = policy.BatchSize
	}
	result, err := db.ReconcileFreeRADIUSAccounting(batchSize)
	if err != nil {
		report.Status = "blocked"
		report.Message = err.Error()
		return report, err
	}
	if err := db.PruneFreeRADIUSSQLAccounting(
		time.Duration(policy.AccountingRetentionDays)*24*time.Hour,
		time.Duration(policy.PostAuthRetentionDays)*24*time.Hour,
		time.Now().UTC(),
	); err != nil {
		report.Status = "degraded"
		report.Message = err.Error()
		return report, err
	}
	summary, err := db.GetFreeRADIUSAccountingSummary(time.Duration(policy.StaleAfterSeconds) * time.Second)
	if err != nil {
		return report, err
	}
	report.Result = result
	report.Summary = summary
	report.Status = result.Status
	report.Message = fmt.Sprintf("FreeRADIUS SQL reconciliation scanned %d row(s), reconciled %d, created %d session(s), updated %d, closed %d, and recorded %d error(s).",
		result.Scanned, result.Reconciled, result.CreatedSessions, result.UpdatedSessions, result.ClosedSessions, result.ErrorCount)
	if report.Status == "" {
		report.Status = "ok"
	}
	_ = db.UpsertRuntimeStatus("radius_sql_accounting", report.Status, report.Message, map[string]any{
		"scanned":            result.Scanned,
		"reconciled":         result.Reconciled,
		"created_sessions":   result.CreatedSessions,
		"updated_sessions":   result.UpdatedSessions,
		"closed_sessions":    result.ClosedSessions,
		"error_count":        result.ErrorCount,
		"pending_rows":       summary.PendingRows,
		"stale_pending_rows": summary.StalePendingRows,
		"radacct_rows":       summary.RadAcctRows,
		"radpostauth_rows":   summary.PostAuthRows,
	})
	return report, nil
}

func StartSQLAccountingReconciler(ctx context.Context, cfg *config.Config) {
	policy := EffectiveSQLAccountingPolicy(cfg)
	if !policy.Enabled || !policy.ReconcileEnabled || policy.ReconcileIntervalSeconds <= 0 {
		return
	}
	interval := time.Duration(policy.ReconcileIntervalSeconds) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if _, err := ReconcileSQLAccounting(ctx, cfg, policy.BatchSize); err != nil {
			zap.L().Warn("FreeRADIUS SQL accounting reconciliation failed", zap.Error(err))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
