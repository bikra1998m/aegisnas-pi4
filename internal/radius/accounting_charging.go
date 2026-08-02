package radius

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"go.uber.org/zap"
)

const AccountingChargingSchemaVersion = 1

type AccountingChargingPolicy struct {
	SchemaVersion            int    `json:"schema_version"`
	Enabled                  bool   `json:"enabled"`
	RatingEnabled            bool   `json:"rating_enabled"`
	ExportEnabled            bool   `json:"export_enabled"`
	ReconcileIntervalSeconds int    `json:"reconcile_interval_seconds"`
	BatchSize                int    `json:"batch_size"`
	MaxExportRecords         int    `json:"max_export_records"`
	ExportFormat             string `json:"export_format"`
	DefaultPlan              string `json:"default_plan"`
	Currency                 string `json:"currency"`
	InputMicrosPerGiB        int64  `json:"input_micros_per_gib"`
	OutputMicrosPerGiB       int64  `json:"output_micros_per_gib"`
	SessionMicrosPerHour     int64  `json:"session_micros_per_hour"`
	MinimumChargeMicros      int64  `json:"minimum_charge_micros"`
	OpenRetentionDays        int    `json:"open_retention_days"`
	ClosedRetentionDays      int    `json:"closed_retention_days"`
	ExportRetentionDays      int    `json:"export_retention_days"`
	IntegritySampleLimit     int    `json:"integrity_sample_limit"`
}

type AccountingChargingReport struct {
	SchemaVersion int                           `json:"schema_version"`
	Enabled       bool                          `json:"enabled"`
	Status        string                        `json:"status"`
	Message       string                        `json:"message"`
	Policy        AccountingChargingPolicy      `json:"policy"`
	Summary       db.AccountingChargingSummary  `json:"summary"`
	Recent        []db.AccountingChargingRecord `json:"recent,omitempty"`
	Exports       []db.AccountingChargingExport `json:"exports,omitempty"`
	Attributes    []string                      `json:"attributes"`
	Vendors       []string                      `json:"vendors"`
	RFCs          []string                      `json:"rfcs"`
	Guarantees    []string                      `json:"guarantees"`
	Warnings      []string                      `json:"warnings,omitempty"`
}

type AccountingChargingReconcileReport struct {
	GeneratedAt string                               `json:"generated_at"`
	Status      string                               `json:"status"`
	Message     string                               `json:"message"`
	Result      db.AccountingChargingReconcileResult `json:"result"`
	Summary     db.AccountingChargingSummary         `json:"summary"`
}

func EffectiveAccountingChargingPolicy(cfg *config.Config) AccountingChargingPolicy {
	policy := AccountingChargingPolicy{SchemaVersion: AccountingChargingSchemaVersion}
	if cfg == nil {
		return policy
	}
	raw := config.EffectiveRadiusAccountingChargingConfig(cfg.Radius.AccountingCharging)
	policy.Enabled = raw.Enabled
	policy.RatingEnabled = raw.RatingEnabled
	policy.ExportEnabled = raw.ExportEnabled
	policy.ReconcileIntervalSeconds = raw.ReconcileIntervalSeconds
	policy.BatchSize = raw.BatchSize
	policy.MaxExportRecords = raw.MaxExportRecords
	policy.ExportFormat = strings.ToLower(strings.TrimSpace(raw.ExportFormat))
	policy.DefaultPlan = strings.TrimSpace(raw.DefaultPlan)
	policy.Currency = strings.ToUpper(strings.TrimSpace(raw.Currency))
	policy.InputMicrosPerGiB = raw.InputMicrosPerGiB
	policy.OutputMicrosPerGiB = raw.OutputMicrosPerGiB
	policy.SessionMicrosPerHour = raw.SessionMicrosPerHour
	policy.MinimumChargeMicros = raw.MinimumChargeMicros
	policy.OpenRetentionDays = raw.OpenRetentionDays
	policy.ClosedRetentionDays = raw.ClosedRetentionDays
	policy.ExportRetentionDays = raw.ExportRetentionDays
	policy.IntegritySampleLimit = raw.IntegritySampleLimit
	return policy
}

func BuildAccountingChargingReport(cfg *config.Config) AccountingChargingReport {
	policy := EffectiveAccountingChargingPolicy(cfg)
	report := AccountingChargingReport{
		SchemaVersion: AccountingChargingSchemaVersion,
		Enabled:       policy.Enabled,
		Status:        "disabled",
		Message:       "Accounting charging, rating, and export are disabled.",
		Policy:        policy,
		Attributes: []string{
			"Acct-Status-Type",
			"Acct-Session-Id",
			"Acct-Unique-Session-Id",
			"Acct-Input-Octets",
			"Acct-Input-Gigawords",
			"Acct-Output-Octets",
			"Acct-Output-Gigawords",
			"Acct-Session-Time",
			"Acct-Multi-Session-Id",
			"Acct-Link-Count",
			"Class",
			"Vendor-Specific charging, APN, bearer, call, and service identifiers",
		},
		Vendors: []string{
			"3GPP",
			"3GPP2",
			"Starent/Cisco ASR",
			"Ericsson",
			"Juniper ERX",
			"Nokia SR",
			"Huawei",
			"BNG/BRAS",
			"BroadSoft",
			"Acme Packet",
			"ISP billing systems",
		},
		RFCs: []string{"RFC 2865", "RFC 2866", "RFC 3162", "RFC 5080"},
		Guarantees: []string{
			"applied accounting events are idempotently projected into durable CDR records",
			"CDRs retain hashed subscriber identities, service correlation, counters, session duration, and termination state",
			"rating is deterministic from configured micros-per-unit policy and preserves chargeable unit evidence",
			"exports include payload SHA-256, manifest SHA-256, and previous-manifest chaining",
			"closed rated records are exported once and late accounting corrections are returned to pending export state",
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
		report.Message = "Database is not initialized; charging records cannot be inspected."
		return report
	}
	integrityErrors, err := db.VerifyAccountingChargingIntegrity(policy.IntegritySampleLimit)
	if err != nil {
		report.Status = "blocked"
		report.Message = err.Error()
		return report
	}
	summary, err := db.GetAccountingChargingSummary()
	if err != nil {
		report.Status = "blocked"
		report.Message = err.Error()
		return report
	}
	summary.IntegrityErrorRows += integrityErrors
	recent, err := db.ListAccountingChargingRecords(db.AccountingChargingRecordQuery{Limit: 25})
	if err != nil {
		report.Status = "blocked"
		report.Message = err.Error()
		return report
	}
	exports, err := db.ListAccountingChargingExports(10)
	if err != nil {
		report.Status = "blocked"
		report.Message = err.Error()
		return report
	}
	report.Summary = summary
	report.Recent = recent
	report.Exports = exports
	switch {
	case !policy.RatingEnabled:
		report.Status = "degraded"
		report.Message = "Charging CDR projection is active, but rating is disabled."
		report.Warnings = append(report.Warnings, "Enable radius.accounting_charging.rating_enabled before billing exports.")
	case !policy.ExportEnabled:
		report.Status = "degraded"
		report.Message = "Charging CDR projection and rating are active, but export is disabled."
		report.Warnings = append(report.Warnings, "Enable radius.accounting_charging.export_enabled before billing handoff.")
	case summary.RatingErrorRecords > 0:
		report.Status = "degraded"
		report.Message = fmt.Sprintf("Charging has %d rating error record(s).", summary.RatingErrorRecords)
	case summary.IntegrityErrorRows > 0:
		report.Status = "degraded"
		report.Message = fmt.Sprintf("Charging has %d CDR integrity error record(s).", summary.IntegrityErrorRows)
	case summary.PendingExportRecords > 0:
		report.Status = "ready"
		report.Message = fmt.Sprintf("Charging is active with %d record(s) pending export.", summary.PendingExportRecords)
	default:
		report.Status = "ready"
		report.Message = "Charging is active and export queue is caught up."
	}
	if summary.UnratedRecords > 0 {
		report.Warnings = append(report.Warnings, fmt.Sprintf("%d CDR(s) are waiting for rating reconciliation.", summary.UnratedRecords))
	}
	if summary.LastError != "" {
		report.Warnings = append(report.Warnings, summary.LastError)
	}
	return report
}

func ReconcileAccountingCharging(ctx context.Context, cfg *config.Config, batchSize int) (AccountingChargingReconcileReport, error) {
	policy := EffectiveAccountingChargingPolicy(cfg)
	report := AccountingChargingReconcileReport{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Status:      "disabled",
		Message:     "Accounting charging is disabled.",
	}
	if cfg == nil {
		report.Status = "blocked"
		report.Message = "Configuration is required."
		return report, fmt.Errorf("config is required")
	}
	if !policy.Enabled {
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
	result, err := db.ReconcileAccountingChargingFromEvents(ctx, batchSize)
	if err != nil {
		report.Status = "blocked"
		report.Message = err.Error()
		return report, err
	}
	rated, err := db.RateAccountingChargingRecords(ctx, db.AccountingChargingRatingPolicy{
		RatingEnabled:        policy.RatingEnabled,
		DefaultPlan:          policy.DefaultPlan,
		Currency:             policy.Currency,
		InputMicrosPerGiB:    policy.InputMicrosPerGiB,
		OutputMicrosPerGiB:   policy.OutputMicrosPerGiB,
		SessionMicrosPerHour: policy.SessionMicrosPerHour,
		MinimumChargeMicros:  policy.MinimumChargeMicros,
	}, batchSize)
	if err != nil {
		result.Errors++
		result.LastError = err.Error()
		report.Status = "degraded"
		report.Message = err.Error()
	}
	result.Rated = rated
	if err := db.PruneAccountingChargingEvidence(
		time.Duration(policy.OpenRetentionDays)*24*time.Hour,
		time.Duration(policy.ClosedRetentionDays)*24*time.Hour,
		time.Duration(policy.ExportRetentionDays)*24*time.Hour,
		time.Now().UTC(),
	); err != nil {
		result.Errors++
		result.LastError = err.Error()
		report.Status = "degraded"
		report.Message = err.Error()
	}
	summary, err := db.GetAccountingChargingSummary()
	if err != nil {
		return report, err
	}
	report.Result = result
	report.Summary = summary
	if report.Status == "disabled" {
		report.Status = "ok"
		report.Message = fmt.Sprintf("Charging reconciliation scanned %d event(s), projected %d CDR(s), rated %d CDR(s), and recorded %d error(s).",
			result.Scanned, result.Projected, result.Rated, result.Errors)
		if result.Errors > 0 || summary.RatingErrorRecords > 0 {
			report.Status = "degraded"
		}
	}
	_ = db.UpsertRuntimeStatus("radius_accounting_charging", report.Status, report.Message, map[string]any{
		"scanned":                result.Scanned,
		"projected":              result.Projected,
		"rated":                  result.Rated,
		"errors":                 result.Errors,
		"cdr_rows":               summary.CDRRows,
		"closed_records":         summary.ClosedRecords,
		"pending_export_records": summary.PendingExportRecords,
		"rating_error_records":   summary.RatingErrorRecords,
		"export_batch_rows":      summary.ExportBatchRows,
	})
	if result.Errors > 0 {
		return report, fmt.Errorf("charging reconciliation recorded %d error(s): %s", result.Errors, result.LastError)
	}
	return report, nil
}

func ExportAccountingCharging(ctx context.Context, cfg *config.Config, format string, limit int, createdBy string) (db.AccountingChargingExportResult, error) {
	policy := EffectiveAccountingChargingPolicy(cfg)
	if cfg == nil {
		return db.AccountingChargingExportResult{Status: "blocked", Message: "Configuration is required."}, fmt.Errorf("config is required")
	}
	if !policy.Enabled || !policy.ExportEnabled {
		return db.AccountingChargingExportResult{Status: "disabled", Message: "Accounting charging export is disabled.", Format: policy.ExportFormat}, nil
	}
	if !policy.RatingEnabled {
		return db.AccountingChargingExportResult{Status: "disabled", Message: "Accounting charging export requires rating to be enabled.", Format: policy.ExportFormat}, nil
	}
	if limit <= 0 || limit > policy.MaxExportRecords {
		limit = policy.MaxExportRecords
	}
	if strings.TrimSpace(format) == "" {
		format = policy.ExportFormat
	}
	result, err := db.ExportAccountingChargingRecords(ctx, format, limit, createdBy)
	if err != nil {
		_ = db.UpsertRuntimeStatus("radius_accounting_charging_export", "degraded", err.Error(), map[string]any{
			"format": format,
			"limit":  limit,
		})
		return result, err
	}
	_ = db.UpsertRuntimeStatus("radius_accounting_charging_export", result.Status, result.Message, map[string]any{
		"export_id":           result.ExportID,
		"format":              result.Format,
		"record_count":        result.RecordCount,
		"total_amount_micros": result.TotalAmountMicros,
		"payload_sha256":      result.PayloadSHA256,
		"manifest_sha256":     result.ManifestSHA256,
	})
	return result, nil
}

func StartAccountingChargingReconciler(ctx context.Context, cfg *config.Config) {
	policy := EffectiveAccountingChargingPolicy(cfg)
	if !policy.Enabled || policy.ReconcileIntervalSeconds <= 0 {
		return
	}
	interval := time.Duration(policy.ReconcileIntervalSeconds) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if _, err := ReconcileAccountingCharging(ctx, cfg, policy.BatchSize); err != nil {
			zap.L().Warn("accounting charging reconciliation failed", zap.Error(err))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
