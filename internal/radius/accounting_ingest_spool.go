package radius

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"go.uber.org/zap"
)

const AccountingIngestSpoolSchemaVersion = 1

type AccountingIngestSpoolPolicy struct {
	SchemaVersion           int  `json:"schema_version"`
	Enabled                 bool `json:"enabled"`
	ReplayEnabled           bool `json:"replay_enabled"`
	MaxQueueRecords         int  `json:"max_queue_records"`
	MaxAttempts             int  `json:"max_attempts"`
	InitialRetrySeconds     int  `json:"initial_retry_seconds"`
	MaxRetrySeconds         int  `json:"max_retry_seconds"`
	RecordTTLSeconds        int  `json:"record_ttl_seconds"`
	ReplayIntervalSeconds   int  `json:"replay_interval_seconds"`
	BatchSize               int  `json:"batch_size"`
	LockSeconds             int  `json:"lock_seconds"`
	AppliedRetentionSeconds int  `json:"applied_retention_seconds"`
	PoisonRetentionSeconds  int  `json:"poison_retention_seconds"`
	LossSLOSeconds          int  `json:"loss_slo_seconds"`
}

type AccountingIngestSpoolReport struct {
	SchemaVersion int                              `json:"schema_version"`
	Enabled       bool                             `json:"enabled"`
	Status        string                           `json:"status"`
	Message       string                           `json:"message"`
	Policy        AccountingIngestSpoolPolicy      `json:"policy"`
	Summary       db.AccountingIngestSpoolSummary  `json:"summary"`
	Recent        []db.AccountingIngestSpoolRecord `json:"recent,omitempty"`
	RFCs          []string                         `json:"rfcs"`
	Guarantees    []string                         `json:"guarantees"`
	Warnings      []string                         `json:"warnings,omitempty"`
}

type AccountingIngestSpoolReplayReport struct {
	GeneratedAt string                          `json:"generated_at"`
	Status      string                          `json:"status"`
	Message     string                          `json:"message"`
	Claimed     int                             `json:"claimed"`
	Applied     int                             `json:"applied"`
	Failed      int                             `json:"failed"`
	Poisoned    int                             `json:"poisoned"`
	Expired     int                             `json:"expired"`
	Summary     db.AccountingIngestSpoolSummary `json:"summary"`
}

func EffectiveAccountingIngestSpoolPolicy(cfg *config.Config) AccountingIngestSpoolPolicy {
	policy := AccountingIngestSpoolPolicy{SchemaVersion: AccountingIngestSpoolSchemaVersion}
	if cfg == nil {
		return policy
	}
	raw := config.EffectiveRadiusAccountingIngestSpoolConfig(cfg.Radius.AccountingIngestSpool)
	policy.Enabled = raw.Enabled
	policy.ReplayEnabled = raw.ReplayEnabled
	policy.MaxQueueRecords = raw.MaxQueueRecords
	policy.MaxAttempts = raw.MaxAttempts
	policy.InitialRetrySeconds = raw.InitialRetrySeconds
	policy.MaxRetrySeconds = raw.MaxRetrySeconds
	policy.RecordTTLSeconds = raw.RecordTTLSeconds
	policy.ReplayIntervalSeconds = raw.ReplayIntervalSeconds
	policy.BatchSize = raw.BatchSize
	policy.LockSeconds = raw.LockSeconds
	policy.AppliedRetentionSeconds = raw.AppliedRetentionSeconds
	policy.PoisonRetentionSeconds = raw.PoisonRetentionSeconds
	policy.LossSLOSeconds = raw.LossSLOSeconds
	return policy
}

func BuildAccountingIngestSpoolReport(cfg *config.Config) AccountingIngestSpoolReport {
	policy := EffectiveAccountingIngestSpoolPolicy(cfg)
	report := AccountingIngestSpoolReport{
		SchemaVersion: AccountingIngestSpoolSchemaVersion,
		Enabled:       policy.Enabled,
		Status:        "disabled",
		Message:       "Accounting ingest spool is disabled.",
		Policy:        policy,
		RFCs:          []string{"RFC 2866", "RFC 5080"},
		Guarantees: []string{
			"local accounting records are written to a durable queue before ledger apply",
			"queued records replay through the same idempotent accounting event ledger",
			"queue capacity provides explicit backpressure instead of silent loss",
			"checksum mismatches and exhausted retries become poison evidence for operator review",
			"loss-SLO breaches are visible in status, readiness, and support bundles",
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
		report.Message = "Database is not initialized; accounting ingest spool cannot persist records."
		return report
	}
	summary, err := db.GetAccountingIngestSpoolSummary(policy.MaxQueueRecords, policy.LossSLOSeconds)
	if err != nil {
		report.Status = "blocked"
		report.Message = err.Error()
		return report
	}
	recent, err := db.ListAccountingIngestSpool("", 25)
	if err != nil {
		report.Status = "blocked"
		report.Message = err.Error()
		return report
	}
	report.Summary = summary
	report.Recent = recent
	switch {
	case !policy.ReplayEnabled:
		report.Status = "degraded"
		report.Message = "Accounting ingest spool is active, but automatic replay is disabled."
		report.Warnings = append(report.Warnings, "Enable radius.accounting_ingest_spool.replay_enabled before production accounting.")
	case summary.PoisonCount > 0:
		report.Status = "degraded"
		report.Message = fmt.Sprintf("Accounting ingest spool has %d poison record(s) requiring operator review.", summary.PoisonCount)
	case summary.ExpiredCount > 0:
		report.Status = "degraded"
		report.Message = fmt.Sprintf("Accounting ingest spool has %d expired record(s).", summary.ExpiredCount)
	case summary.LossSLOBreachCount > 0:
		report.Status = "degraded"
		report.Message = fmt.Sprintf("Accounting ingest spool has %d record(s) older than the %d second loss SLO.", summary.LossSLOBreachCount, policy.LossSLOSeconds)
	case summary.QueueUtilization >= 90:
		report.Status = "degraded"
		report.Message = fmt.Sprintf("Accounting ingest spool is active but queue utilization is %d%%.", summary.QueueUtilization)
	case summary.QueuedCount+summary.RetryingCount > 0:
		report.Status = "ready"
		report.Message = fmt.Sprintf("Accounting ingest spool is active with %d queued/retrying record(s).", summary.QueuedCount+summary.RetryingCount)
	default:
		report.Status = "ready"
		report.Message = "Accounting ingest spool is active and caught up."
	}
	if summary.LastError != "" {
		report.Warnings = append(report.Warnings, summary.LastError)
	}
	return report
}

func ReplayAccountingIngestSpool(ctx context.Context, cfg *config.Config, batchSize int) (AccountingIngestSpoolReplayReport, error) {
	policy := EffectiveAccountingIngestSpoolPolicy(cfg)
	report := AccountingIngestSpoolReplayReport{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Status:      "disabled",
		Message:     "Accounting ingest spool is disabled.",
	}
	if cfg == nil {
		report.Status = "blocked"
		report.Message = "Configuration is required."
		return report, fmt.Errorf("config is required")
	}
	if !policy.Enabled {
		return report, nil
	}
	if !policy.ReplayEnabled {
		report.Status = "degraded"
		report.Message = "Accounting ingest spool replay is disabled."
		return report, nil
	}
	if db.DB == nil {
		report.Status = "blocked"
		report.Message = "Database is not initialized."
		return report, fmt.Errorf("database not initialized")
	}
	if batchSize <= 0 {
		batchSize = policy.BatchSize
	}
	now := time.Now().UTC()
	expired, err := db.ExpireDueAccountingIngestSpool(now)
	if err != nil {
		return report, err
	}
	report.Expired = expired
	claimed, err := db.ClaimAccountingIngestSpool(batchSize, accountingSpoolOwner(cfg), now, time.Duration(policy.LockSeconds)*time.Second)
	if err != nil {
		return report, err
	}
	report.Claimed = len(claimed)
	for _, record := range claimed {
		status, result, eventID, message, latency, nextAttempt := replayAccountingIngestSpoolRecord(ctx, policy, record, now)
		update := db.AccountingIngestSpoolAttemptUpdate{
			RecordID:      record.RecordID,
			Result:        result,
			Error:         message,
			EventID:       eventID,
			LatencyMs:     latency.Milliseconds(),
			AttemptedAt:   time.Now().UTC(),
			NextAttemptAt: nextAttempt,
			Status:        status,
		}
		if err := db.CompleteAccountingIngestSpoolAttempt(record, update); err != nil {
			report.Failed++
			zap.L().Warn("failed to record accounting ingest spool attempt", zap.String("record_id", record.RecordID), zap.Error(err))
			continue
		}
		switch status {
		case db.AccountingIngestSpoolStatusApplied:
			report.Applied++
		case db.AccountingIngestSpoolStatusPoison:
			report.Poisoned++
		default:
			report.Failed++
		}
	}
	if err := db.PruneAccountingIngestSpool(time.Duration(policy.AppliedRetentionSeconds)*time.Second, time.Duration(policy.PoisonRetentionSeconds)*time.Second, time.Now().UTC()); err != nil {
		zap.L().Warn("failed to prune accounting ingest spool", zap.Error(err))
	}
	summary, err := db.GetAccountingIngestSpoolSummary(policy.MaxQueueRecords, policy.LossSLOSeconds)
	if err != nil {
		return report, err
	}
	report.Summary = summary
	report.Status = "ok"
	report.Message = fmt.Sprintf("Accounting ingest spool replay processed %d record(s): %d applied, %d failed, %d poisoned, %d expired.", report.Claimed, report.Applied, report.Failed, report.Poisoned, report.Expired)
	if report.Failed > 0 || report.Poisoned > 0 || summary.LossSLOBreachCount > 0 {
		report.Status = "degraded"
	}
	_ = db.UpsertRuntimeStatus("radius_accounting_ingest_spool", report.Status, report.Message, map[string]any{
		"claimed":           report.Claimed,
		"applied":           report.Applied,
		"failed":            report.Failed,
		"poisoned":          report.Poisoned,
		"expired":           report.Expired,
		"queued":            summary.QueuedCount,
		"retrying":          summary.RetryingCount,
		"queue_percent":     summary.QueueUtilization,
		"loss_slo_breaches": summary.LossSLOBreachCount,
	})
	return report, nil
}

func StartAccountingIngestSpoolReplayer(ctx context.Context, cfg *config.Config) {
	policy := EffectiveAccountingIngestSpoolPolicy(cfg)
	if !policy.Enabled || !policy.ReplayEnabled || policy.ReplayIntervalSeconds <= 0 {
		return
	}
	interval := time.Duration(policy.ReplayIntervalSeconds) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if _, err := ReplayAccountingIngestSpool(ctx, cfg, policy.BatchSize); err != nil {
			zap.L().Warn("accounting ingest spool replay failed", zap.Error(err))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func processAccountingWithIngestSpool(ctx context.Context, cfg *config.Config, event db.AccountingEventRecord) error {
	policy := EffectiveAccountingIngestSpoolPolicy(cfg)
	if !policy.Enabled || db.DB == nil {
		_, err := applyAccountingIngestEvent(ctx, event)
		return err
	}
	now := time.Now().UTC()
	record, _, err := db.EnqueueAccountingIngestSpool(db.AccountingIngestSpoolCreate{
		Event:         event,
		MaxAttempts:   policy.MaxAttempts,
		NextAttemptAt: now,
		ExpiresAt:     now.Add(time.Duration(policy.RecordTTLSeconds) * time.Second),
		OwnerNode:     accountingSpoolOwner(cfg),
	}, policy.MaxQueueRecords)
	if err != nil {
		return err
	}
	if record.Status == db.AccountingIngestSpoolStatusApplied {
		_, err := applyAccountingIngestEvent(ctx, event)
		return err
	}
	start := time.Now()
	eventID, applyErr := applyAccountingIngestEvent(ctx, event)
	latency := time.Since(start)
	status := db.AccountingIngestSpoolStatusApplied
	result := db.AccountingIngestSpoolAttemptApplied
	message := ""
	var nextAttempt time.Time
	if applyErr != nil {
		message = applyErr.Error()
		nextAttemptNumber := record.AttemptCount + 1
		if nextAttemptNumber >= record.MaxAttempts {
			status = db.AccountingIngestSpoolStatusPoison
			result = db.AccountingIngestSpoolAttemptPoison
		} else {
			status = db.AccountingIngestSpoolStatusQueued
			result = db.AccountingIngestSpoolAttemptFailed
			nextAttempt = now.Add(accountingIngestSpoolBackoff(policy, nextAttemptNumber))
		}
	}
	updateErr := db.CompleteAccountingIngestSpoolAttempt(record, db.AccountingIngestSpoolAttemptUpdate{
		RecordID:      record.RecordID,
		Result:        result,
		Error:         message,
		EventID:       eventID,
		LatencyMs:     latency.Milliseconds(),
		AttemptedAt:   time.Now().UTC(),
		NextAttemptAt: nextAttempt,
		Status:        status,
	})
	if applyErr != nil {
		if updateErr != nil {
			return fmt.Errorf("%w; additionally failed to update accounting ingest spool: %v", applyErr, updateErr)
		}
		return applyErr
	}
	return updateErr
}

func replayAccountingIngestSpoolRecord(ctx context.Context, policy AccountingIngestSpoolPolicy, record db.AccountingIngestSpoolRecord, now time.Time) (string, string, string, string, time.Duration, time.Time) {
	payloadSHA := sha256.Sum256([]byte(record.PayloadJSON))
	if hex.EncodeToString(payloadSHA[:]) != strings.TrimSpace(record.PayloadSHA256) {
		return db.AccountingIngestSpoolStatusPoison, db.AccountingIngestSpoolAttemptPoison, "", "payload checksum mismatch", 0, time.Time{}
	}
	var event db.AccountingEventRecord
	if err := json.Unmarshal([]byte(record.PayloadJSON), &event); err != nil {
		return db.AccountingIngestSpoolStatusPoison, db.AccountingIngestSpoolAttemptPoison, "", err.Error(), 0, time.Time{}
	}
	start := time.Now()
	eventID, err := applyAccountingIngestEvent(ctx, event)
	latency := time.Since(start)
	if err == nil {
		return db.AccountingIngestSpoolStatusApplied, db.AccountingIngestSpoolAttemptApplied, eventID, "", latency, time.Time{}
	}
	nextAttemptNumber := record.AttemptCount + 1
	if nextAttemptNumber >= record.MaxAttempts {
		return db.AccountingIngestSpoolStatusPoison, db.AccountingIngestSpoolAttemptPoison, eventID, err.Error(), latency, time.Time{}
	}
	return db.AccountingIngestSpoolStatusQueued, db.AccountingIngestSpoolAttemptFailed, eventID, err.Error(), latency, now.Add(accountingIngestSpoolBackoff(policy, nextAttemptNumber))
}

func applyAccountingIngestEvent(ctx context.Context, event db.AccountingEventRecord) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ingested, err := db.IngestAccountingEvent(ctx, event)
	if err != nil {
		return "", err
	}
	if _, err := db.ApplyAccountingEventByID(ctx, ingested.Event.EventID); err != nil {
		return ingested.Event.EventID, err
	}
	return ingested.Event.EventID, nil
}

func accountingIngestSpoolBackoff(policy AccountingIngestSpoolPolicy, attemptNumber int) time.Duration {
	if attemptNumber < 1 {
		attemptNumber = 1
	}
	initial := time.Duration(policy.InitialRetrySeconds) * time.Second
	if initial <= 0 {
		initial = 5 * time.Second
	}
	maximum := time.Duration(policy.MaxRetrySeconds) * time.Second
	if maximum <= 0 {
		maximum = 5 * time.Minute
	}
	delay := initial
	for i := 1; i < attemptNumber; i++ {
		if delay >= maximum/2 {
			delay = maximum
			break
		}
		delay *= 2
	}
	if delay > maximum {
		return maximum
	}
	return delay
}
