package radius

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"go.uber.org/zap"
)

const AccountingSpoolSchemaVersion = 1

type AccountingSpoolPolicy struct {
	SchemaVersion          int  `json:"schema_version"`
	Enabled                bool `json:"enabled"`
	MaxQueueRecords        int  `json:"max_queue_records"`
	MaxAttempts            int  `json:"max_attempts"`
	InitialRetrySeconds    int  `json:"initial_retry_seconds"`
	MaxRetrySeconds        int  `json:"max_retry_seconds"`
	RecordTTLSeconds       int  `json:"record_ttl_seconds"`
	ReplayIntervalSeconds  int  `json:"replay_interval_seconds"`
	BatchSize              int  `json:"batch_size"`
	LockSeconds            int  `json:"lock_seconds"`
	SentRetentionSeconds   int  `json:"sent_retention_seconds"`
	PoisonRetentionSeconds int  `json:"poison_retention_seconds"`
}

type AccountingSpoolReport struct {
	SchemaVersion int                              `json:"schema_version"`
	Enabled       bool                             `json:"enabled"`
	Status        string                           `json:"status"`
	Message       string                           `json:"message"`
	Policy        AccountingSpoolPolicy            `json:"policy"`
	Summary       db.RadiusAccountingSpoolSummary  `json:"summary"`
	Recent        []db.RadiusAccountingSpoolRecord `json:"recent,omitempty"`
	RFCs          []string                         `json:"rfcs"`
	Warnings      []string                         `json:"warnings,omitempty"`
}

type AccountingSpoolReplayReport struct {
	GeneratedAt string                          `json:"generated_at"`
	Status      string                          `json:"status"`
	Message     string                          `json:"message"`
	Claimed     int                             `json:"claimed"`
	Sent        int                             `json:"sent"`
	Failed      int                             `json:"failed"`
	Poisoned    int                             `json:"poisoned"`
	Expired     int                             `json:"expired"`
	Summary     db.RadiusAccountingSpoolSummary `json:"summary"`
}

func EffectiveAccountingSpoolPolicy(cfg *config.Config) AccountingSpoolPolicy {
	policy := AccountingSpoolPolicy{
		SchemaVersion: AccountingSpoolSchemaVersion,
	}
	if cfg == nil {
		return policy
	}
	raw := config.EffectiveRadiusAccountingSpoolConfig(cfg.Radius.Upstream.AccountingSpool)
	policy.Enabled = cfg.Radius.Upstream.Enabled && raw.Enabled
	policy.MaxQueueRecords = raw.MaxQueueRecords
	policy.MaxAttempts = raw.MaxAttempts
	policy.InitialRetrySeconds = raw.InitialRetrySeconds
	policy.MaxRetrySeconds = raw.MaxRetrySeconds
	policy.RecordTTLSeconds = raw.RecordTTLSeconds
	policy.ReplayIntervalSeconds = raw.ReplayIntervalSeconds
	policy.BatchSize = raw.BatchSize
	policy.LockSeconds = raw.LockSeconds
	policy.SentRetentionSeconds = raw.SentRetentionSeconds
	policy.PoisonRetentionSeconds = raw.PoisonRetentionSeconds
	return policy
}

func BuildAccountingSpoolReport(cfg *config.Config) AccountingSpoolReport {
	policy := EffectiveAccountingSpoolPolicy(cfg)
	report := AccountingSpoolReport{
		SchemaVersion: AccountingSpoolSchemaVersion,
		Enabled:       policy.Enabled,
		Status:        "disabled",
		Message:       "Accounting spool is disabled.",
		Policy:        policy,
		RFCs:          []string{"RFC 2866", "RFC 5080", "RFC 6614"},
	}
	if cfg == nil {
		report.Status = "blocked"
		report.Message = "Configuration is not loaded."
		return report
	}
	if !cfg.Radius.Upstream.Enabled {
		report.Message = "Upstream AAA proxying is disabled; accounting spool is idle."
		return report
	}
	if !policy.Enabled {
		report.Status = "degraded"
		report.Message = "Upstream AAA is enabled but durable accounting spooling is disabled."
		report.Warnings = append(report.Warnings, "Enable radius.upstream.accounting_spool before production proxy accounting.")
		return report
	}
	if db.DB == nil {
		report.Status = "blocked"
		report.Message = "Database is not initialized; durable accounting spool cannot persist records."
		return report
	}
	summary, err := db.GetRadiusAccountingSpoolSummary(policy.MaxQueueRecords)
	if err != nil {
		report.Status = "blocked"
		report.Message = err.Error()
		return report
	}
	recent, err := db.ListRadiusAccountingSpool("", 25)
	if err != nil {
		report.Status = "blocked"
		report.Message = err.Error()
		return report
	}
	report.Summary = summary
	report.Recent = recent
	switch {
	case summary.PoisonCount > 0:
		report.Status = "degraded"
		report.Message = fmt.Sprintf("Accounting spool is active with %d poison record(s) requiring operator review.", summary.PoisonCount)
	case summary.QueueUtilization >= 90:
		report.Status = "degraded"
		report.Message = fmt.Sprintf("Accounting spool is active but queue utilization is %d%%.", summary.QueueUtilization)
	case summary.QueuedCount+summary.RetryingCount > 0:
		report.Status = "ready"
		report.Message = fmt.Sprintf("Accounting spool is active with %d queued/retrying record(s).", summary.QueuedCount+summary.RetryingCount)
	default:
		report.Status = "ready"
		report.Message = "Accounting spool is active and currently empty."
	}
	return report
}

func ReplayAccountingSpool(ctx context.Context, cfg *config.Config, batchSize int) (AccountingSpoolReplayReport, error) {
	policy := EffectiveAccountingSpoolPolicy(cfg)
	report := AccountingSpoolReplayReport{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Status:      "disabled",
		Message:     "Accounting spool is disabled.",
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
	if batchSize <= 0 {
		batchSize = policy.BatchSize
	}
	now := time.Now().UTC()
	expired, err := db.ExpireDueRadiusAccountingSpool(now)
	if err != nil {
		return report, err
	}
	report.Expired = expired
	claimed, err := db.ClaimRadiusAccountingSpool(batchSize, accountingSpoolOwner(cfg), now, time.Duration(policy.LockSeconds)*time.Second)
	if err != nil {
		return report, err
	}
	report.Claimed = len(claimed)
	for _, record := range claimed {
		status, result, responseCode, message, latency, nextAttempt := replayAccountingSpoolRecord(ctx, cfg, policy, record, now)
		update := db.RadiusAccountingSpoolAttemptUpdate{
			RecordID:      record.RecordID,
			Result:        result,
			Error:         message,
			ResponseCode:  responseCode,
			Route:         record.Route,
			Realm:         record.Realm,
			ServerName:    record.ServerName,
			LatencyMs:     latency.Milliseconds(),
			AttemptedAt:   time.Now().UTC(),
			NextAttemptAt: nextAttempt,
			Status:        status,
		}
		if err := db.CompleteRadiusAccountingSpoolAttempt(record, update); err != nil {
			report.Failed++
			zap.L().Warn("failed to record accounting spool attempt", zap.String("record_id", record.RecordID), zap.Error(err))
			continue
		}
		switch status {
		case db.RadiusAccountingSpoolStatusSent:
			report.Sent++
		case db.RadiusAccountingSpoolStatusPoison:
			report.Poisoned++
		default:
			report.Failed++
		}
	}
	if err := db.PruneRadiusAccountingSpool(time.Duration(policy.SentRetentionSeconds)*time.Second, time.Duration(policy.PoisonRetentionSeconds)*time.Second, time.Now().UTC()); err != nil {
		zap.L().Warn("failed to prune accounting spool", zap.Error(err))
	}
	summary, err := db.GetRadiusAccountingSpoolSummary(policy.MaxQueueRecords)
	if err != nil {
		return report, err
	}
	report.Summary = summary
	report.Status = "ok"
	report.Message = fmt.Sprintf("Accounting spool replay processed %d record(s): %d sent, %d failed, %d poisoned, %d expired.", report.Claimed, report.Sent, report.Failed, report.Poisoned, report.Expired)
	if report.Failed > 0 || report.Poisoned > 0 {
		report.Status = "degraded"
	}
	_ = db.UpsertRuntimeStatus("radius_accounting_spool", report.Status, report.Message, map[string]any{
		"claimed":       report.Claimed,
		"sent":          report.Sent,
		"failed":        report.Failed,
		"poisoned":      report.Poisoned,
		"expired":       report.Expired,
		"queued":        summary.QueuedCount,
		"retrying":      summary.RetryingCount,
		"queue_percent": summary.QueueUtilization,
	})
	return report, nil
}

func StartAccountingSpoolReplayer(ctx context.Context, cfg *config.Config) {
	policy := EffectiveAccountingSpoolPolicy(cfg)
	if !policy.Enabled || policy.ReplayIntervalSeconds <= 0 {
		return
	}
	interval := time.Duration(policy.ReplayIntervalSeconds) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if _, err := ReplayAccountingSpool(ctx, cfg, policy.BatchSize); err != nil {
			zap.L().Warn("accounting spool replay failed", zap.Error(err))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func queueAccountingFailure(ctx context.Context, cfg *config.Config, rec *AccountingRecord, reason string) (db.RadiusAccountingSpoolRecord, bool, error) {
	_ = ctx
	policy := EffectiveAccountingSpoolPolicy(cfg)
	if !policy.Enabled || rec == nil || db.DB == nil {
		return db.RadiusAccountingSpoolRecord{}, false, nil
	}
	now := time.Now().UTC()
	payload, payloadSHA, normalized, err := marshalAccountingSpoolPayload(rec, now)
	if err != nil {
		return db.RadiusAccountingSpoolRecord{}, false, err
	}
	route, realm, serverName := accountingSpoolRouteMetadata(cfg)
	recordID := "acct-" + payloadSHA[:32]
	return db.EnqueueRadiusAccountingSpool(db.RadiusAccountingSpoolCreate{
		RecordID:       recordID,
		Route:          route,
		Realm:          realm,
		ServerName:     serverName,
		Username:       normalized.Username,
		SessionID:      normalized.SessionID,
		AcctStatusType: normalized.AcctStatusType,
		PayloadJSON:    string(payload),
		PayloadSHA256:  payloadSHA,
		MaxAttempts:    policy.MaxAttempts,
		NextAttemptAt:  now.Add(time.Duration(policy.InitialRetrySeconds) * time.Second),
		ExpiresAt:      now.Add(time.Duration(policy.RecordTTLSeconds) * time.Second),
		OwnerNode:      accountingSpoolOwner(cfg),
	}, policy.MaxQueueRecords)
}

func replayAccountingSpoolRecord(ctx context.Context, cfg *config.Config, policy AccountingSpoolPolicy, record db.RadiusAccountingSpoolRecord, now time.Time) (string, string, string, string, time.Duration, time.Time) {
	payloadSHA := sha256.Sum256([]byte(record.PayloadJSON))
	if hex.EncodeToString(payloadSHA[:]) != strings.TrimSpace(record.PayloadSHA256) {
		return db.RadiusAccountingSpoolStatusPoison, db.RadiusAccountingSpoolAttemptPoison, "", "payload checksum mismatch", 0, time.Time{}
	}
	var rec AccountingRecord
	if err := json.Unmarshal([]byte(record.PayloadJSON), &rec); err != nil {
		return db.RadiusAccountingSpoolStatusPoison, db.RadiusAccountingSpoolAttemptPoison, "", err.Error(), 0, time.Time{}
	}
	result, err := accountingPacketSender(ctx, cfg, &rec)
	if err == nil {
		return db.RadiusAccountingSpoolStatusSent, db.RadiusAccountingSpoolAttemptSent, result.ResponseCode, "", result.Latency, time.Time{}
	}
	nextAttemptNumber := record.AttemptCount + 1
	if nextAttemptNumber >= record.MaxAttempts {
		return db.RadiusAccountingSpoolStatusPoison, db.RadiusAccountingSpoolAttemptPoison, result.ResponseCode, err.Error(), result.Latency, time.Time{}
	}
	return db.RadiusAccountingSpoolStatusQueued, db.RadiusAccountingSpoolAttemptFailed, result.ResponseCode, err.Error(), result.Latency, now.Add(accountingSpoolBackoff(policy, nextAttemptNumber))
}

func accountingSpoolBackoff(policy AccountingSpoolPolicy, attemptNumber int) time.Duration {
	if attemptNumber < 1 {
		attemptNumber = 1
	}
	initial := time.Duration(policy.InitialRetrySeconds) * time.Second
	if initial <= 0 {
		initial = 30 * time.Second
	}
	maximum := time.Duration(policy.MaxRetrySeconds) * time.Second
	if maximum <= 0 {
		maximum = time.Hour
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

func marshalAccountingSpoolPayload(rec *AccountingRecord, now time.Time) ([]byte, string, AccountingRecord, error) {
	if rec == nil {
		return nil, "", AccountingRecord{}, fmt.Errorf("accounting record is required")
	}
	normalized := *rec
	if normalized.Timestamp.IsZero() {
		normalized.Timestamp = now
	}
	normalized.Timestamp = normalized.Timestamp.UTC()
	payload, err := json.Marshal(normalized)
	if err != nil {
		return nil, "", AccountingRecord{}, err
	}
	sum := sha256.Sum256(payload)
	return payload, hex.EncodeToString(sum[:]), normalized, nil
}

func accountingSpoolRouteMetadata(cfg *config.Config) (string, string, string) {
	if cfg == nil {
		return "", "", ""
	}
	routes, err := EffectiveProxyRoutes(cfg)
	if err != nil || len(routes) == 0 {
		return "", strings.TrimSpace(cfg.Radius.Upstream.Realm), ""
	}
	selected := routes[0]
	for _, route := range routes {
		if route.Default {
			selected = route
			break
		}
	}
	serverName := ""
	if len(selected.ServerNames) > 0 {
		serverName = selected.ServerNames[0]
	}
	return selected.Name, selected.Realm, serverName
}

func accountingSpoolOwner(cfg *config.Config) string {
	if cfg != nil && strings.TrimSpace(cfg.Radius.NASIdentifier) != "" {
		return strings.TrimSpace(cfg.Radius.NASIdentifier)
	}
	if hostname, err := os.Hostname(); err == nil && strings.TrimSpace(hostname) != "" {
		return strings.TrimSpace(hostname)
	}
	return "aegisnas-node"
}
