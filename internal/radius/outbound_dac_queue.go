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

const OutboundDACQueueSchemaVersion = 1

type OutboundDACQueuePolicy struct {
	SchemaVersion              int  `json:"schema_version"`
	Enabled                    bool `json:"enabled"`
	ReplayEnabled              bool `json:"replay_enabled"`
	MaxQueueRecords            int  `json:"max_queue_records"`
	MaxAttempts                int  `json:"max_attempts"`
	InitialRetrySeconds        int  `json:"initial_retry_seconds"`
	MaxRetrySeconds            int  `json:"max_retry_seconds"`
	RecordTTLSeconds           int  `json:"record_ttl_seconds"`
	ReplayIntervalSeconds      int  `json:"replay_interval_seconds"`
	BatchSize                  int  `json:"batch_size"`
	LockSeconds                int  `json:"lock_seconds"`
	ACKRetentionSeconds        int  `json:"ack_retention_seconds"`
	DeadLetterRetentionSeconds int  `json:"dead_letter_retention_seconds"`
	IdempotencyWindowSeconds   int  `json:"idempotency_window_seconds"`
}

type OutboundDACQueueReport struct {
	SchemaVersion int                                `json:"schema_version"`
	Enabled       bool                               `json:"enabled"`
	Status        string                             `json:"status"`
	Message       string                             `json:"message"`
	Policy        OutboundDACQueuePolicy             `json:"policy"`
	Summary       db.OutboundDACQueueSummary         `json:"summary"`
	Recent        []db.OutboundDACQueueRecord        `json:"recent,omitempty"`
	Attempts      []db.OutboundDACQueueAttemptRecord `json:"attempts,omitempty"`
	RFCs          []string                           `json:"rfcs"`
	Warnings      []string                           `json:"warnings,omitempty"`
}

type OutboundDACEnqueueResult struct {
	Status    string                    `json:"status"`
	Message   string                    `json:"message"`
	Created   bool                      `json:"created"`
	Preview   OutboundDACPreview        `json:"preview"`
	Queue     db.OutboundDACQueueRecord `json:"queue"`
	Duplicate bool                      `json:"duplicate"`
}

type OutboundDACReplayReport struct {
	GeneratedAt string                     `json:"generated_at"`
	Status      string                     `json:"status"`
	Message     string                     `json:"message"`
	Claimed     int                        `json:"claimed"`
	ACK         int                        `json:"ack"`
	NAK         int                        `json:"nak"`
	Failed      int                        `json:"failed"`
	Poisoned    int                        `json:"poisoned"`
	Expired     int                        `json:"expired"`
	Summary     db.OutboundDACQueueSummary `json:"summary"`
}

type OutboundDACQueueActionResult struct {
	Status  string                    `json:"status"`
	Message string                    `json:"message"`
	Queue   db.OutboundDACQueueRecord `json:"queue"`
}

func EffectiveOutboundDACQueuePolicy(cfg *config.Config) OutboundDACQueuePolicy {
	policy := OutboundDACQueuePolicy{SchemaVersion: OutboundDACQueueSchemaVersion}
	if cfg == nil {
		return policy
	}
	raw := config.EffectiveDynamicAuthConfig(cfg.Radius.DynamicAuth)
	policy.Enabled = raw.OutboundEnabled && raw.OutboundQueueEnabled
	policy.ReplayEnabled = policy.Enabled && raw.OutboundReplayEnabled
	policy.MaxQueueRecords = raw.OutboundMaxQueueRecords
	policy.MaxAttempts = raw.OutboundMaxAttempts
	policy.InitialRetrySeconds = raw.OutboundInitialRetrySeconds
	policy.MaxRetrySeconds = raw.OutboundMaxRetrySeconds
	policy.RecordTTLSeconds = raw.OutboundRecordTTLSeconds
	policy.ReplayIntervalSeconds = raw.OutboundReplayIntervalSeconds
	policy.BatchSize = raw.OutboundBatchSize
	policy.LockSeconds = raw.OutboundLockSeconds
	policy.ACKRetentionSeconds = raw.OutboundACKRetentionSeconds
	policy.DeadLetterRetentionSeconds = raw.OutboundDeadLetterRetentionSeconds
	policy.IdempotencyWindowSeconds = raw.OutboundIdempotencyWindowSeconds
	return policy
}

func BuildOutboundDACQueueReport(cfg *config.Config, status, queueID string, limit int) OutboundDACQueueReport {
	policy := EffectiveOutboundDACQueuePolicy(cfg)
	report := OutboundDACQueueReport{
		SchemaVersion: OutboundDACQueueSchemaVersion,
		Enabled:       policy.Enabled,
		Status:        "disabled",
		Message:       "Durable outbound DAC queue is disabled.",
		Policy:        policy,
		RFCs:          []string{"RFC 2865", "RFC 3576", "RFC 5176"},
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
		report.Message = "Database is not initialized; outbound DAC queue cannot persist records."
		return report
	}
	summary, err := db.GetOutboundDACQueueSummary(policy.MaxQueueRecords)
	if err != nil {
		report.Status = "blocked"
		report.Message = err.Error()
		return report
	}
	recent, err := db.ListOutboundDACQueue(status, limit)
	if err != nil {
		report.Status = "blocked"
		report.Message = err.Error()
		return report
	}
	report.Summary = summary
	report.Recent = recent
	if strings.TrimSpace(queueID) != "" {
		attempts, err := db.ListOutboundDACQueueAttempts(queueID, limit)
		if err != nil {
			report.Status = "blocked"
			report.Message = err.Error()
			return report
		}
		report.Attempts = attempts
	}
	switch {
	case summary.PoisonCount > 0 || summary.ErrorCount > 0:
		report.Status = "degraded"
		report.Message = fmt.Sprintf("Outbound DAC queue has %d record(s) requiring operator review.", summary.PoisonCount+summary.ErrorCount)
	case summary.QueueUtilization >= 90:
		report.Status = "degraded"
		report.Message = fmt.Sprintf("Outbound DAC queue is active but queue utilization is %d%%.", summary.QueueUtilization)
	case summary.QueuedCount+summary.RetryingCount > 0:
		report.Status = "ready"
		report.Message = fmt.Sprintf("Outbound DAC queue is active with %d queued/retrying record(s).", summary.QueuedCount+summary.RetryingCount)
	default:
		report.Status = "ready"
		report.Message = "Outbound DAC queue is active and currently empty."
	}
	if policy.Enabled && !policy.ReplayEnabled {
		report.Warnings = append(report.Warnings, "Automatic replay is disabled; use the manual replay API for queued records.")
	}
	return report
}

func EnqueueOutboundDAC(ctx context.Context, cfg *config.Config, request OutboundDACRequest, requestedBy string) (OutboundDACEnqueueResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	policy := EffectiveOutboundDACQueuePolicy(cfg)
	if cfg == nil {
		return OutboundDACEnqueueResult{}, fmt.Errorf("config is required")
	}
	if !policy.Enabled {
		return OutboundDACEnqueueResult{Status: "disabled", Message: "Durable outbound DAC queue is disabled."}, nil
	}
	if db.DB == nil {
		return OutboundDACEnqueueResult{}, fmt.Errorf("database not initialized")
	}
	effective := config.EffectiveDynamicAuthConfig(dynamicAuthConfig(cfg))
	request = normalizeOutboundDACRequest(request)
	request, _ = enrichOutboundDACRequestFromSession(request)
	preview, err := PreviewOutboundDAC(ctx, cfg, request)
	if err != nil {
		return OutboundDACEnqueueResult{}, err
	}
	if effective.OutboundRequireConfirmation && !request.Confirm && len(preview.Blockers) == 0 {
		preview.Status = "blocked"
		preview.Blockers = append(preview.Blockers, "confirm=true is required before queueing outbound dynamic authorization")
		preview.Message = "confirm=true is required before queueing outbound dynamic authorization."
	}
	if len(preview.Blockers) > 0 {
		return OutboundDACEnqueueResult{Status: "blocked", Message: preview.Message, Preview: preview}, nil
	}
	now := time.Now().UTC()
	attrs := dbAttributesFromPlan(preview.Attributes)
	payload, payloadSHA, normalized, err := marshalOutboundDACQueuePayload(request)
	if err != nil {
		return OutboundDACEnqueueResult{}, err
	}
	idempotencyKey := outboundDACIdempotencyKey(normalized, preview)
	queueID := "dacq-" + db.FingerprintOutboundDAC(idempotencyKey, preview.Target.Endpoint, now.Format(time.RFC3339Nano))[:24]
	record, created, err := db.EnqueueOutboundDACQueue(db.OutboundDACQueueCreate{
		QueueID:              queueID,
		IdempotencyKey:       idempotencyKey,
		Action:               normalized.Action,
		Status:               db.OutboundDACQueueStatusQueued,
		TargetAddress:        preview.Target.Address,
		TargetPort:           preview.Target.Port,
		TargetTransport:      preview.Target.Transport,
		NASIdentifier:        firstNonEmptyString(normalized.NASIdentifier, preview.Target.NASIdentifier),
		NASIPAddress:         firstNonEmptyString(normalized.NASIPAddress, preview.Target.NASIPAddress),
		NASType:              firstNonEmptyString(preview.Target.NASType, normalized.NASType),
		ShortName:            firstNonEmptyString(preview.Target.ShortName, normalized.ShortName),
		SessionID:            firstNonEmptyString(normalized.AcctSessionID, normalized.SessionID),
		Username:             normalized.UserName,
		CallingStationID:     normalized.CallingStationID,
		FramedIPAddress:      normalized.FramedIPAddress,
		Attributes:           attrs,
		PayloadJSON:          string(payload),
		PayloadSHA256:        payloadSHA,
		RequestCode:          preview.RequestCode,
		CorrelationID:        firstNonEmptyString(normalized.CorrelationID, queueID),
		RequestedBy:          requestedBy,
		RequestFingerprint:   preview.RequestFingerprint,
		MaxAttempts:          policy.MaxAttempts,
		NextAttemptAt:        now,
		ExpiresAt:            now.Add(time.Duration(policy.RecordTTLSeconds) * time.Second),
		IdempotencyExpiresAt: now.Add(time.Duration(policy.IdempotencyWindowSeconds) * time.Second),
		OwnerNode:            outboundDACQueueOwner(cfg),
	}, policy.MaxQueueRecords)
	if err != nil {
		return OutboundDACEnqueueResult{}, err
	}
	message := fmt.Sprintf("Outbound %s request queued as %s.", outboundDACActionLabel(normalized.Action), record.QueueID)
	status := "queued"
	duplicate := !created
	if duplicate {
		status = "duplicate"
		message = fmt.Sprintf("Duplicate outbound %s request suppressed by idempotency key; existing queue record is %s.", outboundDACActionLabel(normalized.Action), record.QueueID)
	}
	_ = db.UpsertRuntimeStatus(OutboundDACRuntimeComponent, status, message, map[string]any{
		"queue_id":        record.QueueID,
		"action":          normalized.Action,
		"target":          preview.Target.Endpoint,
		"idempotency_key": idempotencyKey,
		"duplicate":       duplicate,
	})
	return OutboundDACEnqueueResult{Status: status, Message: message, Created: created, Preview: preview, Queue: record, Duplicate: duplicate}, nil
}

func ReplayOutboundDACQueue(ctx context.Context, cfg *config.Config, batchSize int) (OutboundDACReplayReport, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	policy := EffectiveOutboundDACQueuePolicy(cfg)
	report := OutboundDACReplayReport{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Status:      "disabled",
		Message:     "Durable outbound DAC queue is disabled.",
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
	expired, err := db.ExpireDueOutboundDACQueue(now)
	if err != nil {
		return report, err
	}
	report.Expired = expired
	claimed, err := db.ClaimOutboundDACQueue(batchSize, outboundDACQueueOwner(cfg), now, time.Duration(policy.LockSeconds)*time.Second)
	if err != nil {
		return report, err
	}
	report.Claimed = len(claimed)
	for _, record := range claimed {
		update := replayOutboundDACQueueRecord(ctx, cfg, policy, record, now)
		if err := db.CompleteOutboundDACQueueAttempt(record, update); err != nil {
			report.Failed++
			zap.L().Warn("failed to record outbound DAC queue attempt", zap.String("queue_id", record.QueueID), zap.Error(err))
			continue
		}
		switch update.Result {
		case db.OutboundDACQueueAttemptACK:
			report.ACK++
		case db.OutboundDACQueueAttemptNAK:
			report.NAK++
		case db.OutboundDACQueueAttemptPoison:
			report.Poisoned++
		default:
			report.Failed++
		}
	}
	if err := db.PruneOutboundDACQueue(time.Duration(policy.ACKRetentionSeconds)*time.Second, time.Duration(policy.DeadLetterRetentionSeconds)*time.Second, time.Now().UTC()); err != nil {
		zap.L().Warn("failed to prune outbound DAC queue", zap.Error(err))
	}
	summary, err := db.GetOutboundDACQueueSummary(policy.MaxQueueRecords)
	if err != nil {
		return report, err
	}
	report.Summary = summary
	report.Status = "ok"
	report.Message = fmt.Sprintf("Outbound DAC queue replay processed %d record(s): %d ACK, %d NAK, %d failed, %d poisoned, %d expired.", report.Claimed, report.ACK, report.NAK, report.Failed, report.Poisoned, report.Expired)
	if report.Failed > 0 || report.Poisoned > 0 {
		report.Status = "degraded"
	}
	_ = db.UpsertRuntimeStatus(OutboundDACRuntimeComponent, report.Status, report.Message, map[string]any{
		"claimed":       report.Claimed,
		"ack":           report.ACK,
		"nak":           report.NAK,
		"failed":        report.Failed,
		"poisoned":      report.Poisoned,
		"expired":       report.Expired,
		"queued":        summary.QueuedCount,
		"retrying":      summary.RetryingCount,
		"queue_percent": summary.QueueUtilization,
	})
	return report, nil
}

func StartOutboundDACQueueReplayer(ctx context.Context, cfg *config.Config) {
	policy := EffectiveOutboundDACQueuePolicy(cfg)
	if !policy.ReplayEnabled || policy.ReplayIntervalSeconds <= 0 {
		return
	}
	interval := time.Duration(policy.ReplayIntervalSeconds) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if _, err := ReplayOutboundDACQueue(ctx, cfg, policy.BatchSize); err != nil {
			zap.L().Warn("outbound DAC queue replay failed", zap.Error(err))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func CancelOutboundDACQueue(ctx context.Context, cfg *config.Config, queueID, canceledBy, reason string) (OutboundDACQueueActionResult, error) {
	_ = ctx
	if cfg == nil {
		return OutboundDACQueueActionResult{}, fmt.Errorf("config is required")
	}
	if !EffectiveOutboundDACQueuePolicy(cfg).Enabled {
		return OutboundDACQueueActionResult{Status: "disabled", Message: "Durable outbound DAC queue is disabled."}, nil
	}
	record, err := db.CancelOutboundDACQueue(queueID, canceledBy, reason, time.Now().UTC())
	if err != nil {
		return OutboundDACQueueActionResult{}, err
	}
	message := fmt.Sprintf("Outbound DAC queue record %s canceled.", record.QueueID)
	_ = db.UpsertRuntimeStatus(OutboundDACRuntimeComponent, "canceled", message, map[string]any{"queue_id": record.QueueID})
	return OutboundDACQueueActionResult{Status: "canceled", Message: message, Queue: record}, nil
}

func RetryOutboundDACQueue(ctx context.Context, cfg *config.Config, queueID string) (OutboundDACQueueActionResult, error) {
	_ = ctx
	if cfg == nil {
		return OutboundDACQueueActionResult{}, fmt.Errorf("config is required")
	}
	policy := EffectiveOutboundDACQueuePolicy(cfg)
	if !policy.Enabled {
		return OutboundDACQueueActionResult{Status: "disabled", Message: "Durable outbound DAC queue is disabled."}, nil
	}
	now := time.Now().UTC()
	record, err := db.RequeueOutboundDACQueue(
		queueID,
		now,
		now.Add(time.Duration(policy.RecordTTLSeconds)*time.Second),
		now.Add(time.Duration(policy.IdempotencyWindowSeconds)*time.Second),
		outboundDACQueueOwner(cfg),
	)
	if err != nil {
		return OutboundDACQueueActionResult{}, err
	}
	message := fmt.Sprintf("Outbound DAC queue record %s is queued for retry.", record.QueueID)
	_ = db.UpsertRuntimeStatus(OutboundDACRuntimeComponent, "queued", message, map[string]any{"queue_id": record.QueueID})
	return OutboundDACQueueActionResult{Status: "queued", Message: message, Queue: record}, nil
}

func replayOutboundDACQueueRecord(ctx context.Context, cfg *config.Config, policy OutboundDACQueuePolicy, record db.OutboundDACQueueRecord, now time.Time) db.OutboundDACQueueAttemptUpdate {
	fail := func(result, status, message string, next time.Time) db.OutboundDACQueueAttemptUpdate {
		return db.OutboundDACQueueAttemptUpdate{
			QueueID:            record.QueueID,
			Result:             result,
			Status:             status,
			TargetAddress:      record.TargetAddress,
			TargetPort:         record.TargetPort,
			TargetTransport:    record.TargetTransport,
			RequestCode:        record.RequestCode,
			RequestFingerprint: record.RequestFingerprint,
			ErrorMessage:       message,
			AttemptedAt:        time.Now().UTC(),
			NextAttemptAt:      next,
		}
	}
	payloadSHA := sha256.Sum256([]byte(record.PayloadJSON))
	if hex.EncodeToString(payloadSHA[:]) != strings.TrimSpace(record.PayloadSHA256) {
		return fail(db.OutboundDACQueueAttemptPoison, db.OutboundDACQueueStatusPoison, "payload checksum mismatch", time.Time{})
	}
	var request OutboundDACRequest
	if err := json.Unmarshal([]byte(record.PayloadJSON), &request); err != nil {
		return fail(db.OutboundDACQueueAttemptPoison, db.OutboundDACQueueStatusPoison, err.Error(), time.Time{})
	}
	request.Confirm = true
	if request.CorrelationID == "" {
		request.CorrelationID = record.CorrelationID
	}
	requestID := record.QueueID
	preview, err := PreviewOutboundDAC(ctx, cfg, request)
	if err != nil {
		return nextOutboundDACQueueFailure(record, policy, err.Error(), 0, 0, "", "", now)
	}
	if len(preview.Blockers) > 0 {
		return nextOutboundDACQueueFailure(record, policy, preview.Message, 0, 0, "", "", now)
	}
	target, secret, _, blockers := resolveOutboundDACTarget(ctx, cfg, config.EffectiveDynamicAuthConfig(dynamicAuthConfig(cfg)), request)
	if len(blockers) > 0 {
		return nextOutboundDACQueueFailure(record, policy, strings.Join(blockers, "; "), 0, 0, "", "", now)
	}
	packet, attrs, err := buildOutboundDACPacket(request, secret, config.EffectiveDynamicAuthConfig(dynamicAuthConfig(cfg)).OutboundMaxAttributes)
	if err != nil {
		return nextOutboundDACQueueFailure(record, policy, err.Error(), 0, 0, "", "", now)
	}
	if err := setMessageAuthenticator(packet); err != nil {
		return nextOutboundDACQueueFailure(record, policy, fmt.Sprintf("set Message-Authenticator: %v", err), 0, 0, "", "", now)
	}
	requestWire, err := packet.Encode()
	if err != nil {
		return nextOutboundDACQueueFailure(record, policy, fmt.Sprintf("encode outbound DAC packet: %v", err), 0, 0, "", "", now)
	}
	requestHash := packetWireSHA256(requestWire)
	ensureOutboundDACQueueHistoryRequest(cfg, requestID, request, record, target, attrs, int(packet.Code), requestHash)
	outcome := sendOutboundDACPacket(ctx, packet, target.Endpoint, time.Duration(config.EffectiveDynamicAuthConfig(dynamicAuthConfig(cfg)).OutboundTimeoutSeconds)*time.Second, requestWire, requestHash)
	status, failure, responseCode, errorCause, errorCauseName, replyMessage := classifyOutboundDACResponse(request.Action, outcome.Response, outcome.Err)
	_ = db.RecordOutboundDACAttempt(db.OutboundDACAttemptCreate{
		RequestID:           requestID,
		Attempt:             record.AttemptCount + 1,
		Status:              status,
		TargetAddress:       target.Address,
		TargetPort:          target.Port,
		TargetTransport:     target.Transport,
		RequestCode:         int(packet.Code),
		ResponseCode:        responseCode,
		ErrorCause:          errorCause,
		ErrorCauseName:      errorCauseName,
		ReplyMessage:        replyMessage,
		LatencyMS:           outcome.Latency.Milliseconds(),
		PacketIdentifier:    int(packet.Identifier),
		RequestFingerprint:  requestHash,
		ResponseFingerprint: outcome.ResponseHash,
		ErrorMessage:        failure,
	})
	queueStatus := db.OutboundDACQueueStatusQueued
	result := db.OutboundDACQueueAttemptFailed
	nextAttempt := time.Time{}
	switch status {
	case db.OutboundDACStatusACK:
		queueStatus = db.OutboundDACQueueStatusACK
		result = db.OutboundDACQueueAttemptACK
	case db.OutboundDACStatusNAK:
		queueStatus = db.OutboundDACQueueStatusNAK
		result = db.OutboundDACQueueAttemptNAK
	default:
		update := nextOutboundDACQueueFailure(record, policy, failure, responseCode, errorCause, errorCauseName, replyMessage, now)
		queueStatus = update.Status
		result = update.Result
		nextAttempt = update.NextAttemptAt
	}
	_, _ = db.CompleteOutboundDACRequest(db.OutboundDACComplete{
		RequestID:           requestID,
		Status:              status,
		ResponseCode:        responseCode,
		ErrorCause:          errorCause,
		ErrorCauseName:      errorCauseName,
		ReplyMessage:        replyMessage,
		CompletedAt:         time.Now().UTC(),
		LatencyMS:           outcome.Latency.Milliseconds(),
		FailureReason:       failure,
		ResponseFingerprint: outcome.ResponseHash,
	})
	message := outboundDACResultMessage(request.Action, status, failure, replyMessage, errorCauseName)
	RecordVendorDynamicAuth(cfg, outcome.Response, request.Action, status == db.OutboundDACStatusACK, message)
	return db.OutboundDACQueueAttemptUpdate{
		QueueID:             record.QueueID,
		Result:              result,
		Status:              queueStatus,
		TargetAddress:       target.Address,
		TargetPort:          target.Port,
		TargetTransport:     target.Transport,
		RequestCode:         int(packet.Code),
		ResponseCode:        responseCode,
		ErrorCause:          errorCause,
		ErrorCauseName:      errorCauseName,
		ReplyMessage:        replyMessage,
		LatencyMS:           outcome.Latency.Milliseconds(),
		PacketIdentifier:    int(packet.Identifier),
		RequestFingerprint:  requestHash,
		ResponseFingerprint: outcome.ResponseHash,
		ErrorMessage:        failure,
		AttemptedAt:         time.Now().UTC(),
		NextAttemptAt:       nextAttempt,
	}
}

func nextOutboundDACQueueFailure(record db.OutboundDACQueueRecord, policy OutboundDACQueuePolicy, message string, responseCode, errorCause int, errorCauseName, replyMessage string, now time.Time) db.OutboundDACQueueAttemptUpdate {
	nextAttemptNumber := record.AttemptCount + 1
	status := db.OutboundDACQueueStatusQueued
	result := db.OutboundDACQueueAttemptFailed
	nextAttempt := now.Add(outboundDACQueueBackoff(policy, nextAttemptNumber))
	if nextAttemptNumber >= record.MaxAttempts {
		status = db.OutboundDACQueueStatusPoison
		result = db.OutboundDACQueueAttemptPoison
		nextAttempt = time.Time{}
	}
	return db.OutboundDACQueueAttemptUpdate{
		QueueID:            record.QueueID,
		Result:             result,
		Status:             status,
		TargetAddress:      record.TargetAddress,
		TargetPort:         record.TargetPort,
		TargetTransport:    record.TargetTransport,
		RequestCode:        record.RequestCode,
		ResponseCode:       responseCode,
		ErrorCause:         errorCause,
		ErrorCauseName:     errorCauseName,
		ReplyMessage:       replyMessage,
		ErrorMessage:       firstNonEmptyString(message, "outbound DAC attempt failed"),
		RequestFingerprint: record.RequestFingerprint,
		AttemptedAt:        time.Now().UTC(),
		NextAttemptAt:      nextAttempt,
	}
}

func outboundDACQueueBackoff(policy OutboundDACQueuePolicy, attemptNumber int) time.Duration {
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

func marshalOutboundDACQueuePayload(request OutboundDACRequest) ([]byte, string, OutboundDACRequest, error) {
	normalized := normalizeOutboundDACRequest(request)
	normalized.Confirm = true
	payload, err := json.Marshal(normalized)
	if err != nil {
		return nil, "", OutboundDACRequest{}, err
	}
	sum := sha256.Sum256(payload)
	return payload, hex.EncodeToString(sum[:]), normalized, nil
}

func outboundDACIdempotencyKey(request OutboundDACRequest, preview OutboundDACPreview) string {
	raw := strings.TrimSpace(request.IdempotencyKey)
	if raw == "" {
		raw = db.FingerprintOutboundDAC(request.CorrelationID, preview.RequestFingerprint)
	}
	return "sha256:" + db.FingerprintOutboundDAC("outbound-dac-idempotency", raw)
}

func ensureOutboundDACQueueHistoryRequest(cfg *config.Config, requestID string, request OutboundDACRequest, record db.OutboundDACQueueRecord, target OutboundDACTarget, attrs []db.OutboundDACAttribute, requestCode int, requestHash string) {
	if db.DB == nil {
		return
	}
	if _, err := db.GetOutboundDACRequest(requestID); err == nil {
		return
	}
	now := time.Now().UTC()
	_, _ = db.CreateOutboundDACRequest(db.OutboundDACCreate{
		RequestID:            requestID,
		Action:               request.Action,
		Status:               db.OutboundDACStatusSent,
		TargetAddress:        target.Address,
		TargetPort:           target.Port,
		TargetTransport:      target.Transport,
		NASIdentifier:        firstNonEmptyString(request.NASIdentifier, target.NASIdentifier),
		NASIPAddress:         firstNonEmptyString(request.NASIPAddress, target.NASIPAddress),
		NASType:              firstNonEmptyString(target.NASType, request.NASType),
		ShortName:            firstNonEmptyString(target.ShortName, request.ShortName),
		SessionID:            firstNonEmptyString(request.AcctSessionID, request.SessionID, record.SessionID),
		Username:             request.UserName,
		CallingStationID:     request.CallingStationID,
		FramedIPAddress:      request.FramedIPAddress,
		Attributes:           attrs,
		RequestCode:          requestCode,
		CorrelationID:        firstNonEmptyString(request.CorrelationID, record.CorrelationID, requestID),
		RequestedBy:          record.RequestedBy,
		RequestedAt:          now,
		SentAt:               now,
		MessageAuthenticator: true,
		RequestFingerprint:   requestHash,
	}, config.EffectiveDynamicAuthConfig(dynamicAuthConfig(cfg)).OutboundHistoryLimit)
}

func outboundDACQueueOwner(cfg *config.Config) string {
	if cfg != nil && strings.TrimSpace(cfg.Radius.NASIdentifier) != "" {
		return strings.TrimSpace(cfg.Radius.NASIdentifier)
	}
	if hostname, err := os.Hostname(); err == nil && strings.TrimSpace(hostname) != "" {
		return strings.TrimSpace(hostname)
	}
	return "aegisnas-node"
}
