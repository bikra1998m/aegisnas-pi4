package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	OutboundDACQueueStatusQueued   = "queued"
	OutboundDACQueueStatusRetrying = "retrying"
	OutboundDACQueueStatusACK      = "ack"
	OutboundDACQueueStatusNAK      = "nak"
	OutboundDACQueueStatusError    = "error"
	OutboundDACQueueStatusPoison   = "poison"
	OutboundDACQueueStatusExpired  = "expired"
	OutboundDACQueueStatusCanceled = "canceled"

	OutboundDACQueueAttemptACK      = "ack"
	OutboundDACQueueAttemptNAK      = "nak"
	OutboundDACQueueAttemptFailed   = "failed"
	OutboundDACQueueAttemptPoison   = "poison"
	OutboundDACQueueAttemptExpired  = "expired"
	OutboundDACQueueAttemptCanceled = "canceled"
)

type OutboundDACQueueCreate struct {
	QueueID                string
	IdempotencyKey         string
	Action                 string
	Status                 string
	TargetAddress          string
	TargetPort             int
	TargetTransport        string
	DeliveryMode           string
	ProxyRoute             string
	ProxyRealm             string
	ProxyHomeServer        string
	ProxyHopCount          int
	ProxyState             []string
	VendorAction           string
	VendorPacks            []string
	VendorCompilerStatus   string
	VendorCompilerWarnings []string
	OwnershipSessionID     string
	OwnershipStatus        string
	OwnershipSource        string
	OwnershipOwnerNode     string
	CapabilityDecision     string
	CapabilityWarnings     []string
	HandoffDecision        string
	HandoffOwnerNode       string
	HandoffLeaseID         string
	HandoffFencingToken    string
	HandoffWarnings        []string
	NASIdentifier          string
	NASIPAddress           string
	NASType                string
	ShortName              string
	SessionID              string
	Username               string
	CallingStationID       string
	FramedIPAddress        string
	Attributes             []OutboundDACAttribute
	PayloadJSON            string
	PayloadSHA256          string
	RequestCode            int
	CorrelationID          string
	RequestedBy            string
	RequestFingerprint     string
	MaxAttempts            int
	NextAttemptAt          time.Time
	ExpiresAt              time.Time
	IdempotencyExpiresAt   time.Time
	OwnerNode              string
}

type OutboundDACQueueRecord struct {
	ID                     int                    `json:"id"`
	QueueID                string                 `json:"queue_id"`
	IdempotencyKey         string                 `json:"idempotency_key"`
	Action                 string                 `json:"action"`
	Status                 string                 `json:"status"`
	TargetAddress          string                 `json:"target_address"`
	TargetPort             int                    `json:"target_port"`
	TargetTransport        string                 `json:"target_transport"`
	DeliveryMode           string                 `json:"delivery_mode"`
	ProxyRoute             string                 `json:"proxy_route,omitempty"`
	ProxyRealm             string                 `json:"proxy_realm,omitempty"`
	ProxyHomeServer        string                 `json:"proxy_home_server,omitempty"`
	ProxyHopCount          int                    `json:"proxy_hop_count"`
	ProxyState             []string               `json:"proxy_state,omitempty"`
	VendorAction           string                 `json:"vendor_action,omitempty"`
	VendorPacks            []string               `json:"vendor_packs,omitempty"`
	VendorCompilerStatus   string                 `json:"vendor_compiler_status"`
	VendorCompilerWarnings []string               `json:"vendor_compiler_warnings,omitempty"`
	OwnershipSessionID     string                 `json:"ownership_session_id,omitempty"`
	OwnershipStatus        string                 `json:"ownership_status,omitempty"`
	OwnershipSource        string                 `json:"ownership_source,omitempty"`
	OwnershipOwnerNode     string                 `json:"ownership_owner_node,omitempty"`
	CapabilityDecision     string                 `json:"capability_decision"`
	CapabilityWarnings     []string               `json:"capability_warnings,omitempty"`
	HandoffDecision        string                 `json:"handoff_decision"`
	HandoffOwnerNode       string                 `json:"handoff_owner_node,omitempty"`
	HandoffLeaseID         string                 `json:"handoff_lease_id,omitempty"`
	HandoffFencingToken    string                 `json:"handoff_fencing_token,omitempty"`
	HandoffWarnings        []string               `json:"handoff_warnings,omitempty"`
	NASIdentifier          string                 `json:"nas_identifier,omitempty"`
	NASIPAddress           string                 `json:"nas_ip_address,omitempty"`
	NASType                string                 `json:"nas_type,omitempty"`
	ShortName              string                 `json:"shortname,omitempty"`
	SessionID              string                 `json:"session_id,omitempty"`
	UsernameHash           string                 `json:"username_hash,omitempty"`
	CallingStationHash     string                 `json:"calling_station_hash,omitempty"`
	FramedIPAddress        string                 `json:"framed_ip_address,omitempty"`
	Attributes             []OutboundDACAttribute `json:"attributes,omitempty"`
	PayloadJSON            string                 `json:"-"`
	PayloadSHA256          string                 `json:"payload_sha256"`
	RequestCode            int                    `json:"request_code"`
	CorrelationID          string                 `json:"correlation_id"`
	RequestedBy            string                 `json:"requested_by,omitempty"`
	RequestFingerprint     string                 `json:"request_fingerprint"`
	AttemptCount           int                    `json:"attempt_count"`
	MaxAttempts            int                    `json:"max_attempts"`
	LastError              string                 `json:"last_error,omitempty"`
	LastResponseCode       int                    `json:"last_response_code,omitempty"`
	LastErrorCause         int                    `json:"last_error_cause,omitempty"`
	LastErrorCauseName     string                 `json:"last_error_cause_name,omitempty"`
	LastReplyMessage       string                 `json:"last_reply_message,omitempty"`
	LastLatencyMS          int64                  `json:"last_latency_ms"`
	NextAttemptAt          string                 `json:"next_attempt_at,omitempty"`
	ExpiresAt              string                 `json:"expires_at"`
	IdempotencyExpiresAt   string                 `json:"idempotency_expires_at"`
	OwnerNode              string                 `json:"owner_node,omitempty"`
	LockedUntil            string                 `json:"locked_until,omitempty"`
	SentAt                 string                 `json:"sent_at,omitempty"`
	CompletedAt            string                 `json:"completed_at,omitempty"`
	CanceledAt             string                 `json:"canceled_at,omitempty"`
	CanceledBy             string                 `json:"canceled_by,omitempty"`
	CancelReason           string                 `json:"cancel_reason,omitempty"`
	CreatedAt              string                 `json:"created_at"`
	UpdatedAt              string                 `json:"updated_at"`
}

type OutboundDACQueueAttemptRecord struct {
	ID                  int      `json:"id"`
	QueueID             string   `json:"queue_id"`
	AttemptNumber       int      `json:"attempt_number"`
	Result              string   `json:"result"`
	Status              string   `json:"status"`
	TargetAddress       string   `json:"target_address"`
	TargetPort          int      `json:"target_port"`
	TargetTransport     string   `json:"target_transport"`
	DeliveryMode        string   `json:"delivery_mode"`
	ProxyRoute          string   `json:"proxy_route,omitempty"`
	ProxyRealm          string   `json:"proxy_realm,omitempty"`
	ProxyHomeServer     string   `json:"proxy_home_server,omitempty"`
	ProxyHopCount       int      `json:"proxy_hop_count"`
	ProxyState          []string `json:"proxy_state,omitempty"`
	RequestCode         int      `json:"request_code"`
	ResponseCode        int      `json:"response_code,omitempty"`
	ErrorCause          int      `json:"error_cause,omitempty"`
	ErrorCauseName      string   `json:"error_cause_name,omitempty"`
	ReplyMessage        string   `json:"reply_message,omitempty"`
	LatencyMS           int64    `json:"latency_ms"`
	PacketIdentifier    int      `json:"packet_identifier"`
	RequestFingerprint  string   `json:"request_fingerprint"`
	ResponseFingerprint string   `json:"response_fingerprint,omitempty"`
	ErrorMessage        string   `json:"error_message,omitempty"`
	AttemptedAt         string   `json:"attempted_at"`
	NextAttemptAt       string   `json:"next_attempt_at,omitempty"`
}

type OutboundDACQueueAttemptUpdate struct {
	QueueID             string
	Result              string
	Status              string
	TargetAddress       string
	TargetPort          int
	TargetTransport     string
	DeliveryMode        string
	ProxyRoute          string
	ProxyRealm          string
	ProxyHomeServer     string
	ProxyHopCount       int
	ProxyState          []string
	RequestCode         int
	ResponseCode        int
	ErrorCause          int
	ErrorCauseName      string
	ReplyMessage        string
	LatencyMS           int64
	PacketIdentifier    int
	RequestFingerprint  string
	ResponseFingerprint string
	ErrorMessage        string
	AttemptedAt         time.Time
	NextAttemptAt       time.Time
}

type OutboundDACQueueSummary struct {
	TotalRecords     int    `json:"total_records"`
	QueuedCount      int    `json:"queued_count"`
	RetryingCount    int    `json:"retrying_count"`
	ACKCount         int    `json:"ack_count"`
	NAKCount         int    `json:"nak_count"`
	ErrorCount       int    `json:"error_count"`
	PoisonCount      int    `json:"poison_count"`
	ExpiredCount     int    `json:"expired_count"`
	CanceledCount    int    `json:"canceled_count"`
	DueCount         int    `json:"due_count"`
	AttemptCount     int    `json:"attempt_count"`
	OldestQueuedAt   string `json:"oldest_queued_at,omitempty"`
	NextAttemptAt    string `json:"next_attempt_at,omitempty"`
	LastACKAt        string `json:"last_ack_at,omitempty"`
	LastNAKAt        string `json:"last_nak_at,omitempty"`
	LastPoisonAt     string `json:"last_poison_at,omitempty"`
	LastAttemptAt    string `json:"last_attempt_at,omitempty"`
	LastError        string `json:"last_error,omitempty"`
	QueueCapacity    int    `json:"queue_capacity"`
	QueueUtilization int    `json:"queue_utilization_percent"`
}

func EnqueueOutboundDACQueue(create OutboundDACQueueCreate, maxQueueRecords int) (OutboundDACQueueRecord, bool, error) {
	if DB == nil {
		return OutboundDACQueueRecord{}, false, fmt.Errorf("database not initialized")
	}
	create = normalizeOutboundDACQueueCreate(create)
	if create.QueueID == "" || create.IdempotencyKey == "" || create.Action == "" || create.TargetAddress == "" ||
		create.TargetPort <= 0 || create.PayloadJSON == "" || create.PayloadSHA256 == "" || create.RequestCode == 0 ||
		create.RequestFingerprint == "" {
		return OutboundDACQueueRecord{}, false, fmt.Errorf("queue_id, idempotency_key, action, target, payload, request_code, and request_fingerprint are required")
	}
	if existing, err := GetOutboundDACQueueByIdempotencyKey(create.IdempotencyKey); err == nil && existing.ID != 0 {
		return existing, false, nil
	} else if err != nil && err != sql.ErrNoRows {
		return OutboundDACQueueRecord{}, false, err
	}
	if maxQueueRecords > 0 {
		var queued int
		if err := DB.QueryRow(`SELECT COUNT(*) FROM radius_outbound_dac_queue WHERE status IN (?, ?)`,
			OutboundDACQueueStatusQueued, OutboundDACQueueStatusRetrying).Scan(&queued); err != nil {
			return OutboundDACQueueRecord{}, false, fmt.Errorf("count outbound DAC queue: %w", err)
		}
		if queued >= maxQueueRecords {
			return OutboundDACQueueRecord{}, false, fmt.Errorf("outbound DAC queue is full (%d queued/retrying records)", queued)
		}
	}
	attrsJSON, err := json.Marshal(redactOutboundDACAttributesForHistory(create.Attributes))
	if err != nil {
		return OutboundDACQueueRecord{}, false, fmt.Errorf("encode outbound DAC queue attributes: %w", err)
	}
	proxyStateJSON, err := json.Marshal(normalizeOutboundDACProxyState(create.ProxyState))
	if err != nil {
		return OutboundDACQueueRecord{}, false, fmt.Errorf("encode outbound DAC queue proxy state: %w", err)
	}
	vendorPacksJSON, err := json.Marshal(normalizeOutboundDACStringList(create.VendorPacks, 16))
	if err != nil {
		return OutboundDACQueueRecord{}, false, fmt.Errorf("encode outbound DAC queue vendor packs: %w", err)
	}
	vendorWarningsJSON, err := json.Marshal(normalizeOutboundDACStringList(create.VendorCompilerWarnings, 32))
	if err != nil {
		return OutboundDACQueueRecord{}, false, fmt.Errorf("encode outbound DAC queue vendor compiler warnings: %w", err)
	}
	capabilityWarningsJSON, err := json.Marshal(normalizeOutboundDACStringList(create.CapabilityWarnings, 32))
	if err != nil {
		return OutboundDACQueueRecord{}, false, fmt.Errorf("encode outbound DAC queue capability warnings: %w", err)
	}
	handoffWarningsJSON, err := json.Marshal(normalizeOutboundDACStringList(create.HandoffWarnings, 32))
	if err != nil {
		return OutboundDACQueueRecord{}, false, fmt.Errorf("encode outbound DAC queue handoff warnings: %w", err)
	}
	now := time.Now().UTC()
	_, err = DB.Exec(`INSERT INTO radius_outbound_dac_queue (
		queue_id, idempotency_key, action, status, target_address, target_port, target_transport,
		delivery_mode, proxy_route, proxy_realm, proxy_home_server, proxy_hop_count, proxy_state_json,
		vendor_action, vendor_packs_json, vendor_compiler_status, vendor_compiler_warnings_json,
		ownership_session_id, ownership_status, ownership_source, ownership_owner_node, capability_decision, capability_warnings_json,
		handoff_decision, handoff_owner_node, handoff_lease_id, handoff_fencing_token, handoff_warnings_json,
		nas_identifier, nas_ip_address, nas_type, shortname, session_id, username_hash,
		calling_station_hash, framed_ip_address, attributes_json, payload_json, payload_sha256,
		request_code, correlation_id, requested_by, request_fingerprint, max_attempts,
		next_attempt_at, expires_at, idempotency_expires_at, owner_node, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		create.QueueID, create.IdempotencyKey, create.Action, create.Status, create.TargetAddress, create.TargetPort,
		create.TargetTransport, normalizeOutboundDACDeliveryMode(create.DeliveryMode), nullIfEmpty(create.ProxyRoute),
		nullIfEmpty(create.ProxyRealm), nullIfEmpty(create.ProxyHomeServer), create.ProxyHopCount, string(proxyStateJSON),
		nullIfEmpty(create.VendorAction), string(vendorPacksJSON), normalizeOutboundDACVendorCompilerStatus(create.VendorCompilerStatus), string(vendorWarningsJSON),
		nullIfEmpty(create.OwnershipSessionID), nullIfEmpty(create.OwnershipStatus), nullIfEmpty(create.OwnershipSource),
		nullIfEmpty(create.OwnershipOwnerNode), normalizeOutboundDACCapabilityDecision(create.CapabilityDecision), string(capabilityWarningsJSON),
		normalizeOutboundDACHandoffDecision(create.HandoffDecision), nullIfEmpty(create.HandoffOwnerNode), nullIfEmpty(create.HandoffLeaseID),
		nullIfEmpty(create.HandoffFencingToken), string(handoffWarningsJSON),
		nullIfEmpty(create.NASIdentifier), nullIfEmpty(create.NASIPAddress), nullIfEmpty(create.NASType),
		nullIfEmpty(create.ShortName), nullIfEmpty(create.SessionID), nullIfEmpty(HashEAPIdentity(create.Username)),
		nullIfEmpty(HashEAPIdentity(create.CallingStationID)), nullIfEmpty(create.FramedIPAddress), string(attrsJSON),
		create.PayloadJSON, create.PayloadSHA256, create.RequestCode, create.CorrelationID, nullIfEmpty(create.RequestedBy),
		create.RequestFingerprint, create.MaxAttempts, formatSpoolTime(create.NextAttemptAt), formatSpoolTime(create.ExpiresAt),
		formatSpoolTime(create.IdempotencyExpiresAt), nullIfEmpty(create.OwnerNode), formatSpoolTime(now), formatSpoolTime(now))
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			existing, getErr := GetOutboundDACQueueByIdempotencyKey(create.IdempotencyKey)
			return existing, false, getErr
		}
		return OutboundDACQueueRecord{}, false, fmt.Errorf("enqueue outbound DAC queue: %w", err)
	}
	record, err := GetOutboundDACQueueByQueueID(create.QueueID)
	return record, true, err
}

func GetOutboundDACQueueByQueueID(queueID string) (OutboundDACQueueRecord, error) {
	if DB == nil {
		return OutboundDACQueueRecord{}, fmt.Errorf("database not initialized")
	}
	return getOutboundDACQueueRecord("queue_id", strings.TrimSpace(queueID))
}

func GetOutboundDACQueueByIdempotencyKey(idempotencyKey string) (OutboundDACQueueRecord, error) {
	if DB == nil {
		return OutboundDACQueueRecord{}, fmt.Errorf("database not initialized")
	}
	return getOutboundDACQueueRecord("idempotency_key", strings.TrimSpace(idempotencyKey))
}

func ClaimOutboundDACQueue(batchSize int, ownerNode string, now time.Time, lockFor time.Duration) ([]OutboundDACQueueRecord, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	if batchSize <= 0 {
		batchSize = 50
	}
	if lockFor <= 0 {
		lockFor = time.Minute
	}
	now = now.UTC()
	lockUntil := now.Add(lockFor)
	tx, err := DB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	rows, err := tx.Query(`SELECT id FROM radius_outbound_dac_queue
		WHERE status IN (?, ?)
		  AND datetime(next_attempt_at) <= datetime(?)
		  AND datetime(expires_at) > datetime(?)
		  AND (locked_until IS NULL OR locked_until = '' OR datetime(locked_until) <= datetime(?))
		ORDER BY datetime(next_attempt_at), id
		LIMIT ?`, OutboundDACQueueStatusQueued, OutboundDACQueueStatusRetrying, formatSpoolTime(now), formatSpoolTime(now), formatSpoolTime(now), batchSize)
	if err != nil {
		return nil, fmt.Errorf("select outbound DAC queue claims: %w", err)
	}
	ids := []any{}
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	if len(ids) == 0 {
		return nil, tx.Commit()
	}
	placeholders := strings.TrimRight(strings.Repeat("?,", len(ids)), ",")
	args := []any{OutboundDACQueueStatusRetrying, strings.TrimSpace(ownerNode), formatSpoolTime(lockUntil), formatSpoolTime(now)}
	args = append(args, ids...)
	if _, err := tx.Exec(`UPDATE radius_outbound_dac_queue
		SET status = ?, owner_node = ?, locked_until = ?, updated_at = ?
		WHERE id IN (`+placeholders+`)`, args...); err != nil {
		return nil, fmt.Errorf("claim outbound DAC queue records: %w", err)
	}
	claimedRows, err := tx.Query(outboundDACQueueSelectSQL()+` WHERE id IN (`+placeholders+`) ORDER BY datetime(next_attempt_at), id`, ids...)
	if err != nil {
		return nil, fmt.Errorf("load claimed outbound DAC queue records: %w", err)
	}
	records, err := scanOutboundDACQueueRows(claimedRows)
	claimedRows.Close()
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return records, nil
}

func CompleteOutboundDACQueueAttempt(record OutboundDACQueueRecord, update OutboundDACQueueAttemptUpdate) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	if record.ID == 0 {
		return fmt.Errorf("outbound DAC queue record is required")
	}
	update.QueueID = strings.TrimSpace(update.QueueID)
	if update.QueueID == "" {
		update.QueueID = record.QueueID
	}
	update.Result = normalizeOutboundDACQueueAttemptResult(update.Result)
	update.Status = normalizeOutboundDACQueueStatus(update.Status)
	if update.Result == "" || update.Status == "" {
		return fmt.Errorf("result and status are required")
	}
	if update.AttemptedAt.IsZero() {
		update.AttemptedAt = time.Now().UTC()
	}
	update.DeliveryMode = normalizeOutboundDACDeliveryMode(firstNonEmptyString(update.DeliveryMode, record.DeliveryMode))
	if update.ProxyRoute == "" {
		update.ProxyRoute = record.ProxyRoute
	}
	if update.ProxyRealm == "" {
		update.ProxyRealm = record.ProxyRealm
	}
	if update.ProxyHomeServer == "" {
		update.ProxyHomeServer = record.ProxyHomeServer
	}
	if update.ProxyHopCount == 0 {
		update.ProxyHopCount = record.ProxyHopCount
	}
	if len(update.ProxyState) == 0 {
		update.ProxyState = record.ProxyState
	}
	proxyStateJSON, err := json.Marshal(normalizeOutboundDACProxyState(update.ProxyState))
	if err != nil {
		return fmt.Errorf("encode outbound DAC queue attempt proxy state: %w", err)
	}
	attemptNumber := record.AttemptCount + 1
	nextAttempt := ""
	if !update.NextAttemptAt.IsZero() {
		nextAttempt = formatSpoolTime(update.NextAttemptAt)
	}
	sentAt := any(nil)
	completedAt := any(nil)
	if update.Status == OutboundDACQueueStatusACK || update.Status == OutboundDACQueueStatusNAK ||
		update.Status == OutboundDACQueueStatusError || update.Status == OutboundDACQueueStatusPoison {
		completedAt = formatSpoolTime(update.AttemptedAt)
	}
	if update.Status == OutboundDACQueueStatusACK || update.Status == OutboundDACQueueStatusNAK {
		sentAt = formatSpoolTime(update.AttemptedAt)
	}
	tx, err := DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO radius_outbound_dac_queue_attempts (
		queue_id, attempt_number, result, status, target_address, target_port, target_transport,
		delivery_mode, proxy_route, proxy_realm, proxy_home_server, proxy_hop_count, proxy_state_json,
		request_code, response_code, error_cause, error_cause_name, reply_message, latency_ms,
		packet_identifier, request_fingerprint, response_fingerprint, error_message, attempted_at, next_attempt_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		update.QueueID, attemptNumber, update.Result, update.Status, strings.TrimSpace(update.TargetAddress), update.TargetPort,
		normalizeOutboundDACTransport(update.TargetTransport), update.DeliveryMode, nullIfEmpty(update.ProxyRoute),
		nullIfEmpty(update.ProxyRealm), nullIfEmpty(update.ProxyHomeServer), update.ProxyHopCount, string(proxyStateJSON),
		update.RequestCode, nullIntIfZero(update.ResponseCode),
		nullIntIfZero(update.ErrorCause), nullIfEmpty(update.ErrorCauseName), nullIfEmpty(update.ReplyMessage),
		update.LatencyMS, update.PacketIdentifier, update.RequestFingerprint, nullIfEmpty(update.ResponseFingerprint),
		nullIfEmpty(update.ErrorMessage), formatSpoolTime(update.AttemptedAt), nullIfEmpty(nextAttempt)); err != nil {
		return fmt.Errorf("insert outbound DAC queue attempt: %w", err)
	}
	if _, err := tx.Exec(`UPDATE radius_outbound_dac_queue
		SET status = ?, attempt_count = ?, last_error = ?, last_response_code = ?, last_error_cause = ?,
		    last_error_cause_name = ?, last_reply_message = ?, last_latency_ms = ?, last_attempt_at = ?,
		    next_attempt_at = ?, locked_until = NULL, sent_at = COALESCE(?, sent_at),
		    completed_at = COALESCE(?, completed_at), updated_at = ?
		WHERE id = ?`,
		update.Status, attemptNumber, nullIfEmpty(update.ErrorMessage), nullIntIfZero(update.ResponseCode),
		nullIntIfZero(update.ErrorCause), nullIfEmpty(update.ErrorCauseName), nullIfEmpty(update.ReplyMessage),
		update.LatencyMS, formatSpoolTime(update.AttemptedAt), nullIfEmpty(nextAttempt), sentAt, completedAt,
		formatSpoolTime(update.AttemptedAt), record.ID); err != nil {
		return fmt.Errorf("update outbound DAC queue attempt: %w", err)
	}
	return tx.Commit()
}

func ExpireDueOutboundDACQueue(now time.Time) (int, error) {
	if DB == nil {
		return 0, fmt.Errorf("database not initialized")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	res, err := DB.Exec(`UPDATE radius_outbound_dac_queue
		SET status = ?, locked_until = NULL, completed_at = ?, updated_at = ?
		WHERE status IN (?, ?)
		  AND datetime(expires_at) <= datetime(?)`,
		OutboundDACQueueStatusExpired, formatSpoolTime(now), formatSpoolTime(now),
		OutboundDACQueueStatusQueued, OutboundDACQueueStatusRetrying, formatSpoolTime(now))
	if err != nil {
		return 0, fmt.Errorf("expire outbound DAC queue records: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func CancelOutboundDACQueue(queueID, canceledBy, reason string, now time.Time) (OutboundDACQueueRecord, error) {
	if DB == nil {
		return OutboundDACQueueRecord{}, fmt.Errorf("database not initialized")
	}
	queueID = strings.TrimSpace(queueID)
	if queueID == "" {
		return OutboundDACQueueRecord{}, fmt.Errorf("queue_id is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	res, err := DB.Exec(`UPDATE radius_outbound_dac_queue
		SET status = ?, locked_until = NULL, canceled_at = ?, canceled_by = ?, cancel_reason = ?,
		    completed_at = ?, updated_at = ?
		WHERE queue_id = ? AND status IN (?, ?)`,
		OutboundDACQueueStatusCanceled, formatSpoolTime(now), nullIfEmpty(canceledBy), nullIfEmpty(reason),
		formatSpoolTime(now), formatSpoolTime(now), queueID, OutboundDACQueueStatusQueued, OutboundDACQueueStatusRetrying)
	if err != nil {
		return OutboundDACQueueRecord{}, fmt.Errorf("cancel outbound DAC queue record: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return OutboundDACQueueRecord{}, fmt.Errorf("outbound DAC queue record %q is not cancelable", queueID)
	}
	record, err := GetOutboundDACQueueByQueueID(queueID)
	if err == nil {
		if attemptErr := recordOutboundDACQueueOperatorAttempt(record, OutboundDACQueueAttemptCanceled, OutboundDACQueueStatusCanceled, reason, now); attemptErr != nil {
			return record, attemptErr
		}
	}
	return record, err
}

func RequeueOutboundDACQueue(queueID string, nextAttemptAt, expiresAt, idempotencyExpiresAt time.Time, ownerNode string) (OutboundDACQueueRecord, error) {
	if DB == nil {
		return OutboundDACQueueRecord{}, fmt.Errorf("database not initialized")
	}
	queueID = strings.TrimSpace(queueID)
	if queueID == "" {
		return OutboundDACQueueRecord{}, fmt.Errorf("queue_id is required")
	}
	if nextAttemptAt.IsZero() {
		nextAttemptAt = time.Now().UTC()
	}
	if expiresAt.IsZero() {
		expiresAt = nextAttemptAt.Add(time.Hour)
	}
	if idempotencyExpiresAt.IsZero() {
		idempotencyExpiresAt = expiresAt
	}
	res, err := DB.Exec(`UPDATE radius_outbound_dac_queue
		SET status = ?, attempt_count = 0, last_error = NULL, last_response_code = NULL,
		    last_error_cause = NULL, last_error_cause_name = NULL, last_reply_message = NULL,
		    locked_until = NULL, next_attempt_at = ?, completed_at = NULL, canceled_at = NULL,
		    canceled_by = NULL, cancel_reason = NULL, expires_at = ?, idempotency_expires_at = ?,
		    owner_node = ?, updated_at = ?
		WHERE queue_id = ? AND status IN (?, ?, ?, ?, ?)`,
		OutboundDACQueueStatusQueued, formatSpoolTime(nextAttemptAt), formatSpoolTime(expiresAt),
		formatSpoolTime(idempotencyExpiresAt), nullIfEmpty(ownerNode), formatSpoolTime(nextAttemptAt),
		queueID, OutboundDACQueueStatusNAK, OutboundDACQueueStatusError,
		OutboundDACQueueStatusPoison, OutboundDACQueueStatusExpired, OutboundDACQueueStatusCanceled)
	if err != nil {
		return OutboundDACQueueRecord{}, fmt.Errorf("retry outbound DAC queue record: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return OutboundDACQueueRecord{}, fmt.Errorf("outbound DAC queue record %q is not retryable", queueID)
	}
	return GetOutboundDACQueueByQueueID(queueID)
}

func UpdateOutboundDACQueueHandoff(queueID, decision, ownerNode, leaseID, fencingToken string, warnings []string) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	queueID = strings.TrimSpace(queueID)
	if queueID == "" {
		return fmt.Errorf("queue_id is required")
	}
	warningsJSON, err := json.Marshal(normalizeOutboundDACStringList(warnings, 32))
	if err != nil {
		return fmt.Errorf("encode outbound DAC queue handoff warnings: %w", err)
	}
	_, err = DB.Exec(`UPDATE radius_outbound_dac_queue
		SET handoff_decision = ?, handoff_owner_node = ?, handoff_lease_id = ?,
		    handoff_fencing_token = ?, handoff_warnings_json = ?, updated_at = ?
		WHERE queue_id = ?`,
		normalizeOutboundDACHandoffDecision(decision), nullIfEmpty(ownerNode), nullIfEmpty(leaseID),
		nullIfEmpty(fencingToken), string(warningsJSON), formatSpoolTime(time.Now().UTC()), queueID)
	if err != nil {
		return fmt.Errorf("update outbound DAC queue handoff: %w", err)
	}
	return nil
}

func ListOutboundDACQueue(status string, limit int) ([]OutboundDACQueueRecord, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	status = normalizeOutboundDACQueueStatus(status)
	args := []any{}
	query := outboundDACQueueSelectSQL()
	if status != "" {
		query += ` WHERE status = ?`
		args = append(args, status)
	}
	query += ` ORDER BY CASE status WHEN 'queued' THEN 0 WHEN 'retrying' THEN 1 WHEN 'poison' THEN 2 WHEN 'error' THEN 3 WHEN 'expired' THEN 4 ELSE 5 END,
		datetime(next_attempt_at), id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := DB.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list outbound DAC queue records: %w", err)
	}
	defer rows.Close()
	return scanOutboundDACQueueRows(rows)
}

func ListOutboundDACQueueAttempts(queueID string, limit int) ([]OutboundDACQueueAttemptRecord, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	queueID = strings.TrimSpace(queueID)
	args := []any{}
	query := `SELECT id, queue_id, attempt_number, result, status, target_address, target_port,
		target_transport, COALESCE(delivery_mode, 'direct'), COALESCE(proxy_route, ''),
		COALESCE(proxy_realm, ''), COALESCE(proxy_home_server, ''), COALESCE(proxy_hop_count, 0),
		COALESCE(proxy_state_json, '[]'), request_code, COALESCE(response_code, 0), COALESCE(error_cause, 0),
		COALESCE(error_cause_name, ''), COALESCE(reply_message, ''), latency_ms, packet_identifier,
		request_fingerprint, COALESCE(response_fingerprint, ''), COALESCE(error_message, ''),
		attempted_at, COALESCE(next_attempt_at, '')
		FROM radius_outbound_dac_queue_attempts`
	if queueID != "" {
		query += ` WHERE queue_id = ?`
		args = append(args, queueID)
	}
	query += ` ORDER BY datetime(attempted_at) DESC, id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := DB.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list outbound DAC queue attempts: %w", err)
	}
	defer rows.Close()
	attempts := []OutboundDACQueueAttemptRecord{}
	for rows.Next() {
		var item OutboundDACQueueAttemptRecord
		var proxyStateJSON string
		if err := rows.Scan(&item.ID, &item.QueueID, &item.AttemptNumber, &item.Result, &item.Status,
			&item.TargetAddress, &item.TargetPort, &item.TargetTransport, &item.DeliveryMode, &item.ProxyRoute,
			&item.ProxyRealm, &item.ProxyHomeServer, &item.ProxyHopCount, &proxyStateJSON, &item.RequestCode,
			&item.ResponseCode, &item.ErrorCause, &item.ErrorCauseName, &item.ReplyMessage, &item.LatencyMS, &item.PacketIdentifier,
			&item.RequestFingerprint, &item.ResponseFingerprint, &item.ErrorMessage, &item.AttemptedAt,
			&item.NextAttemptAt); err != nil {
			return nil, fmt.Errorf("scan outbound DAC queue attempt: %w", err)
		}
		_ = json.Unmarshal([]byte(proxyStateJSON), &item.ProxyState)
		attempts = append(attempts, item)
	}
	return attempts, rows.Err()
}

func GetOutboundDACQueueSummary(maxQueueRecords int) (OutboundDACQueueSummary, error) {
	summary := OutboundDACQueueSummary{QueueCapacity: maxQueueRecords}
	if DB == nil {
		return summary, nil
	}
	now := formatSpoolTime(time.Now().UTC())
	err := DB.QueryRow(`SELECT
		COUNT(*),
		COALESCE(SUM(CASE WHEN status = 'queued' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'retrying' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'ack' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'nak' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'poison' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'expired' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'canceled' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status IN ('queued', 'retrying') AND datetime(next_attempt_at) <= datetime(?) THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(attempt_count), 0),
		COALESCE(MIN(CASE WHEN status IN ('queued', 'retrying') THEN created_at END), ''),
		COALESCE(MIN(CASE WHEN status IN ('queued', 'retrying') THEN next_attempt_at END), ''),
		COALESCE(MAX(CASE WHEN status = 'ack' THEN completed_at END), ''),
		COALESCE(MAX(CASE WHEN status = 'nak' THEN completed_at END), ''),
		COALESCE(MAX(CASE WHEN status = 'poison' THEN updated_at END), ''),
		COALESCE(MAX(last_attempt_at), ''),
		COALESCE(MAX(CASE WHEN last_error IS NOT NULL AND last_error <> '' THEN last_error END), '')
		FROM radius_outbound_dac_queue`, now).Scan(
		&summary.TotalRecords, &summary.QueuedCount, &summary.RetryingCount, &summary.ACKCount,
		&summary.NAKCount, &summary.ErrorCount, &summary.PoisonCount, &summary.ExpiredCount,
		&summary.CanceledCount, &summary.DueCount, &summary.AttemptCount, &summary.OldestQueuedAt,
		&summary.NextAttemptAt, &summary.LastACKAt, &summary.LastNAKAt, &summary.LastPoisonAt,
		&summary.LastAttemptAt, &summary.LastError)
	if err != nil {
		if tableMissing(err) {
			return summary, nil
		}
		return summary, fmt.Errorf("get outbound DAC queue summary: %w", err)
	}
	if maxQueueRecords > 0 {
		active := summary.QueuedCount + summary.RetryingCount
		summary.QueueUtilization = int((int64(active) * 100) / int64(maxQueueRecords))
	}
	return summary, nil
}

func PruneOutboundDACQueue(ackRetention, deadLetterRetention time.Duration, now time.Time) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if ackRetention <= 0 {
		ackRetention = 24 * time.Hour
	}
	if deadLetterRetention <= 0 {
		deadLetterRetention = 30 * 24 * time.Hour
	}
	ackCutoff := formatSpoolTime(now.Add(-ackRetention))
	deadCutoff := formatSpoolTime(now.Add(-deadLetterRetention))
	if _, err := DB.Exec(`DELETE FROM radius_outbound_dac_queue_attempts
		WHERE queue_id IN (
			SELECT queue_id FROM radius_outbound_dac_queue
			WHERE (status = ? AND datetime(COALESCE(completed_at, updated_at)) < datetime(?))
			   OR (status IN (?, ?, ?, ?, ?) AND datetime(updated_at) < datetime(?))
		)`, OutboundDACQueueStatusACK, ackCutoff, OutboundDACQueueStatusNAK, OutboundDACQueueStatusError,
		OutboundDACQueueStatusPoison, OutboundDACQueueStatusExpired, OutboundDACQueueStatusCanceled, deadCutoff); err != nil {
		return fmt.Errorf("prune outbound DAC queue attempts: %w", err)
	}
	if _, err := DB.Exec(`DELETE FROM radius_outbound_dac_queue
		WHERE (status = ? AND datetime(COALESCE(completed_at, updated_at)) < datetime(?))
		   OR (status IN (?, ?, ?, ?, ?) AND datetime(updated_at) < datetime(?))`,
		OutboundDACQueueStatusACK, ackCutoff, OutboundDACQueueStatusNAK, OutboundDACQueueStatusError,
		OutboundDACQueueStatusPoison, OutboundDACQueueStatusExpired, OutboundDACQueueStatusCanceled, deadCutoff); err != nil {
		return fmt.Errorf("prune outbound DAC queue: %w", err)
	}
	return nil
}

func getOutboundDACQueueRecord(column, value string) (OutboundDACQueueRecord, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return OutboundDACQueueRecord{}, sql.ErrNoRows
	}
	rows, err := DB.Query(outboundDACQueueSelectSQL()+` WHERE `+column+` = ? LIMIT 1`, value)
	if err != nil {
		return OutboundDACQueueRecord{}, err
	}
	defer rows.Close()
	records, err := scanOutboundDACQueueRows(rows)
	if err != nil {
		return OutboundDACQueueRecord{}, err
	}
	if len(records) == 0 {
		return OutboundDACQueueRecord{}, sql.ErrNoRows
	}
	return records[0], nil
}

func normalizeOutboundDACQueueCreate(create OutboundDACQueueCreate) OutboundDACQueueCreate {
	create.QueueID = strings.TrimSpace(create.QueueID)
	create.IdempotencyKey = strings.TrimSpace(create.IdempotencyKey)
	create.Action = normalizeOutboundDACAction(create.Action)
	create.Status = normalizeOutboundDACQueueStatus(create.Status)
	if create.Status == "" {
		create.Status = OutboundDACQueueStatusQueued
	}
	create.TargetAddress = strings.TrimSpace(create.TargetAddress)
	create.TargetTransport = normalizeOutboundDACTransport(create.TargetTransport)
	create.DeliveryMode = normalizeOutboundDACDeliveryMode(create.DeliveryMode)
	create.ProxyRoute = strings.TrimSpace(create.ProxyRoute)
	create.ProxyRealm = strings.TrimSpace(create.ProxyRealm)
	create.ProxyHomeServer = strings.TrimSpace(create.ProxyHomeServer)
	create.ProxyState = normalizeOutboundDACProxyState(create.ProxyState)
	create.VendorAction = strings.TrimSpace(strings.ToLower(create.VendorAction))
	create.VendorPacks = normalizeOutboundDACStringList(create.VendorPacks, 16)
	create.VendorCompilerStatus = normalizeOutboundDACVendorCompilerStatus(create.VendorCompilerStatus)
	create.VendorCompilerWarnings = normalizeOutboundDACStringList(create.VendorCompilerWarnings, 32)
	create.OwnershipSessionID = strings.TrimSpace(create.OwnershipSessionID)
	create.OwnershipStatus = normalizeOutboundDACOwnershipStatus(create.OwnershipStatus)
	create.OwnershipSource = strings.TrimSpace(create.OwnershipSource)
	create.OwnershipOwnerNode = strings.TrimSpace(create.OwnershipOwnerNode)
	create.CapabilityDecision = normalizeOutboundDACCapabilityDecision(create.CapabilityDecision)
	create.CapabilityWarnings = normalizeOutboundDACStringList(create.CapabilityWarnings, 32)
	create.HandoffDecision = normalizeOutboundDACHandoffDecision(create.HandoffDecision)
	create.HandoffOwnerNode = strings.TrimSpace(create.HandoffOwnerNode)
	create.HandoffLeaseID = strings.TrimSpace(create.HandoffLeaseID)
	create.HandoffFencingToken = strings.TrimSpace(create.HandoffFencingToken)
	create.HandoffWarnings = normalizeOutboundDACStringList(create.HandoffWarnings, 32)
	create.NASIdentifier = strings.TrimSpace(create.NASIdentifier)
	create.NASIPAddress = strings.TrimSpace(create.NASIPAddress)
	create.NASType = strings.TrimSpace(strings.ToLower(create.NASType))
	create.ShortName = strings.TrimSpace(create.ShortName)
	create.SessionID = strings.TrimSpace(create.SessionID)
	create.Username = strings.TrimSpace(create.Username)
	create.CallingStationID = strings.TrimSpace(create.CallingStationID)
	create.FramedIPAddress = strings.TrimSpace(create.FramedIPAddress)
	create.CorrelationID = strings.TrimSpace(create.CorrelationID)
	if create.CorrelationID == "" {
		create.CorrelationID = create.QueueID
	}
	create.RequestedBy = strings.TrimSpace(create.RequestedBy)
	create.PayloadJSON = strings.TrimSpace(create.PayloadJSON)
	create.PayloadSHA256 = strings.TrimSpace(create.PayloadSHA256)
	create.RequestFingerprint = strings.TrimSpace(create.RequestFingerprint)
	if create.MaxAttempts <= 0 {
		create.MaxAttempts = 1
	}
	now := time.Now().UTC()
	if create.NextAttemptAt.IsZero() {
		create.NextAttemptAt = now
	}
	if create.ExpiresAt.IsZero() {
		create.ExpiresAt = now.Add(time.Hour)
	}
	if create.IdempotencyExpiresAt.IsZero() {
		create.IdempotencyExpiresAt = create.ExpiresAt
	}
	create.OwnerNode = strings.TrimSpace(create.OwnerNode)
	return create
}

func normalizeOutboundDACQueueStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case OutboundDACQueueStatusQueued, OutboundDACQueueStatusRetrying, OutboundDACQueueStatusACK, OutboundDACQueueStatusNAK,
		OutboundDACQueueStatusError, OutboundDACQueueStatusPoison, OutboundDACQueueStatusExpired, OutboundDACQueueStatusCanceled:
		return strings.ToLower(strings.TrimSpace(status))
	default:
		return strings.ToLower(strings.TrimSpace(status))
	}
}

func normalizeOutboundDACQueueAttemptResult(result string) string {
	switch strings.ToLower(strings.TrimSpace(result)) {
	case OutboundDACQueueAttemptACK, OutboundDACQueueAttemptNAK, OutboundDACQueueAttemptFailed,
		OutboundDACQueueAttemptPoison, OutboundDACQueueAttemptExpired, OutboundDACQueueAttemptCanceled:
		return strings.ToLower(strings.TrimSpace(result))
	default:
		return strings.ToLower(strings.TrimSpace(result))
	}
}

func outboundDACQueueSelectSQL() string {
	return `SELECT id, queue_id, idempotency_key, action, status, target_address, target_port, target_transport,
		COALESCE(delivery_mode, 'direct'), COALESCE(proxy_route, ''), COALESCE(proxy_realm, ''),
		COALESCE(proxy_home_server, ''), COALESCE(proxy_hop_count, 0), COALESCE(proxy_state_json, '[]'),
		COALESCE(vendor_action, ''), COALESCE(vendor_packs_json, '[]'),
		COALESCE(vendor_compiler_status, 'not_requested'), COALESCE(vendor_compiler_warnings_json, '[]'),
		COALESCE(ownership_session_id, ''), COALESCE(ownership_status, ''), COALESCE(ownership_source, ''),
		COALESCE(ownership_owner_node, ''), COALESCE(capability_decision, 'not_evaluated'), COALESCE(capability_warnings_json, '[]'),
		COALESCE(handoff_decision, 'not_evaluated'), COALESCE(handoff_owner_node, ''), COALESCE(handoff_lease_id, ''),
		COALESCE(handoff_fencing_token, ''), COALESCE(handoff_warnings_json, '[]'),
		COALESCE(nas_identifier, ''), COALESCE(nas_ip_address, ''), COALESCE(nas_type, ''),
		COALESCE(shortname, ''), COALESCE(session_id, ''), COALESCE(username_hash, ''),
		COALESCE(calling_station_hash, ''), COALESCE(framed_ip_address, ''), attributes_json,
		payload_json, payload_sha256, request_code, correlation_id, COALESCE(requested_by, ''),
		request_fingerprint, attempt_count, max_attempts, COALESCE(last_error, ''),
		COALESCE(last_response_code, 0), COALESCE(last_error_cause, 0),
		COALESCE(last_error_cause_name, ''), COALESCE(last_reply_message, ''),
		last_latency_ms, COALESCE(next_attempt_at, ''), expires_at, idempotency_expires_at,
		COALESCE(owner_node, ''), COALESCE(locked_until, ''), COALESCE(sent_at, ''),
		COALESCE(completed_at, ''), COALESCE(canceled_at, ''), COALESCE(canceled_by, ''),
		COALESCE(cancel_reason, ''), created_at, updated_at
		FROM radius_outbound_dac_queue`
}

func scanOutboundDACQueueRows(rows *sql.Rows) ([]OutboundDACQueueRecord, error) {
	records := []OutboundDACQueueRecord{}
	for rows.Next() {
		var (
			record              OutboundDACQueueRecord
			attrsJSON           string
			proxyStateJSON      string
			vendorPacksJSON     string
			vendorWarningsJSON  string
			capWarningsJSON     string
			handoffWarningsJSON string
		)
		if err := rows.Scan(&record.ID, &record.QueueID, &record.IdempotencyKey, &record.Action,
			&record.Status, &record.TargetAddress, &record.TargetPort, &record.TargetTransport,
			&record.DeliveryMode, &record.ProxyRoute, &record.ProxyRealm, &record.ProxyHomeServer,
			&record.ProxyHopCount, &proxyStateJSON, &record.VendorAction, &vendorPacksJSON,
			&record.VendorCompilerStatus, &vendorWarningsJSON, &record.OwnershipSessionID, &record.OwnershipStatus,
			&record.OwnershipSource, &record.OwnershipOwnerNode, &record.CapabilityDecision, &capWarningsJSON,
			&record.HandoffDecision, &record.HandoffOwnerNode, &record.HandoffLeaseID, &record.HandoffFencingToken, &handoffWarningsJSON,
			&record.NASIdentifier, &record.NASIPAddress, &record.NASType, &record.ShortName,
			&record.SessionID, &record.UsernameHash, &record.CallingStationHash, &record.FramedIPAddress,
			&attrsJSON, &record.PayloadJSON, &record.PayloadSHA256, &record.RequestCode, &record.CorrelationID,
			&record.RequestedBy, &record.RequestFingerprint, &record.AttemptCount, &record.MaxAttempts,
			&record.LastError, &record.LastResponseCode, &record.LastErrorCause, &record.LastErrorCauseName,
			&record.LastReplyMessage, &record.LastLatencyMS, &record.NextAttemptAt, &record.ExpiresAt,
			&record.IdempotencyExpiresAt, &record.OwnerNode, &record.LockedUntil, &record.SentAt,
			&record.CompletedAt, &record.CanceledAt, &record.CanceledBy, &record.CancelReason,
			&record.CreatedAt, &record.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan outbound DAC queue record: %w", err)
		}
		_ = json.Unmarshal([]byte(attrsJSON), &record.Attributes)
		_ = json.Unmarshal([]byte(proxyStateJSON), &record.ProxyState)
		_ = json.Unmarshal([]byte(vendorPacksJSON), &record.VendorPacks)
		_ = json.Unmarshal([]byte(vendorWarningsJSON), &record.VendorCompilerWarnings)
		_ = json.Unmarshal([]byte(capWarningsJSON), &record.CapabilityWarnings)
		_ = json.Unmarshal([]byte(handoffWarningsJSON), &record.HandoffWarnings)
		records = append(records, record)
	}
	return records, rows.Err()
}

func recordOutboundDACQueueOperatorAttempt(record OutboundDACQueueRecord, result, status, message string, now time.Time) error {
	return CompleteOutboundDACQueueAttempt(record, OutboundDACQueueAttemptUpdate{
		QueueID:            record.QueueID,
		Result:             result,
		Status:             status,
		TargetAddress:      record.TargetAddress,
		TargetPort:         record.TargetPort,
		TargetTransport:    record.TargetTransport,
		RequestCode:        record.RequestCode,
		RequestFingerprint: record.RequestFingerprint,
		ErrorMessage:       strings.TrimSpace(message),
		AttemptedAt:        now,
	})
}
