package db

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type outboundDACRows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
}

const (
	OutboundDACStatusPreviewed = "previewed"
	OutboundDACStatusSent      = "sent"
	OutboundDACStatusACK       = "ack"
	OutboundDACStatusNAK       = "nak"
	OutboundDACStatusError     = "error"
	OutboundDACStatusBlocked   = "blocked"
)

type OutboundDACAttribute struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type OutboundDACRequestRecord struct {
	ID                   int                    `json:"id"`
	RequestID            string                 `json:"request_id"`
	Action               string                 `json:"action"`
	Status               string                 `json:"status"`
	TargetAddress        string                 `json:"target_address"`
	TargetPort           int                    `json:"target_port"`
	TargetTransport      string                 `json:"target_transport"`
	NASIdentifier        string                 `json:"nas_identifier,omitempty"`
	NASIPAddress         string                 `json:"nas_ip_address,omitempty"`
	NASType              string                 `json:"nas_type,omitempty"`
	ShortName            string                 `json:"shortname,omitempty"`
	SessionID            string                 `json:"session_id,omitempty"`
	UsernameHash         string                 `json:"username_hash,omitempty"`
	CallingStationHash   string                 `json:"calling_station_hash,omitempty"`
	FramedIPAddress      string                 `json:"framed_ip_address,omitempty"`
	Attributes           []OutboundDACAttribute `json:"attributes,omitempty"`
	RequestCode          int                    `json:"request_code"`
	ResponseCode         int                    `json:"response_code,omitempty"`
	ErrorCause           int                    `json:"error_cause,omitempty"`
	ErrorCauseName       string                 `json:"error_cause_name,omitempty"`
	ReplyMessage         string                 `json:"reply_message,omitempty"`
	CorrelationID        string                 `json:"correlation_id"`
	RequestedBy          string                 `json:"requested_by,omitempty"`
	RequestedAt          string                 `json:"requested_at"`
	SentAt               string                 `json:"sent_at,omitempty"`
	CompletedAt          string                 `json:"completed_at,omitempty"`
	LatencyMS            int64                  `json:"latency_ms"`
	FailureReason        string                 `json:"failure_reason,omitempty"`
	MessageAuthenticator bool                   `json:"message_authenticator"`
	RequestFingerprint   string                 `json:"request_fingerprint"`
	ResponseFingerprint  string                 `json:"response_fingerprint,omitempty"`
	CreatedAt            string                 `json:"created_at,omitempty"`
	UpdatedAt            string                 `json:"updated_at,omitempty"`
}

type OutboundDACAttemptRecord struct {
	ID                  int    `json:"id"`
	RequestID           string `json:"request_id"`
	Attempt             int    `json:"attempt"`
	Status              string `json:"status"`
	TargetAddress       string `json:"target_address"`
	TargetPort          int    `json:"target_port"`
	TargetTransport     string `json:"target_transport"`
	RequestCode         int    `json:"request_code"`
	ResponseCode        int    `json:"response_code,omitempty"`
	ErrorCause          int    `json:"error_cause,omitempty"`
	ErrorCauseName      string `json:"error_cause_name,omitempty"`
	ReplyMessage        string `json:"reply_message,omitempty"`
	LatencyMS           int64  `json:"latency_ms"`
	PacketIdentifier    int    `json:"packet_identifier"`
	RequestFingerprint  string `json:"request_fingerprint"`
	ResponseFingerprint string `json:"response_fingerprint,omitempty"`
	ErrorMessage        string `json:"error_message,omitempty"`
	CreatedAt           string `json:"created_at,omitempty"`
}

type OutboundDACSummary struct {
	TotalRequests       int    `json:"total_requests"`
	ACKCount            int    `json:"ack_count"`
	NAKCount            int    `json:"nak_count"`
	ErrorCount          int    `json:"error_count"`
	BlockedCount        int    `json:"blocked_count"`
	SentCount           int    `json:"sent_count"`
	AttemptCount        int    `json:"attempt_count"`
	LastRequestAt       string `json:"last_request_at,omitempty"`
	LastCompletedAt     string `json:"last_completed_at,omitempty"`
	LastFailureReason   string `json:"last_failure_reason,omitempty"`
	HistoryRetentionMax int    `json:"history_retention_max"`
}

type OutboundDACTargetHint struct {
	SessionID        string
	AcctSessionID    string
	Username         string
	CallingStationID string
	FramedIPAddress  string
	NASIdentifier    string
}

type OutboundDACRequestQuery struct {
	Status        string
	Action        string
	TargetAddress string
	SessionID     string
	Limit         int
}

type OutboundDACCreate struct {
	RequestID            string
	Action               string
	Status               string
	TargetAddress        string
	TargetPort           int
	TargetTransport      string
	NASIdentifier        string
	NASIPAddress         string
	NASType              string
	ShortName            string
	SessionID            string
	Username             string
	CallingStationID     string
	FramedIPAddress      string
	Attributes           []OutboundDACAttribute
	RequestCode          int
	CorrelationID        string
	RequestedBy          string
	MessageAuthenticator bool
	RequestFingerprint   string
	RequestedAt          time.Time
	SentAt               time.Time
	FailureReason        string
}

type OutboundDACComplete struct {
	RequestID           string
	Status              string
	ResponseCode        int
	ErrorCause          int
	ErrorCauseName      string
	ReplyMessage        string
	CompletedAt         time.Time
	LatencyMS           int64
	FailureReason       string
	ResponseFingerprint string
}

type OutboundDACAttemptCreate struct {
	RequestID           string
	Attempt             int
	Status              string
	TargetAddress       string
	TargetPort          int
	TargetTransport     string
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
}

func CreateOutboundDACRequest(create OutboundDACCreate, retentionLimit int) (OutboundDACRequestRecord, error) {
	if DB == nil {
		return OutboundDACRequestRecord{}, fmt.Errorf("database not initialized")
	}
	create = normalizeOutboundDACCreate(create)
	if create.RequestID == "" || create.Action == "" || create.TargetAddress == "" || create.TargetPort <= 0 || create.RequestCode == 0 || create.RequestFingerprint == "" {
		return OutboundDACRequestRecord{}, fmt.Errorf("request_id, action, target, request_code, and request_fingerprint are required")
	}
	attrsJSON, err := json.Marshal(redactOutboundDACAttributesForHistory(create.Attributes))
	if err != nil {
		return OutboundDACRequestRecord{}, fmt.Errorf("encode outbound DAC attributes: %w", err)
	}
	_, err = DB.Exec(`INSERT INTO radius_outbound_dac_requests (
		request_id, action, status, target_address, target_port, target_transport,
		nas_identifier, nas_ip_address, nas_type, shortname, session_id, username_hash,
		calling_station_hash, framed_ip_address, attributes_json, request_code,
		correlation_id, requested_by, requested_at, sent_at, failure_reason,
		message_authenticator, request_fingerprint, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		create.RequestID, create.Action, create.Status, create.TargetAddress, create.TargetPort, create.TargetTransport,
		nullIfEmpty(create.NASIdentifier), nullIfEmpty(create.NASIPAddress), nullIfEmpty(create.NASType), nullIfEmpty(create.ShortName),
		nullIfEmpty(create.SessionID), nullIfEmpty(HashEAPIdentity(create.Username)), nullIfEmpty(HashEAPIdentity(create.CallingStationID)),
		nullIfEmpty(create.FramedIPAddress), string(attrsJSON), create.RequestCode, create.CorrelationID, nullIfEmpty(create.RequestedBy),
		formatOutboundDACTime(create.RequestedAt), nullIfEmptyTime(create.SentAt), nullIfEmpty(create.FailureReason),
		create.MessageAuthenticator, create.RequestFingerprint, formatOutboundDACTime(create.RequestedAt), formatOutboundDACTime(create.RequestedAt))
	if err != nil {
		return OutboundDACRequestRecord{}, fmt.Errorf("create outbound DAC request: %w", err)
	}
	_ = pruneOutboundDACRequests(retentionLimit)
	return GetOutboundDACRequest(create.RequestID)
}

func CompleteOutboundDACRequest(update OutboundDACComplete) (OutboundDACRequestRecord, error) {
	if DB == nil {
		return OutboundDACRequestRecord{}, fmt.Errorf("database not initialized")
	}
	update.RequestID = strings.TrimSpace(update.RequestID)
	update.Status = normalizeOutboundDACStatus(update.Status)
	if update.RequestID == "" || update.Status == "" {
		return OutboundDACRequestRecord{}, fmt.Errorf("request_id and status are required")
	}
	completedAt := update.CompletedAt.UTC()
	if completedAt.IsZero() {
		completedAt = time.Now().UTC()
	}
	_, err := DB.Exec(`UPDATE radius_outbound_dac_requests SET
		status = ?, response_code = ?, error_cause = ?, error_cause_name = ?, reply_message = ?,
		completed_at = ?, latency_ms = ?, failure_reason = ?, response_fingerprint = ?, updated_at = ?
		WHERE request_id = ?`,
		update.Status, nullIntIfZero(update.ResponseCode), nullIntIfZero(update.ErrorCause), nullIfEmpty(update.ErrorCauseName),
		nullIfEmpty(update.ReplyMessage), formatOutboundDACTime(completedAt), update.LatencyMS, nullIfEmpty(update.FailureReason),
		nullIfEmpty(update.ResponseFingerprint), formatOutboundDACTime(completedAt), update.RequestID)
	if err != nil {
		return OutboundDACRequestRecord{}, fmt.Errorf("complete outbound DAC request: %w", err)
	}
	return GetOutboundDACRequest(update.RequestID)
}

func RecordOutboundDACAttempt(create OutboundDACAttemptCreate) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	create.RequestID = strings.TrimSpace(create.RequestID)
	create.Status = normalizeOutboundDACStatus(create.Status)
	create.TargetTransport = normalizeOutboundDACTransport(create.TargetTransport)
	if create.Attempt <= 0 {
		create.Attempt = 1
	}
	if create.RequestID == "" || create.Status == "" || create.TargetAddress == "" || create.TargetPort <= 0 || create.RequestCode == 0 || create.RequestFingerprint == "" {
		return fmt.Errorf("request_id, status, target, request_code, and request_fingerprint are required")
	}
	_, err := DB.Exec(`INSERT INTO radius_outbound_dac_attempts (
		request_id, attempt, status, target_address, target_port, target_transport,
		request_code, response_code, error_cause, error_cause_name, reply_message,
		latency_ms, packet_identifier, request_fingerprint, response_fingerprint, error_message, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		create.RequestID, create.Attempt, create.Status, strings.TrimSpace(create.TargetAddress), create.TargetPort, create.TargetTransport,
		create.RequestCode, nullIntIfZero(create.ResponseCode), nullIntIfZero(create.ErrorCause), nullIfEmpty(create.ErrorCauseName),
		nullIfEmpty(create.ReplyMessage), create.LatencyMS, create.PacketIdentifier, create.RequestFingerprint,
		nullIfEmpty(create.ResponseFingerprint), nullIfEmpty(create.ErrorMessage), formatOutboundDACTime(time.Now().UTC()))
	if err != nil {
		return fmt.Errorf("record outbound DAC attempt: %w", err)
	}
	return nil
}

func GetOutboundDACRequest(requestID string) (OutboundDACRequestRecord, error) {
	if DB == nil {
		return OutboundDACRequestRecord{}, fmt.Errorf("database not initialized")
	}
	rows, err := DB.Query(outboundDACSelectSQL()+` WHERE request_id = ? LIMIT 1`, strings.TrimSpace(requestID))
	if err != nil {
		return OutboundDACRequestRecord{}, err
	}
	defer rows.Close()
	records, err := scanOutboundDACRequestRows(rows)
	if err != nil {
		return OutboundDACRequestRecord{}, err
	}
	if len(records) == 0 {
		return OutboundDACRequestRecord{}, fmt.Errorf("outbound DAC request %q not found", requestID)
	}
	return records[0], nil
}

func ListOutboundDACRequests(query OutboundDACRequestQuery) ([]OutboundDACRequestRecord, error) {
	if DB == nil {
		return nil, nil
	}
	limit := query.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	where := []string{"1=1"}
	args := []any{}
	if strings.TrimSpace(query.Status) != "" {
		where = append(where, "status = ?")
		args = append(args, strings.TrimSpace(strings.ToLower(query.Status)))
	}
	if strings.TrimSpace(query.Action) != "" {
		where = append(where, "action = ?")
		args = append(args, strings.TrimSpace(strings.ToLower(query.Action)))
	}
	if strings.TrimSpace(query.TargetAddress) != "" {
		where = append(where, "target_address = ?")
		args = append(args, strings.TrimSpace(query.TargetAddress))
	}
	if strings.TrimSpace(query.SessionID) != "" {
		where = append(where, "session_id = ?")
		args = append(args, strings.TrimSpace(query.SessionID))
	}
	args = append(args, limit)
	rows, err := DB.Query(outboundDACSelectSQL()+` WHERE `+strings.Join(where, " AND ")+` ORDER BY requested_at DESC, id DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanOutboundDACRequestRows(rows)
}

func ListOutboundDACAttempts(requestID string, limit int) ([]OutboundDACAttemptRecord, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := DB.Query(`SELECT id, request_id, attempt, status, target_address, target_port, target_transport,
		request_code, COALESCE(response_code, 0), COALESCE(error_cause, 0), COALESCE(error_cause_name, ''),
		COALESCE(reply_message, ''), latency_ms, packet_identifier, request_fingerprint,
		COALESCE(response_fingerprint, ''), COALESCE(error_message, ''), created_at
		FROM radius_outbound_dac_attempts
		WHERE (? = '' OR request_id = ?)
		ORDER BY created_at DESC, id DESC LIMIT ?`, strings.TrimSpace(requestID), strings.TrimSpace(requestID), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	attempts := []OutboundDACAttemptRecord{}
	for rows.Next() {
		var attempt OutboundDACAttemptRecord
		if err := rows.Scan(&attempt.ID, &attempt.RequestID, &attempt.Attempt, &attempt.Status, &attempt.TargetAddress,
			&attempt.TargetPort, &attempt.TargetTransport, &attempt.RequestCode, &attempt.ResponseCode,
			&attempt.ErrorCause, &attempt.ErrorCauseName, &attempt.ReplyMessage, &attempt.LatencyMS,
			&attempt.PacketIdentifier, &attempt.RequestFingerprint, &attempt.ResponseFingerprint, &attempt.ErrorMessage,
			&attempt.CreatedAt); err != nil {
			return nil, err
		}
		attempts = append(attempts, attempt)
	}
	return attempts, rows.Err()
}

func GetOutboundDACSummary(retentionLimit int) (OutboundDACSummary, error) {
	summary := OutboundDACSummary{HistoryRetentionMax: retentionLimit}
	if DB == nil {
		return summary, nil
	}
	err := DB.QueryRow(`SELECT COUNT(*),
		COALESCE(SUM(CASE WHEN status = 'ack' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'nak' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'sent' THEN 1 ELSE 0 END), 0),
		COALESCE(MAX(requested_at), ''),
		COALESCE(MAX(completed_at), '')
		FROM radius_outbound_dac_requests`).
		Scan(&summary.TotalRequests, &summary.ACKCount, &summary.NAKCount, &summary.ErrorCount,
			&summary.BlockedCount, &summary.SentCount, &summary.LastRequestAt, &summary.LastCompletedAt)
	if err != nil {
		if tableMissing(err) {
			return summary, nil
		}
		return summary, err
	}
	if err := DB.QueryRow(`SELECT COUNT(*) FROM radius_outbound_dac_attempts`).Scan(&summary.AttemptCount); err != nil && !tableMissing(err) {
		return summary, err
	}
	_ = DB.QueryRow(`SELECT COALESCE(failure_reason, '') FROM radius_outbound_dac_requests
		WHERE failure_reason IS NOT NULL AND failure_reason <> ''
		ORDER BY completed_at DESC, requested_at DESC LIMIT 1`).Scan(&summary.LastFailureReason)
	return summary, nil
}

func LookupOutboundDACTargetHint(sessionID string) (OutboundDACTargetHint, error) {
	if DB == nil {
		return OutboundDACTargetHint{}, fmt.Errorf("database not initialized")
	}
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return OutboundDACTargetHint{}, fmt.Errorf("session_id is required")
	}
	var hint OutboundDACTargetHint
	err := DB.QueryRow(`SELECT id, COALESCE(radius_session_id, ''), COALESCE(username, ''),
		COALESCE(mac, ''), COALESCE(ip, ''), COALESCE(nas_identifier, '')
		FROM sessions
		WHERE id = ? OR radius_session_id = ?
		ORDER BY CASE WHEN end_time IS NULL OR end_time = '' THEN 0 ELSE 1 END, start_time DESC
		LIMIT 1`, sessionID, sessionID).
		Scan(&hint.SessionID, &hint.AcctSessionID, &hint.Username, &hint.CallingStationID, &hint.FramedIPAddress, &hint.NASIdentifier)
	if err != nil {
		return OutboundDACTargetHint{}, err
	}
	return hint, nil
}

func FingerprintOutboundDAC(parts ...string) string {
	normalized := make([]string, 0, len(parts))
	for _, part := range parts {
		normalized = append(normalized, strings.TrimSpace(part))
	}
	sum := sha256.Sum256([]byte(strings.Join(normalized, "|")))
	return hex.EncodeToString(sum[:])
}

func normalizeOutboundDACCreate(create OutboundDACCreate) OutboundDACCreate {
	create.RequestID = strings.TrimSpace(create.RequestID)
	create.Action = normalizeOutboundDACAction(create.Action)
	create.Status = normalizeOutboundDACStatus(create.Status)
	if create.Status == "" {
		create.Status = OutboundDACStatusSent
	}
	create.TargetAddress = strings.TrimSpace(create.TargetAddress)
	create.TargetTransport = normalizeOutboundDACTransport(create.TargetTransport)
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
		create.CorrelationID = create.RequestID
	}
	create.RequestedBy = strings.TrimSpace(create.RequestedBy)
	if create.RequestedAt.IsZero() {
		create.RequestedAt = time.Now().UTC()
	}
	create.RequestedAt = create.RequestedAt.UTC()
	return create
}

func normalizeOutboundDACAction(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "disconnect", "disconnect-request":
		return "disconnect"
	case "coa", "coa-request", "change-of-authorization":
		return "coa"
	default:
		return strings.ToLower(strings.TrimSpace(action))
	}
}

func normalizeOutboundDACStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case OutboundDACStatusPreviewed, OutboundDACStatusSent, OutboundDACStatusACK, OutboundDACStatusNAK, OutboundDACStatusError, OutboundDACStatusBlocked:
		return strings.ToLower(strings.TrimSpace(status))
	default:
		return strings.ToLower(strings.TrimSpace(status))
	}
}

func normalizeOutboundDACTransport(transport string) string {
	switch strings.ToLower(strings.TrimSpace(transport)) {
	case "radsec":
		return "radsec"
	default:
		return "udp"
	}
}

func outboundDACSelectSQL() string {
	return `SELECT id, request_id, action, status, target_address, target_port, target_transport,
		COALESCE(nas_identifier, ''), COALESCE(nas_ip_address, ''), COALESCE(nas_type, ''),
		COALESCE(shortname, ''), COALESCE(session_id, ''), COALESCE(username_hash, ''),
		COALESCE(calling_station_hash, ''), COALESCE(framed_ip_address, ''), attributes_json,
		request_code, COALESCE(response_code, 0), COALESCE(error_cause, 0), COALESCE(error_cause_name, ''),
		COALESCE(reply_message, ''), correlation_id, COALESCE(requested_by, ''), requested_at,
		COALESCE(sent_at, ''), COALESCE(completed_at, ''), latency_ms, COALESCE(failure_reason, ''),
		message_authenticator, request_fingerprint, COALESCE(response_fingerprint, ''), created_at, updated_at
		FROM radius_outbound_dac_requests`
}

func scanOutboundDACRequestRows(rows outboundDACRows) ([]OutboundDACRequestRecord, error) {
	records := []OutboundDACRequestRecord{}
	for rows.Next() {
		var (
			record    OutboundDACRequestRecord
			attrsJSON string
		)
		if err := rows.Scan(&record.ID, &record.RequestID, &record.Action, &record.Status, &record.TargetAddress,
			&record.TargetPort, &record.TargetTransport, &record.NASIdentifier, &record.NASIPAddress, &record.NASType,
			&record.ShortName, &record.SessionID, &record.UsernameHash, &record.CallingStationHash, &record.FramedIPAddress,
			&attrsJSON, &record.RequestCode, &record.ResponseCode, &record.ErrorCause, &record.ErrorCauseName,
			&record.ReplyMessage, &record.CorrelationID, &record.RequestedBy, &record.RequestedAt, &record.SentAt,
			&record.CompletedAt, &record.LatencyMS, &record.FailureReason, &record.MessageAuthenticator,
			&record.RequestFingerprint, &record.ResponseFingerprint, &record.CreatedAt, &record.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(attrsJSON), &record.Attributes)
		records = append(records, record)
	}
	return records, rows.Err()
}

func pruneOutboundDACRequests(retentionLimit int) error {
	if DB == nil || retentionLimit <= 0 {
		return nil
	}
	_, err := DB.Exec(`DELETE FROM radius_outbound_dac_attempts
		WHERE request_id IN (
			SELECT request_id FROM radius_outbound_dac_requests
			ORDER BY requested_at DESC, id DESC
			LIMIT -1 OFFSET ?
		)`, retentionLimit)
	if err != nil {
		return err
	}
	_, err = DB.Exec(`DELETE FROM radius_outbound_dac_requests
		WHERE id IN (
			SELECT id FROM radius_outbound_dac_requests
			ORDER BY requested_at DESC, id DESC
			LIMIT -1 OFFSET ?
		)`, retentionLimit)
	return err
}

func formatOutboundDACTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func redactOutboundDACAttributesForHistory(attrs []OutboundDACAttribute) []OutboundDACAttribute {
	redacted := make([]OutboundDACAttribute, 0, len(attrs))
	for _, attr := range attrs {
		name := strings.TrimSpace(attr.Name)
		value := strings.TrimSpace(attr.Value)
		switch strings.ToLower(strings.ReplaceAll(name, "_", "-")) {
		case "user-name", "calling-station-id", "class", "state":
			value = hashedOutboundDACAttribute(value)
		}
		redacted = append(redacted, OutboundDACAttribute{Name: name, Value: value})
	}
	return redacted
}

func hashedOutboundDACAttribute(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	return "sha256:" + FingerprintOutboundDAC(value)
}

func nullIfEmptyTime(value time.Time) sql.NullString {
	if value.IsZero() {
		return sql.NullString{}
	}
	return sql.NullString{String: formatOutboundDACTime(value), Valid: true}
}

func nullIntIfZero(value int) sql.NullInt64 {
	if value == 0 {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(value), Valid: true}
}
