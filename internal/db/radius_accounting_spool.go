package db

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

const (
	RadiusAccountingSpoolStatusQueued   = "queued"
	RadiusAccountingSpoolStatusRetrying = "retrying"
	RadiusAccountingSpoolStatusSent     = "sent"
	RadiusAccountingSpoolStatusPoison   = "poison"
	RadiusAccountingSpoolStatusExpired  = "expired"

	RadiusAccountingSpoolAttemptSent   = "sent"
	RadiusAccountingSpoolAttemptFailed = "failed"
	RadiusAccountingSpoolAttemptPoison = "poison"
)

type RadiusAccountingSpoolCreate struct {
	RecordID       string
	Route          string
	Realm          string
	ServerName     string
	Username       string
	SessionID      string
	AcctStatusType string
	PayloadJSON    string
	PayloadSHA256  string
	MaxAttempts    int
	NextAttemptAt  time.Time
	ExpiresAt      time.Time
	OwnerNode      string
}

type RadiusAccountingSpoolRecord struct {
	ID               int    `json:"id"`
	RecordID         string `json:"record_id"`
	Status           string `json:"status"`
	Route            string `json:"route,omitempty"`
	Realm            string `json:"realm,omitempty"`
	ServerName       string `json:"server_name,omitempty"`
	Username         string `json:"username,omitempty"`
	SessionID        string `json:"session_id,omitempty"`
	AcctStatusType   string `json:"acct_status_type,omitempty"`
	PayloadJSON      string `json:"payload_json,omitempty"`
	PayloadSHA256    string `json:"payload_sha256"`
	AttemptCount     int    `json:"attempt_count"`
	MaxAttempts      int    `json:"max_attempts"`
	LastError        string `json:"last_error,omitempty"`
	LastResponseCode string `json:"last_response_code,omitempty"`
	LastAttemptAt    string `json:"last_attempt_at,omitempty"`
	NextAttemptAt    string `json:"next_attempt_at,omitempty"`
	ExpiresAt        string `json:"expires_at"`
	OwnerNode        string `json:"owner_node,omitempty"`
	LockedUntil      string `json:"locked_until,omitempty"`
	SentAt           string `json:"sent_at,omitempty"`
	CreatedAt        string `json:"created_at"`
	UpdatedAt        string `json:"updated_at"`
}

type RadiusAccountingSpoolAttempt struct {
	ID            int    `json:"id"`
	SpoolID       int    `json:"spool_id"`
	RecordID      string `json:"record_id"`
	AttemptNumber int    `json:"attempt_number"`
	Result        string `json:"result"`
	Error         string `json:"error,omitempty"`
	ResponseCode  string `json:"response_code,omitempty"`
	Route         string `json:"route,omitempty"`
	Realm         string `json:"realm,omitempty"`
	ServerName    string `json:"server_name,omitempty"`
	LatencyMs     int64  `json:"latency_ms"`
	AttemptedAt   string `json:"attempted_at"`
	NextAttemptAt string `json:"next_attempt_at,omitempty"`
}

type RadiusAccountingSpoolSummary struct {
	TotalRecords     int    `json:"total_records"`
	QueuedCount      int    `json:"queued_count"`
	RetryingCount    int    `json:"retrying_count"`
	SentCount        int    `json:"sent_count"`
	PoisonCount      int    `json:"poison_count"`
	ExpiredCount     int    `json:"expired_count"`
	DueCount         int    `json:"due_count"`
	AttemptCount     int    `json:"attempt_count"`
	OldestQueuedAt   string `json:"oldest_queued_at,omitempty"`
	NextAttemptAt    string `json:"next_attempt_at,omitempty"`
	LastSentAt       string `json:"last_sent_at,omitempty"`
	LastPoisonAt     string `json:"last_poison_at,omitempty"`
	LastAttemptAt    string `json:"last_attempt_at,omitempty"`
	QueueCapacity    int    `json:"queue_capacity"`
	QueueUtilization int    `json:"queue_utilization_percent"`
}

type RadiusAccountingSpoolAttemptUpdate struct {
	RecordID      string
	Result        string
	Error         string
	ResponseCode  string
	Route         string
	Realm         string
	ServerName    string
	LatencyMs     int64
	AttemptedAt   time.Time
	NextAttemptAt time.Time
	Status        string
}

func EnqueueRadiusAccountingSpool(create RadiusAccountingSpoolCreate, maxQueueRecords int) (RadiusAccountingSpoolRecord, bool, error) {
	if DB == nil {
		return RadiusAccountingSpoolRecord{}, false, fmt.Errorf("database not initialized")
	}
	create.RecordID = strings.TrimSpace(create.RecordID)
	create.PayloadJSON = strings.TrimSpace(create.PayloadJSON)
	create.PayloadSHA256 = strings.TrimSpace(create.PayloadSHA256)
	if create.RecordID == "" || create.PayloadJSON == "" || create.PayloadSHA256 == "" {
		return RadiusAccountingSpoolRecord{}, false, fmt.Errorf("record_id, payload_json, and payload_sha256 are required")
	}
	if create.MaxAttempts <= 0 {
		create.MaxAttempts = 10
	}
	now := time.Now().UTC()
	if create.NextAttemptAt.IsZero() {
		create.NextAttemptAt = now
	}
	if create.ExpiresAt.IsZero() {
		create.ExpiresAt = now.Add(7 * 24 * time.Hour)
	}

	if existing, err := GetRadiusAccountingSpoolByRecordID(create.RecordID); err == nil && existing.ID != 0 {
		return existing, false, nil
	} else if err != nil && err != sql.ErrNoRows {
		return RadiusAccountingSpoolRecord{}, false, err
	}

	if maxQueueRecords > 0 {
		var queued int
		if err := DB.QueryRow(`SELECT COUNT(*) FROM radius_accounting_spool WHERE status IN (?, ?)`,
			RadiusAccountingSpoolStatusQueued, RadiusAccountingSpoolStatusRetrying).Scan(&queued); err != nil {
			return RadiusAccountingSpoolRecord{}, false, fmt.Errorf("count accounting spool queue: %w", err)
		}
		if queued >= maxQueueRecords {
			return RadiusAccountingSpoolRecord{}, false, fmt.Errorf("radius accounting spool is full (%d queued/retrying records)", queued)
		}
	}

	_, err := DB.Exec(`INSERT INTO radius_accounting_spool (
		record_id, status, route, realm, server_name, username, session_id, acct_status_type,
		payload_json, payload_sha256, attempt_count, max_attempts, next_attempt_at, expires_at,
		owner_node, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?)`,
		create.RecordID, RadiusAccountingSpoolStatusQueued, strings.TrimSpace(create.Route), strings.TrimSpace(create.Realm),
		strings.TrimSpace(create.ServerName), strings.TrimSpace(create.Username), strings.TrimSpace(create.SessionID),
		strings.TrimSpace(create.AcctStatusType), create.PayloadJSON, create.PayloadSHA256, create.MaxAttempts,
		formatSpoolTime(create.NextAttemptAt), formatSpoolTime(create.ExpiresAt), strings.TrimSpace(create.OwnerNode),
		formatSpoolTime(now), formatSpoolTime(now))
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			existing, getErr := GetRadiusAccountingSpoolByRecordID(create.RecordID)
			return existing, false, getErr
		}
		return RadiusAccountingSpoolRecord{}, false, fmt.Errorf("enqueue radius accounting spool: %w", err)
	}
	record, err := GetRadiusAccountingSpoolByRecordID(create.RecordID)
	return record, true, err
}

func GetRadiusAccountingSpoolByRecordID(recordID string) (RadiusAccountingSpoolRecord, error) {
	if DB == nil {
		return RadiusAccountingSpoolRecord{}, fmt.Errorf("database not initialized")
	}
	rows, err := DB.Query(radiusAccountingSpoolSelectSQL()+` WHERE record_id = ? LIMIT 1`, strings.TrimSpace(recordID))
	if err != nil {
		return RadiusAccountingSpoolRecord{}, err
	}
	defer rows.Close()
	records, err := scanRadiusAccountingSpoolRows(rows)
	if err != nil {
		return RadiusAccountingSpoolRecord{}, err
	}
	if len(records) == 0 {
		return RadiusAccountingSpoolRecord{}, sql.ErrNoRows
	}
	return records[0], nil
}

func ClaimRadiusAccountingSpool(batchSize int, ownerNode string, now time.Time, lockFor time.Duration) ([]RadiusAccountingSpoolRecord, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	if batchSize <= 0 {
		batchSize = 100
	}
	if lockFor <= 0 {
		lockFor = 2 * time.Minute
	}
	now = now.UTC()
	lockUntil := now.Add(lockFor)

	tx, err := DB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	rows, err := tx.Query(`SELECT id FROM radius_accounting_spool
		WHERE status IN (?, ?)
		  AND datetime(next_attempt_at) <= datetime(?)
		  AND datetime(expires_at) > datetime(?)
		  AND (locked_until IS NULL OR locked_until = '' OR datetime(locked_until) <= datetime(?))
		ORDER BY datetime(next_attempt_at), id
		LIMIT ?`, RadiusAccountingSpoolStatusQueued, RadiusAccountingSpoolStatusRetrying, formatSpoolTime(now), formatSpoolTime(now), formatSpoolTime(now), batchSize)
	if err != nil {
		return nil, fmt.Errorf("select accounting spool claims: %w", err)
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
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return nil, nil
	}
	placeholders := strings.TrimRight(strings.Repeat("?,", len(ids)), ",")
	args := []any{RadiusAccountingSpoolStatusRetrying, strings.TrimSpace(ownerNode), formatSpoolTime(lockUntil), formatSpoolTime(now)}
	args = append(args, ids...)
	if _, err := tx.Exec(`UPDATE radius_accounting_spool
		SET status = ?, owner_node = ?, locked_until = ?, updated_at = ?
		WHERE id IN (`+placeholders+`)`, args...); err != nil {
		return nil, fmt.Errorf("claim accounting spool records: %w", err)
	}
	queryArgs := append([]any{}, ids...)
	claimedRows, err := tx.Query(radiusAccountingSpoolSelectSQL()+` WHERE id IN (`+placeholders+`) ORDER BY datetime(next_attempt_at), id`, queryArgs...)
	if err != nil {
		return nil, fmt.Errorf("load claimed accounting spool records: %w", err)
	}
	records, err := scanRadiusAccountingSpoolRows(claimedRows)
	claimedRows.Close()
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return records, nil
}

func CompleteRadiusAccountingSpoolAttempt(record RadiusAccountingSpoolRecord, update RadiusAccountingSpoolAttemptUpdate) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	if record.ID == 0 {
		return fmt.Errorf("spool record is required")
	}
	update.RecordID = strings.TrimSpace(update.RecordID)
	if update.RecordID == "" {
		update.RecordID = record.RecordID
	}
	if update.AttemptedAt.IsZero() {
		update.AttemptedAt = time.Now().UTC()
	}
	update.Status = strings.TrimSpace(update.Status)
	switch update.Status {
	case RadiusAccountingSpoolStatusQueued, RadiusAccountingSpoolStatusRetrying, RadiusAccountingSpoolStatusSent, RadiusAccountingSpoolStatusPoison, RadiusAccountingSpoolStatusExpired:
	default:
		return fmt.Errorf("invalid accounting spool status %q", update.Status)
	}
	update.Result = strings.TrimSpace(update.Result)
	switch update.Result {
	case RadiusAccountingSpoolAttemptSent, RadiusAccountingSpoolAttemptFailed, RadiusAccountingSpoolAttemptPoison:
	default:
		return fmt.Errorf("invalid accounting spool attempt result %q", update.Result)
	}
	attemptNumber := record.AttemptCount + 1
	nextAttempt := ""
	if !update.NextAttemptAt.IsZero() {
		nextAttempt = formatSpoolTime(update.NextAttemptAt)
	}
	sentAt := any(nil)
	if update.Status == RadiusAccountingSpoolStatusSent {
		sentAt = formatSpoolTime(update.AttemptedAt)
	}

	tx, err := DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO radius_accounting_spool_attempts (
		spool_id, record_id, attempt_number, result, error, response_code, route, realm, server_name,
		latency_ms, attempted_at, next_attempt_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.ID, update.RecordID, attemptNumber, update.Result, strings.TrimSpace(update.Error),
		strings.TrimSpace(update.ResponseCode), strings.TrimSpace(update.Route), strings.TrimSpace(update.Realm),
		strings.TrimSpace(update.ServerName), update.LatencyMs, formatSpoolTime(update.AttemptedAt), nextAttempt); err != nil {
		return fmt.Errorf("insert accounting spool attempt: %w", err)
	}
	if _, err := tx.Exec(`UPDATE radius_accounting_spool
		SET status = ?, attempt_count = ?, last_error = ?, last_response_code = ?, last_attempt_at = ?,
		    next_attempt_at = ?, locked_until = NULL, sent_at = COALESCE(?, sent_at), updated_at = ?
		WHERE id = ?`,
		update.Status, attemptNumber, strings.TrimSpace(update.Error), strings.TrimSpace(update.ResponseCode),
		formatSpoolTime(update.AttemptedAt), nextAttempt, sentAt, formatSpoolTime(update.AttemptedAt), record.ID); err != nil {
		return fmt.Errorf("update accounting spool attempt: %w", err)
	}
	return tx.Commit()
}

func ExpireDueRadiusAccountingSpool(now time.Time) (int, error) {
	if DB == nil {
		return 0, fmt.Errorf("database not initialized")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	res, err := DB.Exec(`UPDATE radius_accounting_spool
		SET status = ?, locked_until = NULL, updated_at = ?
		WHERE status IN (?, ?)
		  AND datetime(expires_at) <= datetime(?)`,
		RadiusAccountingSpoolStatusExpired, formatSpoolTime(now), RadiusAccountingSpoolStatusQueued,
		RadiusAccountingSpoolStatusRetrying, formatSpoolTime(now))
	if err != nil {
		return 0, fmt.Errorf("expire accounting spool records: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func ListRadiusAccountingSpool(status string, limit int) ([]RadiusAccountingSpoolRecord, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	status = strings.TrimSpace(status)
	args := []any{}
	query := radiusAccountingSpoolSelectSQL()
	if status != "" {
		query += ` WHERE status = ?`
		args = append(args, status)
	}
	query += ` ORDER BY CASE status WHEN 'queued' THEN 0 WHEN 'retrying' THEN 1 WHEN 'poison' THEN 2 WHEN 'expired' THEN 3 ELSE 4 END,
		datetime(next_attempt_at), id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := DB.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list accounting spool records: %w", err)
	}
	defer rows.Close()
	return scanRadiusAccountingSpoolRows(rows)
}

func ListRadiusAccountingSpoolAttempts(recordID string, limit int) ([]RadiusAccountingSpoolAttempt, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	recordID = strings.TrimSpace(recordID)
	args := []any{}
	query := `SELECT id, spool_id, COALESCE(record_id, ''), COALESCE(attempt_number, 0), COALESCE(result, ''),
		COALESCE(error, ''), COALESCE(response_code, ''), COALESCE(route, ''), COALESCE(realm, ''),
		COALESCE(server_name, ''), COALESCE(latency_ms, 0), COALESCE(attempted_at, ''), COALESCE(next_attempt_at, '')
		FROM radius_accounting_spool_attempts`
	if recordID != "" {
		query += ` WHERE record_id = ?`
		args = append(args, recordID)
	}
	query += ` ORDER BY datetime(attempted_at) DESC, id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := DB.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list accounting spool attempts: %w", err)
	}
	defer rows.Close()
	attempts := []RadiusAccountingSpoolAttempt{}
	for rows.Next() {
		var item RadiusAccountingSpoolAttempt
		if err := rows.Scan(&item.ID, &item.SpoolID, &item.RecordID, &item.AttemptNumber, &item.Result, &item.Error,
			&item.ResponseCode, &item.Route, &item.Realm, &item.ServerName, &item.LatencyMs, &item.AttemptedAt,
			&item.NextAttemptAt); err != nil {
			return nil, fmt.Errorf("scan accounting spool attempt: %w", err)
		}
		attempts = append(attempts, item)
	}
	return attempts, rows.Err()
}

func GetRadiusAccountingSpoolSummary(maxQueueRecords int) (RadiusAccountingSpoolSummary, error) {
	if DB == nil {
		return RadiusAccountingSpoolSummary{}, fmt.Errorf("database not initialized")
	}
	now := formatSpoolTime(time.Now().UTC())
	var summary RadiusAccountingSpoolSummary
	err := DB.QueryRow(`SELECT
		COUNT(*),
		COALESCE(SUM(CASE WHEN status = 'queued' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'retrying' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'sent' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'poison' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'expired' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status IN ('queued', 'retrying') AND datetime(next_attempt_at) <= datetime(?) THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(attempt_count), 0),
		COALESCE(MIN(CASE WHEN status IN ('queued', 'retrying') THEN created_at END), ''),
		COALESCE(MIN(CASE WHEN status IN ('queued', 'retrying') THEN next_attempt_at END), ''),
		COALESCE(MAX(sent_at), ''),
		COALESCE(MAX(CASE WHEN status = 'poison' THEN updated_at END), ''),
		COALESCE(MAX(last_attempt_at), '')
		FROM radius_accounting_spool`, now).Scan(
		&summary.TotalRecords, &summary.QueuedCount, &summary.RetryingCount, &summary.SentCount,
		&summary.PoisonCount, &summary.ExpiredCount, &summary.DueCount, &summary.AttemptCount,
		&summary.OldestQueuedAt, &summary.NextAttemptAt, &summary.LastSentAt, &summary.LastPoisonAt,
		&summary.LastAttemptAt)
	if err != nil {
		return RadiusAccountingSpoolSummary{}, fmt.Errorf("get accounting spool summary: %w", err)
	}
	summary.QueueCapacity = maxQueueRecords
	if maxQueueRecords > 0 {
		active := summary.QueuedCount + summary.RetryingCount
		summary.QueueUtilization = int((int64(active) * 100) / int64(maxQueueRecords))
	}
	return summary, nil
}

func PruneRadiusAccountingSpool(sentRetention, poisonRetention time.Duration, now time.Time) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if sentRetention <= 0 {
		sentRetention = 7 * 24 * time.Hour
	}
	if poisonRetention <= 0 {
		poisonRetention = 30 * 24 * time.Hour
	}
	sentCutoff := formatSpoolTime(now.Add(-sentRetention))
	terminalCutoff := formatSpoolTime(now.Add(-poisonRetention))
	if _, err := DB.Exec(`DELETE FROM radius_accounting_spool_attempts
		WHERE spool_id IN (
			SELECT id FROM radius_accounting_spool
			WHERE (status = ? AND datetime(COALESCE(sent_at, updated_at)) < datetime(?))
			   OR (status IN (?, ?) AND datetime(updated_at) < datetime(?))
		)`, RadiusAccountingSpoolStatusSent, sentCutoff, RadiusAccountingSpoolStatusPoison,
		RadiusAccountingSpoolStatusExpired, terminalCutoff); err != nil {
		return fmt.Errorf("prune accounting spool attempts: %w", err)
	}
	if _, err := DB.Exec(`DELETE FROM radius_accounting_spool
		WHERE (status = ? AND datetime(COALESCE(sent_at, updated_at)) < datetime(?))
		   OR (status IN (?, ?) AND datetime(updated_at) < datetime(?))`,
		RadiusAccountingSpoolStatusSent, sentCutoff, RadiusAccountingSpoolStatusPoison,
		RadiusAccountingSpoolStatusExpired, terminalCutoff); err != nil {
		return fmt.Errorf("prune accounting spool records: %w", err)
	}
	return nil
}

func radiusAccountingSpoolSelectSQL() string {
	return `SELECT id, COALESCE(record_id, ''), COALESCE(status, ''), COALESCE(route, ''), COALESCE(realm, ''),
		COALESCE(server_name, ''), COALESCE(username, ''), COALESCE(session_id, ''), COALESCE(acct_status_type, ''),
		COALESCE(payload_json, ''), COALESCE(payload_sha256, ''), COALESCE(attempt_count, 0), COALESCE(max_attempts, 0),
		COALESCE(last_error, ''), COALESCE(last_response_code, ''), COALESCE(last_attempt_at, ''),
		COALESCE(next_attempt_at, ''), COALESCE(expires_at, ''), COALESCE(owner_node, ''),
		COALESCE(locked_until, ''), COALESCE(sent_at, ''), COALESCE(created_at, ''), COALESCE(updated_at, '')
		FROM radius_accounting_spool`
}

func scanRadiusAccountingSpoolRows(rows *sql.Rows) ([]RadiusAccountingSpoolRecord, error) {
	records := []RadiusAccountingSpoolRecord{}
	for rows.Next() {
		var item RadiusAccountingSpoolRecord
		if err := rows.Scan(&item.ID, &item.RecordID, &item.Status, &item.Route, &item.Realm, &item.ServerName,
			&item.Username, &item.SessionID, &item.AcctStatusType, &item.PayloadJSON, &item.PayloadSHA256,
			&item.AttemptCount, &item.MaxAttempts, &item.LastError, &item.LastResponseCode, &item.LastAttemptAt,
			&item.NextAttemptAt, &item.ExpiresAt, &item.OwnerNode, &item.LockedUntil, &item.SentAt, &item.CreatedAt,
			&item.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan accounting spool record: %w", err)
		}
		records = append(records, item)
	}
	return records, rows.Err()
}

func formatSpoolTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}
