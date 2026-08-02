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

const (
	AccountingIngestSpoolStatusQueued   = "queued"
	AccountingIngestSpoolStatusRetrying = "retrying"
	AccountingIngestSpoolStatusApplied  = "applied"
	AccountingIngestSpoolStatusPoison   = "poison"
	AccountingIngestSpoolStatusExpired  = "expired"

	AccountingIngestSpoolAttemptApplied = "applied"
	AccountingIngestSpoolAttemptFailed  = "failed"
	AccountingIngestSpoolAttemptPoison  = "poison"
)

type AccountingIngestSpoolCreate struct {
	Event         AccountingEventRecord
	MaxAttempts   int
	NextAttemptAt time.Time
	ExpiresAt     time.Time
	OwnerNode     string
}

type AccountingIngestSpoolRecord struct {
	ID             int    `json:"id"`
	RecordID       string `json:"record_id"`
	Status         string `json:"status"`
	Source         string `json:"source"`
	SessionKey     string `json:"session_key"`
	AcctUniqueID   string `json:"acct_unique_id,omitempty"`
	AcctSessionID  string `json:"acct_session_id,omitempty"`
	AcctStatusType string `json:"acct_status_type,omitempty"`
	UsernameHash   string `json:"username_hash,omitempty"`
	NASIPAddress   string `json:"nas_ip_address,omitempty"`
	PayloadJSON    string `json:"-"`
	PayloadSHA256  string `json:"payload_sha256"`
	AttemptCount   int    `json:"attempt_count"`
	MaxAttempts    int    `json:"max_attempts"`
	LastError      string `json:"last_error,omitempty"`
	LastEventID    string `json:"last_event_id,omitempty"`
	LastAttemptAt  string `json:"last_attempt_at,omitempty"`
	NextAttemptAt  string `json:"next_attempt_at,omitempty"`
	ExpiresAt      string `json:"expires_at"`
	OwnerNode      string `json:"owner_node,omitempty"`
	LockedUntil    string `json:"locked_until,omitempty"`
	AppliedAt      string `json:"applied_at,omitempty"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
}

type AccountingIngestSpoolAttempt struct {
	ID            int    `json:"id"`
	SpoolID       int    `json:"spool_id"`
	RecordID      string `json:"record_id"`
	AttemptNumber int    `json:"attempt_number"`
	Result        string `json:"result"`
	Error         string `json:"error,omitempty"`
	EventID       string `json:"event_id,omitempty"`
	LatencyMs     int64  `json:"latency_ms"`
	AttemptedAt   string `json:"attempted_at"`
	NextAttemptAt string `json:"next_attempt_at,omitempty"`
}

type AccountingIngestSpoolAttemptUpdate struct {
	RecordID      string
	Result        string
	Error         string
	EventID       string
	LatencyMs     int64
	AttemptedAt   time.Time
	NextAttemptAt time.Time
	Status        string
}

type AccountingIngestSpoolSummary struct {
	TotalRecords           int    `json:"total_records"`
	QueuedCount            int    `json:"queued_count"`
	RetryingCount          int    `json:"retrying_count"`
	AppliedCount           int    `json:"applied_count"`
	PoisonCount            int    `json:"poison_count"`
	ExpiredCount           int    `json:"expired_count"`
	DueCount               int    `json:"due_count"`
	AttemptCount           int    `json:"attempt_count"`
	LossSLOBreachCount     int    `json:"loss_slo_breach_count"`
	OldestActiveAgeSeconds int64  `json:"oldest_active_age_seconds"`
	OldestQueuedAt         string `json:"oldest_queued_at,omitempty"`
	NextAttemptAt          string `json:"next_attempt_at,omitempty"`
	LastAppliedAt          string `json:"last_applied_at,omitempty"`
	LastPoisonAt           string `json:"last_poison_at,omitempty"`
	LastAttemptAt          string `json:"last_attempt_at,omitempty"`
	LastError              string `json:"last_error,omitempty"`
	QueueCapacity          int    `json:"queue_capacity"`
	QueueUtilization       int    `json:"queue_utilization_percent"`
}

func EnqueueAccountingIngestSpool(create AccountingIngestSpoolCreate, maxQueueRecords int) (AccountingIngestSpoolRecord, bool, error) {
	if DB == nil {
		return AccountingIngestSpoolRecord{}, false, fmt.Errorf("database not initialized")
	}
	event := normalizeAccountingEventRecord(create.Event)
	if event.EventID == "" || event.SessionKey == "" {
		return AccountingIngestSpoolRecord{}, false, fmt.Errorf("accounting ingest event_id and session_key are required")
	}
	payload, payloadSHA, err := marshalAccountingIngestSpoolPayload(event)
	if err != nil {
		return AccountingIngestSpoolRecord{}, false, err
	}
	recordID := AccountingIngestSpoolRecordID(event)
	if existing, err := GetAccountingIngestSpoolByRecordID(recordID); err == nil && existing.ID != 0 {
		return existing, false, nil
	} else if err != nil && err != sql.ErrNoRows {
		return AccountingIngestSpoolRecord{}, false, err
	}

	if maxQueueRecords > 0 {
		var queued int
		if err := DB.QueryRow(`SELECT COUNT(*) FROM radius_accounting_ingest_spool WHERE status IN (?, ?)`,
			AccountingIngestSpoolStatusQueued, AccountingIngestSpoolStatusRetrying).Scan(&queued); err != nil {
			return AccountingIngestSpoolRecord{}, false, fmt.Errorf("count accounting ingest spool queue: %w", err)
		}
		if queued >= maxQueueRecords {
			return AccountingIngestSpoolRecord{}, false, fmt.Errorf("accounting ingest spool is full (%d queued/retrying records)", queued)
		}
	}

	now := time.Now().UTC()
	if create.NextAttemptAt.IsZero() {
		create.NextAttemptAt = now
	}
	if create.ExpiresAt.IsZero() {
		create.ExpiresAt = now.Add(7 * 24 * time.Hour)
	}
	if create.MaxAttempts <= 0 {
		create.MaxAttempts = 10
	}
	_, err = DB.Exec(`INSERT INTO radius_accounting_ingest_spool (
		record_id, status, source, session_key, acct_unique_id, acct_session_id,
		acct_status_type, username_hash, nas_ip_address, payload_json, payload_sha256,
		attempt_count, max_attempts, next_attempt_at, expires_at, owner_node, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?)`,
		recordID, AccountingIngestSpoolStatusQueued, event.Source, event.SessionKey,
		nullIfEmpty(event.AcctUniqueID), nullIfEmpty(event.AcctSessionID), nullIfEmpty(event.StatusType),
		nullIfEmpty(HashEAPIdentity(event.Username)), nullIfEmpty(event.NASIPAddress),
		string(payload), payloadSHA, create.MaxAttempts, formatSpoolTime(create.NextAttemptAt),
		formatSpoolTime(create.ExpiresAt), strings.TrimSpace(create.OwnerNode),
		formatSpoolTime(now), formatSpoolTime(now))
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			existing, getErr := GetAccountingIngestSpoolByRecordID(recordID)
			return existing, false, getErr
		}
		return AccountingIngestSpoolRecord{}, false, fmt.Errorf("enqueue accounting ingest spool: %w", err)
	}
	record, err := GetAccountingIngestSpoolByRecordID(recordID)
	return record, true, err
}

func AccountingIngestSpoolRecordID(event AccountingEventRecord) string {
	event = normalizeAccountingEventRecord(event)
	return "ingest-" + strings.TrimSpace(event.EventID)
}

func GetAccountingIngestSpoolByRecordID(recordID string) (AccountingIngestSpoolRecord, error) {
	if DB == nil {
		return AccountingIngestSpoolRecord{}, fmt.Errorf("database not initialized")
	}
	rows, err := DB.Query(accountingIngestSpoolSelectSQL()+` WHERE record_id = ? LIMIT 1`, strings.TrimSpace(recordID))
	if err != nil {
		return AccountingIngestSpoolRecord{}, err
	}
	defer rows.Close()
	records, err := scanAccountingIngestSpoolRows(rows)
	if err != nil {
		return AccountingIngestSpoolRecord{}, err
	}
	if len(records) == 0 {
		return AccountingIngestSpoolRecord{}, sql.ErrNoRows
	}
	return records[0], nil
}

func ClaimAccountingIngestSpool(batchSize int, ownerNode string, now time.Time, lockFor time.Duration) ([]AccountingIngestSpoolRecord, error) {
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
	rows, err := tx.Query(`SELECT id FROM radius_accounting_ingest_spool
		WHERE status IN (?, ?)
		  AND datetime(next_attempt_at) <= datetime(?)
		  AND datetime(expires_at) > datetime(?)
		  AND (locked_until IS NULL OR locked_until = '' OR datetime(locked_until) <= datetime(?))
		ORDER BY datetime(next_attempt_at), id
		LIMIT ?`, AccountingIngestSpoolStatusQueued, AccountingIngestSpoolStatusRetrying,
		formatSpoolTime(now), formatSpoolTime(now), formatSpoolTime(now), batchSize)
	if err != nil {
		return nil, fmt.Errorf("select accounting ingest spool claims: %w", err)
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
	args := []any{AccountingIngestSpoolStatusRetrying, strings.TrimSpace(ownerNode), formatSpoolTime(lockUntil), formatSpoolTime(now)}
	args = append(args, ids...)
	if _, err := tx.Exec(`UPDATE radius_accounting_ingest_spool
		SET status = ?, owner_node = ?, locked_until = ?, updated_at = ?
		WHERE id IN (`+placeholders+`)`, args...); err != nil {
		return nil, fmt.Errorf("claim accounting ingest spool records: %w", err)
	}
	claimedRows, err := tx.Query(accountingIngestSpoolSelectSQL()+` WHERE id IN (`+placeholders+`) ORDER BY datetime(next_attempt_at), id`, ids...)
	if err != nil {
		return nil, fmt.Errorf("load claimed accounting ingest spool records: %w", err)
	}
	records, err := scanAccountingIngestSpoolRows(claimedRows)
	claimedRows.Close()
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return records, nil
}

func CompleteAccountingIngestSpoolAttempt(record AccountingIngestSpoolRecord, update AccountingIngestSpoolAttemptUpdate) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	if record.ID == 0 {
		return fmt.Errorf("accounting ingest spool record is required")
	}
	update.RecordID = strings.TrimSpace(update.RecordID)
	if update.RecordID == "" {
		update.RecordID = record.RecordID
	}
	if update.AttemptedAt.IsZero() {
		update.AttemptedAt = time.Now().UTC()
	}
	switch update.Status {
	case AccountingIngestSpoolStatusQueued, AccountingIngestSpoolStatusRetrying, AccountingIngestSpoolStatusApplied, AccountingIngestSpoolStatusPoison, AccountingIngestSpoolStatusExpired:
	default:
		return fmt.Errorf("invalid accounting ingest spool status %q", update.Status)
	}
	switch update.Result {
	case AccountingIngestSpoolAttemptApplied, AccountingIngestSpoolAttemptFailed, AccountingIngestSpoolAttemptPoison:
	default:
		return fmt.Errorf("invalid accounting ingest spool attempt result %q", update.Result)
	}
	attemptNumber := record.AttemptCount + 1
	nextAttempt := ""
	if !update.NextAttemptAt.IsZero() {
		nextAttempt = formatSpoolTime(update.NextAttemptAt)
	}
	appliedAt := any(nil)
	if update.Status == AccountingIngestSpoolStatusApplied {
		appliedAt = formatSpoolTime(update.AttemptedAt)
	}
	tx, err := DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO radius_accounting_ingest_spool_attempts (
		spool_id, record_id, attempt_number, result, error, event_id,
		latency_ms, attempted_at, next_attempt_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.ID, update.RecordID, attemptNumber, update.Result, strings.TrimSpace(update.Error),
		nullIfEmpty(update.EventID), update.LatencyMs, formatSpoolTime(update.AttemptedAt), nextAttempt); err != nil {
		return fmt.Errorf("insert accounting ingest spool attempt: %w", err)
	}
	if _, err := tx.Exec(`UPDATE radius_accounting_ingest_spool
		SET status = ?, attempt_count = ?, last_error = ?, last_event_id = ?,
			last_attempt_at = ?, next_attempt_at = ?, locked_until = NULL,
			applied_at = COALESCE(?, applied_at), updated_at = ?
		WHERE id = ?`,
		update.Status, attemptNumber, strings.TrimSpace(update.Error), nullIfEmpty(update.EventID),
		formatSpoolTime(update.AttemptedAt), nextAttempt, appliedAt, formatSpoolTime(update.AttemptedAt), record.ID); err != nil {
		return fmt.Errorf("update accounting ingest spool attempt: %w", err)
	}
	return tx.Commit()
}

func ExpireDueAccountingIngestSpool(now time.Time) (int, error) {
	if DB == nil {
		return 0, fmt.Errorf("database not initialized")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	res, err := DB.Exec(`UPDATE radius_accounting_ingest_spool
		SET status = ?, locked_until = NULL, updated_at = ?
		WHERE status IN (?, ?)
		  AND datetime(expires_at) <= datetime(?)`,
		AccountingIngestSpoolStatusExpired, formatSpoolTime(now), AccountingIngestSpoolStatusQueued,
		AccountingIngestSpoolStatusRetrying, formatSpoolTime(now))
	if err != nil {
		return 0, fmt.Errorf("expire accounting ingest spool records: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func ListAccountingIngestSpool(status string, limit int) ([]AccountingIngestSpoolRecord, error) {
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
	query := accountingIngestSpoolSelectSQL()
	if status != "" {
		query += ` WHERE status = ?`
		args = append(args, status)
	}
	query += ` ORDER BY CASE status WHEN 'queued' THEN 0 WHEN 'retrying' THEN 1 WHEN 'poison' THEN 2 WHEN 'expired' THEN 3 ELSE 4 END,
		datetime(next_attempt_at), id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := DB.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list accounting ingest spool records: %w", err)
	}
	defer rows.Close()
	return scanAccountingIngestSpoolRows(rows)
}

func ListAccountingIngestSpoolAttempts(recordID string, limit int) ([]AccountingIngestSpoolAttempt, error) {
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
	query := `SELECT id, spool_id, COALESCE(record_id, ''), COALESCE(attempt_number, 0),
		COALESCE(result, ''), COALESCE(error, ''), COALESCE(event_id, ''),
		COALESCE(latency_ms, 0), COALESCE(attempted_at, ''), COALESCE(next_attempt_at, '')
		FROM radius_accounting_ingest_spool_attempts`
	if recordID != "" {
		query += ` WHERE record_id = ?`
		args = append(args, recordID)
	}
	query += ` ORDER BY datetime(attempted_at) DESC, id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := DB.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list accounting ingest spool attempts: %w", err)
	}
	defer rows.Close()
	attempts := []AccountingIngestSpoolAttempt{}
	for rows.Next() {
		var item AccountingIngestSpoolAttempt
		if err := rows.Scan(&item.ID, &item.SpoolID, &item.RecordID, &item.AttemptNumber,
			&item.Result, &item.Error, &item.EventID, &item.LatencyMs, &item.AttemptedAt,
			&item.NextAttemptAt); err != nil {
			return nil, fmt.Errorf("scan accounting ingest spool attempt: %w", err)
		}
		attempts = append(attempts, item)
	}
	return attempts, rows.Err()
}

func GetAccountingIngestSpoolSummary(maxQueueRecords, lossSLOSeconds int) (AccountingIngestSpoolSummary, error) {
	if DB == nil {
		return AccountingIngestSpoolSummary{}, fmt.Errorf("database not initialized")
	}
	now := time.Now().UTC()
	nowText := formatSpoolTime(now)
	lossCutoff := formatSpoolTime(now.Add(-time.Duration(lossSLOSeconds) * time.Second))
	var summary AccountingIngestSpoolSummary
	err := DB.QueryRow(`SELECT
		COUNT(*),
		COALESCE(SUM(CASE WHEN status = 'queued' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'retrying' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'applied' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'poison' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'expired' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status IN ('queued', 'retrying') AND datetime(next_attempt_at) <= datetime(?) THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(attempt_count), 0),
		COALESCE(SUM(CASE WHEN status IN ('queued', 'retrying') AND datetime(created_at) < datetime(?) THEN 1 ELSE 0 END), 0),
		COALESCE(MIN(CASE WHEN status IN ('queued', 'retrying') THEN created_at END), ''),
		COALESCE(MIN(CASE WHEN status IN ('queued', 'retrying') THEN next_attempt_at END), ''),
		COALESCE(MAX(applied_at), ''),
		COALESCE(MAX(CASE WHEN status = 'poison' THEN updated_at END), ''),
		COALESCE(MAX(last_attempt_at), ''),
		COALESCE((SELECT last_error FROM radius_accounting_ingest_spool WHERE last_error IS NOT NULL AND last_error <> '' ORDER BY updated_at DESC, id DESC LIMIT 1), '')
		FROM radius_accounting_ingest_spool`, nowText, lossCutoff).Scan(
		&summary.TotalRecords, &summary.QueuedCount, &summary.RetryingCount, &summary.AppliedCount,
		&summary.PoisonCount, &summary.ExpiredCount, &summary.DueCount, &summary.AttemptCount,
		&summary.LossSLOBreachCount, &summary.OldestQueuedAt, &summary.NextAttemptAt,
		&summary.LastAppliedAt, &summary.LastPoisonAt, &summary.LastAttemptAt, &summary.LastError)
	if err != nil {
		return AccountingIngestSpoolSummary{}, fmt.Errorf("get accounting ingest spool summary: %w", err)
	}
	if summary.OldestQueuedAt != "" {
		if parsed := parseAccountingTime(summary.OldestQueuedAt); !parsed.IsZero() {
			summary.OldestActiveAgeSeconds = int64(now.Sub(parsed).Seconds())
			if summary.OldestActiveAgeSeconds < 0 {
				summary.OldestActiveAgeSeconds = 0
			}
		}
	}
	summary.QueueCapacity = maxQueueRecords
	if maxQueueRecords > 0 {
		active := summary.QueuedCount + summary.RetryingCount
		summary.QueueUtilization = int((int64(active) * 100) / int64(maxQueueRecords))
	}
	return summary, nil
}

func PruneAccountingIngestSpool(appliedRetention, poisonRetention time.Duration, now time.Time) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if appliedRetention <= 0 {
		appliedRetention = 24 * time.Hour
	}
	if poisonRetention <= 0 {
		poisonRetention = 30 * 24 * time.Hour
	}
	appliedCutoff := formatSpoolTime(now.Add(-appliedRetention))
	terminalCutoff := formatSpoolTime(now.Add(-poisonRetention))
	if _, err := DB.Exec(`DELETE FROM radius_accounting_ingest_spool_attempts
		WHERE spool_id IN (
			SELECT id FROM radius_accounting_ingest_spool
			WHERE (status = ? AND datetime(COALESCE(applied_at, updated_at)) < datetime(?))
			   OR (status IN (?, ?) AND datetime(updated_at) < datetime(?))
		)`, AccountingIngestSpoolStatusApplied, appliedCutoff, AccountingIngestSpoolStatusPoison,
		AccountingIngestSpoolStatusExpired, terminalCutoff); err != nil {
		return fmt.Errorf("prune accounting ingest spool attempts: %w", err)
	}
	if _, err := DB.Exec(`DELETE FROM radius_accounting_ingest_spool
		WHERE (status = ? AND datetime(COALESCE(applied_at, updated_at)) < datetime(?))
		   OR (status IN (?, ?) AND datetime(updated_at) < datetime(?))`,
		AccountingIngestSpoolStatusApplied, appliedCutoff, AccountingIngestSpoolStatusPoison,
		AccountingIngestSpoolStatusExpired, terminalCutoff); err != nil {
		return fmt.Errorf("prune accounting ingest spool records: %w", err)
	}
	return nil
}

func accountingIngestSpoolSelectSQL() string {
	return `SELECT id, COALESCE(record_id, ''), COALESCE(status, ''), COALESCE(source, ''),
		COALESCE(session_key, ''), COALESCE(acct_unique_id, ''), COALESCE(acct_session_id, ''),
		COALESCE(acct_status_type, ''), COALESCE(username_hash, ''), COALESCE(nas_ip_address, ''),
		COALESCE(payload_json, ''), COALESCE(payload_sha256, ''), COALESCE(attempt_count, 0),
		COALESCE(max_attempts, 0), COALESCE(last_error, ''), COALESCE(last_event_id, ''),
		COALESCE(last_attempt_at, ''), COALESCE(next_attempt_at, ''), COALESCE(expires_at, ''),
		COALESCE(owner_node, ''), COALESCE(locked_until, ''), COALESCE(applied_at, ''),
		COALESCE(created_at, ''), COALESCE(updated_at, '')
		FROM radius_accounting_ingest_spool`
}

func scanAccountingIngestSpoolRows(rows *sql.Rows) ([]AccountingIngestSpoolRecord, error) {
	records := []AccountingIngestSpoolRecord{}
	for rows.Next() {
		var item AccountingIngestSpoolRecord
		if err := rows.Scan(&item.ID, &item.RecordID, &item.Status, &item.Source,
			&item.SessionKey, &item.AcctUniqueID, &item.AcctSessionID, &item.AcctStatusType,
			&item.UsernameHash, &item.NASIPAddress, &item.PayloadJSON, &item.PayloadSHA256,
			&item.AttemptCount, &item.MaxAttempts, &item.LastError, &item.LastEventID,
			&item.LastAttemptAt, &item.NextAttemptAt, &item.ExpiresAt, &item.OwnerNode,
			&item.LockedUntil, &item.AppliedAt, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan accounting ingest spool record: %w", err)
		}
		records = append(records, item)
	}
	return records, rows.Err()
}

func marshalAccountingIngestSpoolPayload(event AccountingEventRecord) ([]byte, string, error) {
	event = normalizeAccountingEventRecord(event)
	payload, err := json.Marshal(event)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(payload)
	return payload, hex.EncodeToString(sum[:]), nil
}
