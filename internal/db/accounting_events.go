package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type AccountingEventRecord struct {
	ID                  int    `json:"id"`
	EventID             string `json:"event_id"`
	AcctUniqueID        string `json:"acct_unique_id"`
	AcctSessionID       string `json:"acct_session_id"`
	SessionKey          string `json:"session_key"`
	StatusType          string `json:"status_type"`
	EventTime           string `json:"event_time"`
	ArrivalTime         string `json:"arrival_time"`
	Ordinal             int64  `json:"ordinal"`
	Username            string `json:"username,omitempty"`
	Realm               string `json:"realm,omitempty"`
	NASIPAddress        string `json:"nas_ip_address,omitempty"`
	NASPortID           string `json:"nas_port_id,omitempty"`
	NASPortType         string `json:"nas_port_type,omitempty"`
	CallingStationID    string `json:"calling_station_id,omitempty"`
	CalledStationID     string `json:"called_station_id,omitempty"`
	FramedIPAddress     string `json:"framed_ip_address,omitempty"`
	FramedIPv6Address   string `json:"framed_ipv6_address,omitempty"`
	FramedIPv6Prefix    string `json:"framed_ipv6_prefix,omitempty"`
	DelegatedIPv6Prefix string `json:"delegated_ipv6_prefix,omitempty"`
	Class               string `json:"class,omitempty"`
	AcctInputOctets     uint64 `json:"acct_input_octets"`
	AcctOutputOctets    uint64 `json:"acct_output_octets"`
	AcctSessionTime     int64  `json:"acct_session_time"`
	AcctTerminateCause  string `json:"acct_terminate_cause,omitempty"`
	Source              string `json:"source"`
	Fingerprint         string `json:"fingerprint"`
	PayloadJSON         string `json:"payload_json,omitempty"`
	ApplyStatus         string `json:"apply_status"`
	OrderingStatus      string `json:"ordering_status"`
	DuplicateCount      int64  `json:"duplicate_count"`
	LastSeenAt          string `json:"last_seen_at,omitempty"`
	AppliedAt           string `json:"applied_at,omitempty"`
	LastError           string `json:"last_error,omitempty"`
	CreatedAt           string `json:"created_at,omitempty"`
	UpdatedAt           string `json:"updated_at,omitempty"`
}

type AccountingEventIngestResult struct {
	Event          AccountingEventRecord `json:"event"`
	Duplicate      bool                  `json:"duplicate"`
	DuplicateCount int64                 `json:"duplicate_count"`
	Status         string                `json:"status"`
}

type AccountingEventApplyResult struct {
	Scanned         int    `json:"scanned"`
	Applied         int    `json:"applied"`
	Duplicates      int    `json:"duplicates"`
	Reordered       int    `json:"reordered"`
	LateStops       int    `json:"late_stops"`
	CreatedSessions int    `json:"created_sessions"`
	UpdatedSessions int    `json:"updated_sessions"`
	ClosedSessions  int    `json:"closed_sessions"`
	ErrorCount      int    `json:"error_count"`
	LastError       string `json:"last_error,omitempty"`
}

type AccountingEventSummary struct {
	TotalEvents        int    `json:"total_events"`
	PendingEvents      int    `json:"pending_events"`
	AppliedEvents      int    `json:"applied_events"`
	ErrorEvents        int    `json:"error_events"`
	IgnoredEvents      int    `json:"ignored_events"`
	DuplicateEvents    int    `json:"duplicate_events"`
	ReorderedEvents    int    `json:"reordered_events"`
	LateStopEvents     int    `json:"late_stop_events"`
	StalePendingEvents int    `json:"stale_pending_events"`
	LastEventAt        string `json:"last_event_at,omitempty"`
	LastAppliedAt      string `json:"last_applied_at,omitempty"`
	LastError          string `json:"last_error,omitempty"`
}

type accountingSessionSnapshot struct {
	exists          bool
	username        string
	mac             string
	ip              string
	authMethod      string
	startTime       string
	lastActivity    string
	endTime         string
	stopReason      string
	radiusSessionID string
	bytesIn         uint64
	bytesOut        uint64
	acctSessionTime int64
	calledStationID string
	nasIdentifier   string
	radiusClass     string
}

func IngestAccountingEvent(ctx context.Context, event AccountingEventRecord) (AccountingEventIngestResult, error) {
	if DB == nil {
		return AccountingEventIngestResult{}, fmt.Errorf("database not initialized")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	event = normalizeAccountingEventRecord(event)
	if event.EventID == "" {
		return AccountingEventIngestResult{}, fmt.Errorf("accounting event id cannot be empty")
	}
	if event.SessionKey == "" {
		return AccountingEventIngestResult{}, fmt.Errorf("accounting event session key cannot be empty")
	}

	var existed int
	_ = DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM radius_accounting_events WHERE event_id = ?`, event.EventID).Scan(&existed)

	_, err := DB.ExecContext(ctx, `INSERT INTO radius_accounting_events (
		event_id, acct_unique_id, acct_session_id, session_key, status_type, event_time,
		arrival_time, ordinal, username, realm, nas_ip_address, nas_port_id, nas_port_type,
		calling_station_id, called_station_id, framed_ip_address, framed_ipv6_address,
		framed_ipv6_prefix, delegated_ipv6_prefix, class, acct_input_octets, acct_output_octets,
		acct_session_time, acct_terminate_cause, source, fingerprint, payload_json,
		apply_status, ordering_status, duplicate_count, last_seen_at, applied_at, last_error,
		created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(event_id) DO UPDATE SET
		duplicate_count = radius_accounting_events.duplicate_count + 1,
		last_seen_at = excluded.last_seen_at,
		updated_at = excluded.updated_at`,
		event.EventID, event.AcctUniqueID, event.AcctSessionID, event.SessionKey, event.StatusType,
		event.EventTime, event.ArrivalTime, event.Ordinal, nullIfEmpty(event.Username), nullIfEmpty(event.Realm),
		nullIfEmpty(event.NASIPAddress), nullIfEmpty(event.NASPortID), nullIfEmpty(event.NASPortType),
		nullIfEmpty(event.CallingStationID), nullIfEmpty(event.CalledStationID), nullIfEmpty(event.FramedIPAddress),
		nullIfEmpty(event.FramedIPv6Address), nullIfEmpty(event.FramedIPv6Prefix), nullIfEmpty(event.DelegatedIPv6Prefix),
		nullIfEmpty(event.Class), boundedUint64ToInt64(event.AcctInputOctets), boundedUint64ToInt64(event.AcctOutputOctets),
		event.AcctSessionTime, nullIfEmpty(event.AcctTerminateCause), event.Source, event.Fingerprint, event.PayloadJSON,
		event.ApplyStatus, event.OrderingStatus, event.DuplicateCount, event.LastSeenAt, nullIfEmpty(event.AppliedAt),
		nullIfEmpty(event.LastError), event.CreatedAt, event.UpdatedAt)
	if err != nil {
		return AccountingEventIngestResult{}, fmt.Errorf("ingest accounting event: %w", err)
	}

	stored, err := GetAccountingEventByEventID(event.EventID)
	if err != nil {
		return AccountingEventIngestResult{}, err
	}
	return AccountingEventIngestResult{
		Event:          stored,
		Duplicate:      existed > 0,
		DuplicateCount: stored.DuplicateCount,
		Status:         stored.ApplyStatus,
	}, nil
}

func ApplyAccountingEventByID(ctx context.Context, eventID string) (AccountingEventApplyResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	event, err := GetAccountingEventByEventID(eventID)
	if err != nil {
		return AccountingEventApplyResult{}, err
	}
	result := AccountingEventApplyResult{Scanned: 1}
	if event.ApplyStatus == "applied" || event.ApplyStatus == "ignored" {
		result.Duplicates = int(event.DuplicateCount)
		return result, nil
	}
	rowResult, err := applyAccountingEventRecord(ctx, event)
	if err != nil {
		result.ErrorCount = 1
		result.LastError = err.Error()
		_ = markAccountingEventApplied(event.ID, "error", "unknown", "", err.Error())
		return result, err
	}
	result.Applied = 1
	result.CreatedSessions = rowResult.created
	result.UpdatedSessions = rowResult.updated
	result.ClosedSessions = rowResult.closed
	if rowResult.orderingStatus == "reordered" || rowResult.orderingStatus == "late_start" {
		result.Reordered = 1
	}
	if rowResult.orderingStatus == "late_stop" {
		result.LateStops = 1
	}
	return result, nil
}

func ApplyPendingAccountingEvents(ctx context.Context, limit int) (AccountingEventApplyResult, error) {
	if DB == nil {
		return AccountingEventApplyResult{}, fmt.Errorf("database not initialized")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if limit <= 0 || limit > 10000 {
		limit = 1000
	}
	rows, err := DB.QueryContext(ctx, accountingEventSelectSQL()+`
		WHERE apply_status IN ('pending', 'error')
		ORDER BY session_key, event_time,
			CASE status_type WHEN 'Accounting-On' THEN 0 WHEN 'Start' THEN 1 WHEN 'Interim-Update' THEN 2 WHEN 'Stop' THEN 3 WHEN 'Accounting-Off' THEN 4 ELSE 5 END,
			id
		LIMIT ?`, limit)
	if err != nil {
		return AccountingEventApplyResult{}, fmt.Errorf("list pending accounting events: %w", err)
	}
	events, err := scanAccountingEventRows(rows)
	rows.Close()
	if err != nil {
		return AccountingEventApplyResult{}, err
	}
	return applyAccountingEvents(ctx, events)
}

func ReplayAccountingEvents(ctx context.Context, limit int, sessionKey string) (AccountingEventApplyResult, error) {
	if DB == nil {
		return AccountingEventApplyResult{}, fmt.Errorf("database not initialized")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if limit <= 0 || limit > 10000 {
		limit = 1000
	}
	events, err := ListAccountingEvents(limit, "", sessionKey)
	if err != nil {
		return AccountingEventApplyResult{}, err
	}
	for _, event := range events {
		if event.ApplyStatus == "ignored" {
			continue
		}
		if _, err := DB.ExecContext(ctx, `UPDATE radius_accounting_events
			SET apply_status = 'pending', applied_at = NULL, last_error = NULL, updated_at = ?
			WHERE id = ?`, formatAccountingTime(time.Now().UTC()), event.ID); err != nil {
			return AccountingEventApplyResult{}, fmt.Errorf("stage accounting event replay: %w", err)
		}
	}
	return ApplyPendingAccountingEvents(ctx, limit)
}

func ListAccountingEvents(limit int, status, sessionKey string) ([]AccountingEventRecord, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	query := accountingEventSelectSQL()
	args := []any{}
	filters := []string{}
	if status = strings.TrimSpace(status); status != "" {
		filters = append(filters, "apply_status = ?")
		args = append(args, status)
	}
	if sessionKey = strings.TrimSpace(sessionKey); sessionKey != "" {
		filters = append(filters, "session_key = ?")
		args = append(args, sessionKey)
	}
	if len(filters) > 0 {
		query += " WHERE " + strings.Join(filters, " AND ")
	}
	query += ` ORDER BY event_time DESC, id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := DB.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list accounting events: %w", err)
	}
	defer rows.Close()
	return scanAccountingEventRows(rows)
}

func GetAccountingEventByEventID(eventID string) (AccountingEventRecord, error) {
	if DB == nil {
		return AccountingEventRecord{}, fmt.Errorf("database not initialized")
	}
	rows, err := DB.Query(accountingEventSelectSQL()+` WHERE event_id = ? LIMIT 1`, strings.TrimSpace(eventID))
	if err != nil {
		return AccountingEventRecord{}, err
	}
	defer rows.Close()
	events, err := scanAccountingEventRows(rows)
	if err != nil {
		return AccountingEventRecord{}, err
	}
	if len(events) == 0 {
		return AccountingEventRecord{}, sql.ErrNoRows
	}
	return events[0], nil
}

func GetAccountingEventSummary(staleAfter time.Duration) (AccountingEventSummary, error) {
	if DB == nil {
		return AccountingEventSummary{}, fmt.Errorf("database not initialized")
	}
	var summary AccountingEventSummary
	err := DB.QueryRow(`SELECT
		COUNT(*),
		COALESCE(SUM(CASE WHEN apply_status = 'pending' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN apply_status = 'applied' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN apply_status = 'error' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN apply_status = 'ignored' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(duplicate_count), 0),
		COALESCE(SUM(CASE WHEN ordering_status IN ('reordered', 'late_start') THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN ordering_status = 'late_stop' THEN 1 ELSE 0 END), 0),
		COALESCE(MAX(arrival_time), ''),
		COALESCE(MAX(COALESCE(applied_at, '')), ''),
		COALESCE((SELECT last_error FROM radius_accounting_events WHERE apply_status = 'error' ORDER BY updated_at DESC, id DESC LIMIT 1), '')
		FROM radius_accounting_events`).Scan(&summary.TotalEvents, &summary.PendingEvents, &summary.AppliedEvents,
		&summary.ErrorEvents, &summary.IgnoredEvents, &summary.DuplicateEvents, &summary.ReorderedEvents,
		&summary.LateStopEvents, &summary.LastEventAt, &summary.LastAppliedAt, &summary.LastError)
	if err != nil {
		if tableMissing(err) {
			return summary, nil
		}
		return AccountingEventSummary{}, fmt.Errorf("summarize accounting events: %w", err)
	}
	if staleAfter > 0 {
		summary.StalePendingEvents = countStaleAccountingEvents(staleAfter)
	}
	return summary, nil
}

func PruneAccountingEvents(retention time.Duration, now time.Time) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	if retention <= 0 {
		return nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	cutoff := formatAccountingTime(now.Add(-retention))
	_, err := DB.Exec(`DELETE FROM radius_accounting_events
		WHERE apply_status IN ('applied', 'ignored')
			AND event_time < ?`, cutoff)
	if err != nil && !tableMissing(err) {
		return fmt.Errorf("prune accounting events: %w", err)
	}
	return nil
}

func FreeRADIUSAccountingEventFromRecord(record FreeRADIUSAccountingRecord) AccountingEventRecord {
	status := inferAccountingStatusFromRadAcct(record)
	eventTime := firstAccountingTime(record.AcctStopTime, record.AcctUpdateTime, record.AcctStartTime, record.CreatedAt)
	event := AccountingEventRecord{
		AcctUniqueID:        strings.TrimSpace(record.AcctUniqueID),
		AcctSessionID:       strings.TrimSpace(record.AcctSessionID),
		SessionKey:          firstNonEmptyString(record.AegisSessionID, record.AcctSessionID, record.AcctUniqueID),
		StatusType:          status,
		EventTime:           eventTime,
		ArrivalTime:         firstAccountingTime(record.UpdatedAt, record.CreatedAt, eventTime),
		Username:            record.Username,
		Realm:               record.Realm,
		NASIPAddress:        record.NASIPAddress,
		NASPortID:           record.NASPortID,
		NASPortType:         record.NASPortType,
		CallingStationID:    record.CallingStationID,
		CalledStationID:     record.CalledStationID,
		FramedIPAddress:     record.FramedIPAddress,
		FramedIPv6Address:   record.FramedIPv6Address,
		FramedIPv6Prefix:    record.FramedIPv6Prefix,
		DelegatedIPv6Prefix: record.DelegatedIPv6Prefix,
		Class:               record.Class,
		AcctInputOctets:     record.AcctInputOctets,
		AcctOutputOctets:    record.AcctOutputOctets,
		AcctSessionTime:     record.AcctSessionTime,
		AcctTerminateCause:  record.AcctTerminateCause,
		Source:              firstNonEmptyString(record.AegisSource, "freeradius-sql"),
	}
	return normalizeAccountingEventRecord(event)
}

func AccountingEventID(event AccountingEventRecord) string {
	event = normalizeAccountingEventRecordForHash(event)
	sum := sha256.Sum256([]byte(strings.Join([]string{
		event.AcctUniqueID,
		event.AcctSessionID,
		event.SessionKey,
		event.StatusType,
		event.EventTime,
		event.NASIPAddress,
		event.NASPortID,
		event.CallingStationID,
		event.CalledStationID,
		fmt.Sprint(event.AcctInputOctets),
		fmt.Sprint(event.AcctOutputOctets),
		fmt.Sprint(event.AcctSessionTime),
		strings.ToLower(event.AcctTerminateCause),
		strings.ToLower(event.Source),
	}, "\x00")))
	return "acct-" + hex.EncodeToString(sum[:])[:32]
}

type accountingApplyRowResult struct {
	created        int
	updated        int
	closed         int
	orderingStatus string
}

func applyAccountingEvents(ctx context.Context, events []AccountingEventRecord) (AccountingEventApplyResult, error) {
	result := AccountingEventApplyResult{Scanned: len(events)}
	for _, event := range events {
		rowResult, err := applyAccountingEventRecord(ctx, event)
		if err != nil {
			result.ErrorCount++
			result.LastError = err.Error()
			_ = markAccountingEventApplied(event.ID, "error", "unknown", "", err.Error())
			continue
		}
		result.Applied++
		result.CreatedSessions += rowResult.created
		result.UpdatedSessions += rowResult.updated
		result.ClosedSessions += rowResult.closed
		if rowResult.orderingStatus == "reordered" || rowResult.orderingStatus == "late_start" {
			result.Reordered++
		}
		if rowResult.orderingStatus == "late_stop" {
			result.LateStops++
		}
	}
	if result.ErrorCount > 0 {
		return result, fmt.Errorf("accounting event apply recorded %d error(s): %s", result.ErrorCount, result.LastError)
	}
	return result, nil
}

func applyAccountingEventRecord(ctx context.Context, event AccountingEventRecord) (accountingApplyRowResult, error) {
	event = normalizeAccountingEventRecord(event)
	if event.ID == 0 {
		stored, err := GetAccountingEventByEventID(event.EventID)
		if err != nil {
			return accountingApplyRowResult{}, err
		}
		event = stored
	}
	orderingStatus := classifyAccountingEventOrdering(event)
	sessionBefore := loadAccountingSessionSnapshot(event.SessionKey)
	after := mergeAccountingSessionSnapshot(sessionBefore, event)
	if err := upsertAccountingSession(ctx, event.SessionKey, after, sessionBefore.exists); err != nil {
		return accountingApplyRowResult{}, err
	}
	radacct := freeRADIUSRecordFromAccountingEvent(event, after)
	radacct.AegisReconcileStatus = "reconciled"
	radacct.AegisReconciledAt = formatAccountingTime(time.Now().UTC())
	if _, err := UpsertFreeRADIUSAccountingRecord(ctx, radacct); err != nil {
		return accountingApplyRowResult{}, err
	}
	if err := markAccountingEventApplied(event.ID, "applied", orderingStatus, formatAccountingTime(time.Now().UTC()), ""); err != nil {
		return accountingApplyRowResult{}, err
	}
	out := accountingApplyRowResult{orderingStatus: orderingStatus}
	if sessionBefore.exists {
		out.updated = 1
	} else {
		out.created = 1
	}
	if event.StatusType == "Stop" {
		out.closed = 1
	}
	return out, nil
}

func classifyAccountingEventOrdering(event AccountingEventRecord) string {
	eventTime := parseAccountingTime(event.EventTime)
	if eventTime.IsZero() || DB == nil {
		return "unknown"
	}
	session := loadAccountingSessionSnapshot(event.SessionKey)
	if event.StatusType == "Stop" && session.exists && strings.TrimSpace(session.endTime) != "" {
		endTime := parseAccountingTime(session.endTime)
		if endTime.IsZero() || !endTime.Equal(eventTime) {
			return "late_stop"
		}
	}
	var latest string
	_ = DB.QueryRow(`SELECT COALESCE(MAX(event_time), '') FROM radius_accounting_events
		WHERE session_key = ? AND apply_status = 'applied' AND id <> ?`, event.SessionKey, event.ID).Scan(&latest)
	latestTime := parseAccountingTime(latest)
	if !latestTime.IsZero() && eventTime.Before(latestTime) {
		if event.StatusType == "Start" {
			return "late_start"
		}
		return "reordered"
	}
	return "in_order"
}

func loadAccountingSessionSnapshot(sessionID string) accountingSessionSnapshot {
	var out accountingSessionSnapshot
	if DB == nil || strings.TrimSpace(sessionID) == "" {
		return out
	}
	var (
		username, mac, ip, authMethod, startTime, lastActivity, endTime, stopReason sql.NullString
		radiusSessionID, calledStationID, nasIdentifier, radiusClass                sql.NullString
		bytesIn, bytesOut, acctSessionTime                                          sql.NullInt64
	)
	err := DB.QueryRow(`SELECT COALESCE(username, ''), COALESCE(mac, ''), COALESCE(ip, ''),
		COALESCE(auth_method, ''), COALESCE(CAST(start_time AS TEXT), ''),
		COALESCE(CAST(last_activity AS TEXT), ''), COALESCE(CAST(end_time AS TEXT), ''),
		COALESCE(stop_reason, ''), COALESCE(radius_session_id, ''),
		COALESCE(bytes_in, 0), COALESCE(bytes_out, 0), COALESCE(acct_session_time, 0),
		COALESCE(called_station_id, ''), COALESCE(nas_identifier, ''), COALESCE(radius_class, '')
		FROM sessions WHERE id = ?`, sessionID).Scan(&username, &mac, &ip, &authMethod, &startTime, &lastActivity,
		&endTime, &stopReason, &radiusSessionID, &bytesIn, &bytesOut, &acctSessionTime,
		&calledStationID, &nasIdentifier, &radiusClass)
	if err != nil {
		return out
	}
	out.exists = true
	out.username = username.String
	out.mac = mac.String
	out.ip = ip.String
	out.authMethod = authMethod.String
	out.startTime = normalizeAccountingTimeString(startTime.String)
	out.lastActivity = normalizeAccountingTimeString(lastActivity.String)
	out.endTime = normalizeAccountingTimeString(endTime.String)
	out.stopReason = stopReason.String
	out.radiusSessionID = radiusSessionID.String
	out.bytesIn = uint64(maxInt64(bytesIn.Int64, 0))
	out.bytesOut = uint64(maxInt64(bytesOut.Int64, 0))
	out.acctSessionTime = maxInt64(acctSessionTime.Int64, 0)
	out.calledStationID = calledStationID.String
	out.nasIdentifier = nasIdentifier.String
	out.radiusClass = radiusClass.String
	return out
}

func mergeAccountingSessionSnapshot(current accountingSessionSnapshot, event AccountingEventRecord) accountingSessionSnapshot {
	eventTime := normalizeAccountingTimeString(event.EventTime)
	if eventTime == "" {
		eventTime = formatAccountingTime(time.Now().UTC())
	}
	start := current.startTime
	if start == "" {
		start = eventTime
	}
	if event.StatusType != "Start" && event.AcctSessionTime > 0 {
		derived := parseAccountingTime(eventTime).Add(-time.Duration(event.AcctSessionTime) * time.Second)
		if !derived.IsZero() {
			start = minAccountingTime(start, formatAccountingTime(derived))
		}
	}
	if event.StatusType == "Start" {
		start = minAccountingTime(start, eventTime)
	}
	lastActivity := maxAccountingTime(current.lastActivity, eventTime)
	if lastActivity == "" {
		lastActivity = eventTime
	}
	endTime := current.endTime
	stopReason := current.stopReason
	if event.StatusType == "Stop" {
		endTime = maxAccountingTime(endTime, eventTime)
		if strings.TrimSpace(event.AcctTerminateCause) != "" && endTime == eventTime {
			stopReason = strings.TrimSpace(event.AcctTerminateCause)
		} else if stopReason == "" {
			stopReason = "accounting-stop"
		}
	}
	return accountingSessionSnapshot{
		exists:          current.exists,
		username:        firstNonEmptyString(event.Username, current.username, "unknown"),
		mac:             firstNonEmptyString(event.CallingStationID, current.mac),
		ip:              firstNonEmptyString(event.FramedIPAddress, current.ip),
		authMethod:      firstNonEmptyString(current.authMethod, "radius-accounting"),
		startTime:       start,
		lastActivity:    lastActivity,
		endTime:         endTime,
		stopReason:      stopReason,
		radiusSessionID: firstNonEmptyString(event.AcctSessionID, current.radiusSessionID),
		bytesIn:         maxUint64(current.bytesIn, event.AcctInputOctets),
		bytesOut:        maxUint64(current.bytesOut, event.AcctOutputOctets),
		acctSessionTime: maxInt64(current.acctSessionTime, event.AcctSessionTime),
		calledStationID: firstNonEmptyString(event.CalledStationID, current.calledStationID),
		nasIdentifier:   firstNonEmptyString(event.NASIPAddress, current.nasIdentifier),
		radiusClass:     firstNonEmptyString(event.Class, current.radiusClass),
	}
}

func upsertAccountingSession(ctx context.Context, sessionID string, session accountingSessionSnapshot, existed bool) error {
	if ctx == nil {
		ctx = context.Background()
	}
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return fmt.Errorf("session id cannot be empty")
	}
	if !existed {
		_, err := DB.ExecContext(ctx, `INSERT INTO sessions (
			id, username, mac, ip, auth_method, start_time, last_activity, end_time, stop_reason,
			radius_session_id, bytes_in, bytes_out, acct_session_time, called_station_id, nas_identifier, radius_class
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			sessionID, firstNonEmptyString(session.username, "unknown"), nullIfEmpty(session.mac), nullIfEmpty(session.ip),
			nullIfEmpty(session.authMethod), session.startTime, nullIfEmpty(session.lastActivity), nullIfEmpty(session.endTime),
			nullIfEmpty(session.stopReason), nullIfEmpty(session.radiusSessionID), boundedUint64ToInt64(session.bytesIn),
			boundedUint64ToInt64(session.bytesOut), session.acctSessionTime, nullIfEmpty(session.calledStationID),
			nullIfEmpty(session.nasIdentifier), nullIfEmpty(session.radiusClass))
		return err
	}
	_, err := DB.ExecContext(ctx, `UPDATE sessions SET
		username = ?, mac = ?, ip = ?, auth_method = ?, start_time = ?, last_activity = ?,
		end_time = ?, stop_reason = ?, radius_session_id = ?, bytes_in = ?, bytes_out = ?,
		acct_session_time = ?, called_station_id = ?, nas_identifier = ?, radius_class = ?
		WHERE id = ?`,
		firstNonEmptyString(session.username, "unknown"), nullIfEmpty(session.mac), nullIfEmpty(session.ip),
		nullIfEmpty(session.authMethod), session.startTime, nullIfEmpty(session.lastActivity), nullIfEmpty(session.endTime),
		nullIfEmpty(session.stopReason), nullIfEmpty(session.radiusSessionID), boundedUint64ToInt64(session.bytesIn),
		boundedUint64ToInt64(session.bytesOut), session.acctSessionTime, nullIfEmpty(session.calledStationID),
		nullIfEmpty(session.nasIdentifier), nullIfEmpty(session.radiusClass), sessionID)
	return err
}

func markAccountingEventApplied(id int, applyStatus, orderingStatus, appliedAt, lastError string) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	if orderingStatus == "" {
		orderingStatus = "in_order"
	}
	_, err := DB.Exec(`UPDATE radius_accounting_events
		SET apply_status = ?, ordering_status = ?, applied_at = ?, last_error = ?, updated_at = ?
		WHERE id = ?`,
		applyStatus, orderingStatus, nullIfEmpty(appliedAt), nullIfEmpty(lastError), formatAccountingTime(time.Now().UTC()), id)
	return err
}

func freeRADIUSRecordFromAccountingEvent(event AccountingEventRecord, session accountingSessionSnapshot) FreeRADIUSAccountingRecord {
	record := FreeRADIUSAccountingRecord{
		AcctSessionID:        event.AcctSessionID,
		AcctUniqueID:         event.AcctUniqueID,
		Username:             event.Username,
		Realm:                event.Realm,
		NASIPAddress:         event.NASIPAddress,
		NASPortID:            event.NASPortID,
		NASPortType:          event.NASPortType,
		AcctUpdateTime:       event.EventTime,
		AcctSessionTime:      event.AcctSessionTime,
		AcctAuthentic:        "RADIUS",
		AcctInputOctets:      session.bytesIn,
		AcctOutputOctets:     session.bytesOut,
		CalledStationID:      event.CalledStationID,
		CallingStationID:     event.CallingStationID,
		AcctTerminateCause:   event.AcctTerminateCause,
		FramedIPAddress:      event.FramedIPAddress,
		FramedIPv6Address:    event.FramedIPv6Address,
		FramedIPv6Prefix:     event.FramedIPv6Prefix,
		DelegatedIPv6Prefix:  event.DelegatedIPv6Prefix,
		Class:                event.Class,
		AegisSessionID:       event.SessionKey,
		AegisSource:          event.Source,
		AegisReconcileStatus: "pending",
	}
	if record.AcctSessionID == "" {
		record.AcctSessionID = event.SessionKey
	}
	if record.AcctUniqueID == "" {
		record.AcctUniqueID = FreeRADIUSAcctUniqueID(record.AcctSessionID, record.Username, record.NASIPAddress, record.NASPortID, record.CallingStationID)
	}
	if session.startTime != "" {
		record.AcctStartTime = session.startTime
	}
	if event.StatusType == "Start" {
		record.AcctStartTime = event.EventTime
	}
	if event.StatusType == "Stop" {
		record.AcctStopTime = event.EventTime
		if record.AcctTerminateCause == "" {
			record.AcctTerminateCause = firstNonEmptyString(session.stopReason, "accounting-stop")
		}
	}
	return record
}

func accountingEventSelectSQL() string {
	return `SELECT id, event_id, acct_unique_id, acct_session_id, session_key, status_type,
		COALESCE(CAST(event_time AS TEXT), ''), COALESCE(CAST(arrival_time AS TEXT), ''),
		COALESCE(ordinal, 0), COALESCE(username, ''), COALESCE(realm, ''),
		COALESCE(nas_ip_address, ''), COALESCE(nas_port_id, ''), COALESCE(nas_port_type, ''),
		COALESCE(calling_station_id, ''), COALESCE(called_station_id, ''),
		COALESCE(framed_ip_address, ''), COALESCE(framed_ipv6_address, ''),
		COALESCE(framed_ipv6_prefix, ''), COALESCE(delegated_ipv6_prefix, ''),
		COALESCE(class, ''), COALESCE(acct_input_octets, 0), COALESCE(acct_output_octets, 0),
		COALESCE(acct_session_time, 0), COALESCE(acct_terminate_cause, ''), source,
		fingerprint, COALESCE(payload_json, '{}'), apply_status, ordering_status,
		COALESCE(duplicate_count, 0), COALESCE(CAST(last_seen_at AS TEXT), ''),
		COALESCE(CAST(applied_at AS TEXT), ''), COALESCE(last_error, ''),
		COALESCE(CAST(created_at AS TEXT), ''), COALESCE(CAST(updated_at AS TEXT), '')
		FROM radius_accounting_events`
}

func scanAccountingEventRows(rows *sql.Rows) ([]AccountingEventRecord, error) {
	events := []AccountingEventRecord{}
	for rows.Next() {
		var event AccountingEventRecord
		var inputOctets, outputOctets int64
		if err := rows.Scan(&event.ID, &event.EventID, &event.AcctUniqueID, &event.AcctSessionID,
			&event.SessionKey, &event.StatusType, &event.EventTime, &event.ArrivalTime,
			&event.Ordinal, &event.Username, &event.Realm, &event.NASIPAddress, &event.NASPortID,
			&event.NASPortType, &event.CallingStationID, &event.CalledStationID, &event.FramedIPAddress,
			&event.FramedIPv6Address, &event.FramedIPv6Prefix, &event.DelegatedIPv6Prefix, &event.Class,
			&inputOctets, &outputOctets, &event.AcctSessionTime, &event.AcctTerminateCause, &event.Source,
			&event.Fingerprint, &event.PayloadJSON, &event.ApplyStatus, &event.OrderingStatus,
			&event.DuplicateCount, &event.LastSeenAt, &event.AppliedAt, &event.LastError,
			&event.CreatedAt, &event.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan accounting event: %w", err)
		}
		if inputOctets > 0 {
			event.AcctInputOctets = uint64(inputOctets)
		}
		if outputOctets > 0 {
			event.AcctOutputOctets = uint64(outputOctets)
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func normalizeAccountingEventRecord(event AccountingEventRecord) AccountingEventRecord {
	event = normalizeAccountingEventRecordForHash(event)
	now := formatAccountingTime(time.Now().UTC())
	if event.EventTime == "" {
		event.EventTime = now
	}
	if event.ArrivalTime == "" {
		event.ArrivalTime = now
	}
	if event.AcctUniqueID == "" {
		event.AcctUniqueID = FreeRADIUSAcctUniqueID(event.AcctSessionID, event.Username, event.NASIPAddress, event.NASPortID, event.CallingStationID)
	}
	if event.AcctSessionID == "" {
		event.AcctSessionID = event.AcctUniqueID
	}
	if event.SessionKey == "" {
		event.SessionKey = firstNonEmptyString(event.AcctSessionID, event.AcctUniqueID)
	}
	if event.EventID == "" {
		event.EventID = AccountingEventID(event)
	}
	if event.Fingerprint == "" {
		event.Fingerprint = accountingEventFingerprint(event)
	}
	if event.PayloadJSON == "" {
		event.PayloadJSON = accountingEventPayloadJSON(event)
	}
	if event.ApplyStatus == "" {
		event.ApplyStatus = "pending"
	}
	if event.OrderingStatus == "" {
		event.OrderingStatus = "in_order"
	}
	if event.LastSeenAt == "" {
		event.LastSeenAt = event.ArrivalTime
	}
	if event.CreatedAt == "" {
		event.CreatedAt = now
	}
	event.UpdatedAt = now
	return event
}

func normalizeAccountingEventRecordForHash(event AccountingEventRecord) AccountingEventRecord {
	event.EventID = strings.TrimSpace(event.EventID)
	event.AcctUniqueID = strings.TrimSpace(event.AcctUniqueID)
	event.AcctSessionID = strings.TrimSpace(event.AcctSessionID)
	event.SessionKey = strings.TrimSpace(event.SessionKey)
	event.StatusType = canonicalAccountingStatus(event.StatusType)
	event.EventTime = normalizeAccountingTimeString(event.EventTime)
	event.ArrivalTime = normalizeAccountingTimeString(event.ArrivalTime)
	event.Username = strings.TrimSpace(event.Username)
	event.Realm = strings.TrimSpace(event.Realm)
	event.NASIPAddress = strings.TrimSpace(event.NASIPAddress)
	event.NASPortID = strings.TrimSpace(event.NASPortID)
	event.NASPortType = strings.TrimSpace(event.NASPortType)
	event.CallingStationID = strings.TrimSpace(event.CallingStationID)
	event.CalledStationID = strings.TrimSpace(event.CalledStationID)
	event.FramedIPAddress = strings.TrimSpace(event.FramedIPAddress)
	event.FramedIPv6Address = strings.TrimSpace(event.FramedIPv6Address)
	event.FramedIPv6Prefix = strings.TrimSpace(event.FramedIPv6Prefix)
	event.DelegatedIPv6Prefix = strings.TrimSpace(event.DelegatedIPv6Prefix)
	event.Class = strings.TrimSpace(event.Class)
	event.AcctTerminateCause = strings.TrimSpace(event.AcctTerminateCause)
	event.Source = firstNonEmptyString(event.Source, "aegis")
	event.ApplyStatus = strings.TrimSpace(event.ApplyStatus)
	event.OrderingStatus = strings.TrimSpace(event.OrderingStatus)
	if event.AcctSessionTime < 0 {
		event.AcctSessionTime = 0
	}
	return event
}

func canonicalAccountingStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "start", "acct-start":
		return "Start"
	case "interim-update", "interim", "update", "acct-interim-update":
		return "Interim-Update"
	case "stop", "acct-stop":
		return "Stop"
	case "accounting-on", "acct-on":
		return "Accounting-On"
	case "accounting-off", "acct-off":
		return "Accounting-Off"
	default:
		return "Unknown"
	}
}

func inferAccountingStatusFromRadAcct(record FreeRADIUSAccountingRecord) string {
	switch {
	case strings.TrimSpace(record.AcctStopTime) != "":
		return "Stop"
	case strings.TrimSpace(record.AcctStartTime) != "" && strings.TrimSpace(record.AcctUpdateTime) == strings.TrimSpace(record.AcctStartTime) &&
		record.AcctInputOctets == 0 && record.AcctOutputOctets == 0 && record.AcctSessionTime == 0:
		return "Start"
	case strings.TrimSpace(record.AcctStartTime) != "" && strings.TrimSpace(record.AcctUpdateTime) == "":
		return "Start"
	default:
		return "Interim-Update"
	}
}

func accountingEventFingerprint(event AccountingEventRecord) string {
	event = normalizeAccountingEventRecordForHash(event)
	sum := sha256.Sum256([]byte(strings.Join([]string{
		event.AcctUniqueID, event.StatusType, event.EventTime, event.Username, event.NASIPAddress,
		event.NASPortID, event.CallingStationID, event.CalledStationID, event.FramedIPAddress,
		fmt.Sprint(event.AcctInputOctets), fmt.Sprint(event.AcctOutputOctets), fmt.Sprint(event.AcctSessionTime),
		event.AcctTerminateCause,
	}, "\x00")))
	return hex.EncodeToString(sum[:])
}

func accountingEventPayloadJSON(event AccountingEventRecord) string {
	payload := map[string]any{
		"acct_unique_id":          event.AcctUniqueID,
		"acct_session_id":         event.AcctSessionID,
		"status_type":             event.StatusType,
		"event_time":              event.EventTime,
		"username":                event.Username,
		"realm":                   event.Realm,
		"nas_ip_address":          event.NASIPAddress,
		"nas_port_id":             event.NASPortID,
		"calling_station_id":      event.CallingStationID,
		"called_station_id":       event.CalledStationID,
		"framed_ip_address":       event.FramedIPAddress,
		"framed_ipv6_address":     event.FramedIPv6Address,
		"framed_ipv6_prefix":      event.FramedIPv6Prefix,
		"delegated_ipv6_prefix":   event.DelegatedIPv6Prefix,
		"acct_input_octets":       event.AcctInputOctets,
		"acct_output_octets":      event.AcctOutputOctets,
		"acct_session_time":       event.AcctSessionTime,
		"acct_terminate_cause":    event.AcctTerminateCause,
		"source":                  event.Source,
		"nas_0036_schema_version": 1,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}

func minAccountingTime(a, b string) string {
	a = normalizeAccountingTimeString(a)
	b = normalizeAccountingTimeString(b)
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	pa := parseAccountingTime(a)
	pb := parseAccountingTime(b)
	if !pa.IsZero() && !pb.IsZero() {
		if pb.Before(pa) {
			return b
		}
		return a
	}
	if b < a {
		return b
	}
	return a
}

func maxAccountingTime(a, b string) string {
	a = normalizeAccountingTimeString(a)
	b = normalizeAccountingTimeString(b)
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	pa := parseAccountingTime(a)
	pb := parseAccountingTime(b)
	if !pa.IsZero() && !pb.IsZero() {
		if pb.After(pa) {
			return b
		}
		return a
	}
	if b > a {
		return b
	}
	return a
}

func countStaleAccountingEvents(staleAfter time.Duration) int {
	rows, err := DB.Query(`SELECT COALESCE(CAST(event_time AS TEXT), COALESCE(CAST(created_at AS TEXT), ''))
		FROM radius_accounting_events WHERE apply_status = 'pending' LIMIT 5000`)
	if err != nil {
		return 0
	}
	defer rows.Close()
	cutoff := time.Now().UTC().Add(-staleAfter)
	count := 0
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			continue
		}
		parsed := parseAccountingTime(raw)
		if parsed.IsZero() || parsed.Before(cutoff) {
			count++
		}
	}
	return count
}

func maxUint64(a, b uint64) uint64 {
	if b > a {
		return b
	}
	return a
}

func maxInt64(a, b int64) int64 {
	if b > a {
		return b
	}
	return a
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
