package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"
)

type FreeRADIUSAccountingRecord struct {
	RadAcctID            int    `json:"radacctid"`
	AcctSessionID        string `json:"acctsessionid"`
	AcctUniqueID         string `json:"acctuniqueid"`
	Username             string `json:"username,omitempty"`
	Realm                string `json:"realm,omitempty"`
	NASIPAddress         string `json:"nasipaddress,omitempty"`
	NASPortID            string `json:"nasportid,omitempty"`
	NASPortType          string `json:"nasporttype,omitempty"`
	AcctStartTime        string `json:"acctstarttime,omitempty"`
	AcctUpdateTime       string `json:"acctupdatetime,omitempty"`
	AcctStopTime         string `json:"acctstoptime,omitempty"`
	AcctInterval         int64  `json:"acctinterval"`
	AcctSessionTime      int64  `json:"acctsessiontime"`
	AcctAuthentic        string `json:"acctauthentic,omitempty"`
	ConnectInfoStart     string `json:"connectinfo_start,omitempty"`
	ConnectInfoStop      string `json:"connectinfo_stop,omitempty"`
	AcctInputOctets      uint64 `json:"acctinputoctets"`
	AcctOutputOctets     uint64 `json:"acctoutputoctets"`
	CalledStationID      string `json:"calledstationid,omitempty"`
	CallingStationID     string `json:"callingstationid,omitempty"`
	AcctTerminateCause   string `json:"acctterminatecause,omitempty"`
	ServiceType          string `json:"servicetype,omitempty"`
	FramedProtocol       string `json:"framedprotocol,omitempty"`
	FramedIPAddress      string `json:"framedipaddress,omitempty"`
	FramedIPv6Address    string `json:"framedipv6address,omitempty"`
	FramedIPv6Prefix     string `json:"framedipv6prefix,omitempty"`
	FramedInterfaceID    string `json:"framedinterfaceid,omitempty"`
	DelegatedIPv6Prefix  string `json:"delegatedipv6prefix,omitempty"`
	Class                string `json:"class,omitempty"`
	AegisSessionID       string `json:"aegis_session_id,omitempty"`
	AegisSource          string `json:"aegis_source,omitempty"`
	AegisReconcileStatus string `json:"aegis_reconcile_status"`
	AegisReconcileError  string `json:"aegis_reconcile_error,omitempty"`
	AegisReconciledAt    string `json:"aegis_reconciled_at,omitempty"`
	CreatedAt            string `json:"created_at,omitempty"`
	UpdatedAt            string `json:"updated_at,omitempty"`
}

type FreeRADIUSPostAuthRecord struct {
	ID                   int    `json:"id"`
	Username             string `json:"username"`
	Pass                 string `json:"pass,omitempty"`
	Reply                string `json:"reply,omitempty"`
	AuthDate             string `json:"authdate,omitempty"`
	Class                string `json:"class,omitempty"`
	CalledStationID      string `json:"calledstationid,omitempty"`
	CallingStationID     string `json:"callingstationid,omitempty"`
	NASIPAddress         string `json:"nasipaddress,omitempty"`
	NASIdentifier        string `json:"nasidentifier,omitempty"`
	PacketType           string `json:"packet_type,omitempty"`
	Realm                string `json:"realm,omitempty"`
	Reason               string `json:"reason,omitempty"`
	AegisSource          string `json:"aegis_source,omitempty"`
	AegisReconcileStatus string `json:"aegis_reconcile_status,omitempty"`
	CreatedAt            string `json:"created_at,omitempty"`
}

type FreeRADIUSAccountingSummary struct {
	RadAcctRows      int    `json:"radacct_rows"`
	OpenSessions     int    `json:"open_sessions"`
	ClosedSessions   int    `json:"closed_sessions"`
	ReconciledRows   int    `json:"reconciled_rows"`
	PendingRows      int    `json:"pending_rows"`
	ErrorRows        int    `json:"error_rows"`
	IgnoredRows      int    `json:"ignored_rows"`
	StalePendingRows int    `json:"stale_pending_rows"`
	PostAuthRows     int    `json:"radpostauth_rows"`
	SessionRows      int    `json:"session_rows"`
	LastAccountingAt string `json:"last_accounting_at,omitempty"`
	LastReconciledAt string `json:"last_reconciled_at,omitempty"`
	LastPostAuthAt   string `json:"last_postauth_at,omitempty"`
	LastEventAt      string `json:"last_event_at,omitempty"`
	LastEventStatus  string `json:"last_event_status,omitempty"`
	LastEventError   string `json:"last_event_error,omitempty"`
}

type FreeRADIUSAccountingReconcileResult struct {
	EventID         string `json:"event_id"`
	Status          string `json:"status"`
	Scanned         int    `json:"scanned"`
	Reconciled      int    `json:"reconciled"`
	CreatedSessions int    `json:"created_sessions"`
	UpdatedSessions int    `json:"updated_sessions"`
	ClosedSessions  int    `json:"closed_sessions"`
	ErrorCount      int    `json:"error_count"`
	LastError       string `json:"last_error,omitempty"`
	CreatedAt       string `json:"created_at"`
}

func UpsertFreeRADIUSAccountingRecord(ctx context.Context, rec FreeRADIUSAccountingRecord) (FreeRADIUSAccountingRecord, error) {
	if DB == nil {
		return FreeRADIUSAccountingRecord{}, fmt.Errorf("database not initialized")
	}
	rec = normalizeFreeRADIUSAccountingRecord(rec)
	if rec.AcctUniqueID == "" {
		return FreeRADIUSAccountingRecord{}, fmt.Errorf("acctuniqueid cannot be empty")
	}
	now := formatAccountingTime(time.Now().UTC())
	if rec.CreatedAt == "" {
		rec.CreatedAt = now
	}
	rec.UpdatedAt = now
	if rec.AegisReconcileStatus == "" {
		rec.AegisReconcileStatus = "pending"
	}
	query := `INSERT INTO radacct (
		acctsessionid, acctuniqueid, username, realm, nasipaddress, nasportid, nasporttype,
		acctstarttime, acctupdatetime, acctstoptime, acctinterval, acctsessiontime, acctauthentic,
		connectinfo_start, connectinfo_stop, acctinputoctets, acctoutputoctets, calledstationid,
		callingstationid, acctterminatecause, servicetype, framedprotocol, framedipaddress,
		framedipv6address, framedipv6prefix, framedinterfaceid, delegatedipv6prefix, class,
		aegis_session_id, aegis_source, aegis_reconcile_status, aegis_reconcile_error,
		aegis_reconciled_at, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(acctuniqueid) DO UPDATE SET
		acctsessionid = excluded.acctsessionid,
		username = excluded.username,
		realm = excluded.realm,
		nasipaddress = excluded.nasipaddress,
		nasportid = excluded.nasportid,
		nasporttype = excluded.nasporttype,
		acctstarttime = COALESCE(radacct.acctstarttime, excluded.acctstarttime),
		acctupdatetime = excluded.acctupdatetime,
		acctstoptime = COALESCE(excluded.acctstoptime, radacct.acctstoptime),
		acctinterval = excluded.acctinterval,
		acctsessiontime = excluded.acctsessiontime,
		acctauthentic = excluded.acctauthentic,
		connectinfo_start = COALESCE(radacct.connectinfo_start, excluded.connectinfo_start),
		connectinfo_stop = COALESCE(excluded.connectinfo_stop, radacct.connectinfo_stop),
		acctinputoctets = excluded.acctinputoctets,
		acctoutputoctets = excluded.acctoutputoctets,
		calledstationid = excluded.calledstationid,
		callingstationid = excluded.callingstationid,
		acctterminatecause = COALESCE(excluded.acctterminatecause, radacct.acctterminatecause),
		servicetype = excluded.servicetype,
		framedprotocol = excluded.framedprotocol,
		framedipaddress = excluded.framedipaddress,
		framedipv6address = excluded.framedipv6address,
		framedipv6prefix = excluded.framedipv6prefix,
		framedinterfaceid = excluded.framedinterfaceid,
		delegatedipv6prefix = excluded.delegatedipv6prefix,
		class = excluded.class,
		aegis_session_id = COALESCE(excluded.aegis_session_id, radacct.aegis_session_id),
		aegis_source = excluded.aegis_source,
		aegis_reconcile_status = excluded.aegis_reconcile_status,
		aegis_reconcile_error = excluded.aegis_reconcile_error,
		aegis_reconciled_at = excluded.aegis_reconciled_at,
		updated_at = excluded.updated_at`
	if _, err := DB.ExecContext(ctx, query, freeRADIUSAccountingArgs(rec)...); err != nil {
		return FreeRADIUSAccountingRecord{}, fmt.Errorf("upsert radacct: %w", err)
	}
	return GetFreeRADIUSAccountingByUniqueID(rec.AcctUniqueID)
}

func GetFreeRADIUSAccountingByUniqueID(acctUniqueID string) (FreeRADIUSAccountingRecord, error) {
	if DB == nil {
		return FreeRADIUSAccountingRecord{}, fmt.Errorf("database not initialized")
	}
	rows, err := DB.Query(freeRADIUSAccountingSelectSQL()+` WHERE acctuniqueid = ? LIMIT 1`, strings.TrimSpace(acctUniqueID))
	if err != nil {
		return FreeRADIUSAccountingRecord{}, err
	}
	defer rows.Close()
	records, err := scanFreeRADIUSAccountingRows(rows)
	if err != nil {
		return FreeRADIUSAccountingRecord{}, err
	}
	if len(records) == 0 {
		return FreeRADIUSAccountingRecord{}, sql.ErrNoRows
	}
	return records[0], nil
}

func ListFreeRADIUSAccounting(limit int, status string) ([]FreeRADIUSAccountingRecord, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	query := freeRADIUSAccountingSelectSQL()
	args := []any{}
	if status = strings.TrimSpace(status); status != "" {
		query += ` WHERE aegis_reconcile_status = ?`
		args = append(args, status)
	}
	query += ` ORDER BY COALESCE(acctupdatetime, acctstarttime, created_at) DESC, radacctid DESC LIMIT ?`
	args = append(args, limit)
	rows, err := DB.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list radacct: %w", err)
	}
	defer rows.Close()
	return scanFreeRADIUSAccountingRows(rows)
}

func RecordFreeRADIUSPostAuth(record FreeRADIUSPostAuthRecord) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	record.Username = strings.TrimSpace(record.Username)
	if record.Username == "" {
		return fmt.Errorf("username is required")
	}
	if record.AuthDate == "" {
		record.AuthDate = formatAccountingTime(time.Now().UTC())
	}
	if record.AegisSource == "" {
		record.AegisSource = "aegis-broker"
	}
	if record.AegisReconcileStatus == "" {
		record.AegisReconcileStatus = "recorded"
	}
	_, err := DB.Exec(`INSERT INTO radpostauth (
		username, pass, reply, authdate, class, calledstationid, callingstationid, nasipaddress,
		nasidentifier, packet_type, realm, reason, aegis_source, aegis_reconcile_status, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.Username, nullIfEmpty(record.Pass), nullIfEmpty(record.Reply), record.AuthDate, nullIfEmpty(record.Class),
		nullIfEmpty(record.CalledStationID), nullIfEmpty(record.CallingStationID), nullIfEmpty(record.NASIPAddress),
		nullIfEmpty(record.NASIdentifier), nullIfEmpty(record.PacketType), nullIfEmpty(record.Realm), nullIfEmpty(record.Reason),
		record.AegisSource, record.AegisReconcileStatus, formatAccountingTime(time.Now().UTC()))
	if err != nil {
		return fmt.Errorf("record radpostauth: %w", err)
	}
	return nil
}

func ReconcileFreeRADIUSAccounting(limit int) (FreeRADIUSAccountingReconcileResult, error) {
	if DB == nil {
		return FreeRADIUSAccountingReconcileResult{}, fmt.Errorf("database not initialized")
	}
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	rows, err := DB.Query(freeRADIUSAccountingSelectSQL()+`
		WHERE COALESCE(aegis_reconcile_status, 'pending') IN ('pending', 'error')
		ORDER BY radacctid LIMIT ?`, limit)
	if err != nil {
		return FreeRADIUSAccountingReconcileResult{}, fmt.Errorf("load radacct pending rows: %w", err)
	}
	records, err := scanFreeRADIUSAccountingRows(rows)
	rows.Close()
	if err != nil {
		return FreeRADIUSAccountingReconcileResult{}, err
	}
	result := FreeRADIUSAccountingReconcileResult{
		Scanned:   len(records),
		Status:    "ok",
		CreatedAt: formatAccountingTime(time.Now().UTC()),
	}
	for _, record := range records {
		rowResult, err := applyFreeRADIUSAccountingRecord(record)
		if err != nil {
			result.ErrorCount++
			result.LastError = err.Error()
			_ = markFreeRADIUSAccountingReconciled(record.RadAcctID, "", "error", err.Error(), "")
			continue
		}
		result.Reconciled++
		result.CreatedSessions += rowResult.created
		result.UpdatedSessions += rowResult.updated
		result.ClosedSessions += rowResult.closed
	}
	if result.ErrorCount > 0 {
		result.Status = "degraded"
	}
	result.EventID = freeRADIUSAccountingEventID(result)
	if err := recordFreeRADIUSAccountingReconcileEvent(result); err != nil {
		return result, err
	}
	return result, nil
}

func GetFreeRADIUSAccountingSummary(staleAfter time.Duration) (FreeRADIUSAccountingSummary, error) {
	if DB == nil {
		return FreeRADIUSAccountingSummary{}, fmt.Errorf("database not initialized")
	}
	var summary FreeRADIUSAccountingSummary
	err := DB.QueryRow(`SELECT
		COUNT(*),
		COALESCE(SUM(CASE WHEN acctstoptime IS NULL OR acctstoptime = '' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN acctstoptime IS NOT NULL AND acctstoptime <> '' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN aegis_reconcile_status = 'reconciled' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN aegis_reconcile_status = 'pending' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN aegis_reconcile_status = 'error' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN aegis_reconcile_status = 'ignored' THEN 1 ELSE 0 END), 0),
		COALESCE(MAX(COALESCE(acctupdatetime, acctstoptime, acctstarttime, created_at)), ''),
		COALESCE(MAX(COALESCE(aegis_reconciled_at, '')), '')
		FROM radacct`).Scan(&summary.RadAcctRows, &summary.OpenSessions, &summary.ClosedSessions, &summary.ReconciledRows,
		&summary.PendingRows, &summary.ErrorRows, &summary.IgnoredRows, &summary.LastAccountingAt, &summary.LastReconciledAt)
	if err != nil {
		if tableMissing(err) {
			return summary, nil
		}
		return FreeRADIUSAccountingSummary{}, fmt.Errorf("summarize radacct: %w", err)
	}
	_ = DB.QueryRow(`SELECT COUNT(*), COALESCE(MAX(authdate), '') FROM radpostauth`).Scan(&summary.PostAuthRows, &summary.LastPostAuthAt)
	_ = DB.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&summary.SessionRows)
	_ = DB.QueryRow(`SELECT COALESCE(MAX(created_at), ''), COALESCE((SELECT status FROM radius_sql_accounting_reconcile_events ORDER BY created_at DESC, id DESC LIMIT 1), ''), COALESCE((SELECT last_error FROM radius_sql_accounting_reconcile_events ORDER BY created_at DESC, id DESC LIMIT 1), '') FROM radius_sql_accounting_reconcile_events`).Scan(&summary.LastEventAt, &summary.LastEventStatus, &summary.LastEventError)
	if staleAfter > 0 {
		summary.StalePendingRows = countStaleFreeRADIUSAccountingRows(staleAfter)
	}
	return summary, nil
}

func PruneFreeRADIUSSQLAccounting(accountingRetention, postAuthRetention time.Duration, now time.Time) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if accountingRetention > 0 {
		cutoff := formatAccountingTime(now.Add(-accountingRetention))
		if _, err := DB.Exec(`DELETE FROM radacct
			WHERE COALESCE(aegis_reconcile_status, 'pending') IN ('reconciled', 'ignored')
				AND COALESCE(acctstoptime, acctupdatetime, acctstarttime, created_at) < ?`, cutoff); err != nil && !tableMissing(err) {
			return fmt.Errorf("prune radacct: %w", err)
		}
		if _, err := DB.Exec(`DELETE FROM radius_sql_accounting_reconcile_events WHERE created_at < ?`, cutoff); err != nil && !tableMissing(err) {
			return fmt.Errorf("prune accounting reconcile events: %w", err)
		}
	}
	if postAuthRetention > 0 {
		cutoff := formatAccountingTime(now.Add(-postAuthRetention))
		if _, err := DB.Exec(`DELETE FROM radpostauth WHERE authdate < ?`, cutoff); err != nil && !tableMissing(err) {
			return fmt.Errorf("prune radpostauth: %w", err)
		}
	}
	return nil
}

type freeRADIUSAccountingApplyResult struct {
	created int
	updated int
	closed  int
}

func applyFreeRADIUSAccountingRecord(record FreeRADIUSAccountingRecord) (freeRADIUSAccountingApplyResult, error) {
	sessionID := strings.TrimSpace(record.AegisSessionID)
	if sessionID == "" {
		sessionID = strings.TrimSpace(record.AcctSessionID)
	}
	if sessionID == "" {
		sessionID = strings.TrimSpace(record.AcctUniqueID)
	}
	if sessionID == "" {
		return freeRADIUSAccountingApplyResult{}, fmt.Errorf("radacctid %d has no session identifier", record.RadAcctID)
	}
	startTime := firstAccountingTime(record.AcctStartTime, record.AcctUpdateTime, record.AcctStopTime)
	if startTime == "" {
		startTime = formatAccountingTime(time.Now().UTC())
	}
	lastActivity := firstAccountingTime(record.AcctUpdateTime, record.AcctStopTime, record.AcctStartTime)
	if lastActivity == "" {
		lastActivity = startTime
	}
	endTime := ""
	stopReason := ""
	if strings.TrimSpace(record.AcctStopTime) != "" {
		endTime = strings.TrimSpace(record.AcctStopTime)
		stopReason = strings.TrimSpace(record.AcctTerminateCause)
		if stopReason == "" {
			stopReason = "accounting-stop"
		}
	}
	before := 0
	_ = DB.QueryRow(`SELECT COUNT(*) FROM sessions WHERE id = ?`, sessionID).Scan(&before)
	_, err := DB.Exec(`INSERT INTO sessions (
		id, username, mac, ip, auth_method, start_time, last_activity, end_time, stop_reason,
		radius_session_id, bytes_in, bytes_out, acct_session_time, called_station_id, nas_identifier, radius_class
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO UPDATE SET
		username = COALESCE(NULLIF(excluded.username, ''), sessions.username),
		mac = COALESCE(NULLIF(excluded.mac, ''), sessions.mac),
		ip = COALESCE(NULLIF(excluded.ip, ''), sessions.ip),
		auth_method = COALESCE(NULLIF(sessions.auth_method, ''), excluded.auth_method),
		last_activity = excluded.last_activity,
		end_time = COALESCE(excluded.end_time, sessions.end_time),
		stop_reason = COALESCE(excluded.stop_reason, sessions.stop_reason),
		radius_session_id = COALESCE(NULLIF(excluded.radius_session_id, ''), sessions.radius_session_id),
		bytes_in = excluded.bytes_in,
		bytes_out = excluded.bytes_out,
		acct_session_time = excluded.acct_session_time,
		called_station_id = COALESCE(NULLIF(excluded.called_station_id, ''), sessions.called_station_id),
		nas_identifier = COALESCE(NULLIF(excluded.nas_identifier, ''), sessions.nas_identifier),
		radius_class = COALESCE(NULLIF(excluded.radius_class, ''), sessions.radius_class)`,
		sessionID, strings.TrimSpace(record.Username), strings.TrimSpace(record.CallingStationID), strings.TrimSpace(record.FramedIPAddress),
		"radius-accounting", startTime, lastActivity, nullIfEmpty(endTime), nullIfEmpty(stopReason),
		strings.TrimSpace(record.AcctSessionID), boundedUint64ToInt64(record.AcctInputOctets), boundedUint64ToInt64(record.AcctOutputOctets),
		record.AcctSessionTime, nullIfEmpty(record.CalledStationID), nullIfEmpty(record.NASIPAddress), nullIfEmpty(record.Class))
	if err != nil {
		return freeRADIUSAccountingApplyResult{}, fmt.Errorf("apply radacctid %d to sessions: %w", record.RadAcctID, err)
	}
	if err := markFreeRADIUSAccountingReconciled(record.RadAcctID, sessionID, "reconciled", "", formatAccountingTime(time.Now().UTC())); err != nil {
		return freeRADIUSAccountingApplyResult{}, err
	}
	out := freeRADIUSAccountingApplyResult{updated: 1}
	if before == 0 {
		out.created = 1
		out.updated = 0
	}
	if endTime != "" {
		out.closed = 1
	}
	return out, nil
}

func markFreeRADIUSAccountingReconciled(radAcctID int, sessionID, status, message, reconciledAt string) error {
	if status == "" {
		status = "reconciled"
	}
	if reconciledAt == "" && status == "reconciled" {
		reconciledAt = formatAccountingTime(time.Now().UTC())
	}
	_, err := DB.Exec(`UPDATE radacct
		SET aegis_session_id = COALESCE(NULLIF(?, ''), aegis_session_id),
			aegis_reconcile_status = ?,
			aegis_reconcile_error = ?,
			aegis_reconciled_at = COALESCE(NULLIF(?, ''), aegis_reconciled_at),
			updated_at = ?
		WHERE radacctid = ?`,
		strings.TrimSpace(sessionID), status, nullIfEmpty(message), reconciledAt, formatAccountingTime(time.Now().UTC()), radAcctID)
	return err
}

func recordFreeRADIUSAccountingReconcileEvent(result FreeRADIUSAccountingReconcileResult) error {
	details, _ := json.Marshal(map[string]any{
		"feature": "NAS-0035",
	})
	_, err := DB.Exec(`INSERT INTO radius_sql_accounting_reconcile_events (
		event_id, status, scanned, reconciled, created_sessions, updated_sessions,
		closed_sessions, error_count, last_error, details_json, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		result.EventID, result.Status, result.Scanned, result.Reconciled, result.CreatedSessions,
		result.UpdatedSessions, result.ClosedSessions, result.ErrorCount, nullIfEmpty(result.LastError),
		string(details), result.CreatedAt)
	if err != nil {
		return fmt.Errorf("record accounting reconcile event: %w", err)
	}
	return nil
}

func freeRADIUSAccountingSelectSQL() string {
	return `SELECT radacctid, acctsessionid, acctuniqueid, COALESCE(username, ''), COALESCE(realm, ''),
		COALESCE(nasipaddress, ''), COALESCE(nasportid, ''), COALESCE(nasporttype, ''),
		COALESCE(CAST(acctstarttime AS TEXT), ''), COALESCE(CAST(acctupdatetime AS TEXT), ''),
		COALESCE(CAST(acctstoptime AS TEXT), ''), COALESCE(acctinterval, 0), COALESCE(acctsessiontime, 0),
		COALESCE(acctauthentic, ''), COALESCE(connectinfo_start, ''), COALESCE(connectinfo_stop, ''),
		COALESCE(acctinputoctets, 0), COALESCE(acctoutputoctets, 0), COALESCE(calledstationid, ''),
		COALESCE(callingstationid, ''), COALESCE(acctterminatecause, ''), COALESCE(servicetype, ''),
		COALESCE(framedprotocol, ''), COALESCE(framedipaddress, ''), COALESCE(framedipv6address, ''),
		COALESCE(framedipv6prefix, ''), COALESCE(framedinterfaceid, ''), COALESCE(delegatedipv6prefix, ''),
		COALESCE(class, ''), COALESCE(aegis_session_id, ''), COALESCE(aegis_source, ''),
		COALESCE(aegis_reconcile_status, ''), COALESCE(aegis_reconcile_error, ''),
		COALESCE(CAST(aegis_reconciled_at AS TEXT), ''), COALESCE(CAST(created_at AS TEXT), ''),
		COALESCE(CAST(updated_at AS TEXT), '') FROM radacct`
}

func scanFreeRADIUSAccountingRows(rows *sql.Rows) ([]FreeRADIUSAccountingRecord, error) {
	records := []FreeRADIUSAccountingRecord{}
	for rows.Next() {
		var record FreeRADIUSAccountingRecord
		var inputOctets, outputOctets int64
		if err := rows.Scan(&record.RadAcctID, &record.AcctSessionID, &record.AcctUniqueID, &record.Username, &record.Realm,
			&record.NASIPAddress, &record.NASPortID, &record.NASPortType, &record.AcctStartTime, &record.AcctUpdateTime,
			&record.AcctStopTime, &record.AcctInterval, &record.AcctSessionTime, &record.AcctAuthentic, &record.ConnectInfoStart,
			&record.ConnectInfoStop, &inputOctets, &outputOctets, &record.CalledStationID, &record.CallingStationID,
			&record.AcctTerminateCause, &record.ServiceType, &record.FramedProtocol, &record.FramedIPAddress,
			&record.FramedIPv6Address, &record.FramedIPv6Prefix, &record.FramedInterfaceID, &record.DelegatedIPv6Prefix,
			&record.Class, &record.AegisSessionID, &record.AegisSource, &record.AegisReconcileStatus,
			&record.AegisReconcileError, &record.AegisReconciledAt, &record.CreatedAt, &record.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan radacct: %w", err)
		}
		if inputOctets > 0 {
			record.AcctInputOctets = uint64(inputOctets)
		}
		if outputOctets > 0 {
			record.AcctOutputOctets = uint64(outputOctets)
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func freeRADIUSAccountingArgs(rec FreeRADIUSAccountingRecord) []any {
	return []any{
		rec.AcctSessionID, rec.AcctUniqueID, nullIfEmpty(rec.Username), nullIfEmpty(rec.Realm), nullIfEmpty(rec.NASIPAddress),
		nullIfEmpty(rec.NASPortID), nullIfEmpty(rec.NASPortType), nullIfEmpty(rec.AcctStartTime), nullIfEmpty(rec.AcctUpdateTime),
		nullIfEmpty(rec.AcctStopTime), rec.AcctInterval, rec.AcctSessionTime, nullIfEmpty(rec.AcctAuthentic),
		nullIfEmpty(rec.ConnectInfoStart), nullIfEmpty(rec.ConnectInfoStop), boundedUint64ToInt64(rec.AcctInputOctets),
		boundedUint64ToInt64(rec.AcctOutputOctets), nullIfEmpty(rec.CalledStationID), nullIfEmpty(rec.CallingStationID),
		nullIfEmpty(rec.AcctTerminateCause), nullIfEmpty(rec.ServiceType), nullIfEmpty(rec.FramedProtocol),
		nullIfEmpty(rec.FramedIPAddress), nullIfEmpty(rec.FramedIPv6Address), nullIfEmpty(rec.FramedIPv6Prefix),
		nullIfEmpty(rec.FramedInterfaceID), nullIfEmpty(rec.DelegatedIPv6Prefix), nullIfEmpty(rec.Class),
		nullIfEmpty(rec.AegisSessionID), rec.AegisSource, rec.AegisReconcileStatus, nullIfEmpty(rec.AegisReconcileError),
		nullIfEmpty(rec.AegisReconciledAt), rec.CreatedAt, rec.UpdatedAt,
	}
}

func normalizeFreeRADIUSAccountingRecord(rec FreeRADIUSAccountingRecord) FreeRADIUSAccountingRecord {
	rec.AcctSessionID = strings.TrimSpace(rec.AcctSessionID)
	rec.AcctUniqueID = strings.TrimSpace(rec.AcctUniqueID)
	rec.Username = strings.TrimSpace(rec.Username)
	rec.Realm = strings.TrimSpace(rec.Realm)
	rec.NASIPAddress = strings.TrimSpace(rec.NASIPAddress)
	rec.NASPortID = strings.TrimSpace(rec.NASPortID)
	rec.NASPortType = strings.TrimSpace(rec.NASPortType)
	rec.AcctStartTime = normalizeAccountingTimeString(rec.AcctStartTime)
	rec.AcctUpdateTime = normalizeAccountingTimeString(rec.AcctUpdateTime)
	rec.AcctStopTime = normalizeAccountingTimeString(rec.AcctStopTime)
	rec.AcctAuthentic = strings.TrimSpace(rec.AcctAuthentic)
	rec.ConnectInfoStart = strings.TrimSpace(rec.ConnectInfoStart)
	rec.ConnectInfoStop = strings.TrimSpace(rec.ConnectInfoStop)
	rec.CalledStationID = strings.TrimSpace(rec.CalledStationID)
	rec.CallingStationID = strings.TrimSpace(rec.CallingStationID)
	rec.AcctTerminateCause = strings.TrimSpace(rec.AcctTerminateCause)
	rec.ServiceType = strings.TrimSpace(rec.ServiceType)
	rec.FramedProtocol = strings.TrimSpace(rec.FramedProtocol)
	rec.FramedIPAddress = strings.TrimSpace(rec.FramedIPAddress)
	rec.FramedIPv6Address = strings.TrimSpace(rec.FramedIPv6Address)
	rec.FramedIPv6Prefix = strings.TrimSpace(rec.FramedIPv6Prefix)
	rec.FramedInterfaceID = strings.TrimSpace(rec.FramedInterfaceID)
	rec.DelegatedIPv6Prefix = strings.TrimSpace(rec.DelegatedIPv6Prefix)
	rec.Class = strings.TrimSpace(rec.Class)
	rec.AegisSessionID = strings.TrimSpace(rec.AegisSessionID)
	rec.AegisSource = strings.TrimSpace(rec.AegisSource)
	if rec.AegisSource == "" {
		rec.AegisSource = "freeradius-sql"
	}
	rec.AegisReconcileStatus = strings.TrimSpace(rec.AegisReconcileStatus)
	if rec.AegisReconcileStatus == "" {
		rec.AegisReconcileStatus = "pending"
	}
	if rec.AcctUniqueID == "" {
		rec.AcctUniqueID = FreeRADIUSAcctUniqueID(rec.AcctSessionID, rec.Username, rec.NASIPAddress, rec.NASPortID, rec.CallingStationID)
	}
	if rec.AcctSessionID == "" {
		rec.AcctSessionID = rec.AcctUniqueID
	}
	if rec.AcctStartTime == "" {
		rec.AcctStartTime = firstAccountingTime(rec.AcctUpdateTime, rec.AcctStopTime)
	}
	if rec.AcctUpdateTime == "" {
		rec.AcctUpdateTime = firstAccountingTime(rec.AcctStopTime, rec.AcctStartTime)
	}
	return rec
}

func FreeRADIUSAcctUniqueID(parts ...string) string {
	normalized := make([]string, 0, len(parts))
	for _, part := range parts {
		normalized = append(normalized, strings.ToLower(strings.TrimSpace(part)))
	}
	sum := sha256.Sum256([]byte(strings.Join(normalized, "\x00")))
	return hex.EncodeToString(sum[:])[:32]
}

func freeRADIUSAccountingEventID(result FreeRADIUSAccountingReconcileResult) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%d:%d:%d", result.CreatedAt, result.Scanned, result.Reconciled, result.ErrorCount, time.Now().UnixNano())))
	return "acct-reconcile-" + hex.EncodeToString(sum[:])[:24]
}

func firstAccountingTime(values ...string) string {
	for _, value := range values {
		if value = normalizeAccountingTimeString(value); value != "" {
			return value
		}
	}
	return ""
}

func normalizeAccountingTimeString(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if parsed := parseAccountingTime(value); !parsed.IsZero() {
		return formatAccountingTime(parsed)
	}
	return value
}

func parseAccountingTime(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}
	}
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
	} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC()
		}
	}
	return time.Time{}
}

func formatAccountingTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func boundedUint64ToInt64(value uint64) int64 {
	if value > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(value)
}

func countStaleFreeRADIUSAccountingRows(staleAfter time.Duration) int {
	rows, err := DB.Query(`SELECT COALESCE(CAST(acctupdatetime AS TEXT), COALESCE(CAST(acctstarttime AS TEXT), COALESCE(CAST(created_at AS TEXT), '')))
		FROM radacct WHERE COALESCE(aegis_reconcile_status, 'pending') <> 'reconciled' LIMIT 5000`)
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
