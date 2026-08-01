package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type AccountingServiceCorrelationFields struct {
	CorrelationID      string `json:"correlation_id"`
	ParentSessionKey   string `json:"parent_session_key"`
	ChildSessionKey    string `json:"child_session_key"`
	AcctMultiSessionID string `json:"acct_multi_session_id,omitempty"`
	AcctLinkCount      int64  `json:"acct_link_count,omitempty"`
	ServiceKey         string `json:"service_key"`
	ServiceType        string `json:"service_type,omitempty"`
	ServiceCategory    string `json:"service_category"`
	ServiceLegID       string `json:"service_leg_id"`
	BearerID           string `json:"bearer_id,omitempty"`
	CallID             string `json:"call_id,omitempty"`
	RoamingID          string `json:"roaming_id,omitempty"`
	CorrelationSource  string `json:"correlation_source"`
	CorrelationStatus  string `json:"correlation_status"`
	CorrelationError   string `json:"correlation_error,omitempty"`
	LinkedChainID      string `json:"linked_chain_id,omitempty"`
	LinkedChainStatus  string `json:"linked_chain_status,omitempty"`
	LinkedServiceKey   string `json:"linked_service_key,omitempty"`
}

type AccountingServiceCorrelationRecord struct {
	ID                 int    `json:"id"`
	CorrelationID      string `json:"correlation_id"`
	ParentSessionKey   string `json:"parent_session_key"`
	ChildSessionKey    string `json:"child_session_key"`
	AcctUniqueID       string `json:"acct_unique_id,omitempty"`
	AcctSessionID      string `json:"acct_session_id,omitempty"`
	AcctMultiSessionID string `json:"acct_multi_session_id,omitempty"`
	AcctLinkCount      int64  `json:"acct_link_count"`
	ServiceKey         string `json:"service_key"`
	ServiceType        string `json:"service_type,omitempty"`
	ServiceCategory    string `json:"service_category"`
	ServiceLegID       string `json:"service_leg_id"`
	BearerID           string `json:"bearer_id,omitempty"`
	CallID             string `json:"call_id,omitempty"`
	RoamingID          string `json:"roaming_id,omitempty"`
	UsernameHash       string `json:"username_hash,omitempty"`
	CallingStationHash string `json:"calling_station_hash,omitempty"`
	NASIPAddress       string `json:"nas_ip_address,omitempty"`
	LinkedChainID      string `json:"linked_chain_id,omitempty"`
	LinkedChainStatus  string `json:"linked_chain_status,omitempty"`
	LinkedServiceKey   string `json:"linked_service_key,omitempty"`
	FirstEventID       string `json:"first_event_id"`
	LastEventID        string `json:"last_event_id"`
	FirstSeenAt        string `json:"first_seen_at"`
	LastSeenAt         string `json:"last_seen_at"`
	StoppedAt          string `json:"stopped_at,omitempty"`
	AcctSessionTime    int64  `json:"acct_session_time"`
	InputOctets64      string `json:"input_octets_64"`
	OutputOctets64     string `json:"output_octets_64"`
	CorrelationSource  string `json:"correlation_source"`
	CorrelationStatus  string `json:"correlation_status"`
	CorrelationError   string `json:"correlation_error,omitempty"`
	DetailsJSON        string `json:"details_json,omitempty"`
	CreatedAt          string `json:"created_at,omitempty"`
	UpdatedAt          string `json:"updated_at,omitempty"`
}

type AccountingServiceCorrelationSummary struct {
	CorrelationRows          int    `json:"correlation_rows"`
	ActiveCorrelations       int    `json:"active_correlations"`
	ClosedCorrelations       int    `json:"closed_correlations"`
	ConflictCorrelations     int    `json:"conflict_correlations"`
	UnmatchedCorrelations    int    `json:"unmatched_correlations"`
	LinkedSubscriberServices int    `json:"linked_subscriber_services"`
	ParentSessions           int    `json:"parent_sessions"`
	ChildSessions            int    `json:"child_sessions"`
	DataServices             int    `json:"data_services"`
	VoiceServices            int    `json:"voice_services"`
	BearerServices           int    `json:"bearer_services"`
	ReauthServices           int    `json:"reauth_services"`
	VPNServices              int    `json:"vpn_services"`
	PrimaryServices          int    `json:"primary_services"`
	AcctMultiSessionRows     int    `json:"acct_multi_session_rows"`
	CallLegRows              int    `json:"call_leg_rows"`
	BearerLegRows            int    `json:"bearer_leg_rows"`
	LastCorrelationAt        string `json:"last_correlation_at,omitempty"`
	LastCorrelationStatus    string `json:"last_correlation_status,omitempty"`
	LastCorrelationError     string `json:"last_correlation_error,omitempty"`
}

type accountingServiceChainLink struct {
	ChainID         string
	ChainStatus     string
	ServiceKey      string
	AccountingClass string
}

var accountingServiceTokenRegexp = regexp.MustCompile(`[^a-z0-9_.:@-]+`)

func NormalizeAccountingServiceCorrelationFields(event AccountingEventRecord) AccountingServiceCorrelationFields {
	metadata := accountingServiceMetadata(event)
	fields := AccountingServiceCorrelationFields{
		ParentSessionKey:   strings.TrimSpace(event.ParentSessionKey),
		ChildSessionKey:    strings.TrimSpace(event.SessionKey),
		AcctMultiSessionID: strings.TrimSpace(firstNonEmptyString(event.AcctMultiSessionID, metadata["acct_multi_session_id"], metadata["acct-multi-session-id"])),
		AcctLinkCount:      maxInt64(event.AcctLinkCount, 0),
		ServiceKey:         sanitizeAccountingServiceToken(firstNonEmptyString(event.ServiceKey, metadata["service_key"], metadata["service"], metadata["aegis_service"], metadata["apn"])),
		ServiceType:        strings.TrimSpace(firstNonEmptyString(event.ServiceType, metadata["radius_service_type"], metadata["service_type"])),
		ServiceCategory:    sanitizeAccountingServiceToken(firstNonEmptyString(event.ServiceCategory, metadata["service_category"], metadata["category"])),
		ServiceLegID:       sanitizeAccountingServiceLeg(firstNonEmptyString(event.ServiceLegID, metadata["service_leg_id"], metadata["leg_id"], metadata["leg"])),
		BearerID:           sanitizeAccountingServiceLeg(firstNonEmptyString(event.BearerID, metadata["bearer_id"], metadata["bearer"], metadata["3gpp_bearer_id"])),
		CallID:             sanitizeAccountingServiceLeg(firstNonEmptyString(event.CallID, metadata["call_id"], metadata["call"], metadata["h323_conf_id"], metadata["h323-conf-id"])),
		RoamingID:          sanitizeAccountingServiceLeg(firstNonEmptyString(event.RoamingID, metadata["roaming_id"], metadata["roaming"], metadata["visited_network"], metadata["visited-network"])),
		CorrelationStatus:  normalizeAccountingCorrelationStatus(event.CorrelationStatus),
		CorrelationError:   strings.TrimSpace(event.CorrelationError),
	}
	if fields.ChildSessionKey == "" {
		fields.ChildSessionKey = firstNonEmptyString(event.AcctSessionID, event.AcctUniqueID)
	}
	if fields.ParentSessionKey == "" {
		fields.ParentSessionKey = firstNonEmptyString(metadata["parent_session_key"], metadata["parent_session_id"], metadata["parent"], fields.AcctMultiSessionID, fields.ChildSessionKey)
	}
	if fields.ServiceCategory == "" {
		fields.ServiceCategory = inferAccountingServiceCategory(fields, event)
	}
	if fields.ServiceKey == "" {
		fields.ServiceKey = inferAccountingServiceKey(fields, event)
	}
	if fields.ServiceLegID == "" {
		fields.ServiceLegID = firstNonEmptyString(fields.BearerID, fields.CallID, sanitizeAccountingServiceLeg(event.AcctSessionID), sanitizeAccountingServiceLeg(fields.ChildSessionKey), "primary")
	}
	if fields.CorrelationStatus == "" {
		fields.CorrelationStatus = "active"
	}
	fields.CorrelationSource = inferAccountingCorrelationSource(fields, event, metadata)
	fields.CorrelationID = AccountingServiceCorrelationID(fields.ParentSessionKey, fields.ChildSessionKey, fields.ServiceKey, fields.ServiceLegID)
	return fields
}

func RecordAccountingServiceCorrelation(ctx context.Context, event AccountingEventRecord) (AccountingServiceCorrelationRecord, error) {
	if DB == nil {
		return AccountingServiceCorrelationRecord{}, fmt.Errorf("database not initialized")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	event = normalizeAccountingEventRecord(event)
	fields := NormalizeAccountingServiceCorrelationFields(event)
	if fields.ParentSessionKey == "" || fields.ChildSessionKey == "" || fields.CorrelationID == "" {
		return AccountingServiceCorrelationRecord{}, nil
	}
	link, linked := findAccountingSubscriberServiceLink(fields, event)
	if linked {
		fields.LinkedChainID = link.ChainID
		fields.LinkedChainStatus = link.ChainStatus
		fields.LinkedServiceKey = link.ServiceKey
		if fields.ServiceKey == "" || fields.ServiceKey == "primary" {
			fields.ServiceKey = sanitizeAccountingServiceToken(link.ServiceKey)
			fields.CorrelationID = AccountingServiceCorrelationID(fields.ParentSessionKey, fields.ChildSessionKey, fields.ServiceKey, fields.ServiceLegID)
		}
		fields.CorrelationSource = appendAccountingCorrelationSource(fields.CorrelationSource, "subscriber-service-chain")
	}
	fields.CorrelationStatus = accountingCorrelationStatusForEvent(event.StatusType, fields.CorrelationStatus)
	fields = detectAccountingServiceConflict(ctx, fields)
	now := formatAccountingTime(time.Now().UTC())
	eventTime := normalizeAccountingTimeString(event.EventTime)
	if eventTime == "" {
		eventTime = now
	}
	stoppedAt := ""
	if fields.CorrelationStatus == "closed" || event.StatusType == "Stop" || event.StatusType == "Accounting-Off" {
		stoppedAt = eventTime
	}
	detailsJSON := accountingServiceDetailsJSON(fields, event)
	_, err := DB.ExecContext(ctx, `INSERT INTO radius_accounting_service_correlations (
		correlation_id, parent_session_key, child_session_key, acct_unique_id, acct_session_id,
		acct_multi_session_id, acct_link_count, service_key, service_type, service_category,
		service_leg_id, bearer_id, call_id, roaming_id, username_hash, calling_station_hash,
		nas_ip_address, linked_chain_id, linked_chain_status, linked_service_key,
		first_event_id, last_event_id, first_seen_at, last_seen_at, stopped_at,
		acct_session_time, input_octets_64, output_octets_64, correlation_source,
		correlation_status, correlation_error, details_json, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(correlation_id) DO UPDATE SET
		parent_session_key = excluded.parent_session_key,
		child_session_key = excluded.child_session_key,
		acct_unique_id = excluded.acct_unique_id,
		acct_session_id = excluded.acct_session_id,
		acct_multi_session_id = COALESCE(excluded.acct_multi_session_id, radius_accounting_service_correlations.acct_multi_session_id),
		acct_link_count = excluded.acct_link_count,
		service_key = excluded.service_key,
		service_type = COALESCE(excluded.service_type, radius_accounting_service_correlations.service_type),
		service_category = excluded.service_category,
		service_leg_id = excluded.service_leg_id,
		bearer_id = COALESCE(excluded.bearer_id, radius_accounting_service_correlations.bearer_id),
		call_id = COALESCE(excluded.call_id, radius_accounting_service_correlations.call_id),
		roaming_id = COALESCE(excluded.roaming_id, radius_accounting_service_correlations.roaming_id),
		username_hash = COALESCE(excluded.username_hash, radius_accounting_service_correlations.username_hash),
		calling_station_hash = COALESCE(excluded.calling_station_hash, radius_accounting_service_correlations.calling_station_hash),
		nas_ip_address = COALESCE(excluded.nas_ip_address, radius_accounting_service_correlations.nas_ip_address),
		linked_chain_id = COALESCE(excluded.linked_chain_id, radius_accounting_service_correlations.linked_chain_id),
		linked_chain_status = COALESCE(excluded.linked_chain_status, radius_accounting_service_correlations.linked_chain_status),
		linked_service_key = COALESCE(excluded.linked_service_key, radius_accounting_service_correlations.linked_service_key),
		last_event_id = excluded.last_event_id,
		last_seen_at = excluded.last_seen_at,
		stopped_at = COALESCE(excluded.stopped_at, radius_accounting_service_correlations.stopped_at),
		acct_session_time = excluded.acct_session_time,
		input_octets_64 = excluded.input_octets_64,
		output_octets_64 = excluded.output_octets_64,
		correlation_source = excluded.correlation_source,
		correlation_status = excluded.correlation_status,
		correlation_error = COALESCE(excluded.correlation_error, radius_accounting_service_correlations.correlation_error),
		details_json = excluded.details_json,
		updated_at = excluded.updated_at`,
		fields.CorrelationID, fields.ParentSessionKey, fields.ChildSessionKey, event.AcctUniqueID,
		event.AcctSessionID, nullIfEmpty(fields.AcctMultiSessionID), fields.AcctLinkCount,
		fields.ServiceKey, nullIfEmpty(fields.ServiceType), fields.ServiceCategory, fields.ServiceLegID,
		nullIfEmpty(fields.BearerID), nullIfEmpty(fields.CallID), nullIfEmpty(fields.RoamingID),
		nullIfEmpty(hashAccountingServiceIdentity(event.Username)),
		nullIfEmpty(hashAccountingServiceIdentity(event.CallingStationID)), nullIfEmpty(event.NASIPAddress),
		nullIfEmpty(fields.LinkedChainID), nullIfEmpty(fields.LinkedChainStatus), nullIfEmpty(fields.LinkedServiceKey),
		event.EventID, event.EventID, eventTime, eventTime, nullIfEmpty(stoppedAt), event.AcctSessionTime,
		event.AcctInputOctets64, event.AcctOutputOctets64, fields.CorrelationSource, fields.CorrelationStatus,
		nullIfEmpty(fields.CorrelationError), detailsJSON, now, now)
	if err != nil {
		if tableMissing(err) {
			return AccountingServiceCorrelationRecord{}, nil
		}
		return AccountingServiceCorrelationRecord{}, fmt.Errorf("record accounting service correlation: %w", err)
	}
	if fields.LinkedChainID != "" && fields.LinkedServiceKey != "" {
		if err := updateSubscriberServiceAccountingFromCorrelation(ctx, fields, event, eventTime); err != nil {
			return AccountingServiceCorrelationRecord{}, err
		}
	}
	return GetAccountingServiceCorrelation(fields.CorrelationID)
}

func UpdateAccountingEventServiceCorrelationFields(event AccountingEventRecord, fields AccountingServiceCorrelationFields) error {
	if DB == nil || event.ID == 0 {
		return nil
	}
	_, err := DB.Exec(`UPDATE radius_accounting_events
		SET acct_multi_session_id = ?, acct_link_count = ?, service_type = ?,
			framed_protocol = ?, parent_session_key = ?, service_key = ?,
			service_category = ?, service_leg_id = ?, bearer_id = ?, call_id = ?,
			roaming_id = ?, correlation_id = ?, correlation_status = ?,
			correlation_error = ?, updated_at = ?
		WHERE id = ?`,
		nullIfEmpty(fields.AcctMultiSessionID), fields.AcctLinkCount, nullIfEmpty(fields.ServiceType),
		nullIfEmpty(event.FramedProtocol), nullIfEmpty(fields.ParentSessionKey), nullIfEmpty(fields.ServiceKey),
		nullIfEmpty(fields.ServiceCategory), nullIfEmpty(fields.ServiceLegID), nullIfEmpty(fields.BearerID),
		nullIfEmpty(fields.CallID), nullIfEmpty(fields.RoamingID), nullIfEmpty(fields.CorrelationID),
		fields.CorrelationStatus, nullIfEmpty(fields.CorrelationError), formatAccountingTime(time.Now().UTC()), event.ID)
	return err
}

func GetAccountingServiceCorrelation(correlationID string) (AccountingServiceCorrelationRecord, error) {
	if DB == nil {
		return AccountingServiceCorrelationRecord{}, fmt.Errorf("database not initialized")
	}
	rows, err := DB.Query(accountingServiceCorrelationSelectSQL()+` WHERE correlation_id = ? LIMIT 1`, strings.TrimSpace(correlationID))
	if err != nil {
		if tableMissing(err) {
			return AccountingServiceCorrelationRecord{}, sql.ErrNoRows
		}
		return AccountingServiceCorrelationRecord{}, err
	}
	defer rows.Close()
	records, err := scanAccountingServiceCorrelationRows(rows)
	if err != nil {
		return AccountingServiceCorrelationRecord{}, err
	}
	if len(records) == 0 {
		return AccountingServiceCorrelationRecord{}, sql.ErrNoRows
	}
	return records[0], nil
}

func ListAccountingServiceCorrelations(limit int, status, parentSessionKey string) ([]AccountingServiceCorrelationRecord, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	query := accountingServiceCorrelationSelectSQL()
	args := []any{}
	filters := []string{}
	if status = strings.TrimSpace(status); status != "" {
		filters = append(filters, "correlation_status = ?")
		args = append(args, status)
	}
	if parentSessionKey = strings.TrimSpace(parentSessionKey); parentSessionKey != "" {
		filters = append(filters, "parent_session_key = ?")
		args = append(args, parentSessionKey)
	}
	if len(filters) > 0 {
		query += " WHERE " + strings.Join(filters, " AND ")
	}
	query += " ORDER BY last_seen_at DESC, id DESC LIMIT ?"
	args = append(args, limit)
	rows, err := DB.Query(query, args...)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list accounting service correlations: %w", err)
	}
	defer rows.Close()
	return scanAccountingServiceCorrelationRows(rows)
}

func GetAccountingServiceCorrelationSummary() (AccountingServiceCorrelationSummary, error) {
	if DB == nil {
		return AccountingServiceCorrelationSummary{}, fmt.Errorf("database not initialized")
	}
	var summary AccountingServiceCorrelationSummary
	err := DB.QueryRow(`SELECT
		COUNT(*),
		COALESCE(SUM(CASE WHEN correlation_status = 'active' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN correlation_status = 'closed' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN correlation_status = 'conflict' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN correlation_status = 'unmatched' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN linked_chain_id IS NOT NULL AND linked_chain_id <> '' THEN 1 ELSE 0 END), 0),
		COUNT(DISTINCT parent_session_key),
		COUNT(DISTINCT child_session_key),
		COALESCE(SUM(CASE WHEN service_category = 'data' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN service_category = 'voice' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN service_category = 'bearer' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN service_category = 'reauth' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN service_category = 'vpn' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN service_category = 'primary' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN acct_multi_session_id IS NOT NULL AND acct_multi_session_id <> '' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN call_id IS NOT NULL AND call_id <> '' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN bearer_id IS NOT NULL AND bearer_id <> '' THEN 1 ELSE 0 END), 0),
		COALESCE(MAX(last_seen_at), ''),
		COALESCE((SELECT correlation_status FROM radius_accounting_service_correlations ORDER BY last_seen_at DESC, id DESC LIMIT 1), ''),
		COALESCE((SELECT correlation_error FROM radius_accounting_service_correlations WHERE correlation_error IS NOT NULL AND correlation_error <> '' ORDER BY updated_at DESC, id DESC LIMIT 1), '')
		FROM radius_accounting_service_correlations`).Scan(
		&summary.CorrelationRows, &summary.ActiveCorrelations, &summary.ClosedCorrelations,
		&summary.ConflictCorrelations, &summary.UnmatchedCorrelations, &summary.LinkedSubscriberServices,
		&summary.ParentSessions, &summary.ChildSessions, &summary.DataServices, &summary.VoiceServices,
		&summary.BearerServices, &summary.ReauthServices, &summary.VPNServices, &summary.PrimaryServices,
		&summary.AcctMultiSessionRows, &summary.CallLegRows, &summary.BearerLegRows,
		&summary.LastCorrelationAt, &summary.LastCorrelationStatus, &summary.LastCorrelationError)
	if err != nil {
		if tableMissing(err) {
			return summary, nil
		}
		return AccountingServiceCorrelationSummary{}, fmt.Errorf("summarize accounting service correlations: %w", err)
	}
	return summary, nil
}

func PruneAccountingServiceCorrelations(retention time.Duration, now time.Time) error {
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
	_, err := DB.Exec(`DELETE FROM radius_accounting_service_correlations
		WHERE correlation_status IN ('closed', 'unmatched') AND last_seen_at < ?`, cutoff)
	if err != nil && tableMissing(err) {
		return nil
	}
	return err
}

func AccountingServiceCorrelationID(parentSessionKey, childSessionKey, serviceKey, serviceLegID string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		strings.ToLower(strings.TrimSpace(parentSessionKey)),
		strings.ToLower(strings.TrimSpace(childSessionKey)),
		strings.ToLower(strings.TrimSpace(serviceKey)),
		strings.ToLower(strings.TrimSpace(serviceLegID)),
	}, "\x00")))
	return "asc-" + hex.EncodeToString(sum[:])[:24]
}

func accountingServiceCorrelationSelectSQL() string {
	return `SELECT id, correlation_id, parent_session_key, child_session_key,
		COALESCE(acct_unique_id, ''), COALESCE(acct_session_id, ''),
		COALESCE(acct_multi_session_id, ''), COALESCE(acct_link_count, 0),
		service_key, COALESCE(service_type, ''), service_category, service_leg_id,
		COALESCE(bearer_id, ''), COALESCE(call_id, ''), COALESCE(roaming_id, ''),
		COALESCE(username_hash, ''), COALESCE(calling_station_hash, ''),
		COALESCE(nas_ip_address, ''), COALESCE(linked_chain_id, ''),
		COALESCE(linked_chain_status, ''), COALESCE(linked_service_key, ''),
		first_event_id, last_event_id, COALESCE(CAST(first_seen_at AS TEXT), ''),
		COALESCE(CAST(last_seen_at AS TEXT), ''), COALESCE(CAST(stopped_at AS TEXT), ''),
		COALESCE(acct_session_time, 0), COALESCE(input_octets_64, '0'),
		COALESCE(output_octets_64, '0'), correlation_source, correlation_status,
		COALESCE(correlation_error, ''), COALESCE(details_json, '{}'),
		COALESCE(CAST(created_at AS TEXT), ''), COALESCE(CAST(updated_at AS TEXT), '')
		FROM radius_accounting_service_correlations`
}

func scanAccountingServiceCorrelationRows(rows *sql.Rows) ([]AccountingServiceCorrelationRecord, error) {
	records := []AccountingServiceCorrelationRecord{}
	for rows.Next() {
		var record AccountingServiceCorrelationRecord
		if err := rows.Scan(&record.ID, &record.CorrelationID, &record.ParentSessionKey,
			&record.ChildSessionKey, &record.AcctUniqueID, &record.AcctSessionID,
			&record.AcctMultiSessionID, &record.AcctLinkCount, &record.ServiceKey,
			&record.ServiceType, &record.ServiceCategory, &record.ServiceLegID,
			&record.BearerID, &record.CallID, &record.RoamingID, &record.UsernameHash,
			&record.CallingStationHash, &record.NASIPAddress, &record.LinkedChainID,
			&record.LinkedChainStatus, &record.LinkedServiceKey, &record.FirstEventID,
			&record.LastEventID, &record.FirstSeenAt, &record.LastSeenAt, &record.StoppedAt,
			&record.AcctSessionTime, &record.InputOctets64, &record.OutputOctets64,
			&record.CorrelationSource, &record.CorrelationStatus, &record.CorrelationError,
			&record.DetailsJSON, &record.CreatedAt, &record.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan accounting service correlation: %w", err)
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func findAccountingSubscriberServiceLink(fields AccountingServiceCorrelationFields, event AccountingEventRecord) (accountingServiceChainLink, bool) {
	if DB == nil {
		return accountingServiceChainLink{}, false
	}
	sessionKeys := uniqueNonEmptyStrings(fields.ParentSessionKey, fields.ChildSessionKey)
	if len(sessionKeys) == 0 {
		return accountingServiceChainLink{}, false
	}
	query := `SELECT a.chain_id, c.status, a.service_key, COALESCE(a.accounting_class, '')
		FROM subscriber_service_accounting a
		JOIN subscriber_service_chains c ON c.chain_id = a.chain_id
		WHERE a.status IN ('started', 'interim')`
	args := []any{}
	query += " AND a.session_id IN (" + placeholders(len(sessionKeys)) + ")"
	for _, sessionKey := range sessionKeys {
		args = append(args, sessionKey)
	}
	query += ` ORDER BY a.updated_at DESC, a.id DESC LIMIT 50`
	rows, err := DB.Query(query, args...)
	if err != nil {
		return accountingServiceChainLink{}, false
	}
	defer rows.Close()
	links := []accountingServiceChainLink{}
	for rows.Next() {
		var link accountingServiceChainLink
		if err := rows.Scan(&link.ChainID, &link.ChainStatus, &link.ServiceKey, &link.AccountingClass); err != nil {
			return accountingServiceChainLink{}, false
		}
		link.ServiceKey = sanitizeAccountingServiceToken(link.ServiceKey)
		link.AccountingClass = strings.TrimSpace(link.AccountingClass)
		links = append(links, link)
	}
	if len(links) == 0 {
		return accountingServiceChainLink{}, false
	}
	if fields.ServiceKey != "" && fields.ServiceKey != "primary" {
		for _, link := range links {
			if link.ServiceKey == fields.ServiceKey {
				return link, true
			}
		}
	}
	classValues := uniqueNonEmptyStrings(event.Class, accountingServiceMetadata(event)["class"], accountingServiceMetadata(event)["accounting_class"])
	for _, classValue := range classValues {
		for _, link := range links {
			if strings.EqualFold(link.AccountingClass, classValue) || sanitizeAccountingServiceToken(link.AccountingClass) == sanitizeAccountingServiceToken(classValue) {
				return link, true
			}
		}
	}
	if len(links) == 1 && (fields.ServiceKey == "" || fields.ServiceKey == "primary") {
		return links[0], true
	}
	return accountingServiceChainLink{}, false
}

func updateSubscriberServiceAccountingFromCorrelation(ctx context.Context, fields AccountingServiceCorrelationFields, event AccountingEventRecord, eventTime string) error {
	if DB == nil {
		return nil
	}
	status := "interim"
	if event.StatusType == "Start" {
		status = "started"
	}
	if event.StatusType == "Stop" || event.StatusType == "Accounting-Off" {
		status = "stopped"
	}
	interimIncrement := 0
	if event.StatusType == "Interim-Update" {
		interimIncrement = 1
	}
	_, err := DB.ExecContext(ctx, `UPDATE subscriber_service_accounting
		SET status = ?, last_interim_at = COALESCE(NULLIF(?, ''), last_interim_at),
			stopped_at = COALESCE(NULLIF(?, ''), stopped_at),
			input_octets = ?, output_octets = ?,
			interim_count = interim_count + ?, updated_at = ?
		WHERE chain_id = ? AND service_key = ?`,
		status, nullableInterimTime(event.StatusType, eventTime), nullableStopTime(event.StatusType, eventTime),
		boundedUint64ToInt64(accountingEventInputTotal64(event)), boundedUint64ToInt64(accountingEventOutputTotal64(event)),
		interimIncrement, formatAccountingTime(time.Now().UTC()), fields.LinkedChainID, fields.LinkedServiceKey)
	if err != nil && tableMissing(err) {
		return nil
	}
	return err
}

func detectAccountingServiceConflict(ctx context.Context, fields AccountingServiceCorrelationFields) AccountingServiceCorrelationFields {
	if DB == nil || fields.ChildSessionKey == "" || fields.CorrelationID == "" {
		return fields
	}
	var existingCorrelationID, existingParent string
	err := DB.QueryRowContext(ctx, `SELECT correlation_id, parent_session_key
		FROM radius_accounting_service_correlations
		WHERE child_session_key = ? AND correlation_status = 'active' AND correlation_id <> ?
		ORDER BY last_seen_at DESC, id DESC LIMIT 1`,
		fields.ChildSessionKey, fields.CorrelationID).Scan(&existingCorrelationID, &existingParent)
	if err != nil {
		return fields
	}
	fields.CorrelationStatus = "conflict"
	fields.CorrelationError = fmt.Sprintf("child session %s already has active correlation %s under parent %s",
		fields.ChildSessionKey, existingCorrelationID, existingParent)
	return fields
}

func accountingServiceMetadata(event AccountingEventRecord) map[string]string {
	out := map[string]string{}
	for key, value := range parseAccountingKeyValues(event.Class) {
		out[key] = value
	}
	if json.Valid([]byte(event.PayloadJSON)) {
		var payload map[string]any
		if err := json.Unmarshal([]byte(event.PayloadJSON), &payload); err == nil {
			flattenAccountingMetadata(out, payload, "")
		}
	}
	return out
}

func flattenAccountingMetadata(out map[string]string, values map[string]any, prefix string) {
	for key, value := range values {
		normalizedKey := normalizeAccountingMetadataKey(key)
		if prefix != "" {
			normalizedKey = prefix + "." + normalizedKey
		}
		switch typed := value.(type) {
		case string:
			if trimmed := strings.TrimSpace(typed); trimmed != "" {
				out[normalizedKey] = trimmed
			}
		case float64:
			out[normalizedKey] = strconv.FormatInt(int64(typed), 10)
		case map[string]any:
			flattenAccountingMetadata(out, typed, normalizedKey)
		}
	}
}

func parseAccountingKeyValues(value string) map[string]string {
	out := map[string]string{}
	value = strings.TrimSpace(value)
	if value == "" {
		return out
	}
	if json.Valid([]byte(value)) {
		var payload map[string]any
		if err := json.Unmarshal([]byte(value), &payload); err == nil {
			flattenAccountingMetadata(out, payload, "")
			return out
		}
	}
	for _, token := range strings.FieldsFunc(value, func(r rune) bool {
		return r == ';' || r == ',' || r == '\n' || r == '\t'
	}) {
		key, val, ok := strings.Cut(token, "=")
		if !ok {
			key, val, ok = strings.Cut(token, ":")
		}
		if !ok {
			continue
		}
		key = normalizeAccountingMetadataKey(key)
		val = strings.Trim(strings.TrimSpace(val), `"'`)
		if key != "" && val != "" {
			out[key] = val
		}
	}
	return out
}

func normalizeAccountingMetadataKey(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "-", "_")
	value = strings.ReplaceAll(value, " ", "_")
	value = strings.TrimPrefix(value, "aegisnas_")
	value = strings.TrimPrefix(value, "aegis_")
	return value
}

func inferAccountingServiceCategory(fields AccountingServiceCorrelationFields, event AccountingEventRecord) string {
	serviceType := strings.ToLower(strings.TrimSpace(firstNonEmptyString(fields.ServiceType, event.ServiceType)))
	framedProtocol := strings.ToLower(strings.TrimSpace(event.FramedProtocol))
	serviceKey := strings.ToLower(strings.TrimSpace(fields.ServiceKey))
	switch {
	case fields.CallID != "" || strings.Contains(serviceKey, "voice") || strings.Contains(serviceKey, "call") || strings.Contains(serviceType, "voice"):
		return "voice"
	case fields.BearerID != "" || strings.Contains(serviceKey, "bearer") || strings.Contains(serviceKey, "apn") || strings.Contains(serviceType, "3gpp"):
		return "bearer"
	case strings.Contains(serviceKey, "vpn") || strings.Contains(serviceType, "vpn"):
		return "vpn"
	case strings.Contains(serviceKey, "reauth") || strings.Contains(serviceType, "reauth"):
		return "reauth"
	case strings.Contains(serviceType, "framed") || strings.Contains(framedProtocol, "ppp") || strings.Contains(framedProtocol, "ip"):
		return "data"
	case fields.AcctMultiSessionID != "":
		return "data"
	default:
		return "primary"
	}
}

func inferAccountingServiceKey(fields AccountingServiceCorrelationFields, event AccountingEventRecord) string {
	category := fields.ServiceCategory
	if category == "" {
		category = inferAccountingServiceCategory(fields, event)
	}
	switch category {
	case "voice":
		return "voice"
	case "bearer":
		return "bearer"
	case "vpn":
		return "vpn"
	case "reauth":
		return "reauth"
	case "data":
		if protocol := sanitizeAccountingServiceToken(event.FramedProtocol); protocol != "" {
			return "data-" + protocol
		}
		return "data"
	default:
		return "primary"
	}
}

func inferAccountingCorrelationSource(fields AccountingServiceCorrelationFields, event AccountingEventRecord, metadata map[string]string) string {
	sources := []string{}
	if event.ParentSessionKey != "" || event.ServiceKey != "" || event.ServiceLegID != "" || event.BearerID != "" || event.CallID != "" || event.RoamingID != "" {
		sources = append(sources, "explicit")
	}
	if fields.AcctMultiSessionID != "" {
		sources = append(sources, "acct-multi-session-id")
	}
	for _, key := range []string{"service_key", "service", "parent_session_key", "bearer_id", "call_id", "apn"} {
		if strings.TrimSpace(metadata[key]) != "" {
			sources = append(sources, "class")
			break
		}
	}
	if len(sources) == 0 {
		sources = append(sources, "inferred")
	}
	return strings.Join(uniqueSortedStrings(sources), "+")
}

func appendAccountingCorrelationSource(current, next string) string {
	parts := []string{}
	for _, value := range strings.Split(current, "+") {
		if value = strings.TrimSpace(value); value != "" {
			parts = append(parts, value)
		}
	}
	parts = append(parts, next)
	return strings.Join(uniqueSortedStrings(parts), "+")
}

func accountingCorrelationStatusForEvent(statusType, current string) string {
	current = normalizeAccountingCorrelationStatus(current)
	if statusType == "Stop" || statusType == "Accounting-Off" {
		return "closed"
	}
	if current == "" {
		return "active"
	}
	return current
}

func normalizeAccountingCorrelationStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "closed", "stopped":
		return "closed"
	case "unmatched":
		return "unmatched"
	case "conflict", "error":
		return "conflict"
	case "active", "started", "interim", "":
		return "active"
	default:
		return "active"
	}
}

func accountingServiceDetailsJSON(fields AccountingServiceCorrelationFields, event AccountingEventRecord) string {
	details, _ := json.Marshal(map[string]any{
		"feature":                "NAS-0039",
		"event_id":               event.EventID,
		"status_type":            event.StatusType,
		"acct_session_id":        event.AcctSessionID,
		"acct_unique_id":         event.AcctUniqueID,
		"acct_multi_session_id":  fields.AcctMultiSessionID,
		"acct_link_count":        fields.AcctLinkCount,
		"service_key":            fields.ServiceKey,
		"service_category":       fields.ServiceCategory,
		"service_leg_id":         fields.ServiceLegID,
		"correlation_source":     fields.CorrelationSource,
		"linked_chain_id":        fields.LinkedChainID,
		"linked_service_key":     fields.LinkedServiceKey,
		"input_octets_64":        event.AcctInputOctets64,
		"output_octets_64":       event.AcctOutputOctets64,
		"standard_attributes":    []string{"Acct-Multi-Session-Id", "Acct-Link-Count", "Service-Type", "Framed-Protocol", "Class"},
		"subscriber_chain_table": "subscriber_service_accounting",
	})
	return string(details)
}

func hashAccountingServiceIdentity(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	return HashEAPIdentity(value)
}

func sanitizeAccountingServiceToken(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = accountingServiceTokenRegexp.ReplaceAllString(value, "-")
	value = strings.Trim(value, "-_.:")
	if len(value) > 96 {
		value = value[:96]
	}
	return value
}

func sanitizeAccountingServiceLeg(value string) string {
	value = sanitizeAccountingServiceToken(value)
	if len(value) > 128 {
		value = value[:128]
	}
	return value
}

func uniqueNonEmptyStrings(values ...string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	return out
}

func uniqueSortedStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func placeholders(count int) string {
	if count <= 0 {
		return ""
	}
	values := make([]string, count)
	for i := range values {
		values[i] = "?"
	}
	return strings.Join(values, ",")
}

func nullableInterimTime(statusType, value string) string {
	if statusType == "Interim-Update" {
		return value
	}
	return ""
}

func nullableStopTime(statusType, value string) string {
	if statusType == "Stop" || statusType == "Accounting-Off" {
		return value
	}
	return ""
}
