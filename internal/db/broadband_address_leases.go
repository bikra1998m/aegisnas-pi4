package db

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
)

type BroadbandAddressLeaseEventInput struct {
	EventID                  string
	Operation                string
	Status                   string
	PlanFingerprint          string
	Mode                     string
	PoolCount                int
	IPv4PoolCount            int
	IPv6PoolCount            int
	DelegatedPoolCount       int
	ReservationCount         int
	LeaseIntentCount         int
	ActiveLeaseCount         int
	WithdrawnLeaseCount      int
	ConflictCount            int
	ComplianceCheckCount     int
	PassedCheckCount         int
	WarningCount             int
	BlockerCount             int
	ExternalRequirementCount int
	SummaryJSON              string
	ReportJSON               string
	Actor                    string
	Leases                   []BroadbandAddressLeaseInput
}

type BroadbandAddressLeaseInput struct {
	LeaseKey       string
	SubscriberID   string
	Username       string
	SessionID      string
	AcctSessionID  string
	Product        string
	Role           string
	Tenant         string
	Family         string
	AssignmentType string
	PoolName       string
	Address        string
	Prefix         string
	ReservationKey string
	Status         string
	Sticky         bool
	Owner          string
	Revision       int
	SourceEventID  string
	MetadataJSON   string
	InstalledAt    string
	WithdrawnAt    string
	ExpiresAt      string
}

type BroadbandAddressLeaseEvent struct {
	ID                       int    `json:"id"`
	EventID                  string `json:"event_id"`
	Operation                string `json:"operation"`
	Status                   string `json:"status"`
	PlanFingerprint          string `json:"plan_fingerprint"`
	Mode                     string `json:"mode,omitempty"`
	PoolCount                int    `json:"pool_count"`
	IPv4PoolCount            int    `json:"ipv4_pool_count"`
	IPv6PoolCount            int    `json:"ipv6_pool_count"`
	DelegatedPoolCount       int    `json:"delegated_pool_count"`
	ReservationCount         int    `json:"reservation_count"`
	LeaseIntentCount         int    `json:"lease_intent_count"`
	ActiveLeaseCount         int    `json:"active_lease_count"`
	WithdrawnLeaseCount      int    `json:"withdrawn_lease_count"`
	ConflictCount            int    `json:"conflict_count"`
	ComplianceCheckCount     int    `json:"compliance_check_count"`
	PassedCheckCount         int    `json:"passed_check_count"`
	WarningCount             int    `json:"warning_count"`
	BlockerCount             int    `json:"blocker_count"`
	ExternalRequirementCount int    `json:"external_requirement_count"`
	SummaryJSON              string `json:"summary_json"`
	ReportJSON               string `json:"report_json,omitempty"`
	Actor                    string `json:"actor,omitempty"`
	CreatedAt                string `json:"created_at"`
}

type BroadbandAddressLeaseRecord struct {
	ID             int    `json:"id"`
	LeaseKey       string `json:"lease_key"`
	SubscriberID   string `json:"subscriber_id,omitempty"`
	Username       string `json:"username,omitempty"`
	SessionID      string `json:"session_id,omitempty"`
	AcctSessionID  string `json:"acct_session_id,omitempty"`
	Product        string `json:"product,omitempty"`
	Role           string `json:"role,omitempty"`
	Tenant         string `json:"tenant,omitempty"`
	Family         string `json:"family"`
	AssignmentType string `json:"assignment_type"`
	PoolName       string `json:"pool_name,omitempty"`
	Address        string `json:"address,omitempty"`
	Prefix         string `json:"prefix,omitempty"`
	ReservationKey string `json:"reservation_key,omitempty"`
	Status         string `json:"status"`
	Sticky         bool   `json:"sticky"`
	Owner          string `json:"owner,omitempty"`
	Revision       int    `json:"revision"`
	SourceEventID  string `json:"source_event_id,omitempty"`
	MetadataJSON   string `json:"metadata_json"`
	InstalledAt    string `json:"installed_at,omitempty"`
	WithdrawnAt    string `json:"withdrawn_at,omitempty"`
	ExpiresAt      string `json:"expires_at,omitempty"`
	LastSeenAt     string `json:"last_seen_at"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
}

type BroadbandAddressLeaseSummary struct {
	TotalEvents              int    `json:"total_events"`
	PreviewEvents            int    `json:"preview_events"`
	ApplyEvents              int    `json:"apply_events"`
	ReleaseEvents            int    `json:"release_events"`
	ReconcileEvents          int    `json:"reconcile_events"`
	PreviewedCount           int    `json:"previewed_count"`
	AppliedCount             int    `json:"applied_count"`
	BlockedCount             int    `json:"blocked_count"`
	DegradedCount            int    `json:"degraded_count"`
	SkippedCount             int    `json:"skipped_count"`
	FailedCount              int    `json:"failed_count"`
	ReleasedCount            int    `json:"released_count"`
	ReconciledCount          int    `json:"reconciled_count"`
	ActiveLeases             int    `json:"active_leases"`
	ReservedLeases           int    `json:"reserved_leases"`
	PlannedLeases            int    `json:"planned_leases"`
	WithdrawnLeases          int    `json:"withdrawn_leases"`
	ConflictLeases           int    `json:"conflict_leases"`
	StaleLeases              int    `json:"stale_leases"`
	IPv4Leases               int    `json:"ipv4_leases"`
	IPv6Leases               int    `json:"ipv6_leases"`
	DelegatedPrefixLeases    int    `json:"delegated_prefix_leases"`
	LastEventAt              string `json:"last_event_at,omitempty"`
	LastFingerprint          string `json:"last_fingerprint,omitempty"`
	LastPoolCount            int    `json:"last_pool_count"`
	LastReservationCount     int    `json:"last_reservation_count"`
	LastLeaseIntentCount     int    `json:"last_lease_intent_count"`
	LastComplianceCheckCount int    `json:"last_compliance_check_count"`
}

func RecordBroadbandAddressLeaseEvent(input BroadbandAddressLeaseEventInput) (string, error) {
	if DB == nil {
		return "", nil
	}
	input.Operation = normalizeBroadbandAddressLeaseOperation(input.Operation)
	input.Status = normalizeBroadbandAddressLeaseStatus(input.Status)
	input.EventID = strings.TrimSpace(input.EventID)
	if input.EventID == "" {
		input.EventID = newBroadbandAddressLeaseEventID(input)
	}
	if input.Operation == "" || input.Status == "" {
		return "", fmt.Errorf("broadband address lease operation and status are required")
	}
	if strings.TrimSpace(input.PlanFingerprint) == "" {
		return "", fmt.Errorf("broadband address lease plan fingerprint is required")
	}
	if strings.TrimSpace(input.SummaryJSON) == "" {
		input.SummaryJSON = "{}"
	}
	if strings.TrimSpace(input.ReportJSON) == "" {
		input.ReportJSON = "{}"
	}

	tx, err := DB.Begin()
	if err != nil {
		return "", fmt.Errorf("begin broadband address lease event: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.Exec(`INSERT INTO broadband_address_lease_events (
			event_id, operation, status, plan_fingerprint, mode,
			pool_count, ipv4_pool_count, ipv6_pool_count, delegated_pool_count,
			reservation_count, lease_intent_count, active_lease_count, withdrawn_lease_count,
			conflict_count, compliance_check_count, passed_check_count, warning_count, blocker_count,
			external_requirement_count, summary_json, report_json, actor, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(event_id) DO UPDATE SET
			operation = excluded.operation,
			status = excluded.status,
			plan_fingerprint = excluded.plan_fingerprint,
			mode = excluded.mode,
			pool_count = excluded.pool_count,
			ipv4_pool_count = excluded.ipv4_pool_count,
			ipv6_pool_count = excluded.ipv6_pool_count,
			delegated_pool_count = excluded.delegated_pool_count,
			reservation_count = excluded.reservation_count,
			lease_intent_count = excluded.lease_intent_count,
			active_lease_count = excluded.active_lease_count,
			withdrawn_lease_count = excluded.withdrawn_lease_count,
			conflict_count = excluded.conflict_count,
			compliance_check_count = excluded.compliance_check_count,
			passed_check_count = excluded.passed_check_count,
			warning_count = excluded.warning_count,
			blocker_count = excluded.blocker_count,
			external_requirement_count = excluded.external_requirement_count,
			summary_json = excluded.summary_json,
			report_json = excluded.report_json,
			actor = excluded.actor`,
		input.EventID,
		input.Operation,
		input.Status,
		strings.TrimSpace(input.PlanFingerprint),
		nullString(strings.TrimSpace(input.Mode)),
		nonNegativeInt(input.PoolCount),
		nonNegativeInt(input.IPv4PoolCount),
		nonNegativeInt(input.IPv6PoolCount),
		nonNegativeInt(input.DelegatedPoolCount),
		nonNegativeInt(input.ReservationCount),
		nonNegativeInt(input.LeaseIntentCount),
		nonNegativeInt(input.ActiveLeaseCount),
		nonNegativeInt(input.WithdrawnLeaseCount),
		nonNegativeInt(input.ConflictCount),
		nonNegativeInt(input.ComplianceCheckCount),
		nonNegativeInt(input.PassedCheckCount),
		nonNegativeInt(input.WarningCount),
		nonNegativeInt(input.BlockerCount),
		nonNegativeInt(input.ExternalRequirementCount),
		input.SummaryJSON,
		input.ReportJSON,
		nullString(strings.TrimSpace(input.Actor)),
	)
	if err != nil {
		return "", fmt.Errorf("record broadband address lease event: %w", err)
	}
	for _, lease := range input.Leases {
		lease.SourceEventID = firstNonEmptyString(lease.SourceEventID, input.EventID)
		if err := upsertBroadbandAddressLease(tx, lease); err != nil {
			return "", err
		}
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit broadband address lease event: %w", err)
	}
	return input.EventID, nil
}

func ListBroadbandAddressLeaseEvents(limit int) ([]BroadbandAddressLeaseEvent, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := DB.Query(broadbandAddressLeaseEventSelectSQL()+` ORDER BY datetime(created_at) DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list broadband address lease events: %w", err)
	}
	defer rows.Close()
	events := []BroadbandAddressLeaseEvent{}
	for rows.Next() {
		event, scanErr := scanBroadbandAddressLeaseEvent(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list broadband address lease event rows: %w", err)
	}
	return events, nil
}

func ListBroadbandAddressLeases(limit int, status string) ([]BroadbandAddressLeaseRecord, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	status = normalizeBroadbandAddressLeaseStatusValue(status)
	var rows *sql.Rows
	var err error
	if status == "" {
		rows, err = DB.Query(broadbandAddressLeaseSelectSQL()+` ORDER BY datetime(last_seen_at) DESC, id DESC LIMIT ?`, limit)
	} else {
		rows, err = DB.Query(broadbandAddressLeaseSelectSQL()+` WHERE status = ? ORDER BY datetime(last_seen_at) DESC, id DESC LIMIT ?`, status, limit)
	}
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list broadband address leases: %w", err)
	}
	defer rows.Close()
	leases := []BroadbandAddressLeaseRecord{}
	for rows.Next() {
		lease, scanErr := scanBroadbandAddressLease(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		leases = append(leases, lease)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list broadband address lease rows: %w", err)
	}
	return leases, nil
}

func GetBroadbandAddressLeaseSummary() (BroadbandAddressLeaseSummary, error) {
	if DB == nil {
		return BroadbandAddressLeaseSummary{}, nil
	}
	var summary BroadbandAddressLeaseSummary
	err := DB.QueryRow(`SELECT
			COUNT(*),
			COALESCE(SUM(CASE WHEN operation = 'preview' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN operation = 'apply' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN operation = 'release' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN operation = 'reconcile' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'previewed' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'applied' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'degraded' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'skipped' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'released' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'reconciled' THEN 1 ELSE 0 END), 0),
			COALESCE(MAX(created_at), '')
		FROM broadband_address_lease_events`).Scan(
		&summary.TotalEvents,
		&summary.PreviewEvents,
		&summary.ApplyEvents,
		&summary.ReleaseEvents,
		&summary.ReconcileEvents,
		&summary.PreviewedCount,
		&summary.AppliedCount,
		&summary.BlockedCount,
		&summary.DegradedCount,
		&summary.SkippedCount,
		&summary.FailedCount,
		&summary.ReleasedCount,
		&summary.ReconciledCount,
		&summary.LastEventAt,
	)
	if err != nil {
		if tableMissing(err) {
			return BroadbandAddressLeaseSummary{}, nil
		}
		return BroadbandAddressLeaseSummary{}, fmt.Errorf("summarize broadband address lease events: %w", err)
	}
	_ = DB.QueryRow(`SELECT plan_fingerprint, pool_count, reservation_count, lease_intent_count, compliance_check_count
		FROM broadband_address_lease_events
		ORDER BY datetime(created_at) DESC, id DESC LIMIT 1`).Scan(
		&summary.LastFingerprint,
		&summary.LastPoolCount,
		&summary.LastReservationCount,
		&summary.LastLeaseIntentCount,
		&summary.LastComplianceCheckCount,
	)
	err = DB.QueryRow(`SELECT
			COALESCE(SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'reserved' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'planned' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status IN ('withdrawn', 'released') THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'conflict' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'stale' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN family = 'ipv4' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN family = 'ipv6' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN assignment_type = 'delegated-prefix' THEN 1 ELSE 0 END), 0)
		FROM broadband_subscriber_address_leases`).Scan(
		&summary.ActiveLeases,
		&summary.ReservedLeases,
		&summary.PlannedLeases,
		&summary.WithdrawnLeases,
		&summary.ConflictLeases,
		&summary.StaleLeases,
		&summary.IPv4Leases,
		&summary.IPv6Leases,
		&summary.DelegatedPrefixLeases,
	)
	if err != nil && !tableMissing(err) {
		return BroadbandAddressLeaseSummary{}, fmt.Errorf("summarize broadband address leases: %w", err)
	}
	return summary, nil
}

func upsertBroadbandAddressLease(tx *sql.Tx, input BroadbandAddressLeaseInput) error {
	input = normalizeBroadbandAddressLeaseInput(input)
	if input.LeaseKey == "" {
		return fmt.Errorf("broadband address lease key is required")
	}
	if input.Family == "" || input.AssignmentType == "" || input.Status == "" {
		return fmt.Errorf("broadband address lease family, assignment type, and status are required")
	}
	if strings.TrimSpace(input.MetadataJSON) == "" {
		input.MetadataJSON = "{}"
	}
	_, err := tx.Exec(`INSERT INTO broadband_subscriber_address_leases (
			lease_key, subscriber_id, username, session_id, acct_session_id, product, role, tenant,
			family, assignment_type, pool_name, address, prefix, reservation_key, status, sticky,
			owner, revision, source_event_id, metadata_json, installed_at, withdrawn_at, expires_at,
			last_seen_at, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT(lease_key) DO UPDATE SET
			subscriber_id = excluded.subscriber_id,
			username = excluded.username,
			session_id = excluded.session_id,
			acct_session_id = excluded.acct_session_id,
			product = excluded.product,
			role = excluded.role,
			tenant = excluded.tenant,
			family = excluded.family,
			assignment_type = excluded.assignment_type,
			pool_name = excluded.pool_name,
			address = excluded.address,
			prefix = excluded.prefix,
			reservation_key = excluded.reservation_key,
			status = excluded.status,
			sticky = excluded.sticky,
			owner = excluded.owner,
			revision = CASE WHEN excluded.revision > broadband_subscriber_address_leases.revision THEN excluded.revision ELSE broadband_subscriber_address_leases.revision + 1 END,
			source_event_id = excluded.source_event_id,
			metadata_json = excluded.metadata_json,
			installed_at = COALESCE(excluded.installed_at, broadband_subscriber_address_leases.installed_at),
			withdrawn_at = excluded.withdrawn_at,
			expires_at = excluded.expires_at,
			last_seen_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP`,
		input.LeaseKey,
		nullString(input.SubscriberID),
		nullString(input.Username),
		nullString(input.SessionID),
		nullString(input.AcctSessionID),
		nullString(input.Product),
		nullString(input.Role),
		nullString(input.Tenant),
		input.Family,
		input.AssignmentType,
		nullString(input.PoolName),
		nullString(input.Address),
		nullString(input.Prefix),
		nullString(input.ReservationKey),
		input.Status,
		boolToInt(input.Sticky),
		nullString(input.Owner),
		positiveInt(input.Revision, 1),
		nullString(input.SourceEventID),
		input.MetadataJSON,
		nullString(input.InstalledAt),
		nullString(input.WithdrawnAt),
		nullString(input.ExpiresAt),
	)
	if err != nil {
		return fmt.Errorf("upsert broadband address lease %q: %w", input.LeaseKey, err)
	}
	return nil
}

func scanBroadbandAddressLeaseEvent(scanner interface {
	Scan(dest ...any) error
}) (BroadbandAddressLeaseEvent, error) {
	var event BroadbandAddressLeaseEvent
	var mode, actor sql.NullString
	err := scanner.Scan(
		&event.ID,
		&event.EventID,
		&event.Operation,
		&event.Status,
		&event.PlanFingerprint,
		&mode,
		&event.PoolCount,
		&event.IPv4PoolCount,
		&event.IPv6PoolCount,
		&event.DelegatedPoolCount,
		&event.ReservationCount,
		&event.LeaseIntentCount,
		&event.ActiveLeaseCount,
		&event.WithdrawnLeaseCount,
		&event.ConflictCount,
		&event.ComplianceCheckCount,
		&event.PassedCheckCount,
		&event.WarningCount,
		&event.BlockerCount,
		&event.ExternalRequirementCount,
		&event.SummaryJSON,
		&event.ReportJSON,
		&actor,
		&event.CreatedAt,
	)
	if err != nil {
		return BroadbandAddressLeaseEvent{}, fmt.Errorf("scan broadband address lease event: %w", err)
	}
	event.Mode = mode.String
	event.Actor = actor.String
	return event, nil
}

func scanBroadbandAddressLease(scanner interface {
	Scan(dest ...any) error
}) (BroadbandAddressLeaseRecord, error) {
	var record BroadbandAddressLeaseRecord
	var subscriberID, username, sessionID, acctSessionID, product, role, tenant sql.NullString
	var poolName, address, prefix, reservationKey, owner, sourceEventID sql.NullString
	var installedAt, withdrawnAt, expiresAt sql.NullString
	var sticky int
	err := scanner.Scan(
		&record.ID,
		&record.LeaseKey,
		&subscriberID,
		&username,
		&sessionID,
		&acctSessionID,
		&product,
		&role,
		&tenant,
		&record.Family,
		&record.AssignmentType,
		&poolName,
		&address,
		&prefix,
		&reservationKey,
		&record.Status,
		&sticky,
		&owner,
		&record.Revision,
		&sourceEventID,
		&record.MetadataJSON,
		&installedAt,
		&withdrawnAt,
		&expiresAt,
		&record.LastSeenAt,
		&record.CreatedAt,
		&record.UpdatedAt,
	)
	if err != nil {
		return BroadbandAddressLeaseRecord{}, fmt.Errorf("scan broadband address lease: %w", err)
	}
	record.SubscriberID = subscriberID.String
	record.Username = username.String
	record.SessionID = sessionID.String
	record.AcctSessionID = acctSessionID.String
	record.Product = product.String
	record.Role = role.String
	record.Tenant = tenant.String
	record.PoolName = poolName.String
	record.Address = address.String
	record.Prefix = prefix.String
	record.ReservationKey = reservationKey.String
	record.Sticky = sticky != 0
	record.Owner = owner.String
	record.SourceEventID = sourceEventID.String
	record.InstalledAt = installedAt.String
	record.WithdrawnAt = withdrawnAt.String
	record.ExpiresAt = expiresAt.String
	return record, nil
}

func broadbandAddressLeaseEventSelectSQL() string {
	return `SELECT id, event_id, operation, status, plan_fingerprint, mode,
		pool_count, ipv4_pool_count, ipv6_pool_count, delegated_pool_count,
		reservation_count, lease_intent_count, active_lease_count, withdrawn_lease_count,
		conflict_count, compliance_check_count, passed_check_count, warning_count, blocker_count,
		external_requirement_count, summary_json, report_json, actor, created_at
		FROM broadband_address_lease_events`
}

func broadbandAddressLeaseSelectSQL() string {
	return `SELECT id, lease_key, subscriber_id, username, session_id, acct_session_id, product, role, tenant,
		family, assignment_type, pool_name, address, prefix, reservation_key, status, sticky, owner,
		revision, source_event_id, metadata_json, installed_at, withdrawn_at, expires_at,
		last_seen_at, created_at, updated_at
		FROM broadband_subscriber_address_leases`
}

func normalizeBroadbandAddressLeaseInput(input BroadbandAddressLeaseInput) BroadbandAddressLeaseInput {
	input.LeaseKey = strings.TrimSpace(input.LeaseKey)
	input.SubscriberID = strings.TrimSpace(input.SubscriberID)
	input.Username = strings.TrimSpace(input.Username)
	input.SessionID = strings.TrimSpace(input.SessionID)
	input.AcctSessionID = strings.TrimSpace(input.AcctSessionID)
	input.Product = strings.TrimSpace(input.Product)
	input.Role = strings.TrimSpace(input.Role)
	input.Tenant = strings.TrimSpace(input.Tenant)
	input.Family = normalizeBroadbandAddressLeaseFamily(input.Family)
	input.AssignmentType = normalizeBroadbandAddressLeaseAssignmentType(input.AssignmentType)
	input.PoolName = strings.TrimSpace(input.PoolName)
	input.Address = strings.TrimSpace(input.Address)
	input.Prefix = strings.TrimSpace(input.Prefix)
	input.ReservationKey = strings.TrimSpace(input.ReservationKey)
	input.Status = normalizeBroadbandAddressLeaseStatusValue(input.Status)
	input.Owner = strings.TrimSpace(input.Owner)
	input.SourceEventID = strings.TrimSpace(input.SourceEventID)
	input.MetadataJSON = strings.TrimSpace(input.MetadataJSON)
	input.InstalledAt = strings.TrimSpace(input.InstalledAt)
	input.WithdrawnAt = strings.TrimSpace(input.WithdrawnAt)
	input.ExpiresAt = strings.TrimSpace(input.ExpiresAt)
	if input.Family == "" {
		input.Family = "ipv4"
	}
	if input.AssignmentType == "" {
		input.AssignmentType = "address"
	}
	if input.Status == "" {
		input.Status = "planned"
	}
	if input.LeaseKey == "" {
		input.LeaseKey = broadbandAddressLeaseKey(input)
	}
	return input
}

func normalizeBroadbandAddressLeaseOperation(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "preview", "apply", "status", "release", "reconcile":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeBroadbandAddressLeaseStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "previewed", "applied", "blocked", "degraded", "skipped", "failed", "released", "reconciled":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeBroadbandAddressLeaseStatusValue(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "planned", "reserved", "active", "withdrawn", "conflict", "stale", "released":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeBroadbandAddressLeaseFamily(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "ipv4", "v4":
		return "ipv4"
	case "ipv6", "v6", "delegated-prefix", "ipv6-prefix":
		return "ipv6"
	default:
		return ""
	}
}

func normalizeBroadbandAddressLeaseAssignmentType(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "address", "pool":
		return "address"
	case "prefix", "ipv6-prefix":
		return "prefix"
	case "delegated-prefix", "delegated_ipv6_prefix", "pd":
		return "delegated-prefix"
	default:
		return ""
	}
}

func broadbandAddressLeaseKey(input BroadbandAddressLeaseInput) string {
	base := strings.Join([]string{
		input.SubscriberID,
		input.Username,
		input.SessionID,
		input.AcctSessionID,
		input.Product,
		input.Family,
		input.AssignmentType,
		input.PoolName,
		input.Address,
		input.Prefix,
		input.ReservationKey,
	}, "|")
	sum := sha256.Sum256([]byte(base))
	return "bbl_" + hex.EncodeToString(sum[:12])
}

func newBroadbandAddressLeaseEventID(input BroadbandAddressLeaseEventInput) string {
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%s", input.Operation, input.Status, input.PlanFingerprint, input.Actor)))
		return "bale_" + hex.EncodeToString(sum[:8])
	}
	return "bale_" + hex.EncodeToString(random)
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func positiveInt(value, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}
