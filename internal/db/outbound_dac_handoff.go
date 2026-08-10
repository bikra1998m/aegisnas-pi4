package db

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	OutboundDACHandoffStatusActive   = "active"
	OutboundDACHandoffStatusStandby  = "standby"
	OutboundDACHandoffStatusDisabled = "disabled"
	OutboundDACHandoffStatusBlocked  = "blocked"
	OutboundDACHandoffStatusDegraded = "degraded"
	OutboundDACHandoffStatusExpired  = "expired"

	OutboundDACHandoffEventHeartbeat = "heartbeat"
	OutboundDACHandoffEventBlocked   = "blocked"
	OutboundDACHandoffEventObserved  = "observed"
)

type OutboundDACHandoffLeaseInput struct {
	LeaseID         string
	NodeID          string
	InstanceID      string
	HARole          string
	Status          string
	CanSend         bool
	CanQueue        bool
	CanReplay       bool
	FencingToken    string
	LeaseExpiresAt  time.Time
	LastHeartbeatAt time.Time
	Message         string
	Details         map[string]any
}

type OutboundDACHandoffLeaseRecord struct {
	ID              int            `json:"id"`
	LeaseID         string         `json:"lease_id"`
	NodeID          string         `json:"node_id"`
	InstanceID      string         `json:"instance_id,omitempty"`
	HARole          string         `json:"ha_role"`
	Status          string         `json:"status"`
	CanSend         bool           `json:"can_send"`
	CanQueue        bool           `json:"can_queue"`
	CanReplay       bool           `json:"can_replay"`
	Term            int            `json:"term"`
	FencingToken    string         `json:"fencing_token,omitempty"`
	LeaseExpiresAt  string         `json:"lease_expires_at,omitempty"`
	LastHeartbeatAt string         `json:"last_heartbeat_at"`
	Message         string         `json:"message,omitempty"`
	Details         map[string]any `json:"details,omitempty"`
	CreatedAt       string         `json:"created_at"`
	UpdatedAt       string         `json:"updated_at"`
}

type OutboundDACHandoffEventCreate struct {
	EventID    string
	EventType  string
	Status     string
	NodeID     string
	LeaseID    string
	HARole     string
	Message    string
	Details    map[string]any
	ObservedAt time.Time
}

type OutboundDACHandoffEventRecord struct {
	ID         int            `json:"id"`
	EventID    string         `json:"event_id"`
	EventType  string         `json:"event_type"`
	Status     string         `json:"status"`
	NodeID     string         `json:"node_id"`
	LeaseID    string         `json:"lease_id,omitempty"`
	HARole     string         `json:"ha_role"`
	Message    string         `json:"message,omitempty"`
	Details    map[string]any `json:"details,omitempty"`
	ObservedAt string         `json:"observed_at"`
	CreatedAt  string         `json:"created_at"`
}

type OutboundDACHandoffSummary struct {
	SchemaVersion        int    `json:"schema_version"`
	TotalLeases          int    `json:"total_leases"`
	ActiveLeases         int    `json:"active_leases"`
	StandbyLeases        int    `json:"standby_leases"`
	BlockedLeases        int    `json:"blocked_leases"`
	DegradedLeases       int    `json:"degraded_leases"`
	DisabledLeases       int    `json:"disabled_leases"`
	ExpiredLeases        int    `json:"expired_leases"`
	SendCapableLeases    int    `json:"send_capable_leases"`
	QueueCapableLeases   int    `json:"queue_capable_leases"`
	ReplayCapableLeases  int    `json:"replay_capable_leases"`
	LastHeartbeatAt      string `json:"last_heartbeat_at,omitempty"`
	LastBlockedAt        string `json:"last_blocked_at,omitempty"`
	LastEventAt          string `json:"last_event_at,omitempty"`
	LastFencingTokenHash string `json:"last_fencing_token_hash,omitempty"`
}

func UpsertOutboundDACHandoffLease(input OutboundDACHandoffLeaseInput) (OutboundDACHandoffLeaseRecord, error) {
	if DB == nil {
		return OutboundDACHandoffLeaseRecord{}, fmt.Errorf("database not initialized")
	}
	input = normalizeOutboundDACHandoffLeaseInput(input)
	if input.LeaseID == "" || input.NodeID == "" || input.Status == "" {
		return OutboundDACHandoffLeaseRecord{}, fmt.Errorf("lease_id, node_id, and status are required")
	}
	detailsJSON, err := json.Marshal(input.Details)
	if err != nil {
		return OutboundDACHandoffLeaseRecord{}, fmt.Errorf("encode outbound DAC handoff lease details: %w", err)
	}
	now := input.LastHeartbeatAt
	_, err = DB.Exec(`INSERT INTO radius_dac_handoff_leases (
		lease_id, node_id, instance_id, ha_role, status, can_send, can_queue, can_replay,
		term, fencing_token, lease_expires_at, last_heartbeat_at, message, details_json, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(lease_id) DO UPDATE SET
		node_id = excluded.node_id,
		instance_id = excluded.instance_id,
		ha_role = excluded.ha_role,
		status = excluded.status,
		can_send = excluded.can_send,
		can_queue = excluded.can_queue,
		can_replay = excluded.can_replay,
		term = radius_dac_handoff_leases.term + 1,
		fencing_token = excluded.fencing_token,
		lease_expires_at = excluded.lease_expires_at,
		last_heartbeat_at = excluded.last_heartbeat_at,
		message = excluded.message,
		details_json = excluded.details_json,
		updated_at = excluded.updated_at`,
		input.LeaseID, input.NodeID, nullIfEmpty(input.InstanceID), input.HARole, input.Status,
		input.CanSend, input.CanQueue, input.CanReplay, input.FencingToken, nullIfEmpty(formatSpoolTime(input.LeaseExpiresAt)),
		formatSpoolTime(input.LastHeartbeatAt), nullIfEmpty(input.Message), string(detailsJSON), formatSpoolTime(now), formatSpoolTime(now))
	if err != nil {
		return OutboundDACHandoffLeaseRecord{}, fmt.Errorf("upsert outbound DAC handoff lease: %w", err)
	}
	return GetOutboundDACHandoffLease(input.LeaseID)
}

func GetOutboundDACHandoffLease(leaseID string) (OutboundDACHandoffLeaseRecord, error) {
	if DB == nil {
		return OutboundDACHandoffLeaseRecord{}, fmt.Errorf("database not initialized")
	}
	rows, err := DB.Query(outboundDACHandoffLeaseSelectSQL()+` WHERE lease_id = ? LIMIT 1`, strings.TrimSpace(leaseID))
	if err != nil {
		return OutboundDACHandoffLeaseRecord{}, err
	}
	defer rows.Close()
	records, err := scanOutboundDACHandoffLeaseRows(rows)
	if err != nil {
		return OutboundDACHandoffLeaseRecord{}, err
	}
	if len(records) == 0 {
		return OutboundDACHandoffLeaseRecord{}, fmt.Errorf("outbound DAC handoff lease %q not found", leaseID)
	}
	return records[0], nil
}

func ListOutboundDACHandoffLeases(limit int) ([]OutboundDACHandoffLeaseRecord, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := DB.Query(outboundDACHandoffLeaseSelectSQL()+` ORDER BY datetime(updated_at) DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list outbound DAC handoff leases: %w", err)
	}
	defer rows.Close()
	return scanOutboundDACHandoffLeaseRows(rows)
}

func RecordOutboundDACHandoffEvent(create OutboundDACHandoffEventCreate, retentionLimit int) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	create = normalizeOutboundDACHandoffEventCreate(create)
	if create.EventID == "" || create.EventType == "" || create.Status == "" || create.NodeID == "" {
		return fmt.Errorf("event_id, event_type, status, and node_id are required")
	}
	detailsJSON, err := json.Marshal(create.Details)
	if err != nil {
		return fmt.Errorf("encode outbound DAC handoff event details: %w", err)
	}
	_, err = DB.Exec(`INSERT INTO radius_dac_handoff_events (
		event_id, event_type, status, node_id, lease_id, ha_role, message, details_json, observed_at, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(event_id) DO NOTHING`,
		create.EventID, create.EventType, create.Status, create.NodeID, nullIfEmpty(create.LeaseID),
		create.HARole, nullIfEmpty(create.Message), string(detailsJSON), formatSpoolTime(create.ObservedAt), formatSpoolTime(create.ObservedAt))
	if err != nil {
		return fmt.Errorf("record outbound DAC handoff event: %w", err)
	}
	return pruneOutboundDACHandoffEvents(retentionLimit)
}

func ListOutboundDACHandoffEvents(limit int) ([]OutboundDACHandoffEventRecord, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := DB.Query(`SELECT id, event_id, event_type, status, node_id, COALESCE(lease_id, ''),
		COALESCE(ha_role, 'standalone'), COALESCE(message, ''), COALESCE(details_json, '{}'), observed_at, created_at
		FROM radius_dac_handoff_events ORDER BY datetime(observed_at) DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list outbound DAC handoff events: %w", err)
	}
	defer rows.Close()
	records := []OutboundDACHandoffEventRecord{}
	for rows.Next() {
		var record OutboundDACHandoffEventRecord
		var detailsJSON string
		if err := rows.Scan(&record.ID, &record.EventID, &record.EventType, &record.Status, &record.NodeID,
			&record.LeaseID, &record.HARole, &record.Message, &detailsJSON, &record.ObservedAt, &record.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(detailsJSON), &record.Details)
		records = append(records, record)
	}
	return records, rows.Err()
}

func GetOutboundDACHandoffSummary() (OutboundDACHandoffSummary, error) {
	summary := OutboundDACHandoffSummary{SchemaVersion: 1}
	if DB == nil {
		return summary, nil
	}
	now := formatSpoolTime(time.Now().UTC())
	err := DB.QueryRow(`SELECT
		COUNT(*),
		COALESCE(SUM(CASE WHEN status = 'active' AND (lease_expires_at IS NULL OR lease_expires_at = '' OR datetime(lease_expires_at) > datetime(?)) THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'standby' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'degraded' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'disabled' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'expired' OR (lease_expires_at IS NOT NULL AND lease_expires_at <> '' AND datetime(lease_expires_at) <= datetime(?)) THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN can_send THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN can_queue THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN can_replay THEN 1 ELSE 0 END), 0),
		COALESCE(MAX(last_heartbeat_at), '')
		FROM radius_dac_handoff_leases`, now, now).Scan(
		&summary.TotalLeases, &summary.ActiveLeases, &summary.StandbyLeases, &summary.BlockedLeases,
		&summary.DegradedLeases, &summary.DisabledLeases, &summary.ExpiredLeases, &summary.SendCapableLeases,
		&summary.QueueCapableLeases, &summary.ReplayCapableLeases, &summary.LastHeartbeatAt)
	if err != nil {
		if tableMissing(err) {
			return summary, nil
		}
		return summary, fmt.Errorf("get outbound DAC handoff summary: %w", err)
	}
	_ = DB.QueryRow(`SELECT COALESCE(MAX(observed_at), '') FROM radius_dac_handoff_events`).Scan(&summary.LastEventAt)
	_ = DB.QueryRow(`SELECT COALESCE(MAX(observed_at), '') FROM radius_dac_handoff_events WHERE status = 'blocked'`).Scan(&summary.LastBlockedAt)
	var fencingToken string
	_ = DB.QueryRow(`SELECT COALESCE(fencing_token, '') FROM radius_dac_handoff_leases
		WHERE fencing_token IS NOT NULL AND fencing_token <> ''
		ORDER BY datetime(updated_at) DESC LIMIT 1`).Scan(&fencingToken)
	if fencingToken != "" {
		summary.LastFencingTokenHash = "sha256:" + outboundDACHandoffFingerprint(fencingToken)
	}
	return summary, nil
}

func pruneOutboundDACHandoffEvents(retentionLimit int) error {
	if DB == nil || retentionLimit <= 0 {
		return nil
	}
	_, err := DB.Exec(`DELETE FROM radius_dac_handoff_events
		WHERE id IN (
			SELECT id FROM radius_dac_handoff_events
			ORDER BY datetime(observed_at) DESC, id DESC
			LIMIT -1 OFFSET ?
		)`, retentionLimit)
	return err
}

func normalizeOutboundDACHandoffLeaseInput(input OutboundDACHandoffLeaseInput) OutboundDACHandoffLeaseInput {
	input.LeaseID = strings.TrimSpace(input.LeaseID)
	input.NodeID = strings.TrimSpace(input.NodeID)
	input.InstanceID = strings.TrimSpace(input.InstanceID)
	input.HARole = normalizeOutboundDACHandoffRole(input.HARole)
	input.Status = normalizeOutboundDACHandoffStatus(input.Status)
	input.FencingToken = strings.TrimSpace(input.FencingToken)
	input.Message = strings.TrimSpace(input.Message)
	if input.LastHeartbeatAt.IsZero() {
		input.LastHeartbeatAt = time.Now().UTC()
	}
	input.LastHeartbeatAt = input.LastHeartbeatAt.UTC()
	if !input.LeaseExpiresAt.IsZero() {
		input.LeaseExpiresAt = input.LeaseExpiresAt.UTC()
	}
	if input.Details == nil {
		input.Details = map[string]any{}
	}
	return input
}

func normalizeOutboundDACHandoffEventCreate(create OutboundDACHandoffEventCreate) OutboundDACHandoffEventCreate {
	create.EventID = strings.TrimSpace(create.EventID)
	create.EventType = strings.TrimSpace(strings.ToLower(create.EventType))
	create.Status = normalizeOutboundDACHandoffStatus(create.Status)
	create.NodeID = strings.TrimSpace(create.NodeID)
	create.LeaseID = strings.TrimSpace(create.LeaseID)
	create.HARole = normalizeOutboundDACHandoffRole(create.HARole)
	create.Message = strings.TrimSpace(create.Message)
	if create.ObservedAt.IsZero() {
		create.ObservedAt = time.Now().UTC()
	}
	create.ObservedAt = create.ObservedAt.UTC()
	if create.Details == nil {
		create.Details = map[string]any{}
	}
	return create
}

func normalizeOutboundDACHandoffRole(role string) string {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "active", "standby":
		return strings.ToLower(strings.TrimSpace(role))
	default:
		return "standalone"
	}
}

func normalizeOutboundDACHandoffStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case OutboundDACHandoffStatusActive, OutboundDACHandoffStatusStandby, OutboundDACHandoffStatusDisabled,
		OutboundDACHandoffStatusBlocked, OutboundDACHandoffStatusDegraded, OutboundDACHandoffStatusExpired:
		return strings.ToLower(strings.TrimSpace(status))
	default:
		return strings.ToLower(strings.TrimSpace(status))
	}
}

func outboundDACHandoffLeaseSelectSQL() string {
	return `SELECT id, lease_id, node_id, COALESCE(instance_id, ''), COALESCE(ha_role, 'standalone'),
		status, can_send, can_queue, can_replay, term, COALESCE(fencing_token, ''),
		COALESCE(lease_expires_at, ''), last_heartbeat_at, COALESCE(message, ''),
		COALESCE(details_json, '{}'), created_at, updated_at
		FROM radius_dac_handoff_leases`
}

func scanOutboundDACHandoffLeaseRows(rows outboundDACRows) ([]OutboundDACHandoffLeaseRecord, error) {
	records := []OutboundDACHandoffLeaseRecord{}
	for rows.Next() {
		var record OutboundDACHandoffLeaseRecord
		var detailsJSON string
		if err := rows.Scan(&record.ID, &record.LeaseID, &record.NodeID, &record.InstanceID, &record.HARole,
			&record.Status, &record.CanSend, &record.CanQueue, &record.CanReplay, &record.Term,
			&record.FencingToken, &record.LeaseExpiresAt, &record.LastHeartbeatAt, &record.Message,
			&detailsJSON, &record.CreatedAt, &record.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(detailsJSON), &record.Details)
		records = append(records, record)
	}
	return records, rows.Err()
}

func outboundDACHandoffFingerprint(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])
}
