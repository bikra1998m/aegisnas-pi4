package db

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

type RuntimeFirewallSnapshotInput struct {
	SnapshotID             string
	Operation              string
	Status                 string
	Active                 bool
	SessionCount           int
	ManagedSessionCount    int
	QuarantineSessionCount int
	IPv4SessionCount       int
	IPv6SessionCount       int
	RuleCount              int
	AppliedRuleCount       int
	DiagnosticsJSON        string
	RulesetFingerprint     string
	RulesetText            string
	PreviousSnapshotID     string
	Actor                  string
	AppliedAt              *time.Time
	RolledBackAt           *time.Time
}

type RuntimeFirewallSnapshot struct {
	ID                     int    `json:"id"`
	SnapshotID             string `json:"snapshot_id"`
	Operation              string `json:"operation"`
	Status                 string `json:"status"`
	Active                 bool   `json:"active"`
	SessionCount           int    `json:"session_count"`
	ManagedSessionCount    int    `json:"managed_session_count"`
	QuarantineSessionCount int    `json:"quarantine_session_count"`
	IPv4SessionCount       int    `json:"ipv4_session_count"`
	IPv6SessionCount       int    `json:"ipv6_session_count"`
	RuleCount              int    `json:"rule_count"`
	AppliedRuleCount       int    `json:"applied_rule_count"`
	DiagnosticsJSON        string `json:"diagnostics_json"`
	RulesetFingerprint     string `json:"ruleset_fingerprint"`
	RulesetText            string `json:"ruleset_text,omitempty"`
	PreviousSnapshotID     string `json:"previous_snapshot_id,omitempty"`
	Actor                  string `json:"actor,omitempty"`
	CreatedAt              string `json:"created_at"`
	AppliedAt              string `json:"applied_at,omitempty"`
	RolledBackAt           string `json:"rolled_back_at,omitempty"`
}

type RuntimeFirewallEventInput struct {
	EventID                string
	Operation              string
	Status                 string
	SnapshotID             string
	PreviousSnapshotID     string
	SessionCount           int
	ManagedSessionCount    int
	QuarantineSessionCount int
	IPv4SessionCount       int
	IPv6SessionCount       int
	RuleCount              int
	AppliedRuleCount       int
	DiagnosticsJSON        string
	DetailsJSON            string
	Actor                  string
}

type RuntimeFirewallEvent struct {
	ID                     int    `json:"id"`
	EventID                string `json:"event_id"`
	Operation              string `json:"operation"`
	Status                 string `json:"status"`
	SnapshotID             string `json:"snapshot_id,omitempty"`
	PreviousSnapshotID     string `json:"previous_snapshot_id,omitempty"`
	SessionCount           int    `json:"session_count"`
	ManagedSessionCount    int    `json:"managed_session_count"`
	QuarantineSessionCount int    `json:"quarantine_session_count"`
	IPv4SessionCount       int    `json:"ipv4_session_count"`
	IPv6SessionCount       int    `json:"ipv6_session_count"`
	RuleCount              int    `json:"rule_count"`
	AppliedRuleCount       int    `json:"applied_rule_count"`
	DiagnosticsJSON        string `json:"diagnostics_json"`
	DetailsJSON            string `json:"details_json"`
	Actor                  string `json:"actor,omitempty"`
	CreatedAt              string `json:"created_at"`
}

type RuntimeFirewallEventSummary struct {
	TotalEvents              int    `json:"total_events"`
	PreviewEvents            int    `json:"preview_events"`
	ApplyEvents              int    `json:"apply_events"`
	SyncEvents               int    `json:"sync_events"`
	RollbackEvents           int    `json:"rollback_events"`
	AppliedCount             int    `json:"applied_count"`
	PreviewedCount           int    `json:"previewed_count"`
	DegradedCount            int    `json:"degraded_count"`
	BlockedCount             int    `json:"blocked_count"`
	FailedCount              int    `json:"failed_count"`
	RolledBackCount          int    `json:"rolled_back_count"`
	LastEventAt              string `json:"last_event_at,omitempty"`
	ActiveSnapshotID         string `json:"active_snapshot_id,omitempty"`
	ActiveStatus             string `json:"active_status,omitempty"`
	ActiveRulesetFingerprint string `json:"active_ruleset_fingerprint,omitempty"`
	ActiveRuleCount          int    `json:"active_rule_count"`
	ManagedSessionCount      int    `json:"managed_session_count"`
	QuarantineSessionCount   int    `json:"quarantine_session_count"`
	IPv4SessionCount         int    `json:"ipv4_session_count"`
	IPv6SessionCount         int    `json:"ipv6_session_count"`
}

func RecordRuntimeFirewallSnapshot(input RuntimeFirewallSnapshotInput) (string, error) {
	if DB == nil {
		return "", nil
	}
	input.Operation = normalizeRuntimeFirewallOperation(input.Operation)
	input.Status = normalizeRuntimeFirewallStatus(input.Status)
	input.SnapshotID = strings.TrimSpace(input.SnapshotID)
	if input.SnapshotID == "" {
		input.SnapshotID = newRuntimeFirewallID("fw-snap", input.Operation, input.Status, input.RulesetFingerprint)
	}
	if input.Operation == "" || input.Status == "" {
		return "", fmt.Errorf("runtime firewall snapshot operation and status are required")
	}
	if strings.TrimSpace(input.RulesetFingerprint) == "" {
		return "", fmt.Errorf("runtime firewall snapshot ruleset fingerprint is required")
	}
	if strings.TrimSpace(input.DiagnosticsJSON) == "" {
		input.DiagnosticsJSON = "[]"
	}

	tx, err := DB.Begin()
	if err != nil {
		return "", fmt.Errorf("begin runtime firewall snapshot transaction: %w", err)
	}
	defer tx.Rollback()

	if input.Active {
		if _, err := tx.Exec(`UPDATE runtime_firewall_snapshots SET active = 0 WHERE active = 1`); err != nil {
			return "", fmt.Errorf("clear active runtime firewall snapshot: %w", err)
		}
	}
	_, err = tx.Exec(`INSERT INTO runtime_firewall_snapshots (
			snapshot_id, operation, status, active, session_count, managed_session_count,
			quarantine_session_count, ipv4_session_count, ipv6_session_count, rule_count,
			applied_rule_count, diagnostics_json, ruleset_fingerprint, ruleset_text,
			previous_snapshot_id, actor, created_at, applied_at, rolled_back_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?, ?)`,
		input.SnapshotID,
		input.Operation,
		input.Status,
		input.Active,
		nonNegativeInt(input.SessionCount),
		nonNegativeInt(input.ManagedSessionCount),
		nonNegativeInt(input.QuarantineSessionCount),
		nonNegativeInt(input.IPv4SessionCount),
		nonNegativeInt(input.IPv6SessionCount),
		nonNegativeInt(input.RuleCount),
		nonNegativeInt(input.AppliedRuleCount),
		input.DiagnosticsJSON,
		strings.TrimSpace(input.RulesetFingerprint),
		input.RulesetText,
		nullString(strings.TrimSpace(input.PreviousSnapshotID)),
		nullString(strings.TrimSpace(input.Actor)),
		timeOrNil(input.AppliedAt),
		timeOrNil(input.RolledBackAt),
	)
	if err != nil {
		return "", fmt.Errorf("record runtime firewall snapshot: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit runtime firewall snapshot: %w", err)
	}
	return input.SnapshotID, nil
}

func RecordRuntimeFirewallEvent(input RuntimeFirewallEventInput) (string, error) {
	if DB == nil {
		return "", nil
	}
	input.Operation = normalizeRuntimeFirewallOperation(input.Operation)
	input.Status = normalizeRuntimeFirewallStatus(input.Status)
	input.EventID = strings.TrimSpace(input.EventID)
	if input.EventID == "" {
		input.EventID = newRuntimeFirewallID("fw-event", input.Operation, input.Status, input.SnapshotID)
	}
	if input.Operation == "" || input.Status == "" {
		return "", fmt.Errorf("runtime firewall event operation and status are required")
	}
	if strings.TrimSpace(input.DiagnosticsJSON) == "" {
		input.DiagnosticsJSON = "[]"
	}
	if strings.TrimSpace(input.DetailsJSON) == "" {
		input.DetailsJSON = "{}"
	}

	_, err := DB.Exec(`INSERT INTO runtime_firewall_events (
			event_id, operation, status, snapshot_id, previous_snapshot_id,
			session_count, managed_session_count, quarantine_session_count,
			ipv4_session_count, ipv6_session_count, rule_count, applied_rule_count,
			diagnostics_json, details_json, actor, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		input.EventID,
		input.Operation,
		input.Status,
		nullString(strings.TrimSpace(input.SnapshotID)),
		nullString(strings.TrimSpace(input.PreviousSnapshotID)),
		nonNegativeInt(input.SessionCount),
		nonNegativeInt(input.ManagedSessionCount),
		nonNegativeInt(input.QuarantineSessionCount),
		nonNegativeInt(input.IPv4SessionCount),
		nonNegativeInt(input.IPv6SessionCount),
		nonNegativeInt(input.RuleCount),
		nonNegativeInt(input.AppliedRuleCount),
		input.DiagnosticsJSON,
		input.DetailsJSON,
		nullString(strings.TrimSpace(input.Actor)),
	)
	if err != nil {
		return "", fmt.Errorf("record runtime firewall event: %w", err)
	}
	return input.EventID, nil
}

func ListRuntimeFirewallSnapshots(limit int) ([]RuntimeFirewallSnapshot, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	rows, err := DB.Query(`SELECT id, snapshot_id, operation, status, active,
			session_count, managed_session_count, quarantine_session_count,
			ipv4_session_count, ipv6_session_count, rule_count, applied_rule_count,
			diagnostics_json, ruleset_fingerprint, ruleset_text,
			COALESCE(previous_snapshot_id, ''), COALESCE(actor, ''),
			COALESCE(CAST(created_at AS TEXT), ''), COALESCE(CAST(applied_at AS TEXT), ''),
			COALESCE(CAST(rolled_back_at AS TEXT), '')
		FROM runtime_firewall_snapshots
		ORDER BY datetime(created_at) DESC, id DESC
		LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list runtime firewall snapshots: %w", err)
	}
	defer rows.Close()

	var snapshots []RuntimeFirewallSnapshot
	for rows.Next() {
		var item RuntimeFirewallSnapshot
		if err := rows.Scan(
			&item.ID,
			&item.SnapshotID,
			&item.Operation,
			&item.Status,
			&item.Active,
			&item.SessionCount,
			&item.ManagedSessionCount,
			&item.QuarantineSessionCount,
			&item.IPv4SessionCount,
			&item.IPv6SessionCount,
			&item.RuleCount,
			&item.AppliedRuleCount,
			&item.DiagnosticsJSON,
			&item.RulesetFingerprint,
			&item.RulesetText,
			&item.PreviousSnapshotID,
			&item.Actor,
			&item.CreatedAt,
			&item.AppliedAt,
			&item.RolledBackAt,
		); err != nil {
			return nil, fmt.Errorf("scan runtime firewall snapshot: %w", err)
		}
		snapshots = append(snapshots, item)
	}
	return snapshots, rows.Err()
}

func GetRuntimeFirewallSnapshot(snapshotID string) (RuntimeFirewallSnapshot, bool, error) {
	snapshotID = strings.TrimSpace(snapshotID)
	if DB == nil || snapshotID == "" {
		return RuntimeFirewallSnapshot{}, false, nil
	}
	rows, err := DB.Query(`SELECT id, snapshot_id, operation, status, active,
			session_count, managed_session_count, quarantine_session_count,
			ipv4_session_count, ipv6_session_count, rule_count, applied_rule_count,
			diagnostics_json, ruleset_fingerprint, ruleset_text,
			COALESCE(previous_snapshot_id, ''), COALESCE(actor, ''),
			COALESCE(CAST(created_at AS TEXT), ''), COALESCE(CAST(applied_at AS TEXT), ''),
			COALESCE(CAST(rolled_back_at AS TEXT), '')
		FROM runtime_firewall_snapshots
		WHERE snapshot_id = ?
		LIMIT 1`, snapshotID)
	if err != nil {
		return RuntimeFirewallSnapshot{}, false, fmt.Errorf("get runtime firewall snapshot: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return RuntimeFirewallSnapshot{}, false, rows.Err()
	}
	var item RuntimeFirewallSnapshot
	if err := rows.Scan(
		&item.ID,
		&item.SnapshotID,
		&item.Operation,
		&item.Status,
		&item.Active,
		&item.SessionCount,
		&item.ManagedSessionCount,
		&item.QuarantineSessionCount,
		&item.IPv4SessionCount,
		&item.IPv6SessionCount,
		&item.RuleCount,
		&item.AppliedRuleCount,
		&item.DiagnosticsJSON,
		&item.RulesetFingerprint,
		&item.RulesetText,
		&item.PreviousSnapshotID,
		&item.Actor,
		&item.CreatedAt,
		&item.AppliedAt,
		&item.RolledBackAt,
	); err != nil {
		return RuntimeFirewallSnapshot{}, false, fmt.Errorf("scan runtime firewall snapshot: %w", err)
	}
	return item, true, rows.Err()
}

func GetActiveRuntimeFirewallSnapshot() (RuntimeFirewallSnapshot, bool, error) {
	if DB == nil {
		return RuntimeFirewallSnapshot{}, false, nil
	}
	rows, err := DB.Query(`SELECT id, snapshot_id, operation, status, active,
			session_count, managed_session_count, quarantine_session_count,
			ipv4_session_count, ipv6_session_count, rule_count, applied_rule_count,
			diagnostics_json, ruleset_fingerprint, ruleset_text,
			COALESCE(previous_snapshot_id, ''), COALESCE(actor, ''),
			COALESCE(CAST(created_at AS TEXT), ''), COALESCE(CAST(applied_at AS TEXT), ''),
			COALESCE(CAST(rolled_back_at AS TEXT), '')
		FROM runtime_firewall_snapshots
		WHERE active = 1
		ORDER BY datetime(created_at) DESC, id DESC
		LIMIT 1`)
	if err != nil {
		return RuntimeFirewallSnapshot{}, false, fmt.Errorf("get active runtime firewall snapshot: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return RuntimeFirewallSnapshot{}, false, rows.Err()
	}
	var item RuntimeFirewallSnapshot
	if err := rows.Scan(
		&item.ID,
		&item.SnapshotID,
		&item.Operation,
		&item.Status,
		&item.Active,
		&item.SessionCount,
		&item.ManagedSessionCount,
		&item.QuarantineSessionCount,
		&item.IPv4SessionCount,
		&item.IPv6SessionCount,
		&item.RuleCount,
		&item.AppliedRuleCount,
		&item.DiagnosticsJSON,
		&item.RulesetFingerprint,
		&item.RulesetText,
		&item.PreviousSnapshotID,
		&item.Actor,
		&item.CreatedAt,
		&item.AppliedAt,
		&item.RolledBackAt,
	); err != nil {
		return RuntimeFirewallSnapshot{}, false, fmt.Errorf("scan active runtime firewall snapshot: %w", err)
	}
	return item, true, rows.Err()
}

func ListRuntimeFirewallEvents(limit int) ([]RuntimeFirewallEvent, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	rows, err := DB.Query(`SELECT id, event_id, operation, status,
			COALESCE(snapshot_id, ''), COALESCE(previous_snapshot_id, ''),
			session_count, managed_session_count, quarantine_session_count,
			ipv4_session_count, ipv6_session_count, rule_count, applied_rule_count,
			diagnostics_json, details_json, COALESCE(actor, ''),
			COALESCE(CAST(created_at AS TEXT), '')
		FROM runtime_firewall_events
		ORDER BY datetime(created_at) DESC, id DESC
		LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list runtime firewall events: %w", err)
	}
	defer rows.Close()

	var events []RuntimeFirewallEvent
	for rows.Next() {
		var item RuntimeFirewallEvent
		if err := rows.Scan(
			&item.ID,
			&item.EventID,
			&item.Operation,
			&item.Status,
			&item.SnapshotID,
			&item.PreviousSnapshotID,
			&item.SessionCount,
			&item.ManagedSessionCount,
			&item.QuarantineSessionCount,
			&item.IPv4SessionCount,
			&item.IPv6SessionCount,
			&item.RuleCount,
			&item.AppliedRuleCount,
			&item.DiagnosticsJSON,
			&item.DetailsJSON,
			&item.Actor,
			&item.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan runtime firewall event: %w", err)
		}
		events = append(events, item)
	}
	return events, rows.Err()
}

func GetRuntimeFirewallEventSummary() (RuntimeFirewallEventSummary, error) {
	events, err := ListRuntimeFirewallEvents(1000)
	if err != nil {
		return RuntimeFirewallEventSummary{}, err
	}
	summary := RuntimeFirewallEventSummary{}
	for _, event := range events {
		summary.TotalEvents++
		switch event.Operation {
		case "preview":
			summary.PreviewEvents++
		case "apply":
			summary.ApplyEvents++
		case "sync":
			summary.SyncEvents++
		case "rollback":
			summary.RollbackEvents++
		}
		switch event.Status {
		case "previewed":
			summary.PreviewedCount++
		case "applied":
			summary.AppliedCount++
		case "degraded":
			summary.DegradedCount++
		case "blocked":
			summary.BlockedCount++
		case "failed":
			summary.FailedCount++
		case "rolled_back":
			summary.RolledBackCount++
		}
		if summary.LastEventAt == "" || event.CreatedAt > summary.LastEventAt {
			summary.LastEventAt = event.CreatedAt
		}
	}
	active, found, err := GetActiveRuntimeFirewallSnapshot()
	if err != nil {
		return RuntimeFirewallEventSummary{}, err
	}
	if found {
		summary.ActiveSnapshotID = active.SnapshotID
		summary.ActiveStatus = active.Status
		summary.ActiveRulesetFingerprint = active.RulesetFingerprint
		summary.ActiveRuleCount = active.AppliedRuleCount
		summary.ManagedSessionCount = active.ManagedSessionCount
		summary.QuarantineSessionCount = active.QuarantineSessionCount
		summary.IPv4SessionCount = active.IPv4SessionCount
		summary.IPv6SessionCount = active.IPv6SessionCount
	}
	return summary, nil
}

func normalizeRuntimeFirewallOperation(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "preview", "apply", "rollback", "sync":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeRuntimeFirewallStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "previewed", "applied", "rolled_back", "degraded", "blocked", "failed", "skipped":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "blocked"
	}
}

func newRuntimeFirewallID(prefix, operation, status, fingerprint string) string {
	var nonce [8]byte
	_, _ = rand.Read(nonce[:])
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%s:%s:%d:%x",
		prefix,
		operation,
		status,
		fingerprint,
		time.Now().UTC().UnixNano(),
		nonce,
	)))
	return prefix + "-" + hex.EncodeToString(sum[:12])
}

func timeOrNil(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.UTC()
}
