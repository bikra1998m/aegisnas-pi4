package db

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

type SubscriberRouteExportSnapshotInput struct {
	SnapshotID         string
	Operation          string
	Status             string
	Active             bool
	Driver             string
	ProtocolCount      int
	RouteCount         int
	IPv4RouteCount     int
	IPv6RouteCount     int
	WithdrawRouteCount int
	CommandCount       int
	DiagnosticCount    int
	PlanFingerprint    string
	ArtifactPath       string
	ArtifactSHA256     string
	ArtifactText       string
	CommandText        string
	PlanJSON           string
	DiagnosticsJSON    string
	SummaryJSON        string
	PreviousSnapshotID string
	Actor              string
	AppliedAt          *time.Time
	RolledBackAt       *time.Time
}

type SubscriberRouteExportSnapshot struct {
	ID                 int    `json:"id"`
	SnapshotID         string `json:"snapshot_id"`
	Operation          string `json:"operation"`
	Status             string `json:"status"`
	Active             bool   `json:"active"`
	Driver             string `json:"driver"`
	ProtocolCount      int    `json:"protocol_count"`
	RouteCount         int    `json:"route_count"`
	IPv4RouteCount     int    `json:"ipv4_route_count"`
	IPv6RouteCount     int    `json:"ipv6_route_count"`
	WithdrawRouteCount int    `json:"withdraw_route_count"`
	CommandCount       int    `json:"command_count"`
	DiagnosticCount    int    `json:"diagnostic_count"`
	PlanFingerprint    string `json:"plan_fingerprint"`
	ArtifactPath       string `json:"artifact_path,omitempty"`
	ArtifactSHA256     string `json:"artifact_sha256,omitempty"`
	ArtifactText       string `json:"artifact_text,omitempty"`
	CommandText        string `json:"command_text,omitempty"`
	PlanJSON           string `json:"plan_json"`
	DiagnosticsJSON    string `json:"diagnostics_json"`
	SummaryJSON        string `json:"summary_json"`
	PreviousSnapshotID string `json:"previous_snapshot_id,omitempty"`
	Actor              string `json:"actor,omitempty"`
	CreatedAt          string `json:"created_at"`
	AppliedAt          string `json:"applied_at,omitempty"`
	RolledBackAt       string `json:"rolled_back_at,omitempty"`
}

type SubscriberRouteExportEventInput struct {
	EventID            string
	Operation          string
	Status             string
	SnapshotID         string
	PreviousSnapshotID string
	Driver             string
	ProtocolCount      int
	RouteCount         int
	IPv4RouteCount     int
	IPv6RouteCount     int
	WithdrawRouteCount int
	CommandCount       int
	DiagnosticCount    int
	PlanFingerprint    string
	ArtifactSHA256     string
	DiagnosticsJSON    string
	DetailsJSON        string
	Actor              string
}

type SubscriberRouteExportEvent struct {
	ID                 int    `json:"id"`
	EventID            string `json:"event_id"`
	Operation          string `json:"operation"`
	Status             string `json:"status"`
	SnapshotID         string `json:"snapshot_id,omitempty"`
	PreviousSnapshotID string `json:"previous_snapshot_id,omitempty"`
	Driver             string `json:"driver,omitempty"`
	ProtocolCount      int    `json:"protocol_count"`
	RouteCount         int    `json:"route_count"`
	IPv4RouteCount     int    `json:"ipv4_route_count"`
	IPv6RouteCount     int    `json:"ipv6_route_count"`
	WithdrawRouteCount int    `json:"withdraw_route_count"`
	CommandCount       int    `json:"command_count"`
	DiagnosticCount    int    `json:"diagnostic_count"`
	PlanFingerprint    string `json:"plan_fingerprint,omitempty"`
	ArtifactSHA256     string `json:"artifact_sha256,omitempty"`
	DiagnosticsJSON    string `json:"diagnostics_json"`
	DetailsJSON        string `json:"details_json"`
	Actor              string `json:"actor,omitempty"`
	CreatedAt          string `json:"created_at"`
}

type SubscriberRouteExportSummary struct {
	TotalEvents          int    `json:"total_events"`
	PreviewEvents        int    `json:"preview_events"`
	ApplyEvents          int    `json:"apply_events"`
	SyncEvents           int    `json:"sync_events"`
	RollbackEvents       int    `json:"rollback_events"`
	PreviewedCount       int    `json:"previewed_count"`
	AppliedCount         int    `json:"applied_count"`
	DegradedCount        int    `json:"degraded_count"`
	BlockedCount         int    `json:"blocked_count"`
	FailedCount          int    `json:"failed_count"`
	SkippedCount         int    `json:"skipped_count"`
	RolledBackCount      int    `json:"rolled_back_count"`
	LastEventAt          string `json:"last_event_at,omitempty"`
	ActiveSnapshotID     string `json:"active_snapshot_id,omitempty"`
	ActiveStatus         string `json:"active_status,omitempty"`
	ActiveFingerprint    string `json:"active_fingerprint,omitempty"`
	ActiveDriver         string `json:"active_driver,omitempty"`
	ActiveRouteCount     int    `json:"active_route_count"`
	ActiveIPv4RouteCount int    `json:"active_ipv4_route_count"`
	ActiveIPv6RouteCount int    `json:"active_ipv6_route_count"`
}

func RecordSubscriberRouteExportSnapshot(input SubscriberRouteExportSnapshotInput) (string, error) {
	if DB == nil {
		return "", nil
	}
	input.Operation = normalizeSubscriberRouteExportOperation(input.Operation)
	input.Status = normalizeSubscriberRouteExportStatus(input.Status)
	input.SnapshotID = strings.TrimSpace(input.SnapshotID)
	if input.SnapshotID == "" {
		input.SnapshotID = newSubscriberRouteExportID("route-export-snap", input.Operation, input.Status, input.PlanFingerprint)
	}
	if input.Operation == "" || input.Status == "" {
		return "", fmt.Errorf("subscriber route export snapshot operation and status are required")
	}
	if strings.TrimSpace(input.PlanFingerprint) == "" {
		return "", fmt.Errorf("subscriber route export snapshot plan fingerprint is required")
	}
	if strings.TrimSpace(input.PlanJSON) == "" {
		input.PlanJSON = "{}"
	}
	if strings.TrimSpace(input.DiagnosticsJSON) == "" {
		input.DiagnosticsJSON = "[]"
	}
	if strings.TrimSpace(input.SummaryJSON) == "" {
		input.SummaryJSON = "{}"
	}

	tx, err := DB.Begin()
	if err != nil {
		return "", fmt.Errorf("begin subscriber route export snapshot transaction: %w", err)
	}
	defer tx.Rollback()

	if input.Active {
		if _, err := tx.Exec(`UPDATE subscriber_route_export_snapshots SET active = 0 WHERE active = 1`); err != nil {
			return "", fmt.Errorf("deactivate subscriber route export snapshots: %w", err)
		}
	}
	_, err = tx.Exec(`INSERT INTO subscriber_route_export_snapshots (
			snapshot_id, operation, status, active, driver, protocol_count, route_count, ipv4_route_count,
			ipv6_route_count, withdraw_route_count, command_count, diagnostic_count, plan_fingerprint,
			artifact_path, artifact_sha256, artifact_text, command_text, plan_json, diagnostics_json, summary_json,
			previous_snapshot_id, actor, applied_at, rolled_back_at, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(snapshot_id) DO UPDATE SET
			operation = excluded.operation,
			status = excluded.status,
			active = excluded.active,
			driver = excluded.driver,
			protocol_count = excluded.protocol_count,
			route_count = excluded.route_count,
			ipv4_route_count = excluded.ipv4_route_count,
			ipv6_route_count = excluded.ipv6_route_count,
			withdraw_route_count = excluded.withdraw_route_count,
			command_count = excluded.command_count,
			diagnostic_count = excluded.diagnostic_count,
			plan_fingerprint = excluded.plan_fingerprint,
			artifact_path = excluded.artifact_path,
			artifact_sha256 = excluded.artifact_sha256,
			artifact_text = excluded.artifact_text,
			command_text = excluded.command_text,
			plan_json = excluded.plan_json,
			diagnostics_json = excluded.diagnostics_json,
			summary_json = excluded.summary_json,
			previous_snapshot_id = excluded.previous_snapshot_id,
			actor = excluded.actor,
			applied_at = excluded.applied_at,
			rolled_back_at = excluded.rolled_back_at`,
		input.SnapshotID,
		input.Operation,
		input.Status,
		input.Active,
		strings.TrimSpace(input.Driver),
		nonNegativeInt(input.ProtocolCount),
		nonNegativeInt(input.RouteCount),
		nonNegativeInt(input.IPv4RouteCount),
		nonNegativeInt(input.IPv6RouteCount),
		nonNegativeInt(input.WithdrawRouteCount),
		nonNegativeInt(input.CommandCount),
		nonNegativeInt(input.DiagnosticCount),
		strings.TrimSpace(input.PlanFingerprint),
		nullString(strings.TrimSpace(input.ArtifactPath)),
		nullString(strings.TrimSpace(input.ArtifactSHA256)),
		input.ArtifactText,
		input.CommandText,
		input.PlanJSON,
		input.DiagnosticsJSON,
		input.SummaryJSON,
		nullString(strings.TrimSpace(input.PreviousSnapshotID)),
		nullString(strings.TrimSpace(input.Actor)),
		timeOrNil(input.AppliedAt),
		timeOrNil(input.RolledBackAt),
	)
	if err != nil {
		return "", fmt.Errorf("record subscriber route export snapshot: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit subscriber route export snapshot: %w", err)
	}
	return input.SnapshotID, nil
}

func RecordSubscriberRouteExportEvent(input SubscriberRouteExportEventInput) (string, error) {
	if DB == nil {
		return "", nil
	}
	input.Operation = normalizeSubscriberRouteExportOperation(input.Operation)
	input.Status = normalizeSubscriberRouteExportStatus(input.Status)
	input.EventID = strings.TrimSpace(input.EventID)
	if input.EventID == "" {
		input.EventID = newSubscriberRouteExportID("route-export-event", input.Operation, input.Status, input.PlanFingerprint)
	}
	if input.Operation == "" || input.Status == "" {
		return "", fmt.Errorf("subscriber route export event operation and status are required")
	}
	if strings.TrimSpace(input.DiagnosticsJSON) == "" {
		input.DiagnosticsJSON = "[]"
	}
	if strings.TrimSpace(input.DetailsJSON) == "" {
		input.DetailsJSON = "{}"
	}
	_, err := DB.Exec(`INSERT INTO subscriber_route_export_events (
			event_id, operation, status, snapshot_id, previous_snapshot_id, driver, protocol_count, route_count,
			ipv4_route_count, ipv6_route_count, withdraw_route_count, command_count, diagnostic_count,
			plan_fingerprint, artifact_sha256, diagnostics_json, details_json, actor, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		input.EventID,
		input.Operation,
		input.Status,
		nullString(strings.TrimSpace(input.SnapshotID)),
		nullString(strings.TrimSpace(input.PreviousSnapshotID)),
		nullString(strings.TrimSpace(input.Driver)),
		nonNegativeInt(input.ProtocolCount),
		nonNegativeInt(input.RouteCount),
		nonNegativeInt(input.IPv4RouteCount),
		nonNegativeInt(input.IPv6RouteCount),
		nonNegativeInt(input.WithdrawRouteCount),
		nonNegativeInt(input.CommandCount),
		nonNegativeInt(input.DiagnosticCount),
		nullString(strings.TrimSpace(input.PlanFingerprint)),
		nullString(strings.TrimSpace(input.ArtifactSHA256)),
		input.DiagnosticsJSON,
		input.DetailsJSON,
		nullString(strings.TrimSpace(input.Actor)),
	)
	if err != nil {
		return "", fmt.Errorf("record subscriber route export event: %w", err)
	}
	return input.EventID, nil
}

func GetActiveSubscriberRouteExportSnapshot() (SubscriberRouteExportSnapshot, bool, error) {
	if DB == nil {
		return SubscriberRouteExportSnapshot{}, false, nil
	}
	row := DB.QueryRow(subscriberRouteExportSnapshotSelectSQL() + ` WHERE active = 1 ORDER BY datetime(created_at) DESC, id DESC LIMIT 1`)
	snapshot, err := scanSubscriberRouteExportSnapshot(row)
	if err == sql.ErrNoRows {
		return SubscriberRouteExportSnapshot{}, false, nil
	}
	if err != nil {
		if tableMissing(err) {
			return SubscriberRouteExportSnapshot{}, false, nil
		}
		return SubscriberRouteExportSnapshot{}, false, err
	}
	return snapshot, true, nil
}

func GetSubscriberRouteExportSnapshot(snapshotID string) (SubscriberRouteExportSnapshot, bool, error) {
	if DB == nil {
		return SubscriberRouteExportSnapshot{}, false, nil
	}
	snapshotID = strings.TrimSpace(snapshotID)
	if snapshotID == "" {
		return SubscriberRouteExportSnapshot{}, false, nil
	}
	row := DB.QueryRow(subscriberRouteExportSnapshotSelectSQL()+` WHERE snapshot_id = ?`, snapshotID)
	snapshot, err := scanSubscriberRouteExportSnapshot(row)
	if err == sql.ErrNoRows {
		return SubscriberRouteExportSnapshot{}, false, nil
	}
	if err != nil {
		return SubscriberRouteExportSnapshot{}, false, err
	}
	return snapshot, true, nil
}

func ListSubscriberRouteExportSnapshots(limit int) ([]SubscriberRouteExportSnapshot, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := DB.Query(subscriberRouteExportSnapshotSelectSQL()+` ORDER BY datetime(created_at) DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list subscriber route export snapshots: %w", err)
	}
	defer rows.Close()

	var snapshots []SubscriberRouteExportSnapshot
	for rows.Next() {
		snapshot, err := scanSubscriberRouteExportSnapshot(rows)
		if err != nil {
			return nil, err
		}
		snapshots = append(snapshots, snapshot)
	}
	return snapshots, rows.Err()
}

func ListSubscriberRouteExportEvents(limit int) ([]SubscriberRouteExportEvent, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := DB.Query(`SELECT id, event_id, operation, status, COALESCE(snapshot_id, ''), COALESCE(previous_snapshot_id, ''),
			COALESCE(driver, ''), protocol_count, route_count, ipv4_route_count, ipv6_route_count, withdraw_route_count,
			command_count, diagnostic_count, COALESCE(plan_fingerprint, ''), COALESCE(artifact_sha256, ''),
			diagnostics_json, details_json, COALESCE(actor, ''), COALESCE(CAST(created_at AS TEXT), '')
		FROM subscriber_route_export_events
		ORDER BY datetime(created_at) DESC, id DESC
		LIMIT ?`, limit)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list subscriber route export events: %w", err)
	}
	defer rows.Close()

	var events []SubscriberRouteExportEvent
	for rows.Next() {
		var event SubscriberRouteExportEvent
		if err := rows.Scan(
			&event.ID,
			&event.EventID,
			&event.Operation,
			&event.Status,
			&event.SnapshotID,
			&event.PreviousSnapshotID,
			&event.Driver,
			&event.ProtocolCount,
			&event.RouteCount,
			&event.IPv4RouteCount,
			&event.IPv6RouteCount,
			&event.WithdrawRouteCount,
			&event.CommandCount,
			&event.DiagnosticCount,
			&event.PlanFingerprint,
			&event.ArtifactSHA256,
			&event.DiagnosticsJSON,
			&event.DetailsJSON,
			&event.Actor,
			&event.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan subscriber route export event: %w", err)
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func GetSubscriberRouteExportSummary() (SubscriberRouteExportSummary, error) {
	events, err := ListSubscriberRouteExportEvents(1000)
	if err != nil {
		return SubscriberRouteExportSummary{}, err
	}
	summary := SubscriberRouteExportSummary{}
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
		case "skipped":
			summary.SkippedCount++
		case "rolled_back":
			summary.RolledBackCount++
		}
		if summary.LastEventAt == "" || event.CreatedAt > summary.LastEventAt {
			summary.LastEventAt = event.CreatedAt
		}
	}
	if active, found, err := GetActiveSubscriberRouteExportSnapshot(); err != nil {
		return summary, err
	} else if found {
		summary.ActiveSnapshotID = active.SnapshotID
		summary.ActiveStatus = active.Status
		summary.ActiveFingerprint = active.PlanFingerprint
		summary.ActiveDriver = active.Driver
		summary.ActiveRouteCount = active.RouteCount
		summary.ActiveIPv4RouteCount = active.IPv4RouteCount
		summary.ActiveIPv6RouteCount = active.IPv6RouteCount
	}
	return summary, nil
}

func subscriberRouteExportSnapshotSelectSQL() string {
	return `SELECT id, snapshot_id, operation, status, active, COALESCE(driver, ''), protocol_count, route_count,
		ipv4_route_count, ipv6_route_count, withdraw_route_count, command_count, diagnostic_count,
		plan_fingerprint, COALESCE(artifact_path, ''), COALESCE(artifact_sha256, ''), COALESCE(artifact_text, ''),
		COALESCE(command_text, ''), plan_json, diagnostics_json, summary_json, COALESCE(previous_snapshot_id, ''),
		COALESCE(actor, ''), COALESCE(CAST(created_at AS TEXT), ''), COALESCE(CAST(applied_at AS TEXT), ''),
		COALESCE(CAST(rolled_back_at AS TEXT), '')
		FROM subscriber_route_export_snapshots`
}

func scanSubscriberRouteExportSnapshot(scanner interface {
	Scan(dest ...any) error
}) (SubscriberRouteExportSnapshot, error) {
	var snapshot SubscriberRouteExportSnapshot
	if err := scanner.Scan(
		&snapshot.ID,
		&snapshot.SnapshotID,
		&snapshot.Operation,
		&snapshot.Status,
		&snapshot.Active,
		&snapshot.Driver,
		&snapshot.ProtocolCount,
		&snapshot.RouteCount,
		&snapshot.IPv4RouteCount,
		&snapshot.IPv6RouteCount,
		&snapshot.WithdrawRouteCount,
		&snapshot.CommandCount,
		&snapshot.DiagnosticCount,
		&snapshot.PlanFingerprint,
		&snapshot.ArtifactPath,
		&snapshot.ArtifactSHA256,
		&snapshot.ArtifactText,
		&snapshot.CommandText,
		&snapshot.PlanJSON,
		&snapshot.DiagnosticsJSON,
		&snapshot.SummaryJSON,
		&snapshot.PreviousSnapshotID,
		&snapshot.Actor,
		&snapshot.CreatedAt,
		&snapshot.AppliedAt,
		&snapshot.RolledBackAt,
	); err != nil {
		if err == sql.ErrNoRows {
			return SubscriberRouteExportSnapshot{}, err
		}
		return SubscriberRouteExportSnapshot{}, fmt.Errorf("scan subscriber route export snapshot: %w", err)
	}
	return snapshot, nil
}

func normalizeSubscriberRouteExportOperation(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "preview", "apply", "sync", "rollback":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeSubscriberRouteExportStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "previewed", "applied", "degraded", "blocked", "failed", "skipped", "rolled_back":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func newSubscriberRouteExportID(prefix, operation, status, fingerprint string) string {
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
