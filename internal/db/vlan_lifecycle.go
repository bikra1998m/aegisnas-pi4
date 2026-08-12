package db

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

type VLANLifecycleSnapshotInput struct {
	SnapshotID            string
	Operation             string
	Status                string
	Active                bool
	ParentInterface       string
	VLANCount             int
	BridgeCount           int
	SubinterfaceCount     int
	HostapdVLANEntryCount int
	CommandCount          int
	DiagnosticCount       int
	PlanFingerprint       string
	CommandText           string
	HostapdVLANFilePath   string
	HostapdVLANFileText   string
	HostapdVLANFileSHA256 string
	DiagnosticsJSON       string
	SummaryJSON           string
	PlanJSON              string
	PreviousSnapshotID    string
	Actor                 string
	AppliedAt             *time.Time
	RolledBackAt          *time.Time
}

type VLANLifecycleSnapshot struct {
	ID                    int    `json:"id"`
	SnapshotID            string `json:"snapshot_id"`
	Operation             string `json:"operation"`
	Status                string `json:"status"`
	Active                bool   `json:"active"`
	ParentInterface       string `json:"parent_interface,omitempty"`
	VLANCount             int    `json:"vlan_count"`
	BridgeCount           int    `json:"bridge_count"`
	SubinterfaceCount     int    `json:"subinterface_count"`
	HostapdVLANEntryCount int    `json:"hostapd_vlan_entry_count"`
	CommandCount          int    `json:"command_count"`
	DiagnosticCount       int    `json:"diagnostic_count"`
	PlanFingerprint       string `json:"plan_fingerprint"`
	CommandText           string `json:"command_text,omitempty"`
	HostapdVLANFilePath   string `json:"hostapd_vlan_file_path,omitempty"`
	HostapdVLANFileText   string `json:"hostapd_vlan_file_text,omitempty"`
	HostapdVLANFileSHA256 string `json:"hostapd_vlan_file_sha256,omitempty"`
	DiagnosticsJSON       string `json:"diagnostics_json"`
	SummaryJSON           string `json:"summary_json"`
	PlanJSON              string `json:"plan_json"`
	PreviousSnapshotID    string `json:"previous_snapshot_id,omitempty"`
	Actor                 string `json:"actor,omitempty"`
	CreatedAt             string `json:"created_at"`
	AppliedAt             string `json:"applied_at,omitempty"`
	RolledBackAt          string `json:"rolled_back_at,omitempty"`
}

type VLANLifecycleEventInput struct {
	EventID               string
	Operation             string
	Status                string
	SnapshotID            string
	PreviousSnapshotID    string
	ParentInterface       string
	VLANCount             int
	BridgeCount           int
	SubinterfaceCount     int
	HostapdVLANEntryCount int
	CommandCount          int
	DiagnosticCount       int
	PlanFingerprint       string
	DiagnosticsJSON       string
	DetailsJSON           string
	Actor                 string
}

type VLANLifecycleEvent struct {
	ID                    int    `json:"id"`
	EventID               string `json:"event_id"`
	Operation             string `json:"operation"`
	Status                string `json:"status"`
	SnapshotID            string `json:"snapshot_id,omitempty"`
	PreviousSnapshotID    string `json:"previous_snapshot_id,omitempty"`
	ParentInterface       string `json:"parent_interface,omitempty"`
	VLANCount             int    `json:"vlan_count"`
	BridgeCount           int    `json:"bridge_count"`
	SubinterfaceCount     int    `json:"subinterface_count"`
	HostapdVLANEntryCount int    `json:"hostapd_vlan_entry_count"`
	CommandCount          int    `json:"command_count"`
	DiagnosticCount       int    `json:"diagnostic_count"`
	PlanFingerprint       string `json:"plan_fingerprint,omitempty"`
	DiagnosticsJSON       string `json:"diagnostics_json"`
	DetailsJSON           string `json:"details_json"`
	Actor                 string `json:"actor,omitempty"`
	CreatedAt             string `json:"created_at"`
}

type VLANLifecycleEventSummary struct {
	TotalEvents           int    `json:"total_events"`
	PreviewEvents         int    `json:"preview_events"`
	ApplyEvents           int    `json:"apply_events"`
	SyncEvents            int    `json:"sync_events"`
	RollbackEvents        int    `json:"rollback_events"`
	PreviewedCount        int    `json:"previewed_count"`
	AppliedCount          int    `json:"applied_count"`
	DegradedCount         int    `json:"degraded_count"`
	BlockedCount          int    `json:"blocked_count"`
	FailedCount           int    `json:"failed_count"`
	SkippedCount          int    `json:"skipped_count"`
	RolledBackCount       int    `json:"rolled_back_count"`
	LastEventAt           string `json:"last_event_at,omitempty"`
	ActiveSnapshotID      string `json:"active_snapshot_id,omitempty"`
	ActiveStatus          string `json:"active_status,omitempty"`
	ActiveFingerprint     string `json:"active_fingerprint,omitempty"`
	ActiveCommandCount    int    `json:"active_command_count"`
	VLANCount             int    `json:"vlan_count"`
	BridgeCount           int    `json:"bridge_count"`
	SubinterfaceCount     int    `json:"subinterface_count"`
	HostapdVLANEntryCount int    `json:"hostapd_vlan_entry_count"`
}

func RecordVLANLifecycleSnapshot(input VLANLifecycleSnapshotInput) (string, error) {
	if DB == nil {
		return "", nil
	}
	input.Operation = normalizeVLANLifecycleOperation(input.Operation)
	input.Status = normalizeVLANLifecycleStatus(input.Status)
	input.SnapshotID = strings.TrimSpace(input.SnapshotID)
	if input.SnapshotID == "" {
		input.SnapshotID = newRuntimeQoSID("vlan-snap", input.Operation, input.Status, input.PlanFingerprint)
	}
	if input.Operation == "" || input.Status == "" {
		return "", fmt.Errorf("VLAN lifecycle snapshot operation and status are required")
	}
	if strings.TrimSpace(input.PlanFingerprint) == "" {
		return "", fmt.Errorf("VLAN lifecycle snapshot plan fingerprint is required")
	}
	if strings.TrimSpace(input.DiagnosticsJSON) == "" {
		input.DiagnosticsJSON = "[]"
	}
	if strings.TrimSpace(input.SummaryJSON) == "" {
		input.SummaryJSON = "{}"
	}
	if strings.TrimSpace(input.PlanJSON) == "" {
		input.PlanJSON = "{}"
	}

	tx, err := DB.Begin()
	if err != nil {
		return "", fmt.Errorf("begin VLAN lifecycle snapshot transaction: %w", err)
	}
	defer tx.Rollback()

	if input.Active {
		if _, err := tx.Exec(`UPDATE vlan_lifecycle_snapshots SET active = 0 WHERE active = 1`); err != nil {
			return "", fmt.Errorf("clear active VLAN lifecycle snapshot: %w", err)
		}
	}
	_, err = tx.Exec(`INSERT INTO vlan_lifecycle_snapshots (
			snapshot_id, operation, status, active, parent_interface, vlan_count,
			bridge_count, subinterface_count, hostapd_vlan_entry_count, command_count,
			diagnostic_count, plan_fingerprint, command_text, hostapd_vlan_file_path,
			hostapd_vlan_file_text, hostapd_vlan_file_sha256, diagnostics_json,
			summary_json, plan_json, previous_snapshot_id, actor, created_at, applied_at, rolled_back_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?, ?)`,
		input.SnapshotID,
		input.Operation,
		input.Status,
		input.Active,
		nullString(strings.TrimSpace(input.ParentInterface)),
		nonNegativeInt(input.VLANCount),
		nonNegativeInt(input.BridgeCount),
		nonNegativeInt(input.SubinterfaceCount),
		nonNegativeInt(input.HostapdVLANEntryCount),
		nonNegativeInt(input.CommandCount),
		nonNegativeInt(input.DiagnosticCount),
		strings.TrimSpace(input.PlanFingerprint),
		input.CommandText,
		nullString(strings.TrimSpace(input.HostapdVLANFilePath)),
		input.HostapdVLANFileText,
		nullString(strings.TrimSpace(input.HostapdVLANFileSHA256)),
		input.DiagnosticsJSON,
		input.SummaryJSON,
		input.PlanJSON,
		nullString(strings.TrimSpace(input.PreviousSnapshotID)),
		nullString(strings.TrimSpace(input.Actor)),
		timeOrNil(input.AppliedAt),
		timeOrNil(input.RolledBackAt),
	)
	if err != nil {
		return "", fmt.Errorf("record VLAN lifecycle snapshot: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit VLAN lifecycle snapshot: %w", err)
	}
	return input.SnapshotID, nil
}

func RecordVLANLifecycleEvent(input VLANLifecycleEventInput) (string, error) {
	if DB == nil {
		return "", nil
	}
	input.Operation = normalizeVLANLifecycleOperation(input.Operation)
	input.Status = normalizeVLANLifecycleStatus(input.Status)
	input.EventID = strings.TrimSpace(input.EventID)
	if input.EventID == "" {
		input.EventID = newRuntimeQoSID("vlan-event", input.Operation, input.Status, input.SnapshotID)
	}
	if input.Operation == "" || input.Status == "" {
		return "", fmt.Errorf("VLAN lifecycle event operation and status are required")
	}
	if strings.TrimSpace(input.DiagnosticsJSON) == "" {
		input.DiagnosticsJSON = "[]"
	}
	if strings.TrimSpace(input.DetailsJSON) == "" {
		input.DetailsJSON = "{}"
	}

	_, err := DB.Exec(`INSERT INTO vlan_lifecycle_events (
			event_id, operation, status, snapshot_id, previous_snapshot_id, parent_interface,
			vlan_count, bridge_count, subinterface_count, hostapd_vlan_entry_count,
			command_count, diagnostic_count, plan_fingerprint, diagnostics_json,
			details_json, actor, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		input.EventID,
		input.Operation,
		input.Status,
		nullString(strings.TrimSpace(input.SnapshotID)),
		nullString(strings.TrimSpace(input.PreviousSnapshotID)),
		nullString(strings.TrimSpace(input.ParentInterface)),
		nonNegativeInt(input.VLANCount),
		nonNegativeInt(input.BridgeCount),
		nonNegativeInt(input.SubinterfaceCount),
		nonNegativeInt(input.HostapdVLANEntryCount),
		nonNegativeInt(input.CommandCount),
		nonNegativeInt(input.DiagnosticCount),
		nullString(strings.TrimSpace(input.PlanFingerprint)),
		input.DiagnosticsJSON,
		input.DetailsJSON,
		nullString(strings.TrimSpace(input.Actor)),
	)
	if err != nil {
		return "", fmt.Errorf("record VLAN lifecycle event: %w", err)
	}
	return input.EventID, nil
}

func ListVLANLifecycleSnapshots(limit int) ([]VLANLifecycleSnapshot, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	rows, err := DB.Query(`SELECT id, snapshot_id, operation, status, active,
			COALESCE(parent_interface, ''), vlan_count, bridge_count, subinterface_count,
			hostapd_vlan_entry_count, command_count, diagnostic_count, plan_fingerprint,
			command_text, COALESCE(hostapd_vlan_file_path, ''), COALESCE(hostapd_vlan_file_text, ''),
			COALESCE(hostapd_vlan_file_sha256, ''), diagnostics_json, summary_json,
			COALESCE(plan_json, '{}'), COALESCE(previous_snapshot_id, ''), COALESCE(actor, ''),
			COALESCE(CAST(created_at AS TEXT), ''), COALESCE(CAST(applied_at AS TEXT), ''),
			COALESCE(CAST(rolled_back_at AS TEXT), '')
		FROM vlan_lifecycle_snapshots
		ORDER BY datetime(created_at) DESC, id DESC
		LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list VLAN lifecycle snapshots: %w", err)
	}
	defer rows.Close()
	var snapshots []VLANLifecycleSnapshot
	for rows.Next() {
		item, err := scanVLANLifecycleSnapshot(rows)
		if err != nil {
			return nil, err
		}
		snapshots = append(snapshots, item)
	}
	return snapshots, rows.Err()
}

func GetVLANLifecycleSnapshot(snapshotID string) (VLANLifecycleSnapshot, bool, error) {
	if DB == nil || strings.TrimSpace(snapshotID) == "" {
		return VLANLifecycleSnapshot{}, false, nil
	}
	row := DB.QueryRow(`SELECT id, snapshot_id, operation, status, active,
			COALESCE(parent_interface, ''), vlan_count, bridge_count, subinterface_count,
			hostapd_vlan_entry_count, command_count, diagnostic_count, plan_fingerprint,
			command_text, COALESCE(hostapd_vlan_file_path, ''), COALESCE(hostapd_vlan_file_text, ''),
			COALESCE(hostapd_vlan_file_sha256, ''), diagnostics_json, summary_json,
			COALESCE(plan_json, '{}'), COALESCE(previous_snapshot_id, ''), COALESCE(actor, ''),
			COALESCE(CAST(created_at AS TEXT), ''), COALESCE(CAST(applied_at AS TEXT), ''),
			COALESCE(CAST(rolled_back_at AS TEXT), '')
		FROM vlan_lifecycle_snapshots
		WHERE snapshot_id = ?
		LIMIT 1`, strings.TrimSpace(snapshotID))
	item, err := scanVLANLifecycleSnapshot(row)
	if errors.Is(err, sql.ErrNoRows) {
		return VLANLifecycleSnapshot{}, false, nil
	}
	if err != nil {
		return VLANLifecycleSnapshot{}, false, err
	}
	return item, true, nil
}

func GetActiveVLANLifecycleSnapshot() (VLANLifecycleSnapshot, bool, error) {
	if DB == nil {
		return VLANLifecycleSnapshot{}, false, nil
	}
	row := DB.QueryRow(`SELECT id, snapshot_id, operation, status, active,
			COALESCE(parent_interface, ''), vlan_count, bridge_count, subinterface_count,
			hostapd_vlan_entry_count, command_count, diagnostic_count, plan_fingerprint,
			command_text, COALESCE(hostapd_vlan_file_path, ''), COALESCE(hostapd_vlan_file_text, ''),
			COALESCE(hostapd_vlan_file_sha256, ''), diagnostics_json, summary_json,
			COALESCE(plan_json, '{}'), COALESCE(previous_snapshot_id, ''), COALESCE(actor, ''),
			COALESCE(CAST(created_at AS TEXT), ''), COALESCE(CAST(applied_at AS TEXT), ''),
			COALESCE(CAST(rolled_back_at AS TEXT), '')
		FROM vlan_lifecycle_snapshots
		WHERE active = 1
		ORDER BY datetime(created_at) DESC, id DESC
		LIMIT 1`)
	item, err := scanVLANLifecycleSnapshot(row)
	if errors.Is(err, sql.ErrNoRows) {
		return VLANLifecycleSnapshot{}, false, nil
	}
	if err != nil {
		return VLANLifecycleSnapshot{}, false, err
	}
	return item, true, nil
}

func ListVLANLifecycleEvents(limit int) ([]VLANLifecycleEvent, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	rows, err := DB.Query(`SELECT id, event_id, operation, status,
			COALESCE(snapshot_id, ''), COALESCE(previous_snapshot_id, ''),
			COALESCE(parent_interface, ''), vlan_count, bridge_count, subinterface_count,
			hostapd_vlan_entry_count, command_count, diagnostic_count,
			COALESCE(plan_fingerprint, ''), diagnostics_json, details_json,
			COALESCE(actor, ''), COALESCE(CAST(created_at AS TEXT), '')
		FROM vlan_lifecycle_events
		ORDER BY datetime(created_at) DESC, id DESC
		LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list VLAN lifecycle events: %w", err)
	}
	defer rows.Close()
	var events []VLANLifecycleEvent
	for rows.Next() {
		var item VLANLifecycleEvent
		if err := rows.Scan(
			&item.ID,
			&item.EventID,
			&item.Operation,
			&item.Status,
			&item.SnapshotID,
			&item.PreviousSnapshotID,
			&item.ParentInterface,
			&item.VLANCount,
			&item.BridgeCount,
			&item.SubinterfaceCount,
			&item.HostapdVLANEntryCount,
			&item.CommandCount,
			&item.DiagnosticCount,
			&item.PlanFingerprint,
			&item.DiagnosticsJSON,
			&item.DetailsJSON,
			&item.Actor,
			&item.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan VLAN lifecycle event: %w", err)
		}
		events = append(events, item)
	}
	return events, rows.Err()
}

func GetVLANLifecycleEventSummary() (VLANLifecycleEventSummary, error) {
	events, err := ListVLANLifecycleEvents(1000)
	if err != nil {
		return VLANLifecycleEventSummary{}, err
	}
	summary := VLANLifecycleEventSummary{}
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
	active, found, err := GetActiveVLANLifecycleSnapshot()
	if err != nil {
		return VLANLifecycleEventSummary{}, err
	}
	if found {
		summary.ActiveSnapshotID = active.SnapshotID
		summary.ActiveStatus = active.Status
		summary.ActiveFingerprint = active.PlanFingerprint
		summary.ActiveCommandCount = active.CommandCount
		summary.VLANCount = active.VLANCount
		summary.BridgeCount = active.BridgeCount
		summary.SubinterfaceCount = active.SubinterfaceCount
		summary.HostapdVLANEntryCount = active.HostapdVLANEntryCount
	}
	return summary, nil
}

type vlanLifecycleSnapshotScanner interface {
	Scan(dest ...any) error
}

func scanVLANLifecycleSnapshot(row vlanLifecycleSnapshotScanner) (VLANLifecycleSnapshot, error) {
	var item VLANLifecycleSnapshot
	if err := row.Scan(
		&item.ID,
		&item.SnapshotID,
		&item.Operation,
		&item.Status,
		&item.Active,
		&item.ParentInterface,
		&item.VLANCount,
		&item.BridgeCount,
		&item.SubinterfaceCount,
		&item.HostapdVLANEntryCount,
		&item.CommandCount,
		&item.DiagnosticCount,
		&item.PlanFingerprint,
		&item.CommandText,
		&item.HostapdVLANFilePath,
		&item.HostapdVLANFileText,
		&item.HostapdVLANFileSHA256,
		&item.DiagnosticsJSON,
		&item.SummaryJSON,
		&item.PlanJSON,
		&item.PreviousSnapshotID,
		&item.Actor,
		&item.CreatedAt,
		&item.AppliedAt,
		&item.RolledBackAt,
	); err != nil {
		return VLANLifecycleSnapshot{}, fmt.Errorf("scan VLAN lifecycle snapshot: %w", err)
	}
	return item, nil
}

func normalizeVLANLifecycleOperation(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "preview", "apply", "rollback", "sync":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeVLANLifecycleStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "previewed", "applied", "rolled_back", "degraded", "blocked", "failed", "skipped":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "blocked"
	}
}
