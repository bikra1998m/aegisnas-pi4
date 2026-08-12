package db

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

type QoSSchedulerProfile struct {
	ID                   int    `json:"id"`
	ProfileName          string `json:"profile_name"`
	Enabled              bool   `json:"enabled"`
	ParentProfileName    string `json:"parent_profile_name,omitempty"`
	Scheduler            string `json:"scheduler"`
	Priority             int    `json:"priority"`
	DSCPMark             *int   `json:"dscp_mark,omitempty"`
	DownloadMinRateKbps  int    `json:"download_min_rate_kbps"`
	DownloadCeilRateKbps int    `json:"download_ceil_rate_kbps"`
	UploadMinRateKbps    int    `json:"upload_min_rate_kbps"`
	UploadCeilRateKbps   int    `json:"upload_ceil_rate_kbps"`
	BurstKB              int    `json:"burst_kb"`
	CBurstKB             int    `json:"cburst_kb"`
	QuantumBytes         int    `json:"quantum_bytes"`
	MetadataJSON         string `json:"metadata_json"`
	CreatedAt            string `json:"created_at"`
	UpdatedAt            string `json:"updated_at"`
}

type QoSSchedulerProfileInput struct {
	ProfileName          string
	Enabled              bool
	ParentProfileName    string
	Scheduler            string
	Priority             int
	DSCPMark             *int
	DownloadMinRateKbps  int
	DownloadCeilRateKbps int
	UploadMinRateKbps    int
	UploadCeilRateKbps   int
	BurstKB              int
	CBurstKB             int
	QuantumBytes         int
	MetadataJSON         string
}

type RuntimeQoSSnapshotInput struct {
	SnapshotID           string
	Operation            string
	Status               string
	Active               bool
	InterfaceName        string
	IFBDevice            string
	ProfileCount         int
	ClassCount           int
	SessionCount         int
	ShapedSessionCount   int
	UnshapedSessionCount int
	CommandCount         int
	DiagnosticCount      int
	PlanFingerprint      string
	CommandText          string
	DiagnosticsJSON      string
	SummaryJSON          string
	PreviousSnapshotID   string
	Actor                string
	AppliedAt            *time.Time
	RolledBackAt         *time.Time
}

type RuntimeQoSSnapshot struct {
	ID                   int    `json:"id"`
	SnapshotID           string `json:"snapshot_id"`
	Operation            string `json:"operation"`
	Status               string `json:"status"`
	Active               bool   `json:"active"`
	InterfaceName        string `json:"interface_name,omitempty"`
	IFBDevice            string `json:"ifb_device,omitempty"`
	ProfileCount         int    `json:"profile_count"`
	ClassCount           int    `json:"class_count"`
	SessionCount         int    `json:"session_count"`
	ShapedSessionCount   int    `json:"shaped_session_count"`
	UnshapedSessionCount int    `json:"unshaped_session_count"`
	CommandCount         int    `json:"command_count"`
	DiagnosticCount      int    `json:"diagnostic_count"`
	PlanFingerprint      string `json:"plan_fingerprint"`
	CommandText          string `json:"command_text,omitempty"`
	DiagnosticsJSON      string `json:"diagnostics_json"`
	SummaryJSON          string `json:"summary_json"`
	PreviousSnapshotID   string `json:"previous_snapshot_id,omitempty"`
	Actor                string `json:"actor,omitempty"`
	CreatedAt            string `json:"created_at"`
	AppliedAt            string `json:"applied_at,omitempty"`
	RolledBackAt         string `json:"rolled_back_at,omitempty"`
}

type RuntimeQoSEventInput struct {
	EventID              string
	Operation            string
	Status               string
	SnapshotID           string
	PreviousSnapshotID   string
	InterfaceName        string
	IFBDevice            string
	ProfileCount         int
	ClassCount           int
	SessionCount         int
	ShapedSessionCount   int
	UnshapedSessionCount int
	CommandCount         int
	DiagnosticCount      int
	PlanFingerprint      string
	DiagnosticsJSON      string
	DetailsJSON          string
	Actor                string
}

type RuntimeQoSEvent struct {
	ID                   int    `json:"id"`
	EventID              string `json:"event_id"`
	Operation            string `json:"operation"`
	Status               string `json:"status"`
	SnapshotID           string `json:"snapshot_id,omitempty"`
	PreviousSnapshotID   string `json:"previous_snapshot_id,omitempty"`
	InterfaceName        string `json:"interface_name,omitempty"`
	IFBDevice            string `json:"ifb_device,omitempty"`
	ProfileCount         int    `json:"profile_count"`
	ClassCount           int    `json:"class_count"`
	SessionCount         int    `json:"session_count"`
	ShapedSessionCount   int    `json:"shaped_session_count"`
	UnshapedSessionCount int    `json:"unshaped_session_count"`
	CommandCount         int    `json:"command_count"`
	DiagnosticCount      int    `json:"diagnostic_count"`
	PlanFingerprint      string `json:"plan_fingerprint,omitempty"`
	DiagnosticsJSON      string `json:"diagnostics_json"`
	DetailsJSON          string `json:"details_json"`
	Actor                string `json:"actor,omitempty"`
	CreatedAt            string `json:"created_at"`
}

type RuntimeQoSEventSummary struct {
	TotalEvents        int    `json:"total_events"`
	PreviewEvents      int    `json:"preview_events"`
	ApplyEvents        int    `json:"apply_events"`
	SyncEvents         int    `json:"sync_events"`
	RollbackEvents     int    `json:"rollback_events"`
	AppliedCount       int    `json:"applied_count"`
	PreviewedCount     int    `json:"previewed_count"`
	DegradedCount      int    `json:"degraded_count"`
	BlockedCount       int    `json:"blocked_count"`
	FailedCount        int    `json:"failed_count"`
	RolledBackCount    int    `json:"rolled_back_count"`
	LastEventAt        string `json:"last_event_at,omitempty"`
	ActiveSnapshotID   string `json:"active_snapshot_id,omitempty"`
	ActiveStatus       string `json:"active_status,omitempty"`
	ActiveFingerprint  string `json:"active_fingerprint,omitempty"`
	ActiveCommandCount int    `json:"active_command_count"`
	ProfileCount       int    `json:"profile_count"`
	ClassCount         int    `json:"class_count"`
	ShapedSessionCount int    `json:"shaped_session_count"`
}

func UpsertQoSSchedulerProfile(input QoSSchedulerProfileInput) error {
	if DB == nil {
		return nil
	}
	input.ProfileName = strings.TrimSpace(input.ProfileName)
	if input.ProfileName == "" {
		return fmt.Errorf("qos scheduler profile name is required")
	}
	if strings.TrimSpace(input.Scheduler) == "" {
		input.Scheduler = "htb"
	}
	if input.Priority < 0 || input.Priority > 7 {
		return fmt.Errorf("qos scheduler priority must be between 0 and 7")
	}
	if input.MetadataJSON == "" {
		input.MetadataJSON = "{}"
	}
	_, err := DB.Exec(`INSERT INTO qos_scheduler_profiles (
			profile_name, enabled, parent_profile_name, scheduler, priority, dscp_mark,
			download_min_rate_kbps, download_ceil_rate_kbps, upload_min_rate_kbps, upload_ceil_rate_kbps,
			burst_kb, cburst_kb, quantum_bytes, metadata_json, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT(profile_name) DO UPDATE SET
			enabled = excluded.enabled,
			parent_profile_name = excluded.parent_profile_name,
			scheduler = excluded.scheduler,
			priority = excluded.priority,
			dscp_mark = excluded.dscp_mark,
			download_min_rate_kbps = excluded.download_min_rate_kbps,
			download_ceil_rate_kbps = excluded.download_ceil_rate_kbps,
			upload_min_rate_kbps = excluded.upload_min_rate_kbps,
			upload_ceil_rate_kbps = excluded.upload_ceil_rate_kbps,
			burst_kb = excluded.burst_kb,
			cburst_kb = excluded.cburst_kb,
			quantum_bytes = excluded.quantum_bytes,
			metadata_json = excluded.metadata_json,
			updated_at = CURRENT_TIMESTAMP`,
		input.ProfileName,
		input.Enabled,
		nullString(strings.TrimSpace(input.ParentProfileName)),
		strings.ToLower(strings.TrimSpace(input.Scheduler)),
		input.Priority,
		intPtrOrNil(input.DSCPMark),
		nonNegativeInt(input.DownloadMinRateKbps),
		nonNegativeInt(input.DownloadCeilRateKbps),
		nonNegativeInt(input.UploadMinRateKbps),
		nonNegativeInt(input.UploadCeilRateKbps),
		nonNegativeInt(input.BurstKB),
		nonNegativeInt(input.CBurstKB),
		nonNegativeInt(input.QuantumBytes),
		input.MetadataJSON,
	)
	if err != nil {
		return fmt.Errorf("upsert qos scheduler profile: %w", err)
	}
	return nil
}

func DeleteQoSSchedulerProfile(profileName string) error {
	if DB == nil {
		return nil
	}
	profileName = strings.TrimSpace(profileName)
	if profileName == "" {
		return fmt.Errorf("qos scheduler profile name is required")
	}
	_, err := DB.Exec(`DELETE FROM qos_scheduler_profiles WHERE profile_name = ?`, profileName)
	if err != nil {
		return fmt.Errorf("delete qos scheduler profile: %w", err)
	}
	return nil
}

func ListQoSSchedulerProfiles() ([]QoSSchedulerProfile, error) {
	if DB == nil {
		return nil, nil
	}
	rows, err := DB.Query(`SELECT id, profile_name, enabled, COALESCE(parent_profile_name, ''), scheduler,
			priority, dscp_mark, download_min_rate_kbps, download_ceil_rate_kbps,
			upload_min_rate_kbps, upload_ceil_rate_kbps, burst_kb, cburst_kb,
			quantum_bytes, COALESCE(metadata_json, '{}'), COALESCE(CAST(created_at AS TEXT), ''),
			COALESCE(CAST(updated_at AS TEXT), '')
		FROM qos_scheduler_profiles
		ORDER BY profile_name`)
	if err != nil {
		return nil, fmt.Errorf("list qos scheduler profiles: %w", err)
	}
	defer rows.Close()

	var profiles []QoSSchedulerProfile
	for rows.Next() {
		var profile QoSSchedulerProfile
		var dscp sql.NullInt64
		if err := rows.Scan(
			&profile.ID,
			&profile.ProfileName,
			&profile.Enabled,
			&profile.ParentProfileName,
			&profile.Scheduler,
			&profile.Priority,
			&dscp,
			&profile.DownloadMinRateKbps,
			&profile.DownloadCeilRateKbps,
			&profile.UploadMinRateKbps,
			&profile.UploadCeilRateKbps,
			&profile.BurstKB,
			&profile.CBurstKB,
			&profile.QuantumBytes,
			&profile.MetadataJSON,
			&profile.CreatedAt,
			&profile.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan qos scheduler profile: %w", err)
		}
		if dscp.Valid {
			value := int(dscp.Int64)
			profile.DSCPMark = &value
		}
		profiles = append(profiles, profile)
	}
	return profiles, rows.Err()
}

func RecordRuntimeQoSSnapshot(input RuntimeQoSSnapshotInput) (string, error) {
	if DB == nil {
		return "", nil
	}
	input.Operation = normalizeRuntimeQoSOperation(input.Operation)
	input.Status = normalizeRuntimeQoSStatus(input.Status)
	input.SnapshotID = strings.TrimSpace(input.SnapshotID)
	if input.SnapshotID == "" {
		input.SnapshotID = newRuntimeQoSID("qos-snap", input.Operation, input.Status, input.PlanFingerprint)
	}
	if input.Operation == "" || input.Status == "" {
		return "", fmt.Errorf("runtime QoS snapshot operation and status are required")
	}
	if strings.TrimSpace(input.PlanFingerprint) == "" {
		return "", fmt.Errorf("runtime QoS snapshot plan fingerprint is required")
	}
	if strings.TrimSpace(input.DiagnosticsJSON) == "" {
		input.DiagnosticsJSON = "[]"
	}
	if strings.TrimSpace(input.SummaryJSON) == "" {
		input.SummaryJSON = "{}"
	}

	tx, err := DB.Begin()
	if err != nil {
		return "", fmt.Errorf("begin runtime QoS snapshot transaction: %w", err)
	}
	defer tx.Rollback()

	if input.Active {
		if _, err := tx.Exec(`UPDATE runtime_qos_snapshots SET active = 0 WHERE active = 1`); err != nil {
			return "", fmt.Errorf("clear active runtime QoS snapshot: %w", err)
		}
	}
	_, err = tx.Exec(`INSERT INTO runtime_qos_snapshots (
			snapshot_id, operation, status, active, interface_name, ifb_device,
			profile_count, class_count, session_count, shaped_session_count, unshaped_session_count,
			command_count, diagnostic_count, plan_fingerprint, command_text, diagnostics_json,
			summary_json, previous_snapshot_id, actor, created_at, applied_at, rolled_back_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?, ?)`,
		input.SnapshotID,
		input.Operation,
		input.Status,
		input.Active,
		nullString(strings.TrimSpace(input.InterfaceName)),
		nullString(strings.TrimSpace(input.IFBDevice)),
		nonNegativeInt(input.ProfileCount),
		nonNegativeInt(input.ClassCount),
		nonNegativeInt(input.SessionCount),
		nonNegativeInt(input.ShapedSessionCount),
		nonNegativeInt(input.UnshapedSessionCount),
		nonNegativeInt(input.CommandCount),
		nonNegativeInt(input.DiagnosticCount),
		strings.TrimSpace(input.PlanFingerprint),
		input.CommandText,
		input.DiagnosticsJSON,
		input.SummaryJSON,
		nullString(strings.TrimSpace(input.PreviousSnapshotID)),
		nullString(strings.TrimSpace(input.Actor)),
		timeOrNil(input.AppliedAt),
		timeOrNil(input.RolledBackAt),
	)
	if err != nil {
		return "", fmt.Errorf("record runtime QoS snapshot: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit runtime QoS snapshot: %w", err)
	}
	return input.SnapshotID, nil
}

func RecordRuntimeQoSEvent(input RuntimeQoSEventInput) (string, error) {
	if DB == nil {
		return "", nil
	}
	input.Operation = normalizeRuntimeQoSOperation(input.Operation)
	input.Status = normalizeRuntimeQoSStatus(input.Status)
	input.EventID = strings.TrimSpace(input.EventID)
	if input.EventID == "" {
		input.EventID = newRuntimeQoSID("qos-event", input.Operation, input.Status, input.SnapshotID)
	}
	if input.Operation == "" || input.Status == "" {
		return "", fmt.Errorf("runtime QoS event operation and status are required")
	}
	if strings.TrimSpace(input.DiagnosticsJSON) == "" {
		input.DiagnosticsJSON = "[]"
	}
	if strings.TrimSpace(input.DetailsJSON) == "" {
		input.DetailsJSON = "{}"
	}

	_, err := DB.Exec(`INSERT INTO runtime_qos_events (
			event_id, operation, status, snapshot_id, previous_snapshot_id, interface_name, ifb_device,
			profile_count, class_count, session_count, shaped_session_count, unshaped_session_count,
			command_count, diagnostic_count, plan_fingerprint, diagnostics_json, details_json, actor, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		input.EventID,
		input.Operation,
		input.Status,
		nullString(strings.TrimSpace(input.SnapshotID)),
		nullString(strings.TrimSpace(input.PreviousSnapshotID)),
		nullString(strings.TrimSpace(input.InterfaceName)),
		nullString(strings.TrimSpace(input.IFBDevice)),
		nonNegativeInt(input.ProfileCount),
		nonNegativeInt(input.ClassCount),
		nonNegativeInt(input.SessionCount),
		nonNegativeInt(input.ShapedSessionCount),
		nonNegativeInt(input.UnshapedSessionCount),
		nonNegativeInt(input.CommandCount),
		nonNegativeInt(input.DiagnosticCount),
		nullString(strings.TrimSpace(input.PlanFingerprint)),
		input.DiagnosticsJSON,
		input.DetailsJSON,
		nullString(strings.TrimSpace(input.Actor)),
	)
	if err != nil {
		return "", fmt.Errorf("record runtime QoS event: %w", err)
	}
	return input.EventID, nil
}

func ListRuntimeQoSSnapshots(limit int) ([]RuntimeQoSSnapshot, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	rows, err := DB.Query(`SELECT id, snapshot_id, operation, status, active,
			COALESCE(interface_name, ''), COALESCE(ifb_device, ''), profile_count,
			class_count, session_count, shaped_session_count, unshaped_session_count,
			command_count, diagnostic_count, plan_fingerprint, command_text,
			diagnostics_json, summary_json, COALESCE(previous_snapshot_id, ''),
			COALESCE(actor, ''), COALESCE(CAST(created_at AS TEXT), ''),
			COALESCE(CAST(applied_at AS TEXT), ''), COALESCE(CAST(rolled_back_at AS TEXT), '')
		FROM runtime_qos_snapshots
		ORDER BY datetime(created_at) DESC, id DESC
		LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list runtime QoS snapshots: %w", err)
	}
	defer rows.Close()
	var snapshots []RuntimeQoSSnapshot
	for rows.Next() {
		item, err := scanRuntimeQoSSnapshot(rows)
		if err != nil {
			return nil, err
		}
		snapshots = append(snapshots, item)
	}
	return snapshots, rows.Err()
}

func GetRuntimeQoSSnapshot(snapshotID string) (RuntimeQoSSnapshot, bool, error) {
	if DB == nil || strings.TrimSpace(snapshotID) == "" {
		return RuntimeQoSSnapshot{}, false, nil
	}
	row := DB.QueryRow(`SELECT id, snapshot_id, operation, status, active,
			COALESCE(interface_name, ''), COALESCE(ifb_device, ''), profile_count,
			class_count, session_count, shaped_session_count, unshaped_session_count,
			command_count, diagnostic_count, plan_fingerprint, command_text,
			diagnostics_json, summary_json, COALESCE(previous_snapshot_id, ''),
			COALESCE(actor, ''), COALESCE(CAST(created_at AS TEXT), ''),
			COALESCE(CAST(applied_at AS TEXT), ''), COALESCE(CAST(rolled_back_at AS TEXT), '')
		FROM runtime_qos_snapshots
		WHERE snapshot_id = ?
		LIMIT 1`, strings.TrimSpace(snapshotID))
	item, err := scanRuntimeQoSSnapshot(row)
	if errors.Is(err, sql.ErrNoRows) {
		return RuntimeQoSSnapshot{}, false, nil
	}
	if err != nil {
		return RuntimeQoSSnapshot{}, false, err
	}
	return item, true, nil
}

func GetActiveRuntimeQoSSnapshot() (RuntimeQoSSnapshot, bool, error) {
	if DB == nil {
		return RuntimeQoSSnapshot{}, false, nil
	}
	row := DB.QueryRow(`SELECT id, snapshot_id, operation, status, active,
			COALESCE(interface_name, ''), COALESCE(ifb_device, ''), profile_count,
			class_count, session_count, shaped_session_count, unshaped_session_count,
			command_count, diagnostic_count, plan_fingerprint, command_text,
			diagnostics_json, summary_json, COALESCE(previous_snapshot_id, ''),
			COALESCE(actor, ''), COALESCE(CAST(created_at AS TEXT), ''),
			COALESCE(CAST(applied_at AS TEXT), ''), COALESCE(CAST(rolled_back_at AS TEXT), '')
		FROM runtime_qos_snapshots
		WHERE active = 1
		ORDER BY datetime(created_at) DESC, id DESC
		LIMIT 1`)
	item, err := scanRuntimeQoSSnapshot(row)
	if errors.Is(err, sql.ErrNoRows) {
		return RuntimeQoSSnapshot{}, false, nil
	}
	if err != nil {
		return RuntimeQoSSnapshot{}, false, err
	}
	return item, true, nil
}

func ListRuntimeQoSEvents(limit int) ([]RuntimeQoSEvent, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	rows, err := DB.Query(`SELECT id, event_id, operation, status,
			COALESCE(snapshot_id, ''), COALESCE(previous_snapshot_id, ''),
			COALESCE(interface_name, ''), COALESCE(ifb_device, ''), profile_count,
			class_count, session_count, shaped_session_count, unshaped_session_count,
			command_count, diagnostic_count, COALESCE(plan_fingerprint, ''),
			diagnostics_json, details_json, COALESCE(actor, ''),
			COALESCE(CAST(created_at AS TEXT), '')
		FROM runtime_qos_events
		ORDER BY datetime(created_at) DESC, id DESC
		LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list runtime QoS events: %w", err)
	}
	defer rows.Close()
	var events []RuntimeQoSEvent
	for rows.Next() {
		var item RuntimeQoSEvent
		if err := rows.Scan(
			&item.ID,
			&item.EventID,
			&item.Operation,
			&item.Status,
			&item.SnapshotID,
			&item.PreviousSnapshotID,
			&item.InterfaceName,
			&item.IFBDevice,
			&item.ProfileCount,
			&item.ClassCount,
			&item.SessionCount,
			&item.ShapedSessionCount,
			&item.UnshapedSessionCount,
			&item.CommandCount,
			&item.DiagnosticCount,
			&item.PlanFingerprint,
			&item.DiagnosticsJSON,
			&item.DetailsJSON,
			&item.Actor,
			&item.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan runtime QoS event: %w", err)
		}
		events = append(events, item)
	}
	return events, rows.Err()
}

func GetRuntimeQoSEventSummary() (RuntimeQoSEventSummary, error) {
	events, err := ListRuntimeQoSEvents(1000)
	if err != nil {
		return RuntimeQoSEventSummary{}, err
	}
	summary := RuntimeQoSEventSummary{}
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
	active, found, err := GetActiveRuntimeQoSSnapshot()
	if err != nil {
		return RuntimeQoSEventSummary{}, err
	}
	if found {
		summary.ActiveSnapshotID = active.SnapshotID
		summary.ActiveStatus = active.Status
		summary.ActiveFingerprint = active.PlanFingerprint
		summary.ActiveCommandCount = active.CommandCount
		summary.ProfileCount = active.ProfileCount
		summary.ClassCount = active.ClassCount
		summary.ShapedSessionCount = active.ShapedSessionCount
	}
	return summary, nil
}

type runtimeQoSSnapshotScanner interface {
	Scan(dest ...any) error
}

func scanRuntimeQoSSnapshot(row runtimeQoSSnapshotScanner) (RuntimeQoSSnapshot, error) {
	var item RuntimeQoSSnapshot
	if err := row.Scan(
		&item.ID,
		&item.SnapshotID,
		&item.Operation,
		&item.Status,
		&item.Active,
		&item.InterfaceName,
		&item.IFBDevice,
		&item.ProfileCount,
		&item.ClassCount,
		&item.SessionCount,
		&item.ShapedSessionCount,
		&item.UnshapedSessionCount,
		&item.CommandCount,
		&item.DiagnosticCount,
		&item.PlanFingerprint,
		&item.CommandText,
		&item.DiagnosticsJSON,
		&item.SummaryJSON,
		&item.PreviousSnapshotID,
		&item.Actor,
		&item.CreatedAt,
		&item.AppliedAt,
		&item.RolledBackAt,
	); err != nil {
		return RuntimeQoSSnapshot{}, fmt.Errorf("scan runtime QoS snapshot: %w", err)
	}
	return item, nil
}

func normalizeRuntimeQoSOperation(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "preview", "apply", "rollback", "sync":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeRuntimeQoSStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "previewed", "applied", "rolled_back", "degraded", "blocked", "failed", "skipped":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "blocked"
	}
}

func intPtrOrNil(value *int) any {
	if value == nil {
		return nil
	}
	return *value
}

func newRuntimeQoSID(prefix, operation, status, fingerprint string) string {
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
