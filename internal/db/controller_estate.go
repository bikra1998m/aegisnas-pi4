package db

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
)

type ControllerEstateLifecycleEventInput struct {
	EventID                  string
	Operation                string
	Status                   string
	Adapter                  string
	Platform                 string
	Endpoint                 string
	Site                     string
	SyncMode                 string
	DesiredStateHash         string
	PlanFingerprint          string
	InventoryObjectCount     int
	TemplateCount            int
	WLANTemplateCount        int
	ManagedObjectCount       int
	DeleteGuardCount         int
	ComplianceCheckCount     int
	PassedCheckCount         int
	WarningCount             int
	BlockerCount             int
	ExternalRequirementCount int
	SummaryJSON              string
	ReportJSON               string
	Actor                    string
}

type ControllerEstateLifecycleEvent struct {
	ID                       int    `json:"id"`
	EventID                  string `json:"event_id"`
	Operation                string `json:"operation"`
	Status                   string `json:"status"`
	Adapter                  string `json:"adapter"`
	Platform                 string `json:"platform"`
	Endpoint                 string `json:"endpoint,omitempty"`
	Site                     string `json:"site,omitempty"`
	SyncMode                 string `json:"sync_mode,omitempty"`
	DesiredStateHash         string `json:"desired_state_hash,omitempty"`
	PlanFingerprint          string `json:"plan_fingerprint"`
	InventoryObjectCount     int    `json:"inventory_object_count"`
	TemplateCount            int    `json:"template_count"`
	WLANTemplateCount        int    `json:"wlan_template_count"`
	ManagedObjectCount       int    `json:"managed_object_count"`
	DeleteGuardCount         int    `json:"delete_guard_count"`
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

type ControllerEstateLifecycleSummary struct {
	TotalEvents                  int    `json:"total_events"`
	PreviewEvents                int    `json:"preview_events"`
	ApplyEvents                  int    `json:"apply_events"`
	StatusEvents                 int    `json:"status_events"`
	PreviewedCount               int    `json:"previewed_count"`
	AppliedCount                 int    `json:"applied_count"`
	BlockedCount                 int    `json:"blocked_count"`
	DegradedCount                int    `json:"degraded_count"`
	SkippedCount                 int    `json:"skipped_count"`
	FailedCount                  int    `json:"failed_count"`
	LastEventAt                  string `json:"last_event_at,omitempty"`
	LastAdapter                  string `json:"last_adapter,omitempty"`
	LastPlatform                 string `json:"last_platform,omitempty"`
	LastDesiredStateHash         string `json:"last_desired_state_hash,omitempty"`
	LastFingerprint              string `json:"last_fingerprint,omitempty"`
	LastInventoryObjectCount     int    `json:"last_inventory_object_count"`
	LastTemplateCount            int    `json:"last_template_count"`
	LastWLANTemplateCount        int    `json:"last_wlan_template_count"`
	LastManagedObjectCount       int    `json:"last_managed_object_count"`
	LastDeleteGuardCount         int    `json:"last_delete_guard_count"`
	LastComplianceCheckCount     int    `json:"last_compliance_check_count"`
	LastPassedCheckCount         int    `json:"last_passed_check_count"`
	LastWarningCount             int    `json:"last_warning_count"`
	LastBlockerCount             int    `json:"last_blocker_count"`
	LastExternalRequirementCount int    `json:"last_external_requirement_count"`
}

func RecordControllerEstateLifecycleEvent(input ControllerEstateLifecycleEventInput) (string, error) {
	if DB == nil {
		return "", nil
	}
	input.Operation = normalizeControllerEstateLifecycleOperation(input.Operation)
	input.Status = normalizeControllerEstateLifecycleStatus(input.Status)
	input.EventID = strings.TrimSpace(input.EventID)
	if input.EventID == "" {
		input.EventID = newControllerEstateLifecycleEventID(input)
	}
	if input.Operation == "" || input.Status == "" {
		return "", fmt.Errorf("controller estate lifecycle operation and status are required")
	}
	if strings.TrimSpace(input.PlanFingerprint) == "" {
		return "", fmt.Errorf("controller estate lifecycle plan fingerprint is required")
	}
	if strings.TrimSpace(input.Adapter) == "" {
		return "", fmt.Errorf("controller estate lifecycle adapter is required")
	}
	if strings.TrimSpace(input.Platform) == "" {
		return "", fmt.Errorf("controller estate lifecycle platform is required")
	}
	if strings.TrimSpace(input.SummaryJSON) == "" {
		input.SummaryJSON = "{}"
	}
	if strings.TrimSpace(input.ReportJSON) == "" {
		input.ReportJSON = "{}"
	}
	_, err := DB.Exec(`INSERT INTO controller_estate_lifecycle_events (
			event_id, operation, status, adapter, platform, endpoint, site, sync_mode, desired_state_hash,
			plan_fingerprint, inventory_object_count, template_count, wlan_template_count, managed_object_count,
			delete_guard_count, compliance_check_count, passed_check_count, warning_count, blocker_count,
			external_requirement_count, summary_json, report_json, actor, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(event_id) DO UPDATE SET
			operation = excluded.operation,
			status = excluded.status,
			adapter = excluded.adapter,
			platform = excluded.platform,
			endpoint = excluded.endpoint,
			site = excluded.site,
			sync_mode = excluded.sync_mode,
			desired_state_hash = excluded.desired_state_hash,
			plan_fingerprint = excluded.plan_fingerprint,
			inventory_object_count = excluded.inventory_object_count,
			template_count = excluded.template_count,
			wlan_template_count = excluded.wlan_template_count,
			managed_object_count = excluded.managed_object_count,
			delete_guard_count = excluded.delete_guard_count,
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
		strings.TrimSpace(input.Adapter),
		strings.TrimSpace(input.Platform),
		nullString(strings.TrimSpace(input.Endpoint)),
		nullString(strings.TrimSpace(input.Site)),
		nullString(strings.TrimSpace(input.SyncMode)),
		nullString(strings.TrimSpace(input.DesiredStateHash)),
		strings.TrimSpace(input.PlanFingerprint),
		nonNegativeInt(input.InventoryObjectCount),
		nonNegativeInt(input.TemplateCount),
		nonNegativeInt(input.WLANTemplateCount),
		nonNegativeInt(input.ManagedObjectCount),
		nonNegativeInt(input.DeleteGuardCount),
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
		return "", fmt.Errorf("record controller estate lifecycle event: %w", err)
	}
	return input.EventID, nil
}

func ListControllerEstateLifecycleEvents(limit int) ([]ControllerEstateLifecycleEvent, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := DB.Query(controllerEstateLifecycleSelectSQL()+` ORDER BY datetime(created_at) DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list controller estate lifecycle events: %w", err)
	}
	defer rows.Close()
	events := []ControllerEstateLifecycleEvent{}
	for rows.Next() {
		event, scanErr := scanControllerEstateLifecycleEvent(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list controller estate lifecycle rows: %w", err)
	}
	return events, nil
}

func GetControllerEstateLifecycleSummary() (ControllerEstateLifecycleSummary, error) {
	if DB == nil {
		return ControllerEstateLifecycleSummary{}, nil
	}
	var summary ControllerEstateLifecycleSummary
	err := DB.QueryRow(`SELECT
			COUNT(*),
			COALESCE(SUM(CASE WHEN operation = 'preview' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN operation = 'apply' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN operation = 'status' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'previewed' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'applied' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'degraded' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'skipped' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END), 0),
			COALESCE(MAX(created_at), '')
		FROM controller_estate_lifecycle_events`).Scan(
		&summary.TotalEvents,
		&summary.PreviewEvents,
		&summary.ApplyEvents,
		&summary.StatusEvents,
		&summary.PreviewedCount,
		&summary.AppliedCount,
		&summary.BlockedCount,
		&summary.DegradedCount,
		&summary.SkippedCount,
		&summary.FailedCount,
		&summary.LastEventAt,
	)
	if err != nil {
		if tableMissing(err) {
			return ControllerEstateLifecycleSummary{}, nil
		}
		return ControllerEstateLifecycleSummary{}, fmt.Errorf("summarize controller estate lifecycle events: %w", err)
	}
	row := DB.QueryRow(`SELECT adapter, platform, COALESCE(desired_state_hash, ''), plan_fingerprint,
			inventory_object_count, template_count, wlan_template_count, managed_object_count, delete_guard_count,
			compliance_check_count, passed_check_count, warning_count, blocker_count, external_requirement_count
		FROM controller_estate_lifecycle_events
		ORDER BY datetime(created_at) DESC, id DESC LIMIT 1`)
	err = row.Scan(
		&summary.LastAdapter,
		&summary.LastPlatform,
		&summary.LastDesiredStateHash,
		&summary.LastFingerprint,
		&summary.LastInventoryObjectCount,
		&summary.LastTemplateCount,
		&summary.LastWLANTemplateCount,
		&summary.LastManagedObjectCount,
		&summary.LastDeleteGuardCount,
		&summary.LastComplianceCheckCount,
		&summary.LastPassedCheckCount,
		&summary.LastWarningCount,
		&summary.LastBlockerCount,
		&summary.LastExternalRequirementCount,
	)
	if err != nil && err != sql.ErrNoRows {
		return ControllerEstateLifecycleSummary{}, fmt.Errorf("read latest controller estate lifecycle event: %w", err)
	}
	return summary, nil
}

func scanControllerEstateLifecycleEvent(scanner interface{ Scan(dest ...any) error }) (ControllerEstateLifecycleEvent, error) {
	var event ControllerEstateLifecycleEvent
	var endpoint, site, syncMode, desiredHash, actor sql.NullString
	err := scanner.Scan(
		&event.ID,
		&event.EventID,
		&event.Operation,
		&event.Status,
		&event.Adapter,
		&event.Platform,
		&endpoint,
		&site,
		&syncMode,
		&desiredHash,
		&event.PlanFingerprint,
		&event.InventoryObjectCount,
		&event.TemplateCount,
		&event.WLANTemplateCount,
		&event.ManagedObjectCount,
		&event.DeleteGuardCount,
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
		return ControllerEstateLifecycleEvent{}, fmt.Errorf("scan controller estate lifecycle event: %w", err)
	}
	event.Endpoint = endpoint.String
	event.Site = site.String
	event.SyncMode = syncMode.String
	event.DesiredStateHash = desiredHash.String
	event.Actor = actor.String
	return event, nil
}

func controllerEstateLifecycleSelectSQL() string {
	return `SELECT id, event_id, operation, status, adapter, platform, COALESCE(endpoint, ''), COALESCE(site, ''),
		COALESCE(sync_mode, ''), COALESCE(desired_state_hash, ''), plan_fingerprint,
		inventory_object_count, template_count, wlan_template_count, managed_object_count,
		delete_guard_count, compliance_check_count, passed_check_count, warning_count, blocker_count,
		external_requirement_count, summary_json, report_json, COALESCE(actor, ''),
		COALESCE(CAST(created_at AS TEXT), '')
		FROM controller_estate_lifecycle_events`
}

func normalizeControllerEstateLifecycleOperation(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "preview", "apply", "status":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeControllerEstateLifecycleStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "previewed", "applied", "blocked", "degraded", "skipped", "failed":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "blocked"
	}
}

func newControllerEstateLifecycleEventID(input ControllerEstateLifecycleEventInput) string {
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		sum := sha256.Sum256([]byte(strings.Join([]string{input.Operation, input.Status, input.PlanFingerprint}, "\x00")))
		return "controller-estate-" + hex.EncodeToString(sum[:8])
	}
	return "controller-estate-" + hex.EncodeToString(random[:])
}
