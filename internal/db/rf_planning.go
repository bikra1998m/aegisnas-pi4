package db

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
)

type RFPlanningLifecycleEventInput struct {
	EventID                  string
	Operation                string
	Status                   string
	PlanFingerprint          string
	CountryCode              string
	ControllerPlatform       string
	ChannelPlanMode          string
	APCount                  int
	RadioCount               int
	BandCount                int
	ChannelPlanCount         int
	PowerPlanCount           int
	MeshLinkCount            int
	SteeringPolicyCount      int
	ChannelConflictCount     int
	CapacityWarningCount     int
	ComplianceCheckCount     int
	PassedCheckCount         int
	WarningCount             int
	BlockerCount             int
	ExternalRequirementCount int
	SummaryJSON              string
	ReportJSON               string
	Actor                    string
}

type RFPlanningLifecycleEvent struct {
	ID                       int    `json:"id"`
	EventID                  string `json:"event_id"`
	Operation                string `json:"operation"`
	Status                   string `json:"status"`
	PlanFingerprint          string `json:"plan_fingerprint"`
	CountryCode              string `json:"country_code,omitempty"`
	ControllerPlatform       string `json:"controller_platform,omitempty"`
	ChannelPlanMode          string `json:"channel_plan_mode,omitempty"`
	APCount                  int    `json:"ap_count"`
	RadioCount               int    `json:"radio_count"`
	BandCount                int    `json:"band_count"`
	ChannelPlanCount         int    `json:"channel_plan_count"`
	PowerPlanCount           int    `json:"power_plan_count"`
	MeshLinkCount            int    `json:"mesh_link_count"`
	SteeringPolicyCount      int    `json:"steering_policy_count"`
	ChannelConflictCount     int    `json:"channel_conflict_count"`
	CapacityWarningCount     int    `json:"capacity_warning_count"`
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

type RFPlanningLifecycleSummary struct {
	TotalEvents              int    `json:"total_events"`
	PreviewEvents            int    `json:"preview_events"`
	ApplyEvents              int    `json:"apply_events"`
	StatusEvents             int    `json:"status_events"`
	PreviewedCount           int    `json:"previewed_count"`
	AppliedCount             int    `json:"applied_count"`
	BlockedCount             int    `json:"blocked_count"`
	DegradedCount            int    `json:"degraded_count"`
	SkippedCount             int    `json:"skipped_count"`
	FailedCount              int    `json:"failed_count"`
	LastEventAt              string `json:"last_event_at,omitempty"`
	LastFingerprint          string `json:"last_fingerprint,omitempty"`
	LastRadioCount           int    `json:"last_radio_count"`
	LastChannelPlanCount     int    `json:"last_channel_plan_count"`
	LastPowerPlanCount       int    `json:"last_power_plan_count"`
	LastMeshLinkCount        int    `json:"last_mesh_link_count"`
	LastSteeringPolicyCount  int    `json:"last_steering_policy_count"`
	LastChannelConflictCount int    `json:"last_channel_conflict_count"`
	LastCapacityWarningCount int    `json:"last_capacity_warning_count"`
}

func RecordRFPlanningLifecycleEvent(input RFPlanningLifecycleEventInput) (string, error) {
	if DB == nil {
		return "", nil
	}
	input.Operation = normalizeRFPlanningOperation(input.Operation)
	input.Status = normalizeRFPlanningStatus(input.Status)
	input.EventID = strings.TrimSpace(input.EventID)
	if input.EventID == "" {
		input.EventID = newRFPlanningEventID(input)
	}
	if input.Operation == "" || input.Status == "" {
		return "", fmt.Errorf("RF planning lifecycle operation and status are required")
	}
	if strings.TrimSpace(input.PlanFingerprint) == "" {
		return "", fmt.Errorf("RF planning lifecycle plan fingerprint is required")
	}
	if strings.TrimSpace(input.SummaryJSON) == "" {
		input.SummaryJSON = "{}"
	}
	if strings.TrimSpace(input.ReportJSON) == "" {
		input.ReportJSON = "{}"
	}

	_, err := DB.Exec(`INSERT INTO rf_planning_lifecycle_events (
			event_id, operation, status, plan_fingerprint, country_code, controller_platform,
			channel_plan_mode, ap_count, radio_count, band_count, channel_plan_count,
			power_plan_count, mesh_link_count, steering_policy_count, channel_conflict_count,
			capacity_warning_count, compliance_check_count, passed_check_count, warning_count,
			blocker_count, external_requirement_count, summary_json, report_json, actor, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(event_id) DO UPDATE SET
			operation = excluded.operation,
			status = excluded.status,
			plan_fingerprint = excluded.plan_fingerprint,
			country_code = excluded.country_code,
			controller_platform = excluded.controller_platform,
			channel_plan_mode = excluded.channel_plan_mode,
			ap_count = excluded.ap_count,
			radio_count = excluded.radio_count,
			band_count = excluded.band_count,
			channel_plan_count = excluded.channel_plan_count,
			power_plan_count = excluded.power_plan_count,
			mesh_link_count = excluded.mesh_link_count,
			steering_policy_count = excluded.steering_policy_count,
			channel_conflict_count = excluded.channel_conflict_count,
			capacity_warning_count = excluded.capacity_warning_count,
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
		nullString(strings.ToUpper(strings.TrimSpace(input.CountryCode))),
		nullString(strings.TrimSpace(input.ControllerPlatform)),
		nullString(strings.TrimSpace(input.ChannelPlanMode)),
		nonNegativeInt(input.APCount),
		nonNegativeInt(input.RadioCount),
		nonNegativeInt(input.BandCount),
		nonNegativeInt(input.ChannelPlanCount),
		nonNegativeInt(input.PowerPlanCount),
		nonNegativeInt(input.MeshLinkCount),
		nonNegativeInt(input.SteeringPolicyCount),
		nonNegativeInt(input.ChannelConflictCount),
		nonNegativeInt(input.CapacityWarningCount),
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
		return "", fmt.Errorf("record RF planning lifecycle event: %w", err)
	}
	return input.EventID, nil
}

func ListRFPlanningLifecycleEvents(limit int) ([]RFPlanningLifecycleEvent, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := DB.Query(rfPlanningSelectSQL()+` ORDER BY datetime(created_at) DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list RF planning lifecycle events: %w", err)
	}
	defer rows.Close()
	events := []RFPlanningLifecycleEvent{}
	for rows.Next() {
		event, scanErr := scanRFPlanningLifecycleEvent(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list RF planning lifecycle rows: %w", err)
	}
	return events, nil
}

func GetRFPlanningLifecycleSummary() (RFPlanningLifecycleSummary, error) {
	if DB == nil {
		return RFPlanningLifecycleSummary{}, nil
	}
	var summary RFPlanningLifecycleSummary
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
		FROM rf_planning_lifecycle_events`).Scan(
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
			return RFPlanningLifecycleSummary{}, nil
		}
		return RFPlanningLifecycleSummary{}, fmt.Errorf("summarize RF planning lifecycle events: %w", err)
	}
	row := DB.QueryRow(`SELECT plan_fingerprint, radio_count, channel_plan_count,
			power_plan_count, mesh_link_count, steering_policy_count,
			channel_conflict_count, capacity_warning_count
		FROM rf_planning_lifecycle_events
		ORDER BY datetime(created_at) DESC, id DESC LIMIT 1`)
	err = row.Scan(
		&summary.LastFingerprint,
		&summary.LastRadioCount,
		&summary.LastChannelPlanCount,
		&summary.LastPowerPlanCount,
		&summary.LastMeshLinkCount,
		&summary.LastSteeringPolicyCount,
		&summary.LastChannelConflictCount,
		&summary.LastCapacityWarningCount,
	)
	if err != nil && err != sql.ErrNoRows {
		return RFPlanningLifecycleSummary{}, fmt.Errorf("read latest RF planning lifecycle event: %w", err)
	}
	return summary, nil
}

func scanRFPlanningLifecycleEvent(scanner interface {
	Scan(dest ...any) error
}) (RFPlanningLifecycleEvent, error) {
	var event RFPlanningLifecycleEvent
	var country, platform, mode, actor sql.NullString
	err := scanner.Scan(
		&event.ID,
		&event.EventID,
		&event.Operation,
		&event.Status,
		&event.PlanFingerprint,
		&country,
		&platform,
		&mode,
		&event.APCount,
		&event.RadioCount,
		&event.BandCount,
		&event.ChannelPlanCount,
		&event.PowerPlanCount,
		&event.MeshLinkCount,
		&event.SteeringPolicyCount,
		&event.ChannelConflictCount,
		&event.CapacityWarningCount,
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
		return RFPlanningLifecycleEvent{}, fmt.Errorf("scan RF planning lifecycle event: %w", err)
	}
	event.CountryCode = country.String
	event.ControllerPlatform = platform.String
	event.ChannelPlanMode = mode.String
	event.Actor = actor.String
	return event, nil
}

func rfPlanningSelectSQL() string {
	return `SELECT id, event_id, operation, status, plan_fingerprint,
		COALESCE(country_code, ''), COALESCE(controller_platform, ''),
		COALESCE(channel_plan_mode, ''), ap_count, radio_count, band_count,
		channel_plan_count, power_plan_count, mesh_link_count, steering_policy_count,
		channel_conflict_count, capacity_warning_count, compliance_check_count,
		passed_check_count, warning_count, blocker_count, external_requirement_count,
		summary_json, report_json, COALESCE(actor, ''), COALESCE(CAST(created_at AS TEXT), '')
		FROM rf_planning_lifecycle_events`
}

func normalizeRFPlanningOperation(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "preview", "apply", "status":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeRFPlanningStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "previewed", "applied", "blocked", "degraded", "skipped", "failed":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "blocked"
	}
}

func newRFPlanningEventID(input RFPlanningLifecycleEventInput) string {
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		sum := sha256.Sum256([]byte(strings.Join([]string{input.Operation, input.Status, input.PlanFingerprint}, "\x00")))
		return "rf-plan-" + hex.EncodeToString(sum[:8])
	}
	return "rf-plan-" + hex.EncodeToString(random[:])
}
