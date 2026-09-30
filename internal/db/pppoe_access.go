package db

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
)

type PPPoEAccessLifecycleEventInput struct {
	EventID                  string
	Operation                string
	Status                   string
	PlanFingerprint          string
	Mode                     string
	AccessConcentratorName   string
	ServiceName              string
	InterfaceCount           int
	ProfileCount             int
	SessionLimit             int
	RadiusAttributeCount     int
	PacketStageCount         int
	EnforcementActionCount   int
	ComplianceCheckCount     int
	PassedCheckCount         int
	WarningCount             int
	BlockerCount             int
	ExternalRequirementCount int
	SummaryJSON              string
	ReportJSON               string
	Actor                    string
}

type PPPoEAccessLifecycleEvent struct {
	ID                       int    `json:"id"`
	EventID                  string `json:"event_id"`
	Operation                string `json:"operation"`
	Status                   string `json:"status"`
	PlanFingerprint          string `json:"plan_fingerprint"`
	Mode                     string `json:"mode,omitempty"`
	AccessConcentratorName   string `json:"access_concentrator_name,omitempty"`
	ServiceName              string `json:"service_name,omitempty"`
	InterfaceCount           int    `json:"interface_count"`
	ProfileCount             int    `json:"profile_count"`
	SessionLimit             int    `json:"session_limit"`
	RadiusAttributeCount     int    `json:"radius_attribute_count"`
	PacketStageCount         int    `json:"packet_stage_count"`
	EnforcementActionCount   int    `json:"enforcement_action_count"`
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

type PPPoEAccessLifecycleSummary struct {
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
	LastInterfaceCount       int    `json:"last_interface_count"`
	LastProfileCount         int    `json:"last_profile_count"`
	LastSessionLimit         int    `json:"last_session_limit"`
	LastRadiusAttributeCount int    `json:"last_radius_attribute_count"`
	LastPacketStageCount     int    `json:"last_packet_stage_count"`
	LastEnforcementAction    int    `json:"last_enforcement_action_count"`
	LastComplianceCheckCount int    `json:"last_compliance_check_count"`
}

func RecordPPPoEAccessLifecycleEvent(input PPPoEAccessLifecycleEventInput) (string, error) {
	if DB == nil {
		return "", nil
	}
	input.Operation = normalizePPPoEAccessOperation(input.Operation)
	input.Status = normalizePPPoEAccessStatus(input.Status)
	input.EventID = strings.TrimSpace(input.EventID)
	if input.EventID == "" {
		input.EventID = newPPPoEAccessEventID(input)
	}
	if input.Operation == "" || input.Status == "" {
		return "", fmt.Errorf("PPPoE access lifecycle operation and status are required")
	}
	if strings.TrimSpace(input.PlanFingerprint) == "" {
		return "", fmt.Errorf("PPPoE access lifecycle plan fingerprint is required")
	}
	if strings.TrimSpace(input.SummaryJSON) == "" {
		input.SummaryJSON = "{}"
	}
	if strings.TrimSpace(input.ReportJSON) == "" {
		input.ReportJSON = "{}"
	}

	_, err := DB.Exec(`INSERT INTO pppoe_access_lifecycle_events (
			event_id, operation, status, plan_fingerprint, mode, access_concentrator_name, service_name,
			interface_count, profile_count, session_limit, radius_attribute_count, packet_stage_count,
			enforcement_action_count, compliance_check_count, passed_check_count, warning_count,
			blocker_count, external_requirement_count, summary_json, report_json, actor, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(event_id) DO UPDATE SET
			operation = excluded.operation,
			status = excluded.status,
			plan_fingerprint = excluded.plan_fingerprint,
			mode = excluded.mode,
			access_concentrator_name = excluded.access_concentrator_name,
			service_name = excluded.service_name,
			interface_count = excluded.interface_count,
			profile_count = excluded.profile_count,
			session_limit = excluded.session_limit,
			radius_attribute_count = excluded.radius_attribute_count,
			packet_stage_count = excluded.packet_stage_count,
			enforcement_action_count = excluded.enforcement_action_count,
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
		nullString(strings.TrimSpace(input.AccessConcentratorName)),
		nullString(strings.TrimSpace(input.ServiceName)),
		nonNegativeInt(input.InterfaceCount),
		nonNegativeInt(input.ProfileCount),
		nonNegativeInt(input.SessionLimit),
		nonNegativeInt(input.RadiusAttributeCount),
		nonNegativeInt(input.PacketStageCount),
		nonNegativeInt(input.EnforcementActionCount),
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
		return "", fmt.Errorf("record PPPoE access lifecycle event: %w", err)
	}
	return input.EventID, nil
}

func ListPPPoEAccessLifecycleEvents(limit int) ([]PPPoEAccessLifecycleEvent, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := DB.Query(pppoeAccessSelectSQL()+` ORDER BY datetime(created_at) DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list PPPoE access lifecycle events: %w", err)
	}
	defer rows.Close()
	events := []PPPoEAccessLifecycleEvent{}
	for rows.Next() {
		event, scanErr := scanPPPoEAccessLifecycleEvent(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list PPPoE access lifecycle rows: %w", err)
	}
	return events, nil
}

func GetPPPoEAccessLifecycleSummary() (PPPoEAccessLifecycleSummary, error) {
	if DB == nil {
		return PPPoEAccessLifecycleSummary{}, nil
	}
	var summary PPPoEAccessLifecycleSummary
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
		FROM pppoe_access_lifecycle_events`).Scan(
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
			return PPPoEAccessLifecycleSummary{}, nil
		}
		return PPPoEAccessLifecycleSummary{}, fmt.Errorf("summarize PPPoE access lifecycle events: %w", err)
	}
	row := DB.QueryRow(`SELECT plan_fingerprint, interface_count, profile_count, session_limit,
			radius_attribute_count, packet_stage_count, enforcement_action_count, compliance_check_count
		FROM pppoe_access_lifecycle_events
		ORDER BY datetime(created_at) DESC, id DESC LIMIT 1`)
	err = row.Scan(
		&summary.LastFingerprint,
		&summary.LastInterfaceCount,
		&summary.LastProfileCount,
		&summary.LastSessionLimit,
		&summary.LastRadiusAttributeCount,
		&summary.LastPacketStageCount,
		&summary.LastEnforcementAction,
		&summary.LastComplianceCheckCount,
	)
	if err != nil && err != sql.ErrNoRows {
		return PPPoEAccessLifecycleSummary{}, fmt.Errorf("read latest PPPoE access lifecycle event: %w", err)
	}
	return summary, nil
}

func scanPPPoEAccessLifecycleEvent(scanner interface {
	Scan(dest ...any) error
}) (PPPoEAccessLifecycleEvent, error) {
	var event PPPoEAccessLifecycleEvent
	var mode, acName, serviceName, actor sql.NullString
	err := scanner.Scan(
		&event.ID,
		&event.EventID,
		&event.Operation,
		&event.Status,
		&event.PlanFingerprint,
		&mode,
		&acName,
		&serviceName,
		&event.InterfaceCount,
		&event.ProfileCount,
		&event.SessionLimit,
		&event.RadiusAttributeCount,
		&event.PacketStageCount,
		&event.EnforcementActionCount,
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
		return PPPoEAccessLifecycleEvent{}, fmt.Errorf("scan PPPoE access lifecycle event: %w", err)
	}
	event.Mode = mode.String
	event.AccessConcentratorName = acName.String
	event.ServiceName = serviceName.String
	event.Actor = actor.String
	return event, nil
}

func pppoeAccessSelectSQL() string {
	return `SELECT id, event_id, operation, status, plan_fingerprint,
		COALESCE(mode, ''), COALESCE(access_concentrator_name, ''), COALESCE(service_name, ''),
		interface_count, profile_count, session_limit, radius_attribute_count, packet_stage_count,
		enforcement_action_count, compliance_check_count, passed_check_count, warning_count,
		blocker_count, external_requirement_count, summary_json, report_json,
		COALESCE(actor, ''), COALESCE(CAST(created_at AS TEXT), '')
		FROM pppoe_access_lifecycle_events`
}

func normalizePPPoEAccessOperation(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "preview", "apply", "status":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizePPPoEAccessStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "previewed", "applied", "blocked", "degraded", "skipped", "failed":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "blocked"
	}
}

func newPPPoEAccessEventID(input PPPoEAccessLifecycleEventInput) string {
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		sum := sha256.Sum256([]byte(strings.Join([]string{input.Operation, input.Status, input.PlanFingerprint}, "\x00")))
		return "pppoe-" + hex.EncodeToString(sum[:8])
	}
	return "pppoe-" + hex.EncodeToString(random[:])
}
