package db

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
)

type WirelessSecurityLifecycleEventInput struct {
	EventID                  string
	Operation                string
	Status                   string
	PlanFingerprint          string
	Mode                     string
	ControllerPlatform       string
	SensorCount              int
	RoguePolicyCount         int
	WIPSDetectionCount       int
	SpectrumChannelCount     int
	LocationZoneCount        int
	MulticastPolicyCount     int
	ContainmentGuardCount    int
	PrivacyCheckCount        int
	ComplianceCheckCount     int
	PassedCheckCount         int
	WarningCount             int
	BlockerCount             int
	ExternalRequirementCount int
	SummaryJSON              string
	ReportJSON               string
	Actor                    string
}

type WirelessSecurityLifecycleEvent struct {
	ID                       int    `json:"id"`
	EventID                  string `json:"event_id"`
	Operation                string `json:"operation"`
	Status                   string `json:"status"`
	PlanFingerprint          string `json:"plan_fingerprint"`
	Mode                     string `json:"mode,omitempty"`
	ControllerPlatform       string `json:"controller_platform,omitempty"`
	SensorCount              int    `json:"sensor_count"`
	RoguePolicyCount         int    `json:"rogue_policy_count"`
	WIPSDetectionCount       int    `json:"wips_detection_count"`
	SpectrumChannelCount     int    `json:"spectrum_channel_count"`
	LocationZoneCount        int    `json:"location_zone_count"`
	MulticastPolicyCount     int    `json:"multicast_policy_count"`
	ContainmentGuardCount    int    `json:"containment_guard_count"`
	PrivacyCheckCount        int    `json:"privacy_check_count"`
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

type WirelessSecurityLifecycleSummary struct {
	TotalEvents               int    `json:"total_events"`
	PreviewEvents             int    `json:"preview_events"`
	ApplyEvents               int    `json:"apply_events"`
	StatusEvents              int    `json:"status_events"`
	PreviewedCount            int    `json:"previewed_count"`
	AppliedCount              int    `json:"applied_count"`
	BlockedCount              int    `json:"blocked_count"`
	DegradedCount             int    `json:"degraded_count"`
	SkippedCount              int    `json:"skipped_count"`
	FailedCount               int    `json:"failed_count"`
	LastEventAt               string `json:"last_event_at,omitempty"`
	LastFingerprint           string `json:"last_fingerprint,omitempty"`
	LastSensorCount           int    `json:"last_sensor_count"`
	LastRoguePolicyCount      int    `json:"last_rogue_policy_count"`
	LastWIPSDetectionCount    int    `json:"last_wips_detection_count"`
	LastSpectrumChannelCount  int    `json:"last_spectrum_channel_count"`
	LastLocationZoneCount     int    `json:"last_location_zone_count"`
	LastMulticastPolicyCount  int    `json:"last_multicast_policy_count"`
	LastContainmentGuardCount int    `json:"last_containment_guard_count"`
	LastPrivacyCheckCount     int    `json:"last_privacy_check_count"`
}

func RecordWirelessSecurityLifecycleEvent(input WirelessSecurityLifecycleEventInput) (string, error) {
	if DB == nil {
		return "", nil
	}
	input.Operation = normalizeWirelessSecurityOperation(input.Operation)
	input.Status = normalizeWirelessSecurityStatus(input.Status)
	input.EventID = strings.TrimSpace(input.EventID)
	if input.EventID == "" {
		input.EventID = newWirelessSecurityEventID(input)
	}
	if input.Operation == "" || input.Status == "" {
		return "", fmt.Errorf("wireless security lifecycle operation and status are required")
	}
	if strings.TrimSpace(input.PlanFingerprint) == "" {
		return "", fmt.Errorf("wireless security lifecycle plan fingerprint is required")
	}
	if strings.TrimSpace(input.SummaryJSON) == "" {
		input.SummaryJSON = "{}"
	}
	if strings.TrimSpace(input.ReportJSON) == "" {
		input.ReportJSON = "{}"
	}

	_, err := DB.Exec(`INSERT INTO wireless_security_lifecycle_events (
			event_id, operation, status, plan_fingerprint, mode, controller_platform,
			sensor_count, rogue_policy_count, wips_detection_count, spectrum_channel_count,
			location_zone_count, multicast_policy_count, containment_guard_count,
			privacy_check_count, compliance_check_count, passed_check_count, warning_count,
			blocker_count, external_requirement_count, summary_json, report_json, actor, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(event_id) DO UPDATE SET
			operation = excluded.operation,
			status = excluded.status,
			plan_fingerprint = excluded.plan_fingerprint,
			mode = excluded.mode,
			controller_platform = excluded.controller_platform,
			sensor_count = excluded.sensor_count,
			rogue_policy_count = excluded.rogue_policy_count,
			wips_detection_count = excluded.wips_detection_count,
			spectrum_channel_count = excluded.spectrum_channel_count,
			location_zone_count = excluded.location_zone_count,
			multicast_policy_count = excluded.multicast_policy_count,
			containment_guard_count = excluded.containment_guard_count,
			privacy_check_count = excluded.privacy_check_count,
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
		nullString(strings.TrimSpace(input.ControllerPlatform)),
		nonNegativeInt(input.SensorCount),
		nonNegativeInt(input.RoguePolicyCount),
		nonNegativeInt(input.WIPSDetectionCount),
		nonNegativeInt(input.SpectrumChannelCount),
		nonNegativeInt(input.LocationZoneCount),
		nonNegativeInt(input.MulticastPolicyCount),
		nonNegativeInt(input.ContainmentGuardCount),
		nonNegativeInt(input.PrivacyCheckCount),
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
		return "", fmt.Errorf("record wireless security lifecycle event: %w", err)
	}
	return input.EventID, nil
}

func ListWirelessSecurityLifecycleEvents(limit int) ([]WirelessSecurityLifecycleEvent, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := DB.Query(wirelessSecuritySelectSQL()+` ORDER BY datetime(created_at) DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list wireless security lifecycle events: %w", err)
	}
	defer rows.Close()
	events := []WirelessSecurityLifecycleEvent{}
	for rows.Next() {
		event, scanErr := scanWirelessSecurityLifecycleEvent(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list wireless security lifecycle rows: %w", err)
	}
	return events, nil
}

func GetWirelessSecurityLifecycleSummary() (WirelessSecurityLifecycleSummary, error) {
	if DB == nil {
		return WirelessSecurityLifecycleSummary{}, nil
	}
	var summary WirelessSecurityLifecycleSummary
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
		FROM wireless_security_lifecycle_events`).Scan(
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
			return WirelessSecurityLifecycleSummary{}, nil
		}
		return WirelessSecurityLifecycleSummary{}, fmt.Errorf("summarize wireless security lifecycle events: %w", err)
	}
	row := DB.QueryRow(`SELECT plan_fingerprint, sensor_count, rogue_policy_count,
			wips_detection_count, spectrum_channel_count, location_zone_count,
			multicast_policy_count, containment_guard_count, privacy_check_count
		FROM wireless_security_lifecycle_events
		ORDER BY datetime(created_at) DESC, id DESC LIMIT 1`)
	err = row.Scan(
		&summary.LastFingerprint,
		&summary.LastSensorCount,
		&summary.LastRoguePolicyCount,
		&summary.LastWIPSDetectionCount,
		&summary.LastSpectrumChannelCount,
		&summary.LastLocationZoneCount,
		&summary.LastMulticastPolicyCount,
		&summary.LastContainmentGuardCount,
		&summary.LastPrivacyCheckCount,
	)
	if err != nil && err != sql.ErrNoRows {
		return WirelessSecurityLifecycleSummary{}, fmt.Errorf("read latest wireless security lifecycle event: %w", err)
	}
	return summary, nil
}

func scanWirelessSecurityLifecycleEvent(scanner interface {
	Scan(dest ...any) error
}) (WirelessSecurityLifecycleEvent, error) {
	var event WirelessSecurityLifecycleEvent
	var mode, platform, actor sql.NullString
	err := scanner.Scan(
		&event.ID,
		&event.EventID,
		&event.Operation,
		&event.Status,
		&event.PlanFingerprint,
		&mode,
		&platform,
		&event.SensorCount,
		&event.RoguePolicyCount,
		&event.WIPSDetectionCount,
		&event.SpectrumChannelCount,
		&event.LocationZoneCount,
		&event.MulticastPolicyCount,
		&event.ContainmentGuardCount,
		&event.PrivacyCheckCount,
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
		return WirelessSecurityLifecycleEvent{}, fmt.Errorf("scan wireless security lifecycle event: %w", err)
	}
	event.Mode = mode.String
	event.ControllerPlatform = platform.String
	event.Actor = actor.String
	return event, nil
}

func wirelessSecuritySelectSQL() string {
	return `SELECT id, event_id, operation, status, plan_fingerprint,
		COALESCE(mode, ''), COALESCE(controller_platform, ''),
		sensor_count, rogue_policy_count, wips_detection_count, spectrum_channel_count,
		location_zone_count, multicast_policy_count, containment_guard_count,
		privacy_check_count, compliance_check_count, passed_check_count,
		warning_count, blocker_count, external_requirement_count, summary_json, report_json,
		COALESCE(actor, ''), COALESCE(CAST(created_at AS TEXT), '')
		FROM wireless_security_lifecycle_events`
}

func normalizeWirelessSecurityOperation(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "preview", "apply", "status":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeWirelessSecurityStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "previewed", "applied", "blocked", "degraded", "skipped", "failed":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "blocked"
	}
}

func newWirelessSecurityEventID(input WirelessSecurityLifecycleEventInput) string {
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		sum := sha256.Sum256([]byte(strings.Join([]string{input.Operation, input.Status, input.PlanFingerprint}, "\x00")))
		return "wsec-" + hex.EncodeToString(sum[:8])
	}
	return "wsec-" + hex.EncodeToString(random[:])
}
