package db

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
)

type CWAPortalLifecycleEventInput struct {
	EventID                  string
	Operation                string
	Status                   string
	PlanFingerprint          string
	Mode                     string
	PortalBaseURL            string
	ControllerPlatform       string
	GuestSSIDCount           int
	WalledGardenCount        int
	ControllerPolicyCount    int
	RedirectRuleCount        int
	CoAActionCount           int
	ComplianceCheckCount     int
	PassedCheckCount         int
	WarningCount             int
	BlockerCount             int
	ExternalRequirementCount int
	SummaryJSON              string
	ReportJSON               string
	Actor                    string
}

type CWAPortalLifecycleEvent struct {
	ID                       int    `json:"id"`
	EventID                  string `json:"event_id"`
	Operation                string `json:"operation"`
	Status                   string `json:"status"`
	PlanFingerprint          string `json:"plan_fingerprint"`
	Mode                     string `json:"mode,omitempty"`
	PortalBaseURL            string `json:"portal_base_url,omitempty"`
	ControllerPlatform       string `json:"controller_platform,omitempty"`
	GuestSSIDCount           int    `json:"guest_ssid_count"`
	WalledGardenCount        int    `json:"walled_garden_count"`
	ControllerPolicyCount    int    `json:"controller_policy_count"`
	RedirectRuleCount        int    `json:"redirect_rule_count"`
	CoAActionCount           int    `json:"coa_action_count"`
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

type CWAPortalLifecycleSummary struct {
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
	LastGuestSSIDCount       int    `json:"last_guest_ssid_count"`
	LastWalledGardenCount    int    `json:"last_walled_garden_count"`
	LastControllerPolicy     int    `json:"last_controller_policy_count"`
	LastRedirectRuleCount    int    `json:"last_redirect_rule_count"`
	LastCoAActionCount       int    `json:"last_coa_action_count"`
	LastComplianceCheckCount int    `json:"last_compliance_check_count"`
}

func RecordCWAPortalLifecycleEvent(input CWAPortalLifecycleEventInput) (string, error) {
	if DB == nil {
		return "", nil
	}
	input.Operation = normalizeCWAPortalOperation(input.Operation)
	input.Status = normalizeCWAPortalStatus(input.Status)
	input.EventID = strings.TrimSpace(input.EventID)
	if input.EventID == "" {
		input.EventID = newCWAPortalEventID(input)
	}
	if input.Operation == "" || input.Status == "" {
		return "", fmt.Errorf("CWA portal lifecycle operation and status are required")
	}
	if strings.TrimSpace(input.PlanFingerprint) == "" {
		return "", fmt.Errorf("CWA portal lifecycle plan fingerprint is required")
	}
	if strings.TrimSpace(input.SummaryJSON) == "" {
		input.SummaryJSON = "{}"
	}
	if strings.TrimSpace(input.ReportJSON) == "" {
		input.ReportJSON = "{}"
	}

	_, err := DB.Exec(`INSERT INTO cwa_portal_lifecycle_events (
			event_id, operation, status, plan_fingerprint, mode, portal_base_url, controller_platform,
			guest_ssid_count, walled_garden_count, controller_policy_count, redirect_rule_count,
			coa_action_count, compliance_check_count, passed_check_count, warning_count,
			blocker_count, external_requirement_count, summary_json, report_json, actor, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(event_id) DO UPDATE SET
			operation = excluded.operation,
			status = excluded.status,
			plan_fingerprint = excluded.plan_fingerprint,
			mode = excluded.mode,
			portal_base_url = excluded.portal_base_url,
			controller_platform = excluded.controller_platform,
			guest_ssid_count = excluded.guest_ssid_count,
			walled_garden_count = excluded.walled_garden_count,
			controller_policy_count = excluded.controller_policy_count,
			redirect_rule_count = excluded.redirect_rule_count,
			coa_action_count = excluded.coa_action_count,
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
		nullString(strings.TrimSpace(input.PortalBaseURL)),
		nullString(strings.TrimSpace(input.ControllerPlatform)),
		nonNegativeInt(input.GuestSSIDCount),
		nonNegativeInt(input.WalledGardenCount),
		nonNegativeInt(input.ControllerPolicyCount),
		nonNegativeInt(input.RedirectRuleCount),
		nonNegativeInt(input.CoAActionCount),
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
		return "", fmt.Errorf("record CWA portal lifecycle event: %w", err)
	}
	return input.EventID, nil
}

func ListCWAPortalLifecycleEvents(limit int) ([]CWAPortalLifecycleEvent, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := DB.Query(cwaPortalSelectSQL()+` ORDER BY datetime(created_at) DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list CWA portal lifecycle events: %w", err)
	}
	defer rows.Close()
	events := []CWAPortalLifecycleEvent{}
	for rows.Next() {
		event, scanErr := scanCWAPortalLifecycleEvent(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list CWA portal lifecycle rows: %w", err)
	}
	return events, nil
}

func GetCWAPortalLifecycleSummary() (CWAPortalLifecycleSummary, error) {
	if DB == nil {
		return CWAPortalLifecycleSummary{}, nil
	}
	var summary CWAPortalLifecycleSummary
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
		FROM cwa_portal_lifecycle_events`).Scan(
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
			return CWAPortalLifecycleSummary{}, nil
		}
		return CWAPortalLifecycleSummary{}, fmt.Errorf("summarize CWA portal lifecycle events: %w", err)
	}
	row := DB.QueryRow(`SELECT plan_fingerprint, guest_ssid_count, walled_garden_count,
			controller_policy_count, redirect_rule_count, coa_action_count, compliance_check_count
		FROM cwa_portal_lifecycle_events
		ORDER BY datetime(created_at) DESC, id DESC LIMIT 1`)
	err = row.Scan(
		&summary.LastFingerprint,
		&summary.LastGuestSSIDCount,
		&summary.LastWalledGardenCount,
		&summary.LastControllerPolicy,
		&summary.LastRedirectRuleCount,
		&summary.LastCoAActionCount,
		&summary.LastComplianceCheckCount,
	)
	if err != nil && err != sql.ErrNoRows {
		return CWAPortalLifecycleSummary{}, fmt.Errorf("read latest CWA portal lifecycle event: %w", err)
	}
	return summary, nil
}

func scanCWAPortalLifecycleEvent(scanner interface {
	Scan(dest ...any) error
}) (CWAPortalLifecycleEvent, error) {
	var event CWAPortalLifecycleEvent
	var mode, baseURL, platform, actor sql.NullString
	err := scanner.Scan(
		&event.ID,
		&event.EventID,
		&event.Operation,
		&event.Status,
		&event.PlanFingerprint,
		&mode,
		&baseURL,
		&platform,
		&event.GuestSSIDCount,
		&event.WalledGardenCount,
		&event.ControllerPolicyCount,
		&event.RedirectRuleCount,
		&event.CoAActionCount,
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
		return CWAPortalLifecycleEvent{}, fmt.Errorf("scan CWA portal lifecycle event: %w", err)
	}
	event.Mode = mode.String
	event.PortalBaseURL = baseURL.String
	event.ControllerPlatform = platform.String
	event.Actor = actor.String
	return event, nil
}

func cwaPortalSelectSQL() string {
	return `SELECT id, event_id, operation, status, plan_fingerprint,
		COALESCE(mode, ''), COALESCE(portal_base_url, ''), COALESCE(controller_platform, ''),
		guest_ssid_count, walled_garden_count, controller_policy_count, redirect_rule_count,
		coa_action_count, compliance_check_count, passed_check_count, warning_count,
		blocker_count, external_requirement_count, summary_json, report_json,
		COALESCE(actor, ''), COALESCE(CAST(created_at AS TEXT), '')
		FROM cwa_portal_lifecycle_events`
}

func normalizeCWAPortalOperation(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "preview", "apply", "status":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeCWAPortalStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "previewed", "applied", "blocked", "degraded", "skipped", "failed":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "blocked"
	}
}

func newCWAPortalEventID(input CWAPortalLifecycleEventInput) string {
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		sum := sha256.Sum256([]byte(strings.Join([]string{input.Operation, input.Status, input.PlanFingerprint}, "\x00")))
		return "cwa-" + hex.EncodeToString(sum[:8])
	}
	return "cwa-" + hex.EncodeToString(random[:])
}
