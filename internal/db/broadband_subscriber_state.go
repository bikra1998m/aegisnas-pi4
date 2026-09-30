package db

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
)

type BroadbandSubscriberStateEventInput struct {
	EventID                   string
	Operation                 string
	Status                    string
	PlanFingerprint           string
	Mode                      string
	AccessMethod              string
	ProductCount              int
	ServicePolicyCount        int
	FailurePolicyCount        int
	StateCount                int
	TransitionCount           int
	RequiredTransitionCount   int
	AccountingTransitionCount int
	RecoveryTransitionCount   int
	ComplianceCheckCount      int
	PassedCheckCount          int
	WarningCount              int
	BlockerCount              int
	ExternalRequirementCount  int
	SummaryJSON               string
	ReportJSON                string
	Actor                     string
}

type BroadbandSubscriberStateEvent struct {
	ID                        int    `json:"id"`
	EventID                   string `json:"event_id"`
	Operation                 string `json:"operation"`
	Status                    string `json:"status"`
	PlanFingerprint           string `json:"plan_fingerprint"`
	Mode                      string `json:"mode,omitempty"`
	AccessMethod              string `json:"access_method,omitempty"`
	ProductCount              int    `json:"product_count"`
	ServicePolicyCount        int    `json:"service_policy_count"`
	FailurePolicyCount        int    `json:"failure_policy_count"`
	StateCount                int    `json:"state_count"`
	TransitionCount           int    `json:"transition_count"`
	RequiredTransitionCount   int    `json:"required_transition_count"`
	AccountingTransitionCount int    `json:"accounting_transition_count"`
	RecoveryTransitionCount   int    `json:"recovery_transition_count"`
	ComplianceCheckCount      int    `json:"compliance_check_count"`
	PassedCheckCount          int    `json:"passed_check_count"`
	WarningCount              int    `json:"warning_count"`
	BlockerCount              int    `json:"blocker_count"`
	ExternalRequirementCount  int    `json:"external_requirement_count"`
	SummaryJSON               string `json:"summary_json"`
	ReportJSON                string `json:"report_json,omitempty"`
	Actor                     string `json:"actor,omitempty"`
	CreatedAt                 string `json:"created_at"`
}

type BroadbandSubscriberStateSummary struct {
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
	LastProductCount         int    `json:"last_product_count"`
	LastServicePolicyCount   int    `json:"last_service_policy_count"`
	LastTransitionCount      int    `json:"last_transition_count"`
	LastComplianceCheckCount int    `json:"last_compliance_check_count"`
}

func RecordBroadbandSubscriberStateEvent(input BroadbandSubscriberStateEventInput) (string, error) {
	if DB == nil {
		return "", nil
	}
	input.Operation = normalizeBroadbandSubscriberStateOperation(input.Operation)
	input.Status = normalizeBroadbandSubscriberStateStatus(input.Status)
	input.EventID = strings.TrimSpace(input.EventID)
	if input.EventID == "" {
		input.EventID = newBroadbandSubscriberStateEventID(input)
	}
	if input.Operation == "" || input.Status == "" {
		return "", fmt.Errorf("broadband subscriber state operation and status are required")
	}
	if strings.TrimSpace(input.PlanFingerprint) == "" {
		return "", fmt.Errorf("broadband subscriber state plan fingerprint is required")
	}
	if strings.TrimSpace(input.SummaryJSON) == "" {
		input.SummaryJSON = "{}"
	}
	if strings.TrimSpace(input.ReportJSON) == "" {
		input.ReportJSON = "{}"
	}

	_, err := DB.Exec(`INSERT INTO broadband_subscriber_state_events (
			event_id, operation, status, plan_fingerprint, mode, access_method,
			product_count, service_policy_count, failure_policy_count, state_count, transition_count,
			required_transition_count, accounting_transition_count, recovery_transition_count,
			compliance_check_count, passed_check_count, warning_count, blocker_count,
			external_requirement_count, summary_json, report_json, actor, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(event_id) DO UPDATE SET
			operation = excluded.operation,
			status = excluded.status,
			plan_fingerprint = excluded.plan_fingerprint,
			mode = excluded.mode,
			access_method = excluded.access_method,
			product_count = excluded.product_count,
			service_policy_count = excluded.service_policy_count,
			failure_policy_count = excluded.failure_policy_count,
			state_count = excluded.state_count,
			transition_count = excluded.transition_count,
			required_transition_count = excluded.required_transition_count,
			accounting_transition_count = excluded.accounting_transition_count,
			recovery_transition_count = excluded.recovery_transition_count,
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
		nullString(strings.TrimSpace(input.AccessMethod)),
		nonNegativeInt(input.ProductCount),
		nonNegativeInt(input.ServicePolicyCount),
		nonNegativeInt(input.FailurePolicyCount),
		nonNegativeInt(input.StateCount),
		nonNegativeInt(input.TransitionCount),
		nonNegativeInt(input.RequiredTransitionCount),
		nonNegativeInt(input.AccountingTransitionCount),
		nonNegativeInt(input.RecoveryTransitionCount),
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
		return "", fmt.Errorf("record broadband subscriber state event: %w", err)
	}
	return input.EventID, nil
}

func ListBroadbandSubscriberStateEvents(limit int) ([]BroadbandSubscriberStateEvent, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := DB.Query(broadbandSubscriberStateSelectSQL()+` ORDER BY datetime(created_at) DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list broadband subscriber state events: %w", err)
	}
	defer rows.Close()
	events := []BroadbandSubscriberStateEvent{}
	for rows.Next() {
		event, scanErr := scanBroadbandSubscriberStateEvent(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list broadband subscriber state rows: %w", err)
	}
	return events, nil
}

func GetBroadbandSubscriberStateSummary() (BroadbandSubscriberStateSummary, error) {
	if DB == nil {
		return BroadbandSubscriberStateSummary{}, nil
	}
	var summary BroadbandSubscriberStateSummary
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
		FROM broadband_subscriber_state_events`).Scan(
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
			return BroadbandSubscriberStateSummary{}, nil
		}
		return BroadbandSubscriberStateSummary{}, fmt.Errorf("summarize broadband subscriber state events: %w", err)
	}
	row := DB.QueryRow(`SELECT plan_fingerprint, product_count, service_policy_count, transition_count, compliance_check_count
		FROM broadband_subscriber_state_events
		ORDER BY datetime(created_at) DESC, id DESC LIMIT 1`)
	err = row.Scan(
		&summary.LastFingerprint,
		&summary.LastProductCount,
		&summary.LastServicePolicyCount,
		&summary.LastTransitionCount,
		&summary.LastComplianceCheckCount,
	)
	if err != nil && err != sql.ErrNoRows {
		return BroadbandSubscriberStateSummary{}, fmt.Errorf("read latest broadband subscriber state event: %w", err)
	}
	return summary, nil
}

func scanBroadbandSubscriberStateEvent(scanner interface {
	Scan(dest ...any) error
}) (BroadbandSubscriberStateEvent, error) {
	var event BroadbandSubscriberStateEvent
	var mode, accessMethod, actor sql.NullString
	err := scanner.Scan(
		&event.ID,
		&event.EventID,
		&event.Operation,
		&event.Status,
		&event.PlanFingerprint,
		&mode,
		&accessMethod,
		&event.ProductCount,
		&event.ServicePolicyCount,
		&event.FailurePolicyCount,
		&event.StateCount,
		&event.TransitionCount,
		&event.RequiredTransitionCount,
		&event.AccountingTransitionCount,
		&event.RecoveryTransitionCount,
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
		return BroadbandSubscriberStateEvent{}, fmt.Errorf("scan broadband subscriber state event: %w", err)
	}
	event.Mode = mode.String
	event.AccessMethod = accessMethod.String
	event.Actor = actor.String
	return event, nil
}

func broadbandSubscriberStateSelectSQL() string {
	return `SELECT id, event_id, operation, status, plan_fingerprint, mode, access_method,
		product_count, service_policy_count, failure_policy_count, state_count, transition_count,
		required_transition_count, accounting_transition_count, recovery_transition_count,
		compliance_check_count, passed_check_count, warning_count, blocker_count,
		external_requirement_count, summary_json, report_json, actor, created_at
		FROM broadband_subscriber_state_events`
}

func normalizeBroadbandSubscriberStateOperation(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "preview", "apply", "status":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeBroadbandSubscriberStateStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "previewed", "applied", "blocked", "degraded", "skipped", "failed":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func newBroadbandSubscriberStateEventID(input BroadbandSubscriberStateEventInput) string {
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%s", input.Operation, input.Status, input.PlanFingerprint, input.Actor)))
		return "bssm_" + hex.EncodeToString(sum[:8])
	}
	return "bssm_" + hex.EncodeToString(random)
}
