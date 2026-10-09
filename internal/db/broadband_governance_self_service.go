package db

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
)

type BroadbandGovernanceSelfServiceEventInput struct {
	EventID                  string
	Operation                string
	Status                   string
	PlanFingerprint          string
	Mode                     string
	CaseCount                int
	SelfServiceActionCount   int
	PrivacyPolicyCount       int
	ApprovalPolicyCount      int
	CompiledAttributeCount   int
	ComplianceCheckCount     int
	PassedCheckCount         int
	WarningCount             int
	BlockerCount             int
	ExternalRequirementCount int
	SummaryJSON              string
	ReportJSON               string
	Actor                    string
	Cases                    []BroadbandGovernanceCaseInput
	Requests                 []BroadbandSelfServiceRequestInput
}

type BroadbandGovernanceCaseInput struct {
	CaseKey          string
	Name             string
	CaseID           string
	LegalAuthority   string
	RequestReference string
	SubscriberID     string
	Username         string
	Tenant           string
	Scope            string
	Status           string
	AttributesJSON   string
	SourceEventID    string
	PlanFingerprint  string
}

type BroadbandSelfServiceRequestInput struct {
	RequestKey       string
	Action           string
	Name             string
	Status           string
	RequiresApproval bool
	RequiresMFA      bool
	AttributesJSON   string
	SourceEventID    string
	PlanFingerprint  string
}

type BroadbandGovernanceSelfServiceEvent struct {
	ID                       int    `json:"id"`
	EventID                  string `json:"event_id"`
	Operation                string `json:"operation"`
	Status                   string `json:"status"`
	PlanFingerprint          string `json:"plan_fingerprint"`
	Mode                     string `json:"mode,omitempty"`
	CaseCount                int    `json:"case_count"`
	SelfServiceActionCount   int    `json:"self_service_action_count"`
	PrivacyPolicyCount       int    `json:"privacy_policy_count"`
	ApprovalPolicyCount      int    `json:"approval_policy_count"`
	CompiledAttributeCount   int    `json:"compiled_attribute_count"`
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

type BroadbandGovernanceCaseRecord struct {
	ID              int    `json:"id"`
	CaseKey         string `json:"case_key"`
	Name            string `json:"name"`
	CaseID          string `json:"case_id,omitempty"`
	SubscriberID    string `json:"subscriber_id,omitempty"`
	Username        string `json:"username,omitempty"`
	Tenant          string `json:"tenant,omitempty"`
	Scope           string `json:"scope,omitempty"`
	Status          string `json:"status"`
	AttributesJSON  string `json:"attributes_json"`
	SourceEventID   string `json:"source_event_id,omitempty"`
	PlanFingerprint string `json:"plan_fingerprint"`
	LastSeenAt      string `json:"last_seen_at"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}

type BroadbandSelfServiceRequestRecord struct {
	ID               int    `json:"id"`
	RequestKey       string `json:"request_key"`
	Action           string `json:"action"`
	Name             string `json:"name"`
	Status           string `json:"status"`
	RequiresApproval bool   `json:"requires_approval"`
	RequiresMFA      bool   `json:"requires_mfa"`
	AttributesJSON   string `json:"attributes_json"`
	SourceEventID    string `json:"source_event_id,omitempty"`
	PlanFingerprint  string `json:"plan_fingerprint"`
	LastSeenAt       string `json:"last_seen_at"`
	CreatedAt        string `json:"created_at"`
	UpdatedAt        string `json:"updated_at"`
}

type BroadbandGovernanceSelfServiceSummary struct {
	TotalEvents                int    `json:"total_events"`
	PreviewEvents              int    `json:"preview_events"`
	ApplyEvents                int    `json:"apply_events"`
	PreviewedCount             int    `json:"previewed_count"`
	AppliedCount               int    `json:"applied_count"`
	BlockedCount               int    `json:"blocked_count"`
	DegradedCount              int    `json:"degraded_count"`
	SkippedCount               int    `json:"skipped_count"`
	FailedCount                int    `json:"failed_count"`
	ActiveCaseCount            int    `json:"active_case_count"`
	PlannedCaseCount           int    `json:"planned_case_count"`
	ActiveSelfServiceRequests  int    `json:"active_self_service_requests"`
	PlannedSelfServiceRequests int    `json:"planned_self_service_requests"`
	LastEventAt                string `json:"last_event_at,omitempty"`
	LastFingerprint            string `json:"last_fingerprint,omitempty"`
	LastCaseCount              int    `json:"last_case_count"`
	LastSelfServiceActionCount int    `json:"last_self_service_action_count"`
	LastPrivacyPolicyCount     int    `json:"last_privacy_policy_count"`
	LastCompiledAttributeCount int    `json:"last_compiled_attribute_count"`
}

func RecordBroadbandGovernanceSelfServiceEvent(input BroadbandGovernanceSelfServiceEventInput) (string, error) {
	if DB == nil {
		return "", nil
	}
	input.Operation = normalizeBroadbandGovernanceOperation(input.Operation)
	input.Status = normalizeBroadbandGovernanceStatus(input.Status)
	input.EventID = strings.TrimSpace(input.EventID)
	if input.EventID == "" {
		input.EventID = newBroadbandGovernanceEventID(input)
	}
	if input.Operation == "" || input.Status == "" {
		return "", fmt.Errorf("broadband governance operation and status are required")
	}
	if strings.TrimSpace(input.PlanFingerprint) == "" {
		return "", fmt.Errorf("broadband governance plan fingerprint is required")
	}
	if strings.TrimSpace(input.SummaryJSON) == "" {
		input.SummaryJSON = "{}"
	}
	if strings.TrimSpace(input.ReportJSON) == "" {
		input.ReportJSON = "{}"
	}
	tx, err := DB.Begin()
	if err != nil {
		return "", fmt.Errorf("begin broadband governance event: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO broadband_governance_self_service_events (
			event_id, operation, status, plan_fingerprint, mode,
			case_count, self_service_action_count, privacy_policy_count, approval_policy_count,
			compiled_attribute_count, compliance_check_count, passed_check_count,
			warning_count, blocker_count, external_requirement_count,
			summary_json, report_json, actor, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(event_id) DO UPDATE SET
			operation = excluded.operation,
			status = excluded.status,
			plan_fingerprint = excluded.plan_fingerprint,
			mode = excluded.mode,
			case_count = excluded.case_count,
			self_service_action_count = excluded.self_service_action_count,
			privacy_policy_count = excluded.privacy_policy_count,
			approval_policy_count = excluded.approval_policy_count,
			compiled_attribute_count = excluded.compiled_attribute_count,
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
		nonNegativeInt(input.CaseCount),
		nonNegativeInt(input.SelfServiceActionCount),
		nonNegativeInt(input.PrivacyPolicyCount),
		nonNegativeInt(input.ApprovalPolicyCount),
		nonNegativeInt(input.CompiledAttributeCount),
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
		return "", fmt.Errorf("record broadband governance event: %w", err)
	}
	for _, item := range input.Cases {
		item.SourceEventID = firstNonEmptyString(item.SourceEventID, input.EventID)
		if err := upsertBroadbandGovernanceCase(tx, item); err != nil {
			return "", err
		}
	}
	for _, item := range input.Requests {
		item.SourceEventID = firstNonEmptyString(item.SourceEventID, input.EventID)
		if err := upsertBroadbandSelfServiceRequest(tx, item); err != nil {
			return "", err
		}
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit broadband governance event: %w", err)
	}
	return input.EventID, nil
}

func ListBroadbandGovernanceSelfServiceEvents(limit int) ([]BroadbandGovernanceSelfServiceEvent, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := DB.Query(broadbandGovernanceEventSelectSQL()+` ORDER BY datetime(created_at) DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list broadband governance events: %w", err)
	}
	defer rows.Close()
	var events []BroadbandGovernanceSelfServiceEvent
	for rows.Next() {
		event, err := scanBroadbandGovernanceEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func ListBroadbandGovernanceCases(limit int, status string) ([]BroadbandGovernanceCaseRecord, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	args := []any{}
	query := broadbandGovernanceCaseSelectSQL()
	if strings.TrimSpace(status) != "" {
		query += " WHERE status = ?"
		args = append(args, strings.ToLower(strings.TrimSpace(status)))
	}
	query += " ORDER BY datetime(last_seen_at) DESC, id DESC LIMIT ?"
	args = append(args, limit)
	rows, err := DB.Query(query, args...)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list broadband governance cases: %w", err)
	}
	defer rows.Close()
	var records []BroadbandGovernanceCaseRecord
	for rows.Next() {
		record, err := scanBroadbandGovernanceCase(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func ListBroadbandSelfServiceRequests(limit int, status string) ([]BroadbandSelfServiceRequestRecord, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	args := []any{}
	query := broadbandSelfServiceRequestSelectSQL()
	if strings.TrimSpace(status) != "" {
		query += " WHERE status = ?"
		args = append(args, strings.ToLower(strings.TrimSpace(status)))
	}
	query += " ORDER BY datetime(last_seen_at) DESC, id DESC LIMIT ?"
	args = append(args, limit)
	rows, err := DB.Query(query, args...)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list broadband self-service requests: %w", err)
	}
	defer rows.Close()
	var records []BroadbandSelfServiceRequestRecord
	for rows.Next() {
		record, err := scanBroadbandSelfServiceRequest(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func GetBroadbandGovernanceSelfServiceSummary() (BroadbandGovernanceSelfServiceSummary, error) {
	var summary BroadbandGovernanceSelfServiceSummary
	if DB == nil {
		return summary, nil
	}
	err := DB.QueryRow(`SELECT
		COALESCE(COUNT(*), 0),
		COALESCE(SUM(CASE WHEN operation = 'preview' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN operation = 'apply' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'previewed' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'applied' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'degraded' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'skipped' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END), 0),
		COALESCE(MAX(created_at), ''),
		COALESCE((SELECT plan_fingerprint FROM broadband_governance_self_service_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), ''),
		COALESCE((SELECT case_count FROM broadband_governance_self_service_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), 0),
		COALESCE((SELECT self_service_action_count FROM broadband_governance_self_service_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), 0),
		COALESCE((SELECT privacy_policy_count FROM broadband_governance_self_service_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), 0),
		COALESCE((SELECT compiled_attribute_count FROM broadband_governance_self_service_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), 0)
		FROM broadband_governance_self_service_events`).Scan(
		&summary.TotalEvents,
		&summary.PreviewEvents,
		&summary.ApplyEvents,
		&summary.PreviewedCount,
		&summary.AppliedCount,
		&summary.BlockedCount,
		&summary.DegradedCount,
		&summary.SkippedCount,
		&summary.FailedCount,
		&summary.LastEventAt,
		&summary.LastFingerprint,
		&summary.LastCaseCount,
		&summary.LastSelfServiceActionCount,
		&summary.LastPrivacyPolicyCount,
		&summary.LastCompiledAttributeCount,
	)
	if err != nil {
		if tableMissing(err) {
			return summary, nil
		}
		return summary, fmt.Errorf("summarize broadband governance events: %w", err)
	}
	_ = DB.QueryRow(`SELECT
		COALESCE(SUM(CASE WHEN status = 'ready' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'planned' THEN 1 ELSE 0 END), 0)
		FROM broadband_governance_cases`).Scan(&summary.ActiveCaseCount, &summary.PlannedCaseCount)
	_ = DB.QueryRow(`SELECT
		COALESCE(SUM(CASE WHEN status = 'ready' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'planned' THEN 1 ELSE 0 END), 0)
		FROM broadband_self_service_requests`).Scan(&summary.ActiveSelfServiceRequests, &summary.PlannedSelfServiceRequests)
	return summary, nil
}

func upsertBroadbandGovernanceCase(tx *sql.Tx, input BroadbandGovernanceCaseInput) error {
	key := strings.TrimSpace(input.CaseKey)
	if key == "" {
		key = strings.ToLower(firstNonEmptyString(input.CaseID, input.Name))
	}
	if key == "" {
		return nil
	}
	if strings.TrimSpace(input.AttributesJSON) == "" {
		input.AttributesJSON = "[]"
	}
	_, err := tx.Exec(`INSERT INTO broadband_governance_cases (
			case_key, name, case_id, legal_authority, request_reference,
			subscriber_id, username, tenant, scope, status, attributes_json,
			source_event_id, plan_fingerprint, last_seen_at, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT(case_key) DO UPDATE SET
			name = excluded.name,
			case_id = excluded.case_id,
			legal_authority = excluded.legal_authority,
			request_reference = excluded.request_reference,
			subscriber_id = excluded.subscriber_id,
			username = excluded.username,
			tenant = excluded.tenant,
			scope = excluded.scope,
			status = excluded.status,
			attributes_json = excluded.attributes_json,
			source_event_id = excluded.source_event_id,
			plan_fingerprint = excluded.plan_fingerprint,
			last_seen_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP`,
		key,
		nullString(strings.TrimSpace(input.Name)),
		nullString(strings.TrimSpace(input.CaseID)),
		nullString(strings.TrimSpace(input.LegalAuthority)),
		nullString(strings.TrimSpace(input.RequestReference)),
		nullString(strings.TrimSpace(input.SubscriberID)),
		nullString(strings.TrimSpace(input.Username)),
		nullString(strings.TrimSpace(input.Tenant)),
		nullString(strings.TrimSpace(input.Scope)),
		normalizeBroadbandGovernanceRecordStatus(input.Status),
		input.AttributesJSON,
		nullString(strings.TrimSpace(input.SourceEventID)),
		strings.TrimSpace(input.PlanFingerprint),
	)
	if err != nil {
		return fmt.Errorf("upsert broadband governance case %q: %w", key, err)
	}
	return nil
}

func upsertBroadbandSelfServiceRequest(tx *sql.Tx, input BroadbandSelfServiceRequestInput) error {
	key := strings.TrimSpace(input.RequestKey)
	if key == "" {
		key = strings.ToLower(firstNonEmptyString(input.Name, input.Action))
	}
	if key == "" {
		return nil
	}
	if strings.TrimSpace(input.AttributesJSON) == "" {
		input.AttributesJSON = "[]"
	}
	_, err := tx.Exec(`INSERT INTO broadband_self_service_requests (
			request_key, action, name, status, requires_approval, requires_mfa,
			attributes_json, source_event_id, plan_fingerprint, last_seen_at,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT(request_key) DO UPDATE SET
			action = excluded.action,
			name = excluded.name,
			status = excluded.status,
			requires_approval = excluded.requires_approval,
			requires_mfa = excluded.requires_mfa,
			attributes_json = excluded.attributes_json,
			source_event_id = excluded.source_event_id,
			plan_fingerprint = excluded.plan_fingerprint,
			last_seen_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP`,
		key,
		nullString(strings.TrimSpace(input.Action)),
		nullString(strings.TrimSpace(input.Name)),
		normalizeBroadbandGovernanceRecordStatus(input.Status),
		boolToInt(input.RequiresApproval),
		boolToInt(input.RequiresMFA),
		input.AttributesJSON,
		nullString(strings.TrimSpace(input.SourceEventID)),
		strings.TrimSpace(input.PlanFingerprint),
	)
	if err != nil {
		return fmt.Errorf("upsert broadband self-service request %q: %w", key, err)
	}
	return nil
}

func broadbandGovernanceEventSelectSQL() string {
	return `SELECT id, event_id, operation, status, plan_fingerprint, COALESCE(mode, ''),
		case_count, self_service_action_count, privacy_policy_count, approval_policy_count,
		compiled_attribute_count, compliance_check_count, passed_check_count, warning_count,
		blocker_count, external_requirement_count, summary_json, COALESCE(report_json, ''),
		COALESCE(actor, ''), COALESCE(CAST(created_at AS TEXT), '')
		FROM broadband_governance_self_service_events`
}

func scanBroadbandGovernanceEvent(scanner interface {
	Scan(dest ...any) error
}) (BroadbandGovernanceSelfServiceEvent, error) {
	var event BroadbandGovernanceSelfServiceEvent
	err := scanner.Scan(
		&event.ID,
		&event.EventID,
		&event.Operation,
		&event.Status,
		&event.PlanFingerprint,
		&event.Mode,
		&event.CaseCount,
		&event.SelfServiceActionCount,
		&event.PrivacyPolicyCount,
		&event.ApprovalPolicyCount,
		&event.CompiledAttributeCount,
		&event.ComplianceCheckCount,
		&event.PassedCheckCount,
		&event.WarningCount,
		&event.BlockerCount,
		&event.ExternalRequirementCount,
		&event.SummaryJSON,
		&event.ReportJSON,
		&event.Actor,
		&event.CreatedAt,
	)
	return event, err
}

func broadbandGovernanceCaseSelectSQL() string {
	return `SELECT id, case_key, COALESCE(name, ''), COALESCE(case_id, ''),
		COALESCE(subscriber_id, ''), COALESCE(username, ''), COALESCE(tenant, ''),
		COALESCE(scope, ''), status, attributes_json, COALESCE(source_event_id, ''),
		plan_fingerprint, COALESCE(CAST(last_seen_at AS TEXT), ''),
		COALESCE(CAST(created_at AS TEXT), ''), COALESCE(CAST(updated_at AS TEXT), '')
		FROM broadband_governance_cases`
}

func scanBroadbandGovernanceCase(scanner interface {
	Scan(dest ...any) error
}) (BroadbandGovernanceCaseRecord, error) {
	var record BroadbandGovernanceCaseRecord
	err := scanner.Scan(
		&record.ID,
		&record.CaseKey,
		&record.Name,
		&record.CaseID,
		&record.SubscriberID,
		&record.Username,
		&record.Tenant,
		&record.Scope,
		&record.Status,
		&record.AttributesJSON,
		&record.SourceEventID,
		&record.PlanFingerprint,
		&record.LastSeenAt,
		&record.CreatedAt,
		&record.UpdatedAt,
	)
	return record, err
}

func broadbandSelfServiceRequestSelectSQL() string {
	return `SELECT id, request_key, COALESCE(action, ''), COALESCE(name, ''),
		status, requires_approval, requires_mfa, attributes_json,
		COALESCE(source_event_id, ''), plan_fingerprint,
		COALESCE(CAST(last_seen_at AS TEXT), ''),
		COALESCE(CAST(created_at AS TEXT), ''), COALESCE(CAST(updated_at AS TEXT), '')
		FROM broadband_self_service_requests`
}

func scanBroadbandSelfServiceRequest(scanner interface {
	Scan(dest ...any) error
}) (BroadbandSelfServiceRequestRecord, error) {
	var record BroadbandSelfServiceRequestRecord
	var requiresApproval, requiresMFA int
	err := scanner.Scan(
		&record.ID,
		&record.RequestKey,
		&record.Action,
		&record.Name,
		&record.Status,
		&requiresApproval,
		&requiresMFA,
		&record.AttributesJSON,
		&record.SourceEventID,
		&record.PlanFingerprint,
		&record.LastSeenAt,
		&record.CreatedAt,
		&record.UpdatedAt,
	)
	record.RequiresApproval = requiresApproval != 0
	record.RequiresMFA = requiresMFA != 0
	return record, err
}

func normalizeBroadbandGovernanceOperation(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "preview", "apply":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeBroadbandGovernanceStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "previewed", "applied", "blocked", "degraded", "skipped", "failed":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "previewed"
	}
}

func normalizeBroadbandGovernanceRecordStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "ready", "planned", "blocked", "degraded", "withdrawn":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "planned"
	}
}

func newBroadbandGovernanceEventID(input BroadbandGovernanceSelfServiceEventInput) string {
	var entropy [8]byte
	_, _ = rand.Read(entropy[:])
	sum := sha256.Sum256([]byte(strings.Join([]string{
		input.Operation,
		input.Status,
		input.PlanFingerprint,
		input.Actor,
		hex.EncodeToString(entropy[:]),
	}, "|")))
	return "bng-governance-" + input.Operation + "-" + hex.EncodeToString(sum[:8])
}
