package db

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
)

type MobilePolicyControlEventInput struct {
	EventID                  string
	Operation                string
	Status                   string
	PlanFingerprint          string
	Mode                     string
	PolicyProfileCount       int
	QoSClassCount            int
	RoamingPolicyCount       int
	FeedbackRuleCount        int
	PolicyAttributeCount     int
	ComplianceCheckCount     int
	PassedCheckCount         int
	WarningCount             int
	BlockerCount             int
	ExternalRequirementCount int
	SummaryJSON              string
	ReportJSON               string
	Actor                    string
	Profiles                 []MobilePolicyControlProfileInput
}

type MobilePolicyControlProfileInput struct {
	ProfileKey      string
	ProfileType     string
	Name            string
	Status          string
	QoSClass        string
	RoamingPolicy   string
	TriggerName     string
	AttributesJSON  string
	SourceEventID   string
	PlanFingerprint string
}

type MobilePolicyControlEvent struct {
	ID                       int    `json:"id"`
	EventID                  string `json:"event_id"`
	Operation                string `json:"operation"`
	Status                   string `json:"status"`
	PlanFingerprint          string `json:"plan_fingerprint"`
	Mode                     string `json:"mode,omitempty"`
	PolicyProfileCount       int    `json:"policy_profile_count"`
	QoSClassCount            int    `json:"qos_class_count"`
	RoamingPolicyCount       int    `json:"roaming_policy_count"`
	FeedbackRuleCount        int    `json:"feedback_rule_count"`
	PolicyAttributeCount     int    `json:"policy_attribute_count"`
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

type MobilePolicyControlProfileRecord struct {
	ID              int    `json:"id"`
	ProfileKey      string `json:"profile_key"`
	ProfileType     string `json:"profile_type"`
	Name            string `json:"name"`
	Status          string `json:"status"`
	QoSClass        string `json:"qos_class,omitempty"`
	RoamingPolicy   string `json:"roaming_policy,omitempty"`
	TriggerName     string `json:"trigger_name,omitempty"`
	AttributesJSON  string `json:"attributes_json"`
	SourceEventID   string `json:"source_event_id,omitempty"`
	PlanFingerprint string `json:"plan_fingerprint"`
	LastSeenAt      string `json:"last_seen_at"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}

type MobilePolicyControlSummary struct {
	TotalEvents                  int    `json:"total_events"`
	PreviewEvents                int    `json:"preview_events"`
	ApplyEvents                  int    `json:"apply_events"`
	PreviewedCount               int    `json:"previewed_count"`
	AppliedCount                 int    `json:"applied_count"`
	BlockedCount                 int    `json:"blocked_count"`
	DegradedCount                int    `json:"degraded_count"`
	SkippedCount                 int    `json:"skipped_count"`
	FailedCount                  int    `json:"failed_count"`
	ReconciledCount              int    `json:"reconciled_count"`
	ReadyProfileCount            int    `json:"ready_profile_count"`
	PlannedProfileCount          int    `json:"planned_profile_count"`
	LastEventAt                  string `json:"last_event_at,omitempty"`
	LastFingerprint              string `json:"last_fingerprint,omitempty"`
	LastPolicyProfileCount       int    `json:"last_policy_profile_count"`
	LastQoSClassCount            int    `json:"last_qos_class_count"`
	LastRoamingPolicyCount       int    `json:"last_roaming_policy_count"`
	LastFeedbackRuleCount        int    `json:"last_feedback_rule_count"`
	LastPolicyAttributeCount     int    `json:"last_policy_attribute_count"`
	LastComplianceCheckCount     int    `json:"last_compliance_check_count"`
	LastExternalRequirementCount int    `json:"last_external_requirement_count"`
}

func RecordMobilePolicyControlEvent(input MobilePolicyControlEventInput) (string, error) {
	if DB == nil {
		return "", nil
	}
	input.Operation = normalizeMobilePolicyControlOperation(input.Operation)
	input.Status = normalizeMobilePolicyControlStatus(input.Status)
	input.EventID = strings.TrimSpace(input.EventID)
	if input.EventID == "" {
		input.EventID = newMobilePolicyControlEventID(input)
	}
	if input.Operation == "" || input.Status == "" {
		return "", fmt.Errorf("mobile policy control operation and status are required")
	}
	if strings.TrimSpace(input.PlanFingerprint) == "" {
		return "", fmt.Errorf("mobile policy control plan fingerprint is required")
	}
	if strings.TrimSpace(input.SummaryJSON) == "" {
		input.SummaryJSON = "{}"
	}
	if strings.TrimSpace(input.ReportJSON) == "" {
		input.ReportJSON = "{}"
	}
	tx, err := DB.Begin()
	if err != nil {
		return "", fmt.Errorf("begin mobile policy control event: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO mobile_policy_control_events (
			event_id, operation, status, plan_fingerprint, mode,
			policy_profile_count, qos_class_count, roaming_policy_count, feedback_rule_count,
			policy_attribute_count, compliance_check_count, passed_check_count, warning_count,
			blocker_count, external_requirement_count, summary_json, report_json, actor, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(event_id) DO UPDATE SET
			operation = excluded.operation,
			status = excluded.status,
			plan_fingerprint = excluded.plan_fingerprint,
			mode = excluded.mode,
			policy_profile_count = excluded.policy_profile_count,
			qos_class_count = excluded.qos_class_count,
			roaming_policy_count = excluded.roaming_policy_count,
			feedback_rule_count = excluded.feedback_rule_count,
			policy_attribute_count = excluded.policy_attribute_count,
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
		nonNegativeInt(input.PolicyProfileCount),
		nonNegativeInt(input.QoSClassCount),
		nonNegativeInt(input.RoamingPolicyCount),
		nonNegativeInt(input.FeedbackRuleCount),
		nonNegativeInt(input.PolicyAttributeCount),
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
		return "", fmt.Errorf("record mobile policy control event: %w", err)
	}
	for _, item := range input.Profiles {
		item.SourceEventID = firstNonEmptyString(item.SourceEventID, input.EventID)
		if err := upsertMobilePolicyControlProfile(tx, item); err != nil {
			return "", err
		}
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit mobile policy control event: %w", err)
	}
	return input.EventID, nil
}

func ListMobilePolicyControlEvents(limit int) ([]MobilePolicyControlEvent, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := DB.Query(mobilePolicyControlEventSelectSQL()+` ORDER BY datetime(created_at) DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list mobile policy control events: %w", err)
	}
	defer rows.Close()
	var events []MobilePolicyControlEvent
	for rows.Next() {
		event, err := scanMobilePolicyControlEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func ListMobilePolicyControlProfiles(limit int, profileType string) ([]MobilePolicyControlProfileRecord, error) {
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
	query := mobilePolicyControlProfileSelectSQL()
	if strings.TrimSpace(profileType) != "" {
		query += " WHERE profile_type = ?"
		args = append(args, normalizeMobilePolicyControlProfileType(profileType))
	}
	query += " ORDER BY datetime(last_seen_at) DESC, id DESC LIMIT ?"
	args = append(args, limit)
	rows, err := DB.Query(query, args...)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list mobile policy control profiles: %w", err)
	}
	defer rows.Close()
	var records []MobilePolicyControlProfileRecord
	for rows.Next() {
		record, err := scanMobilePolicyControlProfile(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func GetMobilePolicyControlSummary() (MobilePolicyControlSummary, error) {
	var summary MobilePolicyControlSummary
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
		COALESCE(SUM(CASE WHEN status = 'reconciled' THEN 1 ELSE 0 END), 0),
		COALESCE(MAX(created_at), ''),
		COALESCE((SELECT plan_fingerprint FROM mobile_policy_control_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), ''),
		COALESCE((SELECT policy_profile_count FROM mobile_policy_control_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), 0),
		COALESCE((SELECT qos_class_count FROM mobile_policy_control_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), 0),
		COALESCE((SELECT roaming_policy_count FROM mobile_policy_control_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), 0),
		COALESCE((SELECT feedback_rule_count FROM mobile_policy_control_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), 0),
		COALESCE((SELECT policy_attribute_count FROM mobile_policy_control_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), 0),
		COALESCE((SELECT compliance_check_count FROM mobile_policy_control_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), 0),
		COALESCE((SELECT external_requirement_count FROM mobile_policy_control_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), 0)
		FROM mobile_policy_control_events`).Scan(
		&summary.TotalEvents,
		&summary.PreviewEvents,
		&summary.ApplyEvents,
		&summary.PreviewedCount,
		&summary.AppliedCount,
		&summary.BlockedCount,
		&summary.DegradedCount,
		&summary.SkippedCount,
		&summary.FailedCount,
		&summary.ReconciledCount,
		&summary.LastEventAt,
		&summary.LastFingerprint,
		&summary.LastPolicyProfileCount,
		&summary.LastQoSClassCount,
		&summary.LastRoamingPolicyCount,
		&summary.LastFeedbackRuleCount,
		&summary.LastPolicyAttributeCount,
		&summary.LastComplianceCheckCount,
		&summary.LastExternalRequirementCount,
	)
	if err != nil {
		if tableMissing(err) {
			return summary, nil
		}
		return summary, fmt.Errorf("summarize mobile policy control events: %w", err)
	}
	_ = DB.QueryRow(`SELECT
		COALESCE(SUM(CASE WHEN status = 'ready' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'planned' THEN 1 ELSE 0 END), 0)
		FROM mobile_policy_control_profiles`).Scan(&summary.ReadyProfileCount, &summary.PlannedProfileCount)
	return summary, nil
}

func upsertMobilePolicyControlProfile(tx *sql.Tx, input MobilePolicyControlProfileInput) error {
	key := strings.ToLower(strings.TrimSpace(input.ProfileKey))
	if key == "" {
		key = strings.ToLower(strings.TrimSpace(input.Name))
	}
	if key == "" {
		return nil
	}
	profileType := normalizeMobilePolicyControlProfileType(input.ProfileType)
	if profileType == "" {
		return fmt.Errorf("mobile policy control profile type is required")
	}
	if strings.TrimSpace(input.AttributesJSON) == "" {
		input.AttributesJSON = "{}"
	}
	_, err := tx.Exec(`INSERT INTO mobile_policy_control_profiles (
			profile_key, profile_type, name, status, qos_class, roaming_policy, trigger_name,
			attributes_json, source_event_id, plan_fingerprint, last_seen_at, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT(profile_type, profile_key) DO UPDATE SET
			name = excluded.name,
			status = excluded.status,
			qos_class = excluded.qos_class,
			roaming_policy = excluded.roaming_policy,
			trigger_name = excluded.trigger_name,
			attributes_json = excluded.attributes_json,
			source_event_id = excluded.source_event_id,
			plan_fingerprint = excluded.plan_fingerprint,
			last_seen_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP`,
		key,
		profileType,
		strings.TrimSpace(input.Name),
		normalizeMobilePolicyControlRecordStatus(input.Status),
		nullString(strings.TrimSpace(input.QoSClass)),
		nullString(strings.TrimSpace(input.RoamingPolicy)),
		nullString(strings.TrimSpace(input.TriggerName)),
		input.AttributesJSON,
		nullString(strings.TrimSpace(input.SourceEventID)),
		strings.TrimSpace(input.PlanFingerprint),
	)
	if err != nil {
		return fmt.Errorf("upsert mobile policy control profile %q/%q: %w", profileType, key, err)
	}
	return nil
}

func mobilePolicyControlEventSelectSQL() string {
	return `SELECT id, event_id, operation, status, plan_fingerprint, COALESCE(mode, ''),
		policy_profile_count, qos_class_count, roaming_policy_count, feedback_rule_count,
		policy_attribute_count, compliance_check_count, passed_check_count, warning_count,
		blocker_count, external_requirement_count, summary_json, COALESCE(report_json, ''),
		COALESCE(actor, ''), COALESCE(CAST(created_at AS TEXT), '')
		FROM mobile_policy_control_events`
}

func scanMobilePolicyControlEvent(scanner interface {
	Scan(dest ...any) error
}) (MobilePolicyControlEvent, error) {
	var event MobilePolicyControlEvent
	err := scanner.Scan(
		&event.ID,
		&event.EventID,
		&event.Operation,
		&event.Status,
		&event.PlanFingerprint,
		&event.Mode,
		&event.PolicyProfileCount,
		&event.QoSClassCount,
		&event.RoamingPolicyCount,
		&event.FeedbackRuleCount,
		&event.PolicyAttributeCount,
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

func mobilePolicyControlProfileSelectSQL() string {
	return `SELECT id, profile_key, profile_type, name, status, COALESCE(qos_class, ''),
		COALESCE(roaming_policy, ''), COALESCE(trigger_name, ''), attributes_json,
		COALESCE(source_event_id, ''), plan_fingerprint,
		COALESCE(CAST(last_seen_at AS TEXT), ''),
		COALESCE(CAST(created_at AS TEXT), ''),
		COALESCE(CAST(updated_at AS TEXT), '')
		FROM mobile_policy_control_profiles`
}

func scanMobilePolicyControlProfile(scanner interface {
	Scan(dest ...any) error
}) (MobilePolicyControlProfileRecord, error) {
	var record MobilePolicyControlProfileRecord
	err := scanner.Scan(
		&record.ID,
		&record.ProfileKey,
		&record.ProfileType,
		&record.Name,
		&record.Status,
		&record.QoSClass,
		&record.RoamingPolicy,
		&record.TriggerName,
		&record.AttributesJSON,
		&record.SourceEventID,
		&record.PlanFingerprint,
		&record.LastSeenAt,
		&record.CreatedAt,
		&record.UpdatedAt,
	)
	return record, err
}

func normalizeMobilePolicyControlOperation(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "preview", "apply", "status", "reconcile":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeMobilePolicyControlStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "previewed", "applied", "blocked", "degraded", "skipped", "failed", "reconciled":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeMobilePolicyControlRecordStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "ready", "planned", "blocked", "degraded", "withdrawn":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "planned"
	}
}

func normalizeMobilePolicyControlProfileType(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "policy_profile", "qos_class", "roaming_policy", "feedback_rule":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func newMobilePolicyControlEventID(input MobilePolicyControlEventInput) string {
	var nonce [8]byte
	_, _ = rand.Read(nonce[:])
	hash := sha256.Sum256([]byte(strings.Join([]string{
		input.Operation,
		input.Status,
		input.PlanFingerprint,
		input.Mode,
		hex.EncodeToString(nonce[:]),
	}, "|")))
	return "mobile-policy-" + hex.EncodeToString(hash[:8])
}
