package db

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
)

type WiMAXServiceFlowEventInput struct {
	EventID                  string
	Operation                string
	Status                   string
	PlanFingerprint          string
	Mode                     string
	SubscriberProfileCount   int
	ServiceFlowCount         int
	ASNProfileCount          int
	MobilityPolicyCount      int
	RadiusAttributeCount     int
	ComplianceCheckCount     int
	PassedCheckCount         int
	WarningCount             int
	BlockerCount             int
	ExternalRequirementCount int
	SummaryJSON              string
	ReportJSON               string
	Actor                    string
	Profiles                 []WiMAXServiceFlowProfileInput
}

type WiMAXServiceFlowProfileInput struct {
	ProfileKey      string
	ProfileType     string
	Name            string
	Status          string
	ServiceFlowID   int
	ServiceClass    string
	ASNProfile      string
	MobilityMode    string
	AttributesJSON  string
	SourceEventID   string
	PlanFingerprint string
}

type WiMAXServiceFlowEvent struct {
	ID                       int    `json:"id"`
	EventID                  string `json:"event_id"`
	Operation                string `json:"operation"`
	Status                   string `json:"status"`
	PlanFingerprint          string `json:"plan_fingerprint"`
	Mode                     string `json:"mode,omitempty"`
	SubscriberProfileCount   int    `json:"subscriber_profile_count"`
	ServiceFlowCount         int    `json:"service_flow_count"`
	ASNProfileCount          int    `json:"asn_profile_count"`
	MobilityPolicyCount      int    `json:"mobility_policy_count"`
	RadiusAttributeCount     int    `json:"radius_attribute_count"`
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

type WiMAXServiceFlowProfileRecord struct {
	ID              int    `json:"id"`
	ProfileKey      string `json:"profile_key"`
	ProfileType     string `json:"profile_type"`
	Name            string `json:"name"`
	Status          string `json:"status"`
	ServiceFlowID   int    `json:"service_flow_id,omitempty"`
	ServiceClass    string `json:"service_class,omitempty"`
	ASNProfile      string `json:"asn_profile,omitempty"`
	MobilityMode    string `json:"mobility_mode,omitempty"`
	AttributesJSON  string `json:"attributes_json"`
	SourceEventID   string `json:"source_event_id,omitempty"`
	PlanFingerprint string `json:"plan_fingerprint"`
	LastSeenAt      string `json:"last_seen_at"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}

type WiMAXServiceFlowSummary struct {
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
	LastSubscriberProfileCount   int    `json:"last_subscriber_profile_count"`
	LastServiceFlowCount         int    `json:"last_service_flow_count"`
	LastASNProfileCount          int    `json:"last_asn_profile_count"`
	LastMobilityPolicyCount      int    `json:"last_mobility_policy_count"`
	LastRadiusAttributeCount     int    `json:"last_radius_attribute_count"`
	LastComplianceCheckCount     int    `json:"last_compliance_check_count"`
	LastExternalRequirementCount int    `json:"last_external_requirement_count"`
}

func RecordWiMAXServiceFlowEvent(input WiMAXServiceFlowEventInput) (string, error) {
	if DB == nil {
		return "", nil
	}
	input.Operation = normalizeWiMAXServiceFlowOperation(input.Operation)
	input.Status = normalizeWiMAXServiceFlowStatus(input.Status)
	input.EventID = strings.TrimSpace(input.EventID)
	if input.EventID == "" {
		input.EventID = newWiMAXServiceFlowEventID(input)
	}
	if input.Operation == "" || input.Status == "" {
		return "", fmt.Errorf("wimax service flow operation and status are required")
	}
	if strings.TrimSpace(input.PlanFingerprint) == "" {
		return "", fmt.Errorf("wimax service flow plan fingerprint is required")
	}
	if strings.TrimSpace(input.SummaryJSON) == "" {
		input.SummaryJSON = "{}"
	}
	if strings.TrimSpace(input.ReportJSON) == "" {
		input.ReportJSON = "{}"
	}
	tx, err := DB.Begin()
	if err != nil {
		return "", fmt.Errorf("begin wimax service flow event: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO wimax_service_flow_events (
			event_id, operation, status, plan_fingerprint, mode,
			subscriber_profile_count, service_flow_count, asn_profile_count, mobility_policy_count,
			radius_attribute_count, compliance_check_count, passed_check_count, warning_count,
			blocker_count, external_requirement_count, summary_json, report_json, actor, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(event_id) DO UPDATE SET
			operation = excluded.operation,
			status = excluded.status,
			plan_fingerprint = excluded.plan_fingerprint,
			mode = excluded.mode,
			subscriber_profile_count = excluded.subscriber_profile_count,
			service_flow_count = excluded.service_flow_count,
			asn_profile_count = excluded.asn_profile_count,
			mobility_policy_count = excluded.mobility_policy_count,
			radius_attribute_count = excluded.radius_attribute_count,
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
		nonNegativeInt(input.SubscriberProfileCount),
		nonNegativeInt(input.ServiceFlowCount),
		nonNegativeInt(input.ASNProfileCount),
		nonNegativeInt(input.MobilityPolicyCount),
		nonNegativeInt(input.RadiusAttributeCount),
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
		return "", fmt.Errorf("record wimax service flow event: %w", err)
	}
	for _, item := range input.Profiles {
		item.SourceEventID = firstNonEmptyString(item.SourceEventID, input.EventID)
		if err := upsertWiMAXServiceFlowProfile(tx, item); err != nil {
			return "", err
		}
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit wimax service flow event: %w", err)
	}
	return input.EventID, nil
}

func ListWiMAXServiceFlowEvents(limit int) ([]WiMAXServiceFlowEvent, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := DB.Query(wimaxServiceFlowEventSelectSQL()+` ORDER BY datetime(created_at) DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list wimax service flow events: %w", err)
	}
	defer rows.Close()
	var events []WiMAXServiceFlowEvent
	for rows.Next() {
		event, err := scanWiMAXServiceFlowEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func ListWiMAXServiceFlowProfiles(limit int, profileType string) ([]WiMAXServiceFlowProfileRecord, error) {
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
	query := wimaxServiceFlowProfileSelectSQL()
	if strings.TrimSpace(profileType) != "" {
		query += " WHERE profile_type = ?"
		args = append(args, normalizeWiMAXServiceFlowProfileType(profileType))
	}
	query += " ORDER BY datetime(last_seen_at) DESC, id DESC LIMIT ?"
	args = append(args, limit)
	rows, err := DB.Query(query, args...)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list wimax service flow profiles: %w", err)
	}
	defer rows.Close()
	var records []WiMAXServiceFlowProfileRecord
	for rows.Next() {
		record, err := scanWiMAXServiceFlowProfile(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func GetWiMAXServiceFlowSummary() (WiMAXServiceFlowSummary, error) {
	var summary WiMAXServiceFlowSummary
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
		COALESCE((SELECT plan_fingerprint FROM wimax_service_flow_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), ''),
		COALESCE((SELECT subscriber_profile_count FROM wimax_service_flow_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), 0),
		COALESCE((SELECT service_flow_count FROM wimax_service_flow_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), 0),
		COALESCE((SELECT asn_profile_count FROM wimax_service_flow_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), 0),
		COALESCE((SELECT mobility_policy_count FROM wimax_service_flow_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), 0),
		COALESCE((SELECT radius_attribute_count FROM wimax_service_flow_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), 0),
		COALESCE((SELECT compliance_check_count FROM wimax_service_flow_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), 0),
		COALESCE((SELECT external_requirement_count FROM wimax_service_flow_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), 0)
		FROM wimax_service_flow_events`).Scan(
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
		&summary.LastSubscriberProfileCount,
		&summary.LastServiceFlowCount,
		&summary.LastASNProfileCount,
		&summary.LastMobilityPolicyCount,
		&summary.LastRadiusAttributeCount,
		&summary.LastComplianceCheckCount,
		&summary.LastExternalRequirementCount,
	)
	if err != nil {
		if tableMissing(err) {
			return summary, nil
		}
		return summary, fmt.Errorf("summarize wimax service flow events: %w", err)
	}
	_ = DB.QueryRow(`SELECT
		COALESCE(SUM(CASE WHEN status = 'ready' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'planned' THEN 1 ELSE 0 END), 0)
		FROM wimax_service_flow_profiles`).Scan(&summary.ReadyProfileCount, &summary.PlannedProfileCount)
	return summary, nil
}

func upsertWiMAXServiceFlowProfile(tx *sql.Tx, input WiMAXServiceFlowProfileInput) error {
	key := strings.ToLower(strings.TrimSpace(input.ProfileKey))
	if key == "" {
		key = strings.ToLower(strings.TrimSpace(input.Name))
	}
	if key == "" {
		return nil
	}
	profileType := normalizeWiMAXServiceFlowProfileType(input.ProfileType)
	if profileType == "" {
		return fmt.Errorf("wimax service flow profile type is required")
	}
	if strings.TrimSpace(input.AttributesJSON) == "" {
		input.AttributesJSON = "{}"
	}
	_, err := tx.Exec(`INSERT INTO wimax_service_flow_profiles (
			profile_key, profile_type, name, status, service_flow_id, service_class, asn_profile, mobility_mode,
			attributes_json, source_event_id, plan_fingerprint, last_seen_at, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT(profile_type, profile_key) DO UPDATE SET
			name = excluded.name,
			status = excluded.status,
			service_flow_id = excluded.service_flow_id,
			service_class = excluded.service_class,
			asn_profile = excluded.asn_profile,
			mobility_mode = excluded.mobility_mode,
			attributes_json = excluded.attributes_json,
			source_event_id = excluded.source_event_id,
			plan_fingerprint = excluded.plan_fingerprint,
			last_seen_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP`,
		key,
		profileType,
		strings.TrimSpace(input.Name),
		normalizeWiMAXServiceFlowRecordStatus(input.Status),
		nonNegativeInt(input.ServiceFlowID),
		nullString(strings.TrimSpace(input.ServiceClass)),
		nullString(strings.TrimSpace(input.ASNProfile)),
		nullString(strings.TrimSpace(input.MobilityMode)),
		input.AttributesJSON,
		nullString(strings.TrimSpace(input.SourceEventID)),
		strings.TrimSpace(input.PlanFingerprint),
	)
	if err != nil {
		return fmt.Errorf("upsert wimax service flow profile %q/%q: %w", profileType, key, err)
	}
	return nil
}

func wimaxServiceFlowEventSelectSQL() string {
	return `SELECT id, event_id, operation, status, plan_fingerprint, COALESCE(mode, ''),
		subscriber_profile_count, service_flow_count, asn_profile_count, mobility_policy_count,
		radius_attribute_count, compliance_check_count, passed_check_count, warning_count,
		blocker_count, external_requirement_count, summary_json, COALESCE(report_json, ''),
		COALESCE(actor, ''), COALESCE(CAST(created_at AS TEXT), '')
		FROM wimax_service_flow_events`
}

func scanWiMAXServiceFlowEvent(scanner interface {
	Scan(dest ...any) error
}) (WiMAXServiceFlowEvent, error) {
	var event WiMAXServiceFlowEvent
	err := scanner.Scan(
		&event.ID,
		&event.EventID,
		&event.Operation,
		&event.Status,
		&event.PlanFingerprint,
		&event.Mode,
		&event.SubscriberProfileCount,
		&event.ServiceFlowCount,
		&event.ASNProfileCount,
		&event.MobilityPolicyCount,
		&event.RadiusAttributeCount,
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

func wimaxServiceFlowProfileSelectSQL() string {
	return `SELECT id, profile_key, profile_type, name, status, service_flow_id,
		COALESCE(service_class, ''), COALESCE(asn_profile, ''), COALESCE(mobility_mode, ''),
		attributes_json, COALESCE(source_event_id, ''), plan_fingerprint,
		COALESCE(CAST(last_seen_at AS TEXT), ''),
		COALESCE(CAST(created_at AS TEXT), ''),
		COALESCE(CAST(updated_at AS TEXT), '')
		FROM wimax_service_flow_profiles`
}

func scanWiMAXServiceFlowProfile(scanner interface {
	Scan(dest ...any) error
}) (WiMAXServiceFlowProfileRecord, error) {
	var record WiMAXServiceFlowProfileRecord
	err := scanner.Scan(
		&record.ID,
		&record.ProfileKey,
		&record.ProfileType,
		&record.Name,
		&record.Status,
		&record.ServiceFlowID,
		&record.ServiceClass,
		&record.ASNProfile,
		&record.MobilityMode,
		&record.AttributesJSON,
		&record.SourceEventID,
		&record.PlanFingerprint,
		&record.LastSeenAt,
		&record.CreatedAt,
		&record.UpdatedAt,
	)
	return record, err
}

func normalizeWiMAXServiceFlowOperation(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "preview", "apply", "status", "reconcile":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeWiMAXServiceFlowStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "previewed", "applied", "blocked", "degraded", "skipped", "failed", "reconciled":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeWiMAXServiceFlowRecordStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "ready", "planned", "blocked", "degraded", "withdrawn":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "planned"
	}
}

func normalizeWiMAXServiceFlowProfileType(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "subscriber_profile", "service_flow", "asn_profile", "mobility_policy":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func newWiMAXServiceFlowEventID(input WiMAXServiceFlowEventInput) string {
	var nonce [8]byte
	_, _ = rand.Read(nonce[:])
	hash := sha256.Sum256([]byte(strings.Join([]string{
		input.Operation,
		input.Status,
		input.PlanFingerprint,
		input.Mode,
		hex.EncodeToString(nonce[:]),
	}, "|")))
	return "wimax-flow-" + hex.EncodeToString(hash[:8])
}
