package db

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
)

type DOCSISPolicyEventInput struct {
	EventID                  string
	Operation                string
	Status                   string
	PlanFingerprint          string
	Mode                     string
	ModemProfileCount        int
	ServiceFlowCount         int
	CMTSProfileCount         int
	ChargingPolicyCount      int
	RadiusAttributeCount     int
	ComplianceCheckCount     int
	PassedCheckCount         int
	WarningCount             int
	BlockerCount             int
	ExternalRequirementCount int
	SummaryJSON              string
	ReportJSON               string
	Actor                    string
	Profiles                 []DOCSISPolicyProfileInput
}

type DOCSISPolicyProfileInput struct {
	ProfileKey      string
	ProfileType     string
	Name            string
	Status          string
	ServiceFlowID   int
	ServiceClass    string
	CMTSProfile     string
	ChargingPolicy  string
	AttributesJSON  string
	SourceEventID   string
	PlanFingerprint string
}

type DOCSISPolicyEvent struct {
	ID                       int    `json:"id"`
	EventID                  string `json:"event_id"`
	Operation                string `json:"operation"`
	Status                   string `json:"status"`
	PlanFingerprint          string `json:"plan_fingerprint"`
	Mode                     string `json:"mode,omitempty"`
	ModemProfileCount        int    `json:"modem_profile_count"`
	ServiceFlowCount         int    `json:"service_flow_count"`
	CMTSProfileCount         int    `json:"cmts_profile_count"`
	ChargingPolicyCount      int    `json:"charging_policy_count"`
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

type DOCSISPolicyProfileRecord struct {
	ID              int    `json:"id"`
	ProfileKey      string `json:"profile_key"`
	ProfileType     string `json:"profile_type"`
	Name            string `json:"name"`
	Status          string `json:"status"`
	ServiceFlowID   int    `json:"service_flow_id,omitempty"`
	ServiceClass    string `json:"service_class,omitempty"`
	CMTSProfile     string `json:"cmts_profile,omitempty"`
	ChargingPolicy  string `json:"charging_policy,omitempty"`
	AttributesJSON  string `json:"attributes_json"`
	SourceEventID   string `json:"source_event_id,omitempty"`
	PlanFingerprint string `json:"plan_fingerprint"`
	LastSeenAt      string `json:"last_seen_at"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}

type DOCSISPolicySummary struct {
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
	LastModemProfileCount        int    `json:"last_modem_profile_count"`
	LastServiceFlowCount         int    `json:"last_service_flow_count"`
	LastCMTSProfileCount         int    `json:"last_cmts_profile_count"`
	LastChargingPolicyCount      int    `json:"last_charging_policy_count"`
	LastRadiusAttributeCount     int    `json:"last_radius_attribute_count"`
	LastComplianceCheckCount     int    `json:"last_compliance_check_count"`
	LastExternalRequirementCount int    `json:"last_external_requirement_count"`
}

func RecordDOCSISPolicyEvent(input DOCSISPolicyEventInput) (string, error) {
	if DB == nil {
		return "", nil
	}
	input.Operation = normalizeDOCSISPolicyOperation(input.Operation)
	input.Status = normalizeDOCSISPolicyStatus(input.Status)
	input.EventID = strings.TrimSpace(input.EventID)
	if input.EventID == "" {
		input.EventID = newDOCSISPolicyEventID(input)
	}
	if input.Operation == "" || input.Status == "" {
		return "", fmt.Errorf("docsis policy operation and status are required")
	}
	if strings.TrimSpace(input.PlanFingerprint) == "" {
		return "", fmt.Errorf("docsis policy plan fingerprint is required")
	}
	if strings.TrimSpace(input.SummaryJSON) == "" {
		input.SummaryJSON = "{}"
	}
	if strings.TrimSpace(input.ReportJSON) == "" {
		input.ReportJSON = "{}"
	}
	tx, err := DB.Begin()
	if err != nil {
		return "", fmt.Errorf("begin docsis policy event: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO docsis_policy_events (
			event_id, operation, status, plan_fingerprint, mode,
			modem_profile_count, service_flow_count, cmts_profile_count, charging_policy_count,
			radius_attribute_count, compliance_check_count, passed_check_count, warning_count,
			blocker_count, external_requirement_count, summary_json, report_json, actor, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(event_id) DO UPDATE SET
			operation = excluded.operation,
			status = excluded.status,
			plan_fingerprint = excluded.plan_fingerprint,
			mode = excluded.mode,
			modem_profile_count = excluded.modem_profile_count,
			service_flow_count = excluded.service_flow_count,
			cmts_profile_count = excluded.cmts_profile_count,
			charging_policy_count = excluded.charging_policy_count,
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
		nonNegativeInt(input.ModemProfileCount),
		nonNegativeInt(input.ServiceFlowCount),
		nonNegativeInt(input.CMTSProfileCount),
		nonNegativeInt(input.ChargingPolicyCount),
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
		return "", fmt.Errorf("record docsis policy event: %w", err)
	}
	for _, item := range input.Profiles {
		item.SourceEventID = firstNonEmptyString(item.SourceEventID, input.EventID)
		if err := upsertDOCSISPolicyProfile(tx, item); err != nil {
			return "", err
		}
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit docsis policy event: %w", err)
	}
	return input.EventID, nil
}

func ListDOCSISPolicyEvents(limit int) ([]DOCSISPolicyEvent, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := DB.Query(docsisPolicyEventSelectSQL()+` ORDER BY datetime(created_at) DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list docsis policy events: %w", err)
	}
	defer rows.Close()
	var events []DOCSISPolicyEvent
	for rows.Next() {
		event, err := scanDOCSISPolicyEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func ListDOCSISPolicyProfiles(limit int, profileType string) ([]DOCSISPolicyProfileRecord, error) {
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
	query := docsisPolicyProfileSelectSQL()
	if strings.TrimSpace(profileType) != "" {
		query += " WHERE profile_type = ?"
		args = append(args, normalizeDOCSISPolicyProfileType(profileType))
	}
	query += " ORDER BY datetime(last_seen_at) DESC, id DESC LIMIT ?"
	args = append(args, limit)
	rows, err := DB.Query(query, args...)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list docsis policy profiles: %w", err)
	}
	defer rows.Close()
	var records []DOCSISPolicyProfileRecord
	for rows.Next() {
		record, err := scanDOCSISPolicyProfile(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func GetDOCSISPolicySummary() (DOCSISPolicySummary, error) {
	var summary DOCSISPolicySummary
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
		COALESCE((SELECT plan_fingerprint FROM docsis_policy_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), ''),
		COALESCE((SELECT modem_profile_count FROM docsis_policy_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), 0),
		COALESCE((SELECT service_flow_count FROM docsis_policy_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), 0),
		COALESCE((SELECT cmts_profile_count FROM docsis_policy_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), 0),
		COALESCE((SELECT charging_policy_count FROM docsis_policy_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), 0),
		COALESCE((SELECT radius_attribute_count FROM docsis_policy_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), 0),
		COALESCE((SELECT compliance_check_count FROM docsis_policy_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), 0),
		COALESCE((SELECT external_requirement_count FROM docsis_policy_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), 0)
		FROM docsis_policy_events`).Scan(
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
		&summary.LastModemProfileCount,
		&summary.LastServiceFlowCount,
		&summary.LastCMTSProfileCount,
		&summary.LastChargingPolicyCount,
		&summary.LastRadiusAttributeCount,
		&summary.LastComplianceCheckCount,
		&summary.LastExternalRequirementCount,
	)
	if err != nil {
		if tableMissing(err) {
			return summary, nil
		}
		return summary, fmt.Errorf("summarize docsis policy events: %w", err)
	}
	_ = DB.QueryRow(`SELECT
		COALESCE(SUM(CASE WHEN status = 'ready' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'planned' THEN 1 ELSE 0 END), 0)
		FROM docsis_policy_profiles`).Scan(&summary.ReadyProfileCount, &summary.PlannedProfileCount)
	return summary, nil
}

func upsertDOCSISPolicyProfile(tx *sql.Tx, input DOCSISPolicyProfileInput) error {
	key := strings.ToLower(strings.TrimSpace(input.ProfileKey))
	if key == "" {
		key = strings.ToLower(strings.TrimSpace(input.Name))
	}
	if key == "" {
		return nil
	}
	profileType := normalizeDOCSISPolicyProfileType(input.ProfileType)
	if profileType == "" {
		return fmt.Errorf("docsis policy profile type is required")
	}
	if strings.TrimSpace(input.AttributesJSON) == "" {
		input.AttributesJSON = "{}"
	}
	_, err := tx.Exec(`INSERT INTO docsis_policy_profiles (
			profile_key, profile_type, name, status, service_flow_id, service_class, cmts_profile, charging_policy,
			attributes_json, source_event_id, plan_fingerprint, last_seen_at, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT(profile_type, profile_key) DO UPDATE SET
			name = excluded.name,
			status = excluded.status,
			service_flow_id = excluded.service_flow_id,
			service_class = excluded.service_class,
			cmts_profile = excluded.cmts_profile,
			charging_policy = excluded.charging_policy,
			attributes_json = excluded.attributes_json,
			source_event_id = excluded.source_event_id,
			plan_fingerprint = excluded.plan_fingerprint,
			last_seen_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP`,
		key,
		profileType,
		strings.TrimSpace(input.Name),
		normalizeDOCSISPolicyRecordStatus(input.Status),
		nonNegativeInt(input.ServiceFlowID),
		nullString(strings.TrimSpace(input.ServiceClass)),
		nullString(strings.TrimSpace(input.CMTSProfile)),
		nullString(strings.TrimSpace(input.ChargingPolicy)),
		input.AttributesJSON,
		nullString(strings.TrimSpace(input.SourceEventID)),
		strings.TrimSpace(input.PlanFingerprint),
	)
	if err != nil {
		return fmt.Errorf("upsert docsis policy profile %q/%q: %w", profileType, key, err)
	}
	return nil
}

func docsisPolicyEventSelectSQL() string {
	return `SELECT id, event_id, operation, status, plan_fingerprint, COALESCE(mode, ''),
		modem_profile_count, service_flow_count, cmts_profile_count, charging_policy_count,
		radius_attribute_count, compliance_check_count, passed_check_count, warning_count,
		blocker_count, external_requirement_count, summary_json, COALESCE(report_json, ''),
		COALESCE(actor, ''), COALESCE(CAST(created_at AS TEXT), '')
		FROM docsis_policy_events`
}

func scanDOCSISPolicyEvent(scanner interface {
	Scan(dest ...any) error
}) (DOCSISPolicyEvent, error) {
	var event DOCSISPolicyEvent
	err := scanner.Scan(
		&event.ID,
		&event.EventID,
		&event.Operation,
		&event.Status,
		&event.PlanFingerprint,
		&event.Mode,
		&event.ModemProfileCount,
		&event.ServiceFlowCount,
		&event.CMTSProfileCount,
		&event.ChargingPolicyCount,
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

func docsisPolicyProfileSelectSQL() string {
	return `SELECT id, profile_key, profile_type, name, status, service_flow_id,
		COALESCE(service_class, ''), COALESCE(cmts_profile, ''), COALESCE(charging_policy, ''),
		attributes_json, COALESCE(source_event_id, ''), plan_fingerprint,
		COALESCE(CAST(last_seen_at AS TEXT), ''),
		COALESCE(CAST(created_at AS TEXT), ''),
		COALESCE(CAST(updated_at AS TEXT), '')
		FROM docsis_policy_profiles`
}

func scanDOCSISPolicyProfile(scanner interface {
	Scan(dest ...any) error
}) (DOCSISPolicyProfileRecord, error) {
	var record DOCSISPolicyProfileRecord
	err := scanner.Scan(
		&record.ID,
		&record.ProfileKey,
		&record.ProfileType,
		&record.Name,
		&record.Status,
		&record.ServiceFlowID,
		&record.ServiceClass,
		&record.CMTSProfile,
		&record.ChargingPolicy,
		&record.AttributesJSON,
		&record.SourceEventID,
		&record.PlanFingerprint,
		&record.LastSeenAt,
		&record.CreatedAt,
		&record.UpdatedAt,
	)
	return record, err
}

func normalizeDOCSISPolicyOperation(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "preview", "apply", "status", "reconcile":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeDOCSISPolicyStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "previewed", "applied", "blocked", "degraded", "skipped", "failed", "reconciled":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeDOCSISPolicyRecordStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "ready", "planned", "blocked", "degraded", "withdrawn":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "planned"
	}
}

func normalizeDOCSISPolicyProfileType(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "modem_profile", "service_flow", "cmts_profile", "charging_policy":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func newDOCSISPolicyEventID(input DOCSISPolicyEventInput) string {
	var nonce [8]byte
	_, _ = rand.Read(nonce[:])
	hash := sha256.Sum256([]byte(strings.Join([]string{
		input.Operation,
		input.Status,
		input.PlanFingerprint,
		input.Mode,
		hex.EncodeToString(nonce[:]),
	}, "|")))
	return "docsis-policy-" + hex.EncodeToString(hash[:8])
}
