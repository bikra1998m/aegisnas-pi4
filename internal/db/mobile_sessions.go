package db

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
)

type MobileSessionEventInput struct {
	EventID                  string
	Operation                string
	Status                   string
	PlanFingerprint          string
	Mode                     string
	APNProfileCount          int
	BearerTemplateCount      int
	RoamingPartnerCount      int
	RadiusAttributeCount     int
	StateStepCount           int
	ComplianceCheckCount     int
	PassedCheckCount         int
	WarningCount             int
	BlockerCount             int
	ExternalRequirementCount int
	SummaryJSON              string
	ReportJSON               string
	Actor                    string
	Profiles                 []MobileSessionProfileInput
}

type MobileSessionProfileInput struct {
	ProfileKey      string
	ProfileType     string
	Name            string
	Status          string
	APN             string
	BearerType      string
	Realm           string
	AttributesJSON  string
	SourceEventID   string
	PlanFingerprint string
}

type MobileSessionEvent struct {
	ID                       int    `json:"id"`
	EventID                  string `json:"event_id"`
	Operation                string `json:"operation"`
	Status                   string `json:"status"`
	PlanFingerprint          string `json:"plan_fingerprint"`
	Mode                     string `json:"mode,omitempty"`
	APNProfileCount          int    `json:"apn_profile_count"`
	BearerTemplateCount      int    `json:"bearer_template_count"`
	RoamingPartnerCount      int    `json:"roaming_partner_count"`
	RadiusAttributeCount     int    `json:"radius_attribute_count"`
	StateStepCount           int    `json:"state_step_count"`
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

type MobileSessionProfileRecord struct {
	ID              int    `json:"id"`
	ProfileKey      string `json:"profile_key"`
	ProfileType     string `json:"profile_type"`
	Name            string `json:"name"`
	Status          string `json:"status"`
	APN             string `json:"apn,omitempty"`
	BearerType      string `json:"bearer_type,omitempty"`
	Realm           string `json:"realm,omitempty"`
	AttributesJSON  string `json:"attributes_json"`
	SourceEventID   string `json:"source_event_id,omitempty"`
	PlanFingerprint string `json:"plan_fingerprint"`
	LastSeenAt      string `json:"last_seen_at"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}

type MobileSessionSummary struct {
	TotalEvents              int    `json:"total_events"`
	PreviewEvents            int    `json:"preview_events"`
	ApplyEvents              int    `json:"apply_events"`
	PreviewedCount           int    `json:"previewed_count"`
	AppliedCount             int    `json:"applied_count"`
	BlockedCount             int    `json:"blocked_count"`
	DegradedCount            int    `json:"degraded_count"`
	SkippedCount             int    `json:"skipped_count"`
	FailedCount              int    `json:"failed_count"`
	ReadyProfileCount        int    `json:"ready_profile_count"`
	PlannedProfileCount      int    `json:"planned_profile_count"`
	LastEventAt              string `json:"last_event_at,omitempty"`
	LastFingerprint          string `json:"last_fingerprint,omitempty"`
	LastAPNProfileCount      int    `json:"last_apn_profile_count"`
	LastBearerTemplateCount  int    `json:"last_bearer_template_count"`
	LastRoamingPartnerCount  int    `json:"last_roaming_partner_count"`
	LastRadiusAttributeCount int    `json:"last_radius_attribute_count"`
	LastStateStepCount       int    `json:"last_state_step_count"`
}

func RecordMobileSessionEvent(input MobileSessionEventInput) (string, error) {
	if DB == nil {
		return "", nil
	}
	input.Operation = normalizeMobileSessionOperation(input.Operation)
	input.Status = normalizeMobileSessionStatus(input.Status)
	input.EventID = strings.TrimSpace(input.EventID)
	if input.EventID == "" {
		input.EventID = newMobileSessionEventID(input)
	}
	if input.Operation == "" || input.Status == "" {
		return "", fmt.Errorf("mobile session operation and status are required")
	}
	if strings.TrimSpace(input.PlanFingerprint) == "" {
		return "", fmt.Errorf("mobile session plan fingerprint is required")
	}
	if strings.TrimSpace(input.SummaryJSON) == "" {
		input.SummaryJSON = "{}"
	}
	if strings.TrimSpace(input.ReportJSON) == "" {
		input.ReportJSON = "{}"
	}
	tx, err := DB.Begin()
	if err != nil {
		return "", fmt.Errorf("begin mobile session event: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO mobile_session_state_events (
			event_id, operation, status, plan_fingerprint, mode,
			apn_profile_count, bearer_template_count, roaming_partner_count,
			radius_attribute_count, state_step_count, compliance_check_count,
			passed_check_count, warning_count, blocker_count, external_requirement_count,
			summary_json, report_json, actor, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(event_id) DO UPDATE SET
			operation = excluded.operation,
			status = excluded.status,
			plan_fingerprint = excluded.plan_fingerprint,
			mode = excluded.mode,
			apn_profile_count = excluded.apn_profile_count,
			bearer_template_count = excluded.bearer_template_count,
			roaming_partner_count = excluded.roaming_partner_count,
			radius_attribute_count = excluded.radius_attribute_count,
			state_step_count = excluded.state_step_count,
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
		nonNegativeInt(input.APNProfileCount),
		nonNegativeInt(input.BearerTemplateCount),
		nonNegativeInt(input.RoamingPartnerCount),
		nonNegativeInt(input.RadiusAttributeCount),
		nonNegativeInt(input.StateStepCount),
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
		return "", fmt.Errorf("record mobile session event: %w", err)
	}
	for _, item := range input.Profiles {
		item.SourceEventID = firstNonEmptyString(item.SourceEventID, input.EventID)
		if err := upsertMobileSessionProfile(tx, item); err != nil {
			return "", err
		}
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit mobile session event: %w", err)
	}
	return input.EventID, nil
}

func ListMobileSessionEvents(limit int) ([]MobileSessionEvent, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := DB.Query(mobileSessionEventSelectSQL()+` ORDER BY datetime(created_at) DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list mobile session events: %w", err)
	}
	defer rows.Close()
	var events []MobileSessionEvent
	for rows.Next() {
		event, err := scanMobileSessionEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func ListMobileSessionProfiles(limit int, profileType string) ([]MobileSessionProfileRecord, error) {
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
	query := mobileSessionProfileSelectSQL()
	if strings.TrimSpace(profileType) != "" {
		query += " WHERE profile_type = ?"
		args = append(args, normalizeMobileSessionProfileType(profileType))
	}
	query += " ORDER BY datetime(last_seen_at) DESC, id DESC LIMIT ?"
	args = append(args, limit)
	rows, err := DB.Query(query, args...)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list mobile session profiles: %w", err)
	}
	defer rows.Close()
	var records []MobileSessionProfileRecord
	for rows.Next() {
		record, err := scanMobileSessionProfile(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func GetMobileSessionSummary() (MobileSessionSummary, error) {
	var summary MobileSessionSummary
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
		COALESCE((SELECT plan_fingerprint FROM mobile_session_state_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), ''),
		COALESCE((SELECT apn_profile_count FROM mobile_session_state_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), 0),
		COALESCE((SELECT bearer_template_count FROM mobile_session_state_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), 0),
		COALESCE((SELECT roaming_partner_count FROM mobile_session_state_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), 0),
		COALESCE((SELECT radius_attribute_count FROM mobile_session_state_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), 0),
		COALESCE((SELECT state_step_count FROM mobile_session_state_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), 0)
		FROM mobile_session_state_events`).Scan(
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
		&summary.LastAPNProfileCount,
		&summary.LastBearerTemplateCount,
		&summary.LastRoamingPartnerCount,
		&summary.LastRadiusAttributeCount,
		&summary.LastStateStepCount,
	)
	if err != nil {
		if tableMissing(err) {
			return summary, nil
		}
		return summary, fmt.Errorf("summarize mobile session events: %w", err)
	}
	_ = DB.QueryRow(`SELECT
		COALESCE(SUM(CASE WHEN status = 'ready' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'planned' THEN 1 ELSE 0 END), 0)
		FROM mobile_session_state_profiles`).Scan(&summary.ReadyProfileCount, &summary.PlannedProfileCount)
	return summary, nil
}

func upsertMobileSessionProfile(tx *sql.Tx, input MobileSessionProfileInput) error {
	key := strings.ToLower(strings.TrimSpace(input.ProfileKey))
	if key == "" {
		key = strings.ToLower(firstNonEmptyString(input.Name, input.APN, input.Realm))
	}
	if key == "" {
		return nil
	}
	profileType := normalizeMobileSessionProfileType(input.ProfileType)
	if profileType == "" {
		return fmt.Errorf("mobile session profile type is required")
	}
	if strings.TrimSpace(input.AttributesJSON) == "" {
		input.AttributesJSON = "{}"
	}
	_, err := tx.Exec(`INSERT INTO mobile_session_state_profiles (
			profile_key, profile_type, name, status, apn, bearer_type, realm,
			attributes_json, source_event_id, plan_fingerprint, last_seen_at, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT(profile_type, profile_key) DO UPDATE SET
			name = excluded.name,
			status = excluded.status,
			apn = excluded.apn,
			bearer_type = excluded.bearer_type,
			realm = excluded.realm,
			attributes_json = excluded.attributes_json,
			source_event_id = excluded.source_event_id,
			plan_fingerprint = excluded.plan_fingerprint,
			last_seen_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP`,
		key,
		profileType,
		strings.TrimSpace(input.Name),
		normalizeMobileSessionRecordStatus(input.Status),
		nullString(strings.TrimSpace(input.APN)),
		nullString(strings.TrimSpace(input.BearerType)),
		nullString(strings.TrimSpace(input.Realm)),
		input.AttributesJSON,
		nullString(strings.TrimSpace(input.SourceEventID)),
		strings.TrimSpace(input.PlanFingerprint),
	)
	if err != nil {
		return fmt.Errorf("upsert mobile session profile %q/%q: %w", profileType, key, err)
	}
	return nil
}

func mobileSessionEventSelectSQL() string {
	return `SELECT id, event_id, operation, status, plan_fingerprint, COALESCE(mode, ''),
		apn_profile_count, bearer_template_count, roaming_partner_count,
		radius_attribute_count, state_step_count, compliance_check_count,
		passed_check_count, warning_count, blocker_count, external_requirement_count,
		summary_json, COALESCE(report_json, ''), COALESCE(actor, ''),
		COALESCE(CAST(created_at AS TEXT), '')
		FROM mobile_session_state_events`
}

func scanMobileSessionEvent(scanner interface {
	Scan(dest ...any) error
}) (MobileSessionEvent, error) {
	var event MobileSessionEvent
	err := scanner.Scan(
		&event.ID,
		&event.EventID,
		&event.Operation,
		&event.Status,
		&event.PlanFingerprint,
		&event.Mode,
		&event.APNProfileCount,
		&event.BearerTemplateCount,
		&event.RoamingPartnerCount,
		&event.RadiusAttributeCount,
		&event.StateStepCount,
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

func mobileSessionProfileSelectSQL() string {
	return `SELECT id, profile_key, profile_type, name, status, COALESCE(apn, ''),
		COALESCE(bearer_type, ''), COALESCE(realm, ''), attributes_json,
		COALESCE(source_event_id, ''), plan_fingerprint,
		COALESCE(CAST(last_seen_at AS TEXT), ''),
		COALESCE(CAST(created_at AS TEXT), ''),
		COALESCE(CAST(updated_at AS TEXT), '')
		FROM mobile_session_state_profiles`
}

func scanMobileSessionProfile(scanner interface {
	Scan(dest ...any) error
}) (MobileSessionProfileRecord, error) {
	var record MobileSessionProfileRecord
	err := scanner.Scan(
		&record.ID,
		&record.ProfileKey,
		&record.ProfileType,
		&record.Name,
		&record.Status,
		&record.APN,
		&record.BearerType,
		&record.Realm,
		&record.AttributesJSON,
		&record.SourceEventID,
		&record.PlanFingerprint,
		&record.LastSeenAt,
		&record.CreatedAt,
		&record.UpdatedAt,
	)
	return record, err
}

func normalizeMobileSessionOperation(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "preview", "apply", "status", "reconcile":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeMobileSessionStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "previewed", "applied", "blocked", "degraded", "skipped", "failed", "reconciled":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeMobileSessionRecordStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "ready", "planned", "blocked", "degraded", "withdrawn":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "planned"
	}
}

func normalizeMobileSessionProfileType(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "apn", "bearer", "roaming":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func newMobileSessionEventID(input MobileSessionEventInput) string {
	var nonce [8]byte
	_, _ = rand.Read(nonce[:])
	hash := sha256.Sum256([]byte(strings.Join([]string{
		input.Operation,
		input.Status,
		input.PlanFingerprint,
		input.Mode,
		hex.EncodeToString(nonce[:]),
	}, "|")))
	return "mobile-session-" + hex.EncodeToString(hash[:8])
}
