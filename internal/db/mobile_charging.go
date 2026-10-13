package db

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
)

type MobileChargingEventInput struct {
	EventID                   string
	Operation                 string
	Status                    string
	PlanFingerprint           string
	Mode                      string
	StreamCount               int
	RatingGroupCount          int
	QuotaPolicyCount          int
	CorrelationAttributeCount int
	MediationReferenceCount   int
	ComplianceCheckCount      int
	PassedCheckCount          int
	WarningCount              int
	BlockerCount              int
	ExternalRequirementCount  int
	SummaryJSON               string
	ReportJSON                string
	Actor                     string
	Profiles                  []MobileChargingProfileInput
}

type MobileChargingProfileInput struct {
	ProfileKey      string
	ProfileType     string
	Name            string
	Status          string
	StreamType      string
	RatingGroup     int
	QuotaUnit       string
	AttributesJSON  string
	SourceEventID   string
	PlanFingerprint string
}

type MobileChargingEvent struct {
	ID                        int    `json:"id"`
	EventID                   string `json:"event_id"`
	Operation                 string `json:"operation"`
	Status                    string `json:"status"`
	PlanFingerprint           string `json:"plan_fingerprint"`
	Mode                      string `json:"mode,omitempty"`
	StreamCount               int    `json:"stream_count"`
	RatingGroupCount          int    `json:"rating_group_count"`
	QuotaPolicyCount          int    `json:"quota_policy_count"`
	CorrelationAttributeCount int    `json:"correlation_attribute_count"`
	MediationReferenceCount   int    `json:"mediation_reference_count"`
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

type MobileChargingProfileRecord struct {
	ID              int    `json:"id"`
	ProfileKey      string `json:"profile_key"`
	ProfileType     string `json:"profile_type"`
	Name            string `json:"name"`
	Status          string `json:"status"`
	StreamType      string `json:"stream_type,omitempty"`
	RatingGroup     int    `json:"rating_group,omitempty"`
	QuotaUnit       string `json:"quota_unit,omitempty"`
	AttributesJSON  string `json:"attributes_json"`
	SourceEventID   string `json:"source_event_id,omitempty"`
	PlanFingerprint string `json:"plan_fingerprint"`
	LastSeenAt      string `json:"last_seen_at"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}

type MobileChargingSummary struct {
	TotalEvents                   int    `json:"total_events"`
	PreviewEvents                 int    `json:"preview_events"`
	ApplyEvents                   int    `json:"apply_events"`
	PreviewedCount                int    `json:"previewed_count"`
	AppliedCount                  int    `json:"applied_count"`
	BlockedCount                  int    `json:"blocked_count"`
	DegradedCount                 int    `json:"degraded_count"`
	SkippedCount                  int    `json:"skipped_count"`
	FailedCount                   int    `json:"failed_count"`
	ReconciledCount               int    `json:"reconciled_count"`
	ReadyProfileCount             int    `json:"ready_profile_count"`
	PlannedProfileCount           int    `json:"planned_profile_count"`
	LastEventAt                   string `json:"last_event_at,omitempty"`
	LastFingerprint               string `json:"last_fingerprint,omitempty"`
	LastStreamCount               int    `json:"last_stream_count"`
	LastRatingGroupCount          int    `json:"last_rating_group_count"`
	LastQuotaPolicyCount          int    `json:"last_quota_policy_count"`
	LastCorrelationAttributeCount int    `json:"last_correlation_attribute_count"`
	LastMediationReferenceCount   int    `json:"last_mediation_reference_count"`
	LastComplianceCheckCount      int    `json:"last_compliance_check_count"`
	LastExternalRequirementCount  int    `json:"last_external_requirement_count"`
}

func RecordMobileChargingEvent(input MobileChargingEventInput) (string, error) {
	if DB == nil {
		return "", nil
	}
	input.Operation = normalizeMobileChargingOperation(input.Operation)
	input.Status = normalizeMobileChargingStatus(input.Status)
	input.EventID = strings.TrimSpace(input.EventID)
	if input.EventID == "" {
		input.EventID = newMobileChargingEventID(input)
	}
	if input.Operation == "" || input.Status == "" {
		return "", fmt.Errorf("mobile charging operation and status are required")
	}
	if strings.TrimSpace(input.PlanFingerprint) == "" {
		return "", fmt.Errorf("mobile charging plan fingerprint is required")
	}
	if strings.TrimSpace(input.SummaryJSON) == "" {
		input.SummaryJSON = "{}"
	}
	if strings.TrimSpace(input.ReportJSON) == "" {
		input.ReportJSON = "{}"
	}
	tx, err := DB.Begin()
	if err != nil {
		return "", fmt.Errorf("begin mobile charging event: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO mobile_charging_correlation_events (
			event_id, operation, status, plan_fingerprint, mode,
			stream_count, rating_group_count, quota_policy_count,
			correlation_attribute_count, mediation_reference_count,
			compliance_check_count, passed_check_count, warning_count,
			blocker_count, external_requirement_count, summary_json, report_json,
			actor, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(event_id) DO UPDATE SET
			operation = excluded.operation,
			status = excluded.status,
			plan_fingerprint = excluded.plan_fingerprint,
			mode = excluded.mode,
			stream_count = excluded.stream_count,
			rating_group_count = excluded.rating_group_count,
			quota_policy_count = excluded.quota_policy_count,
			correlation_attribute_count = excluded.correlation_attribute_count,
			mediation_reference_count = excluded.mediation_reference_count,
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
		nonNegativeInt(input.StreamCount),
		nonNegativeInt(input.RatingGroupCount),
		nonNegativeInt(input.QuotaPolicyCount),
		nonNegativeInt(input.CorrelationAttributeCount),
		nonNegativeInt(input.MediationReferenceCount),
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
		return "", fmt.Errorf("record mobile charging event: %w", err)
	}
	for _, item := range input.Profiles {
		item.SourceEventID = firstNonEmptyString(item.SourceEventID, input.EventID)
		if err := upsertMobileChargingProfile(tx, item); err != nil {
			return "", err
		}
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit mobile charging event: %w", err)
	}
	return input.EventID, nil
}

func ListMobileChargingEvents(limit int) ([]MobileChargingEvent, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := DB.Query(mobileChargingEventSelectSQL()+` ORDER BY datetime(created_at) DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list mobile charging events: %w", err)
	}
	defer rows.Close()
	var events []MobileChargingEvent
	for rows.Next() {
		event, err := scanMobileChargingEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func ListMobileChargingProfiles(limit int, profileType string) ([]MobileChargingProfileRecord, error) {
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
	query := mobileChargingProfileSelectSQL()
	if strings.TrimSpace(profileType) != "" {
		query += " WHERE profile_type = ?"
		args = append(args, normalizeMobileChargingProfileType(profileType))
	}
	query += " ORDER BY datetime(last_seen_at) DESC, id DESC LIMIT ?"
	args = append(args, limit)
	rows, err := DB.Query(query, args...)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list mobile charging profiles: %w", err)
	}
	defer rows.Close()
	var records []MobileChargingProfileRecord
	for rows.Next() {
		record, err := scanMobileChargingProfile(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func GetMobileChargingSummary() (MobileChargingSummary, error) {
	var summary MobileChargingSummary
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
		COALESCE((SELECT plan_fingerprint FROM mobile_charging_correlation_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), ''),
		COALESCE((SELECT stream_count FROM mobile_charging_correlation_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), 0),
		COALESCE((SELECT rating_group_count FROM mobile_charging_correlation_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), 0),
		COALESCE((SELECT quota_policy_count FROM mobile_charging_correlation_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), 0),
		COALESCE((SELECT correlation_attribute_count FROM mobile_charging_correlation_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), 0),
		COALESCE((SELECT mediation_reference_count FROM mobile_charging_correlation_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), 0),
		COALESCE((SELECT compliance_check_count FROM mobile_charging_correlation_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), 0),
		COALESCE((SELECT external_requirement_count FROM mobile_charging_correlation_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), 0)
		FROM mobile_charging_correlation_events`).Scan(
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
		&summary.LastStreamCount,
		&summary.LastRatingGroupCount,
		&summary.LastQuotaPolicyCount,
		&summary.LastCorrelationAttributeCount,
		&summary.LastMediationReferenceCount,
		&summary.LastComplianceCheckCount,
		&summary.LastExternalRequirementCount,
	)
	if err != nil {
		if tableMissing(err) {
			return summary, nil
		}
		return summary, fmt.Errorf("summarize mobile charging events: %w", err)
	}
	_ = DB.QueryRow(`SELECT
		COALESCE(SUM(CASE WHEN status = 'ready' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'planned' THEN 1 ELSE 0 END), 0)
		FROM mobile_charging_correlation_profiles`).Scan(&summary.ReadyProfileCount, &summary.PlannedProfileCount)
	return summary, nil
}

func upsertMobileChargingProfile(tx *sql.Tx, input MobileChargingProfileInput) error {
	key := strings.ToLower(strings.TrimSpace(input.ProfileKey))
	if key == "" {
		key = strings.ToLower(strings.TrimSpace(input.Name))
	}
	if key == "" {
		return nil
	}
	profileType := normalizeMobileChargingProfileType(input.ProfileType)
	if profileType == "" {
		return fmt.Errorf("mobile charging profile type is required")
	}
	if strings.TrimSpace(input.AttributesJSON) == "" {
		input.AttributesJSON = "{}"
	}
	_, err := tx.Exec(`INSERT INTO mobile_charging_correlation_profiles (
			profile_key, profile_type, name, status, stream_type, rating_group, quota_unit,
			attributes_json, source_event_id, plan_fingerprint, last_seen_at, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT(profile_type, profile_key) DO UPDATE SET
			name = excluded.name,
			status = excluded.status,
			stream_type = excluded.stream_type,
			rating_group = excluded.rating_group,
			quota_unit = excluded.quota_unit,
			attributes_json = excluded.attributes_json,
			source_event_id = excluded.source_event_id,
			plan_fingerprint = excluded.plan_fingerprint,
			last_seen_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP`,
		key,
		profileType,
		strings.TrimSpace(input.Name),
		normalizeMobileChargingRecordStatus(input.Status),
		nullString(strings.TrimSpace(input.StreamType)),
		nonNegativeInt(input.RatingGroup),
		nullString(strings.TrimSpace(input.QuotaUnit)),
		input.AttributesJSON,
		nullString(strings.TrimSpace(input.SourceEventID)),
		strings.TrimSpace(input.PlanFingerprint),
	)
	if err != nil {
		return fmt.Errorf("upsert mobile charging profile %q/%q: %w", profileType, key, err)
	}
	return nil
}

func mobileChargingEventSelectSQL() string {
	return `SELECT id, event_id, operation, status, plan_fingerprint, COALESCE(mode, ''),
		stream_count, rating_group_count, quota_policy_count,
		correlation_attribute_count, mediation_reference_count,
		compliance_check_count, passed_check_count, warning_count,
		blocker_count, external_requirement_count,
		summary_json, COALESCE(report_json, ''), COALESCE(actor, ''),
		COALESCE(CAST(created_at AS TEXT), '')
		FROM mobile_charging_correlation_events`
}

func scanMobileChargingEvent(scanner interface {
	Scan(dest ...any) error
}) (MobileChargingEvent, error) {
	var event MobileChargingEvent
	err := scanner.Scan(
		&event.ID,
		&event.EventID,
		&event.Operation,
		&event.Status,
		&event.PlanFingerprint,
		&event.Mode,
		&event.StreamCount,
		&event.RatingGroupCount,
		&event.QuotaPolicyCount,
		&event.CorrelationAttributeCount,
		&event.MediationReferenceCount,
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

func mobileChargingProfileSelectSQL() string {
	return `SELECT id, profile_key, profile_type, name, status, COALESCE(stream_type, ''),
		COALESCE(rating_group, 0), COALESCE(quota_unit, ''), attributes_json,
		COALESCE(source_event_id, ''), plan_fingerprint,
		COALESCE(CAST(last_seen_at AS TEXT), ''),
		COALESCE(CAST(created_at AS TEXT), ''),
		COALESCE(CAST(updated_at AS TEXT), '')
		FROM mobile_charging_correlation_profiles`
}

func scanMobileChargingProfile(scanner interface {
	Scan(dest ...any) error
}) (MobileChargingProfileRecord, error) {
	var record MobileChargingProfileRecord
	err := scanner.Scan(
		&record.ID,
		&record.ProfileKey,
		&record.ProfileType,
		&record.Name,
		&record.Status,
		&record.StreamType,
		&record.RatingGroup,
		&record.QuotaUnit,
		&record.AttributesJSON,
		&record.SourceEventID,
		&record.PlanFingerprint,
		&record.LastSeenAt,
		&record.CreatedAt,
		&record.UpdatedAt,
	)
	return record, err
}

func normalizeMobileChargingOperation(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "preview", "apply", "status", "reconcile":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeMobileChargingStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "previewed", "applied", "blocked", "degraded", "skipped", "failed", "reconciled":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeMobileChargingRecordStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "ready", "planned", "blocked", "degraded", "withdrawn":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "planned"
	}
}

func normalizeMobileChargingProfileType(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "stream", "rating_group", "quota_policy":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func newMobileChargingEventID(input MobileChargingEventInput) string {
	var nonce [8]byte
	_, _ = rand.Read(nonce[:])
	hash := sha256.Sum256([]byte(strings.Join([]string{
		input.Operation,
		input.Status,
		input.PlanFingerprint,
		input.Mode,
		hex.EncodeToString(nonce[:]),
	}, "|")))
	return "mobile-charging-" + hex.EncodeToString(hash[:8])
}
