package db

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
)

type MobileGroupedAVPEventInput struct {
	EventID                  string
	Operation                string
	Status                   string
	PlanFingerprint          string
	Mode                     string
	VendorScopeCount         int
	EvidencePolicyCount      int
	CompiledAttributeCount   int
	GroupedAttributeCount    int
	ComplianceCheckCount     int
	PassedCheckCount         int
	WarningCount             int
	BlockerCount             int
	ExternalRequirementCount int
	SummaryJSON              string
	ReportJSON               string
	Actor                    string
	Scopes                   []MobileGroupedAVPScopeInput
}

type MobileGroupedAVPScopeInput struct {
	ScopeKey               string
	Name                   string
	Vendor                 string
	VendorID               uint32
	Dictionary             string
	Domain                 string
	Format                 string
	Status                 string
	RegistryAttributeCount int
	GroupedAttributeCount  int
	CompiledAttributeCount int
	AttributesJSON         string
	SourceEventID          string
	PlanFingerprint        string
}

type MobileGroupedAVPEvent struct {
	ID                       int    `json:"id"`
	EventID                  string `json:"event_id"`
	Operation                string `json:"operation"`
	Status                   string `json:"status"`
	PlanFingerprint          string `json:"plan_fingerprint"`
	Mode                     string `json:"mode,omitempty"`
	VendorScopeCount         int    `json:"vendor_scope_count"`
	EvidencePolicyCount      int    `json:"evidence_policy_count"`
	CompiledAttributeCount   int    `json:"compiled_attribute_count"`
	GroupedAttributeCount    int    `json:"grouped_attribute_count"`
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

type MobileGroupedAVPScopeRecord struct {
	ID                     int    `json:"id"`
	ScopeKey               string `json:"scope_key"`
	Name                   string `json:"name"`
	Vendor                 string `json:"vendor"`
	VendorID               uint32 `json:"vendor_id"`
	Dictionary             string `json:"dictionary,omitempty"`
	Domain                 string `json:"domain,omitempty"`
	Format                 string `json:"format,omitempty"`
	Status                 string `json:"status"`
	RegistryAttributeCount int    `json:"registry_attribute_count"`
	GroupedAttributeCount  int    `json:"grouped_attribute_count"`
	CompiledAttributeCount int    `json:"compiled_attribute_count"`
	AttributesJSON         string `json:"attributes_json"`
	SourceEventID          string `json:"source_event_id,omitempty"`
	PlanFingerprint        string `json:"plan_fingerprint"`
	LastSeenAt             string `json:"last_seen_at"`
	CreatedAt              string `json:"created_at"`
	UpdatedAt              string `json:"updated_at"`
}

type MobileGroupedAVPSummary struct {
	TotalEvents                int    `json:"total_events"`
	PreviewEvents              int    `json:"preview_events"`
	ApplyEvents                int    `json:"apply_events"`
	PreviewedCount             int    `json:"previewed_count"`
	AppliedCount               int    `json:"applied_count"`
	BlockedCount               int    `json:"blocked_count"`
	DegradedCount              int    `json:"degraded_count"`
	SkippedCount               int    `json:"skipped_count"`
	FailedCount                int    `json:"failed_count"`
	ReadyScopeCount            int    `json:"ready_scope_count"`
	PlannedScopeCount          int    `json:"planned_scope_count"`
	LastEventAt                string `json:"last_event_at,omitempty"`
	LastFingerprint            string `json:"last_fingerprint,omitempty"`
	LastVendorScopeCount       int    `json:"last_vendor_scope_count"`
	LastEvidencePolicyCount    int    `json:"last_evidence_policy_count"`
	LastCompiledAttributeCount int    `json:"last_compiled_attribute_count"`
	LastGroupedAttributeCount  int    `json:"last_grouped_attribute_count"`
}

func RecordMobileGroupedAVPEvent(input MobileGroupedAVPEventInput) (string, error) {
	if DB == nil {
		return "", nil
	}
	input.Operation = normalizeMobileGroupedAVPOperation(input.Operation)
	input.Status = normalizeMobileGroupedAVPStatus(input.Status)
	input.EventID = strings.TrimSpace(input.EventID)
	if input.EventID == "" {
		input.EventID = newMobileGroupedAVPEventID(input)
	}
	if input.Operation == "" || input.Status == "" {
		return "", fmt.Errorf("mobile grouped AVP operation and status are required")
	}
	if strings.TrimSpace(input.PlanFingerprint) == "" {
		return "", fmt.Errorf("mobile grouped AVP plan fingerprint is required")
	}
	if strings.TrimSpace(input.SummaryJSON) == "" {
		input.SummaryJSON = "{}"
	}
	if strings.TrimSpace(input.ReportJSON) == "" {
		input.ReportJSON = "{}"
	}
	tx, err := DB.Begin()
	if err != nil {
		return "", fmt.Errorf("begin mobile grouped AVP event: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO mobile_grouped_avp_events (
			event_id, operation, status, plan_fingerprint, mode,
			vendor_scope_count, evidence_policy_count, compiled_attribute_count,
			grouped_attribute_count, compliance_check_count, passed_check_count,
			warning_count, blocker_count, external_requirement_count,
			summary_json, report_json, actor, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(event_id) DO UPDATE SET
			operation = excluded.operation,
			status = excluded.status,
			plan_fingerprint = excluded.plan_fingerprint,
			mode = excluded.mode,
			vendor_scope_count = excluded.vendor_scope_count,
			evidence_policy_count = excluded.evidence_policy_count,
			compiled_attribute_count = excluded.compiled_attribute_count,
			grouped_attribute_count = excluded.grouped_attribute_count,
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
		nonNegativeInt(input.VendorScopeCount),
		nonNegativeInt(input.EvidencePolicyCount),
		nonNegativeInt(input.CompiledAttributeCount),
		nonNegativeInt(input.GroupedAttributeCount),
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
		return "", fmt.Errorf("record mobile grouped AVP event: %w", err)
	}
	for _, item := range input.Scopes {
		item.SourceEventID = firstNonEmptyString(item.SourceEventID, input.EventID)
		if err := upsertMobileGroupedAVPScope(tx, item); err != nil {
			return "", err
		}
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit mobile grouped AVP event: %w", err)
	}
	return input.EventID, nil
}

func ListMobileGroupedAVPEvents(limit int) ([]MobileGroupedAVPEvent, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := DB.Query(mobileGroupedAVPEventSelectSQL()+` ORDER BY datetime(created_at) DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list mobile grouped AVP events: %w", err)
	}
	defer rows.Close()
	var events []MobileGroupedAVPEvent
	for rows.Next() {
		event, err := scanMobileGroupedAVPEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func ListMobileGroupedAVPScopes(limit int, status string) ([]MobileGroupedAVPScopeRecord, error) {
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
	query := mobileGroupedAVPScopeSelectSQL()
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
		return nil, fmt.Errorf("list mobile grouped AVP scopes: %w", err)
	}
	defer rows.Close()
	var records []MobileGroupedAVPScopeRecord
	for rows.Next() {
		record, err := scanMobileGroupedAVPScope(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func GetMobileGroupedAVPSummary() (MobileGroupedAVPSummary, error) {
	var summary MobileGroupedAVPSummary
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
		COALESCE((SELECT plan_fingerprint FROM mobile_grouped_avp_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), ''),
		COALESCE((SELECT vendor_scope_count FROM mobile_grouped_avp_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), 0),
		COALESCE((SELECT evidence_policy_count FROM mobile_grouped_avp_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), 0),
		COALESCE((SELECT compiled_attribute_count FROM mobile_grouped_avp_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), 0),
		COALESCE((SELECT grouped_attribute_count FROM mobile_grouped_avp_events ORDER BY datetime(created_at) DESC, id DESC LIMIT 1), 0)
		FROM mobile_grouped_avp_events`).Scan(
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
		&summary.LastVendorScopeCount,
		&summary.LastEvidencePolicyCount,
		&summary.LastCompiledAttributeCount,
		&summary.LastGroupedAttributeCount,
	)
	if err != nil {
		if tableMissing(err) {
			return summary, nil
		}
		return summary, fmt.Errorf("summarize mobile grouped AVP events: %w", err)
	}
	_ = DB.QueryRow(`SELECT
		COALESCE(SUM(CASE WHEN status = 'ready' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'planned' THEN 1 ELSE 0 END), 0)
		FROM mobile_grouped_avp_scopes`).Scan(&summary.ReadyScopeCount, &summary.PlannedScopeCount)
	return summary, nil
}

func upsertMobileGroupedAVPScope(tx *sql.Tx, input MobileGroupedAVPScopeInput) error {
	key := strings.ToLower(strings.TrimSpace(input.ScopeKey))
	if key == "" {
		key = strings.ToLower(firstNonEmptyString(input.Name, input.Vendor))
	}
	if key == "" {
		return nil
	}
	if strings.TrimSpace(input.AttributesJSON) == "" {
		input.AttributesJSON = "{}"
	}
	_, err := tx.Exec(`INSERT INTO mobile_grouped_avp_scopes (
			scope_key, name, vendor, vendor_id, dictionary, domain, format,
			status, registry_attribute_count, grouped_attribute_count,
			compiled_attribute_count, attributes_json, source_event_id,
			plan_fingerprint, last_seen_at, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT(scope_key) DO UPDATE SET
			name = excluded.name,
			vendor = excluded.vendor,
			vendor_id = excluded.vendor_id,
			dictionary = excluded.dictionary,
			domain = excluded.domain,
			format = excluded.format,
			status = excluded.status,
			registry_attribute_count = excluded.registry_attribute_count,
			grouped_attribute_count = excluded.grouped_attribute_count,
			compiled_attribute_count = excluded.compiled_attribute_count,
			attributes_json = excluded.attributes_json,
			source_event_id = excluded.source_event_id,
			plan_fingerprint = excluded.plan_fingerprint,
			last_seen_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP`,
		key,
		strings.TrimSpace(input.Name),
		strings.TrimSpace(input.Vendor),
		input.VendorID,
		nullString(strings.TrimSpace(input.Dictionary)),
		nullString(strings.TrimSpace(input.Domain)),
		nullString(strings.TrimSpace(input.Format)),
		normalizeMobileGroupedAVPRecordStatus(input.Status),
		nonNegativeInt(input.RegistryAttributeCount),
		nonNegativeInt(input.GroupedAttributeCount),
		nonNegativeInt(input.CompiledAttributeCount),
		input.AttributesJSON,
		nullString(strings.TrimSpace(input.SourceEventID)),
		strings.TrimSpace(input.PlanFingerprint),
	)
	if err != nil {
		return fmt.Errorf("upsert mobile grouped AVP scope %q: %w", key, err)
	}
	return nil
}

func mobileGroupedAVPEventSelectSQL() string {
	return `SELECT id, event_id, operation, status, plan_fingerprint, COALESCE(mode, ''),
		vendor_scope_count, evidence_policy_count, compiled_attribute_count,
		grouped_attribute_count, compliance_check_count, passed_check_count,
		warning_count, blocker_count, external_requirement_count,
		summary_json, COALESCE(report_json, ''), COALESCE(actor, ''),
		COALESCE(CAST(created_at AS TEXT), '')
		FROM mobile_grouped_avp_events`
}

func scanMobileGroupedAVPEvent(scanner interface {
	Scan(dest ...any) error
}) (MobileGroupedAVPEvent, error) {
	var event MobileGroupedAVPEvent
	err := scanner.Scan(
		&event.ID,
		&event.EventID,
		&event.Operation,
		&event.Status,
		&event.PlanFingerprint,
		&event.Mode,
		&event.VendorScopeCount,
		&event.EvidencePolicyCount,
		&event.CompiledAttributeCount,
		&event.GroupedAttributeCount,
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

func mobileGroupedAVPScopeSelectSQL() string {
	return `SELECT id, scope_key, name, vendor, vendor_id, COALESCE(dictionary, ''),
		COALESCE(domain, ''), COALESCE(format, ''), status,
		registry_attribute_count, grouped_attribute_count, compiled_attribute_count,
		attributes_json, COALESCE(source_event_id, ''), plan_fingerprint,
		COALESCE(CAST(last_seen_at AS TEXT), ''),
		COALESCE(CAST(created_at AS TEXT), ''),
		COALESCE(CAST(updated_at AS TEXT), '')
		FROM mobile_grouped_avp_scopes`
}

func scanMobileGroupedAVPScope(scanner interface {
	Scan(dest ...any) error
}) (MobileGroupedAVPScopeRecord, error) {
	var record MobileGroupedAVPScopeRecord
	err := scanner.Scan(
		&record.ID,
		&record.ScopeKey,
		&record.Name,
		&record.Vendor,
		&record.VendorID,
		&record.Dictionary,
		&record.Domain,
		&record.Format,
		&record.Status,
		&record.RegistryAttributeCount,
		&record.GroupedAttributeCount,
		&record.CompiledAttributeCount,
		&record.AttributesJSON,
		&record.SourceEventID,
		&record.PlanFingerprint,
		&record.LastSeenAt,
		&record.CreatedAt,
		&record.UpdatedAt,
	)
	return record, err
}

func normalizeMobileGroupedAVPOperation(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "preview", "apply", "status", "reconcile":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeMobileGroupedAVPStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "previewed", "applied", "blocked", "degraded", "skipped", "failed", "reconciled":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeMobileGroupedAVPRecordStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "ready", "planned", "blocked", "degraded", "withdrawn":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "planned"
	}
}

func newMobileGroupedAVPEventID(input MobileGroupedAVPEventInput) string {
	var nonce [8]byte
	_, _ = rand.Read(nonce[:])
	hash := sha256.Sum256([]byte(strings.Join([]string{
		input.Operation,
		input.Status,
		input.PlanFingerprint,
		input.Mode,
		hex.EncodeToString(nonce[:]),
	}, "|")))
	return "mobile-avp-" + hex.EncodeToString(hash[:8])
}
