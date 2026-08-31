package db

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
)

type AccessVendorPackEventInput struct {
	EventID                   string
	Operation                 string
	Status                    string
	ReleaseProfileID          string
	SourceSHA256              string
	AttributeCount            int
	NativeSemanticMappings    int
	TypedPassThroughMappings  int
	SensitiveRedactedMappings int
	GrammarRuleCount          int
	SoftwareCertifiedMappings int
	SoftwareBlockedMappings   int
	ExternalRequiredMappings  int
	VendorCount               int
	ProductScopeCount         int
	Fingerprint               string
	SummaryJSON               string
	ReportJSON                string
	Actor                     string
}

type AccessVendorPackEvent struct {
	ID                        int    `json:"id"`
	EventID                   string `json:"event_id"`
	Operation                 string `json:"operation"`
	Status                    string `json:"status"`
	ReleaseProfileID          string `json:"release_profile_id"`
	SourceSHA256              string `json:"source_sha256"`
	AttributeCount            int    `json:"attribute_count"`
	NativeSemanticMappings    int    `json:"native_semantic_mappings"`
	TypedPassThroughMappings  int    `json:"typed_passthrough_mappings"`
	SensitiveRedactedMappings int    `json:"sensitive_redacted_mappings"`
	GrammarRuleCount          int    `json:"grammar_rule_count"`
	SoftwareCertifiedMappings int    `json:"software_certified_mappings"`
	SoftwareBlockedMappings   int    `json:"software_blocked_mappings"`
	ExternalRequiredMappings  int    `json:"external_required_mappings"`
	VendorCount               int    `json:"vendor_count"`
	ProductScopeCount         int    `json:"product_scope_count"`
	Fingerprint               string `json:"fingerprint"`
	SummaryJSON               string `json:"summary_json"`
	ReportJSON                string `json:"report_json,omitempty"`
	Actor                     string `json:"actor,omitempty"`
	CreatedAt                 string `json:"created_at"`
}

type AccessVendorPackDBSummary struct {
	TotalEvents           int    `json:"total_events"`
	RecordedCount         int    `json:"recorded_count"`
	BlockedCount          int    `json:"blocked_count"`
	FailedCount           int    `json:"failed_count"`
	LastEventAt           string `json:"last_event_at,omitempty"`
	LastFingerprint       string `json:"last_fingerprint,omitempty"`
	LastAttributeCount    int    `json:"last_attribute_count"`
	LastSoftwareCertified int    `json:"last_software_certified_mappings"`
	LastExternalRequired  int    `json:"last_external_required_mappings"`
	LastVendorCount       int    `json:"last_vendor_count"`
	LastProductScopeCount int    `json:"last_product_scope_count"`
	LastReleaseProfileID  string `json:"last_release_profile_id,omitempty"`
	LastSourceSHA256      string `json:"last_source_sha256,omitempty"`
}

func RecordAccessVendorPackEvent(input AccessVendorPackEventInput) (string, error) {
	if DB == nil {
		return "", nil
	}
	input.Operation = normalizeAccessVendorPackOperation(input.Operation)
	input.Status = normalizeAccessVendorPackStatus(input.Status)
	input.EventID = strings.TrimSpace(input.EventID)
	if input.EventID == "" {
		input.EventID = newAccessVendorPackEventID(input)
	}
	if input.Operation == "" || input.Status == "" {
		return "", fmt.Errorf("access vendor pack operation and status are required")
	}
	if strings.TrimSpace(input.ReleaseProfileID) == "" || strings.TrimSpace(input.SourceSHA256) == "" {
		return "", fmt.Errorf("access vendor pack release profile and source hash are required")
	}
	if strings.TrimSpace(input.Fingerprint) == "" {
		return "", fmt.Errorf("access vendor pack fingerprint is required")
	}
	if strings.TrimSpace(input.SummaryJSON) == "" {
		input.SummaryJSON = "{}"
	}
	if strings.TrimSpace(input.ReportJSON) == "" {
		input.ReportJSON = "{}"
	}

	_, err := DB.Exec(`INSERT INTO access_vendor_pack_events (
			event_id, operation, status, release_profile_id, source_sha256, attribute_count,
			native_semantic_mappings, typed_passthrough_mappings, sensitive_redacted_mappings, grammar_rule_count,
			software_certified_mappings, software_blocked_mappings, external_required_mappings,
			vendor_count, product_scope_count, fingerprint, summary_json, report_json, actor, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(event_id) DO UPDATE SET
			operation = excluded.operation,
			status = excluded.status,
			release_profile_id = excluded.release_profile_id,
			source_sha256 = excluded.source_sha256,
			attribute_count = excluded.attribute_count,
			native_semantic_mappings = excluded.native_semantic_mappings,
			typed_passthrough_mappings = excluded.typed_passthrough_mappings,
			sensitive_redacted_mappings = excluded.sensitive_redacted_mappings,
			grammar_rule_count = excluded.grammar_rule_count,
			software_certified_mappings = excluded.software_certified_mappings,
			software_blocked_mappings = excluded.software_blocked_mappings,
			external_required_mappings = excluded.external_required_mappings,
			vendor_count = excluded.vendor_count,
			product_scope_count = excluded.product_scope_count,
			fingerprint = excluded.fingerprint,
			summary_json = excluded.summary_json,
			report_json = excluded.report_json,
			actor = excluded.actor`,
		input.EventID,
		input.Operation,
		input.Status,
		strings.TrimSpace(input.ReleaseProfileID),
		strings.TrimSpace(input.SourceSHA256),
		nonNegativeInt(input.AttributeCount),
		nonNegativeInt(input.NativeSemanticMappings),
		nonNegativeInt(input.TypedPassThroughMappings),
		nonNegativeInt(input.SensitiveRedactedMappings),
		nonNegativeInt(input.GrammarRuleCount),
		nonNegativeInt(input.SoftwareCertifiedMappings),
		nonNegativeInt(input.SoftwareBlockedMappings),
		nonNegativeInt(input.ExternalRequiredMappings),
		nonNegativeInt(input.VendorCount),
		nonNegativeInt(input.ProductScopeCount),
		strings.TrimSpace(input.Fingerprint),
		input.SummaryJSON,
		input.ReportJSON,
		nullString(strings.TrimSpace(input.Actor)),
	)
	if err != nil {
		return "", fmt.Errorf("record access vendor pack event: %w", err)
	}
	return input.EventID, nil
}

func ListAccessVendorPackEvents(limit int) ([]AccessVendorPackEvent, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := DB.Query(accessVendorPackSelectSQL()+` ORDER BY datetime(created_at) DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list access vendor pack events: %w", err)
	}
	defer rows.Close()
	events := []AccessVendorPackEvent{}
	for rows.Next() {
		event, scanErr := scanAccessVendorPackEvent(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list access vendor pack rows: %w", err)
	}
	return events, nil
}

func GetAccessVendorPackSummary() (AccessVendorPackDBSummary, error) {
	if DB == nil {
		return AccessVendorPackDBSummary{}, nil
	}
	var summary AccessVendorPackDBSummary
	err := DB.QueryRow(`SELECT
			COUNT(*),
			COALESCE(SUM(CASE WHEN status = 'recorded' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END), 0),
			COALESCE(MAX(created_at), '')
		FROM access_vendor_pack_events`).Scan(
		&summary.TotalEvents,
		&summary.RecordedCount,
		&summary.BlockedCount,
		&summary.FailedCount,
		&summary.LastEventAt,
	)
	if err != nil {
		if tableMissing(err) {
			return AccessVendorPackDBSummary{}, nil
		}
		return AccessVendorPackDBSummary{}, fmt.Errorf("summarize access vendor pack events: %w", err)
	}
	row := DB.QueryRow(`SELECT fingerprint, attribute_count, software_certified_mappings, external_required_mappings, vendor_count, product_scope_count, release_profile_id, source_sha256
		FROM access_vendor_pack_events
		ORDER BY datetime(created_at) DESC, id DESC LIMIT 1`)
	err = row.Scan(
		&summary.LastFingerprint,
		&summary.LastAttributeCount,
		&summary.LastSoftwareCertified,
		&summary.LastExternalRequired,
		&summary.LastVendorCount,
		&summary.LastProductScopeCount,
		&summary.LastReleaseProfileID,
		&summary.LastSourceSHA256,
	)
	if err != nil && err != sql.ErrNoRows {
		return AccessVendorPackDBSummary{}, fmt.Errorf("read latest access vendor pack event: %w", err)
	}
	return summary, nil
}

func scanAccessVendorPackEvent(scanner interface {
	Scan(dest ...any) error
}) (AccessVendorPackEvent, error) {
	var event AccessVendorPackEvent
	var actor sql.NullString
	err := scanner.Scan(
		&event.ID,
		&event.EventID,
		&event.Operation,
		&event.Status,
		&event.ReleaseProfileID,
		&event.SourceSHA256,
		&event.AttributeCount,
		&event.NativeSemanticMappings,
		&event.TypedPassThroughMappings,
		&event.SensitiveRedactedMappings,
		&event.GrammarRuleCount,
		&event.SoftwareCertifiedMappings,
		&event.SoftwareBlockedMappings,
		&event.ExternalRequiredMappings,
		&event.VendorCount,
		&event.ProductScopeCount,
		&event.Fingerprint,
		&event.SummaryJSON,
		&event.ReportJSON,
		&actor,
		&event.CreatedAt,
	)
	if err != nil {
		return AccessVendorPackEvent{}, fmt.Errorf("scan access vendor pack event: %w", err)
	}
	if actor.Valid {
		event.Actor = actor.String
	}
	return event, nil
}

func accessVendorPackSelectSQL() string {
	return `SELECT id, event_id, operation, status, release_profile_id, source_sha256,
		attribute_count, native_semantic_mappings, typed_passthrough_mappings, sensitive_redacted_mappings, grammar_rule_count,
		software_certified_mappings, software_blocked_mappings, external_required_mappings,
		vendor_count, product_scope_count, fingerprint, summary_json, report_json, actor, created_at
		FROM access_vendor_pack_events`
}

func normalizeAccessVendorPackOperation(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "record", "scan", "release_gate":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "record"
	}
}

func normalizeAccessVendorPackStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "recorded", "blocked", "failed":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "recorded"
	}
}

func newAccessVendorPackEventID(input AccessVendorPackEventInput) string {
	random := make([]byte, 8)
	if _, err := rand.Read(random); err == nil {
		return "nas-0067-" + hex.EncodeToString(random)
	}
	sum := sha256.Sum256([]byte(strings.Join([]string{
		input.Operation,
		input.ReleaseProfileID,
		input.SourceSHA256,
		input.Fingerprint,
	}, "\x00")))
	return "nas-0067-" + hex.EncodeToString(sum[:8])
}
