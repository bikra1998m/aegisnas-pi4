package db

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
)

type ExternalVendorIntakeEventInput struct {
	EventID                    string
	Operation                  string
	Status                     string
	ReleaseProfileID           string
	ReleaseSourceSHA256        string
	VendorName                 string
	PEN                        uint32
	PackKey                    string
	DictionaryName             string
	SourceURL                  string
	DictionarySHA256           string
	LicenseID                  string
	LicenseState               string
	ProvenanceState            string
	PENState                   string
	SemanticState              string
	AttributeCount             int
	RuntimeDecodableAttributes int
	MetadataOnlyAttributes     int
	NativeSemanticMappings     int
	TypedPassthroughMappings   int
	SensitiveRedactedMappings  int
	SoftwareReadyAttributes    int
	SoftwareBlockedAttributes  int
	ExternalRequiredAttributes int
	Fingerprint                string
	SummaryJSON                string
	ReportJSON                 string
	Actor                      string
}

type ExternalVendorIntakeEvent struct {
	ID                         int    `json:"id"`
	EventID                    string `json:"event_id"`
	Operation                  string `json:"operation"`
	Status                     string `json:"status"`
	ReleaseProfileID           string `json:"release_profile_id"`
	ReleaseSourceSHA256        string `json:"release_source_sha256"`
	VendorName                 string `json:"vendor_name"`
	PEN                        uint32 `json:"pen"`
	PackKey                    string `json:"pack_key"`
	DictionaryName             string `json:"dictionary_name,omitempty"`
	SourceURL                  string `json:"source_url,omitempty"`
	DictionarySHA256           string `json:"dictionary_sha256"`
	LicenseID                  string `json:"license_id"`
	LicenseState               string `json:"license_state"`
	ProvenanceState            string `json:"provenance_state"`
	PENState                   string `json:"pen_state"`
	SemanticState              string `json:"semantic_state"`
	AttributeCount             int    `json:"attribute_count"`
	RuntimeDecodableAttributes int    `json:"runtime_decodable_attributes"`
	MetadataOnlyAttributes     int    `json:"metadata_only_attributes"`
	NativeSemanticMappings     int    `json:"native_semantic_mappings"`
	TypedPassthroughMappings   int    `json:"typed_passthrough_mappings"`
	SensitiveRedactedMappings  int    `json:"sensitive_redacted_mappings"`
	SoftwareReadyAttributes    int    `json:"software_ready_attributes"`
	SoftwareBlockedAttributes  int    `json:"software_blocked_attributes"`
	ExternalRequiredAttributes int    `json:"external_required_attributes"`
	Fingerprint                string `json:"fingerprint"`
	SummaryJSON                string `json:"summary_json"`
	ReportJSON                 string `json:"report_json,omitempty"`
	Actor                      string `json:"actor,omitempty"`
	CreatedAt                  string `json:"created_at"`
}

type ExternalVendorIntakeDBSummary struct {
	TotalEvents                    int    `json:"total_events"`
	RecordedCount                  int    `json:"recorded_count"`
	BlockedCount                   int    `json:"blocked_count"`
	FailedCount                    int    `json:"failed_count"`
	LastEventAt                    string `json:"last_event_at,omitempty"`
	LastFingerprint                string `json:"last_fingerprint,omitempty"`
	LastVendorName                 string `json:"last_vendor_name,omitempty"`
	LastPEN                        uint32 `json:"last_pen,omitempty"`
	LastPackKey                    string `json:"last_pack_key,omitempty"`
	LastDictionarySHA256           string `json:"last_dictionary_sha256,omitempty"`
	LastAttributeCount             int    `json:"last_attribute_count"`
	LastSoftwareReadyAttributes    int    `json:"last_software_ready_attributes"`
	LastExternalRequiredAttributes int    `json:"last_external_required_attributes"`
	LastReleaseProfileID           string `json:"last_release_profile_id,omitempty"`
	LastReleaseSourceSHA256        string `json:"last_release_source_sha256,omitempty"`
}

func RecordExternalVendorIntakeEvent(input ExternalVendorIntakeEventInput) (string, error) {
	if DB == nil {
		return "", nil
	}
	input.Operation = normalizeExternalVendorIntakeOperation(input.Operation)
	input.Status = normalizeExternalVendorIntakeStatus(input.Status)
	input.EventID = strings.TrimSpace(input.EventID)
	if input.EventID == "" {
		input.EventID = newExternalVendorIntakeEventID(input)
	}
	if input.Operation == "" || input.Status == "" {
		return "", fmt.Errorf("external vendor intake operation and status are required")
	}
	if strings.TrimSpace(input.ReleaseProfileID) == "" || strings.TrimSpace(input.ReleaseSourceSHA256) == "" {
		return "", fmt.Errorf("external vendor intake release profile and source hash are required")
	}
	if strings.TrimSpace(input.VendorName) == "" || input.PEN == 0 || strings.TrimSpace(input.PackKey) == "" {
		return "", fmt.Errorf("external vendor intake vendor, PEN, and pack key are required")
	}
	if strings.TrimSpace(input.DictionarySHA256) == "" || strings.TrimSpace(input.Fingerprint) == "" {
		return "", fmt.Errorf("external vendor intake dictionary hash and fingerprint are required")
	}
	if strings.TrimSpace(input.SummaryJSON) == "" {
		input.SummaryJSON = "{}"
	}
	if strings.TrimSpace(input.ReportJSON) == "" {
		input.ReportJSON = "{}"
	}

	_, err := DB.Exec(`INSERT INTO external_vendor_intake_events (
			event_id, operation, status, release_profile_id, release_source_sha256,
			vendor_name, pen, pack_key, dictionary_name, source_url, dictionary_sha256,
			license_id, license_state, provenance_state, pen_state, semantic_state,
			attribute_count, runtime_decodable_attributes, metadata_only_attributes,
			native_semantic_mappings, typed_passthrough_mappings, sensitive_redacted_mappings,
			software_ready_attributes, software_blocked_attributes, external_required_attributes,
			fingerprint, summary_json, report_json, actor, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(event_id) DO UPDATE SET
			operation = excluded.operation,
			status = excluded.status,
			release_profile_id = excluded.release_profile_id,
			release_source_sha256 = excluded.release_source_sha256,
			vendor_name = excluded.vendor_name,
			pen = excluded.pen,
			pack_key = excluded.pack_key,
			dictionary_name = excluded.dictionary_name,
			source_url = excluded.source_url,
			dictionary_sha256 = excluded.dictionary_sha256,
			license_id = excluded.license_id,
			license_state = excluded.license_state,
			provenance_state = excluded.provenance_state,
			pen_state = excluded.pen_state,
			semantic_state = excluded.semantic_state,
			attribute_count = excluded.attribute_count,
			runtime_decodable_attributes = excluded.runtime_decodable_attributes,
			metadata_only_attributes = excluded.metadata_only_attributes,
			native_semantic_mappings = excluded.native_semantic_mappings,
			typed_passthrough_mappings = excluded.typed_passthrough_mappings,
			sensitive_redacted_mappings = excluded.sensitive_redacted_mappings,
			software_ready_attributes = excluded.software_ready_attributes,
			software_blocked_attributes = excluded.software_blocked_attributes,
			external_required_attributes = excluded.external_required_attributes,
			fingerprint = excluded.fingerprint,
			summary_json = excluded.summary_json,
			report_json = excluded.report_json,
			actor = excluded.actor`,
		input.EventID,
		input.Operation,
		input.Status,
		strings.TrimSpace(input.ReleaseProfileID),
		strings.TrimSpace(input.ReleaseSourceSHA256),
		strings.TrimSpace(input.VendorName),
		input.PEN,
		strings.TrimSpace(input.PackKey),
		nullString(strings.TrimSpace(input.DictionaryName)),
		nullString(strings.TrimSpace(input.SourceURL)),
		strings.TrimSpace(input.DictionarySHA256),
		strings.TrimSpace(input.LicenseID),
		strings.TrimSpace(input.LicenseState),
		strings.TrimSpace(input.ProvenanceState),
		strings.TrimSpace(input.PENState),
		strings.TrimSpace(input.SemanticState),
		nonNegativeInt(input.AttributeCount),
		nonNegativeInt(input.RuntimeDecodableAttributes),
		nonNegativeInt(input.MetadataOnlyAttributes),
		nonNegativeInt(input.NativeSemanticMappings),
		nonNegativeInt(input.TypedPassthroughMappings),
		nonNegativeInt(input.SensitiveRedactedMappings),
		nonNegativeInt(input.SoftwareReadyAttributes),
		nonNegativeInt(input.SoftwareBlockedAttributes),
		nonNegativeInt(input.ExternalRequiredAttributes),
		strings.TrimSpace(input.Fingerprint),
		input.SummaryJSON,
		input.ReportJSON,
		nullString(strings.TrimSpace(input.Actor)),
	)
	if err != nil {
		return "", fmt.Errorf("record external vendor intake event: %w", err)
	}
	return input.EventID, nil
}

func ListExternalVendorIntakeEvents(limit int) ([]ExternalVendorIntakeEvent, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := DB.Query(externalVendorIntakeSelectSQL()+` ORDER BY datetime(created_at) DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list external vendor intake events: %w", err)
	}
	defer rows.Close()
	events := []ExternalVendorIntakeEvent{}
	for rows.Next() {
		event, scanErr := scanExternalVendorIntakeEvent(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list external vendor intake rows: %w", err)
	}
	return events, nil
}

func GetExternalVendorIntakeSummary() (ExternalVendorIntakeDBSummary, error) {
	if DB == nil {
		return ExternalVendorIntakeDBSummary{}, nil
	}
	var summary ExternalVendorIntakeDBSummary
	err := DB.QueryRow(`SELECT
			COUNT(*),
			COALESCE(SUM(CASE WHEN status = 'recorded' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END), 0),
			COALESCE(MAX(created_at), '')
		FROM external_vendor_intake_events`).Scan(
		&summary.TotalEvents,
		&summary.RecordedCount,
		&summary.BlockedCount,
		&summary.FailedCount,
		&summary.LastEventAt,
	)
	if err != nil {
		if tableMissing(err) {
			return ExternalVendorIntakeDBSummary{}, nil
		}
		return ExternalVendorIntakeDBSummary{}, fmt.Errorf("summarize external vendor intake events: %w", err)
	}
	row := DB.QueryRow(`SELECT fingerprint, vendor_name, pen, pack_key, dictionary_sha256, attribute_count, software_ready_attributes, external_required_attributes, release_profile_id, release_source_sha256
		FROM external_vendor_intake_events
		ORDER BY datetime(created_at) DESC, id DESC LIMIT 1`)
	err = row.Scan(
		&summary.LastFingerprint,
		&summary.LastVendorName,
		&summary.LastPEN,
		&summary.LastPackKey,
		&summary.LastDictionarySHA256,
		&summary.LastAttributeCount,
		&summary.LastSoftwareReadyAttributes,
		&summary.LastExternalRequiredAttributes,
		&summary.LastReleaseProfileID,
		&summary.LastReleaseSourceSHA256,
	)
	if err != nil && err != sql.ErrNoRows {
		return ExternalVendorIntakeDBSummary{}, fmt.Errorf("read latest external vendor intake event: %w", err)
	}
	return summary, nil
}

func scanExternalVendorIntakeEvent(scanner interface {
	Scan(dest ...any) error
}) (ExternalVendorIntakeEvent, error) {
	var event ExternalVendorIntakeEvent
	var dictionaryName sql.NullString
	var sourceURL sql.NullString
	var actor sql.NullString
	err := scanner.Scan(
		&event.ID,
		&event.EventID,
		&event.Operation,
		&event.Status,
		&event.ReleaseProfileID,
		&event.ReleaseSourceSHA256,
		&event.VendorName,
		&event.PEN,
		&event.PackKey,
		&dictionaryName,
		&sourceURL,
		&event.DictionarySHA256,
		&event.LicenseID,
		&event.LicenseState,
		&event.ProvenanceState,
		&event.PENState,
		&event.SemanticState,
		&event.AttributeCount,
		&event.RuntimeDecodableAttributes,
		&event.MetadataOnlyAttributes,
		&event.NativeSemanticMappings,
		&event.TypedPassthroughMappings,
		&event.SensitiveRedactedMappings,
		&event.SoftwareReadyAttributes,
		&event.SoftwareBlockedAttributes,
		&event.ExternalRequiredAttributes,
		&event.Fingerprint,
		&event.SummaryJSON,
		&event.ReportJSON,
		&actor,
		&event.CreatedAt,
	)
	if err != nil {
		return ExternalVendorIntakeEvent{}, fmt.Errorf("scan external vendor intake event: %w", err)
	}
	if dictionaryName.Valid {
		event.DictionaryName = dictionaryName.String
	}
	if sourceURL.Valid {
		event.SourceURL = sourceURL.String
	}
	if actor.Valid {
		event.Actor = actor.String
	}
	return event, nil
}

func externalVendorIntakeSelectSQL() string {
	return `SELECT id, event_id, operation, status, release_profile_id, release_source_sha256,
		vendor_name, pen, pack_key, dictionary_name, source_url, dictionary_sha256,
		license_id, license_state, provenance_state, pen_state, semantic_state,
		attribute_count, runtime_decodable_attributes, metadata_only_attributes,
		native_semantic_mappings, typed_passthrough_mappings, sensitive_redacted_mappings,
		software_ready_attributes, software_blocked_attributes, external_required_attributes,
		fingerprint, summary_json, report_json, actor, created_at
		FROM external_vendor_intake_events`
}

func normalizeExternalVendorIntakeOperation(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "preview", "record", "release_gate":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "record"
	}
}

func normalizeExternalVendorIntakeStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "recorded", "blocked", "failed":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "recorded"
	}
}

func newExternalVendorIntakeEventID(input ExternalVendorIntakeEventInput) string {
	random := make([]byte, 8)
	if _, err := rand.Read(random); err == nil {
		return "nas-0073-" + hex.EncodeToString(random)
	}
	sum := sha256.Sum256([]byte(strings.Join([]string{
		input.Operation,
		input.ReleaseProfileID,
		input.ReleaseSourceSHA256,
		input.VendorName,
		input.DictionarySHA256,
		input.Fingerprint,
	}, "\x00")))
	return "nas-0073-" + hex.EncodeToString(sum[:8])
}
