package db

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

type VendorMappingCertificationEventInput struct {
	EventID                  string
	Operation                string
	Status                   string
	ReleaseProfileID         string
	SourceSHA256             string
	BaselinePartialMappings  int
	CertifiedMappings        int
	SoftwareBlockedMappings  int
	ExternalRequiredMappings int
	VendorCount              int
	Fingerprint              string
	SummaryJSON              string
	ReportJSON               string
	Actor                    string
}

type VendorMappingCertificationEvent struct {
	ID                       int    `json:"id"`
	EventID                  string `json:"event_id"`
	Operation                string `json:"operation"`
	Status                   string `json:"status"`
	ReleaseProfileID         string `json:"release_profile_id"`
	SourceSHA256             string `json:"source_sha256"`
	BaselinePartialMappings  int    `json:"baseline_partial_mappings"`
	CertifiedMappings        int    `json:"certified_mappings"`
	SoftwareBlockedMappings  int    `json:"software_blocked_mappings"`
	ExternalRequiredMappings int    `json:"external_required_mappings"`
	VendorCount              int    `json:"vendor_count"`
	Fingerprint              string `json:"fingerprint"`
	SummaryJSON              string `json:"summary_json"`
	ReportJSON               string `json:"report_json,omitempty"`
	Actor                    string `json:"actor,omitempty"`
	CreatedAt                string `json:"created_at"`
}

type VendorMappingCertificationDBSummary struct {
	TotalEvents              int    `json:"total_events"`
	RecordedCount            int    `json:"recorded_count"`
	BlockedCount             int    `json:"blocked_count"`
	FailedCount              int    `json:"failed_count"`
	LastEventAt              string `json:"last_event_at,omitempty"`
	LastFingerprint          string `json:"last_fingerprint,omitempty"`
	LastCertifiedMappings    int    `json:"last_certified_mappings"`
	LastExternalRequired     int    `json:"last_external_required_mappings"`
	LastReleaseProfileID     string `json:"last_release_profile_id,omitempty"`
	LastSourceSHA256         string `json:"last_source_sha256,omitempty"`
	LastBaselinePartialCount int    `json:"last_baseline_partial_mappings"`
}

func RecordVendorMappingCertificationEvent(input VendorMappingCertificationEventInput) (string, error) {
	if DB == nil {
		return "", nil
	}
	input.Operation = normalizeVendorMappingCertificationOperation(input.Operation)
	input.Status = normalizeVendorMappingCertificationStatus(input.Status)
	input.EventID = strings.TrimSpace(input.EventID)
	if input.EventID == "" {
		input.EventID = newVendorMappingCertificationEventID(input)
	}
	if input.Operation == "" || input.Status == "" {
		return "", fmt.Errorf("vendor mapping certification operation and status are required")
	}
	if strings.TrimSpace(input.ReleaseProfileID) == "" || strings.TrimSpace(input.SourceSHA256) == "" {
		return "", fmt.Errorf("vendor mapping certification release profile and source hash are required")
	}
	if strings.TrimSpace(input.Fingerprint) == "" {
		return "", fmt.Errorf("vendor mapping certification fingerprint is required")
	}
	if strings.TrimSpace(input.SummaryJSON) == "" {
		input.SummaryJSON = "{}"
	}
	if strings.TrimSpace(input.ReportJSON) == "" {
		input.ReportJSON = "{}"
	}

	_, err := DB.Exec(`INSERT INTO vendor_mapping_certification_events (
			event_id, operation, status, release_profile_id, source_sha256, baseline_partial_mappings,
			certified_mappings, software_blocked_mappings, external_required_mappings, vendor_count,
			fingerprint, summary_json, report_json, actor, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(event_id) DO UPDATE SET
			operation = excluded.operation,
			status = excluded.status,
			release_profile_id = excluded.release_profile_id,
			source_sha256 = excluded.source_sha256,
			baseline_partial_mappings = excluded.baseline_partial_mappings,
			certified_mappings = excluded.certified_mappings,
			software_blocked_mappings = excluded.software_blocked_mappings,
			external_required_mappings = excluded.external_required_mappings,
			vendor_count = excluded.vendor_count,
			fingerprint = excluded.fingerprint,
			summary_json = excluded.summary_json,
			report_json = excluded.report_json,
			actor = excluded.actor`,
		input.EventID,
		input.Operation,
		input.Status,
		strings.TrimSpace(input.ReleaseProfileID),
		strings.TrimSpace(input.SourceSHA256),
		nonNegativeInt(input.BaselinePartialMappings),
		nonNegativeInt(input.CertifiedMappings),
		nonNegativeInt(input.SoftwareBlockedMappings),
		nonNegativeInt(input.ExternalRequiredMappings),
		nonNegativeInt(input.VendorCount),
		strings.TrimSpace(input.Fingerprint),
		input.SummaryJSON,
		input.ReportJSON,
		nullString(strings.TrimSpace(input.Actor)),
	)
	if err != nil {
		return "", fmt.Errorf("record vendor mapping certification event: %w", err)
	}
	return input.EventID, nil
}

func ListVendorMappingCertificationEvents(limit int) ([]VendorMappingCertificationEvent, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := DB.Query(vendorMappingCertificationSelectSQL()+` ORDER BY datetime(created_at) DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list vendor mapping certification events: %w", err)
	}
	defer rows.Close()

	var events []VendorMappingCertificationEvent
	for rows.Next() {
		event, scanErr := scanVendorMappingCertificationEvent(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list vendor mapping certification rows: %w", err)
	}
	return events, nil
}

func GetVendorMappingCertificationSummary() (VendorMappingCertificationDBSummary, error) {
	if DB == nil {
		return VendorMappingCertificationDBSummary{}, nil
	}
	var summary VendorMappingCertificationDBSummary
	err := DB.QueryRow(`SELECT
			COUNT(*),
			COALESCE(SUM(CASE WHEN status = 'recorded' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END), 0),
			COALESCE(MAX(created_at), '')
		FROM vendor_mapping_certification_events`).Scan(
		&summary.TotalEvents,
		&summary.RecordedCount,
		&summary.BlockedCount,
		&summary.FailedCount,
		&summary.LastEventAt,
	)
	if err != nil {
		if tableMissing(err) {
			return VendorMappingCertificationDBSummary{}, nil
		}
		return VendorMappingCertificationDBSummary{}, fmt.Errorf("summarize vendor mapping certification events: %w", err)
	}
	row := DB.QueryRow(`SELECT fingerprint, certified_mappings, external_required_mappings, release_profile_id, source_sha256, baseline_partial_mappings
		FROM vendor_mapping_certification_events
		ORDER BY datetime(created_at) DESC, id DESC LIMIT 1`)
	err = row.Scan(
		&summary.LastFingerprint,
		&summary.LastCertifiedMappings,
		&summary.LastExternalRequired,
		&summary.LastReleaseProfileID,
		&summary.LastSourceSHA256,
		&summary.LastBaselinePartialCount,
	)
	if err != nil && err != sql.ErrNoRows {
		return VendorMappingCertificationDBSummary{}, fmt.Errorf("read latest vendor mapping certification event: %w", err)
	}
	return summary, nil
}

func scanVendorMappingCertificationEvent(scanner interface {
	Scan(dest ...any) error
}) (VendorMappingCertificationEvent, error) {
	var event VendorMappingCertificationEvent
	var actor sql.NullString
	err := scanner.Scan(
		&event.ID,
		&event.EventID,
		&event.Operation,
		&event.Status,
		&event.ReleaseProfileID,
		&event.SourceSHA256,
		&event.BaselinePartialMappings,
		&event.CertifiedMappings,
		&event.SoftwareBlockedMappings,
		&event.ExternalRequiredMappings,
		&event.VendorCount,
		&event.Fingerprint,
		&event.SummaryJSON,
		&event.ReportJSON,
		&actor,
		&event.CreatedAt,
	)
	if err != nil {
		return VendorMappingCertificationEvent{}, fmt.Errorf("scan vendor mapping certification event: %w", err)
	}
	if actor.Valid {
		event.Actor = actor.String
	}
	return event, nil
}

func vendorMappingCertificationSelectSQL() string {
	return `SELECT id, event_id, operation, status, release_profile_id, source_sha256,
		baseline_partial_mappings, certified_mappings, software_blocked_mappings, external_required_mappings,
		vendor_count, fingerprint, summary_json, report_json, actor, created_at
		FROM vendor_mapping_certification_events`
}

func normalizeVendorMappingCertificationOperation(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "record", "scan", "release_gate":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "record"
	}
}

func normalizeVendorMappingCertificationStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "recorded", "blocked", "failed":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "recorded"
	}
}

func newVendorMappingCertificationEventID(input VendorMappingCertificationEventInput) string {
	var nonce [8]byte
	_, _ = rand.Read(nonce[:])
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%s:%s:%d:%x",
		input.Operation,
		input.Status,
		input.Fingerprint,
		input.SourceSHA256,
		time.Now().UTC().UnixNano(),
		nonce,
	)))
	return "vmapcert-" + hex.EncodeToString(sum[:12])
}
