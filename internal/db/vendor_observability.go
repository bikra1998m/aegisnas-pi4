package db

import (
	"fmt"
	"strings"
)

type VendorObservabilityDelta struct {
	VendorKey                 string
	NASType                   string
	AuthSuccessDelta          int
	AuthFailureDelta          int
	VSAParsedDelta            int
	VSAParseFailureDelta      int
	UnsupportedAttributeDelta int
	CoASuccessDelta           int
	CoAFailureDelta           int
	DisconnectSuccessDelta    int
	DisconnectFailureDelta    int
	Message                   string
}

type VendorObservabilityRecord struct {
	VendorKey                 string `json:"vendor_key"`
	NASType                   string `json:"nas_type"`
	AuthSuccessCount          int    `json:"auth_success_count"`
	AuthFailureCount          int    `json:"auth_failure_count"`
	VSAParsedCount            int    `json:"vsa_parsed_count"`
	VSAParseFailureCount      int    `json:"vsa_parse_failure_count"`
	UnsupportedAttributeCount int    `json:"unsupported_attribute_count"`
	CoASuccessCount           int    `json:"coa_success_count"`
	CoAFailureCount           int    `json:"coa_failure_count"`
	DisconnectSuccessCount    int    `json:"disconnect_success_count"`
	DisconnectFailureCount    int    `json:"disconnect_failure_count"`
	CompatibilityScore        int    `json:"compatibility_score"`
	LastMessage               string `json:"last_message"`
	LastEventAt               string `json:"last_event_at"`
}

type VendorObservabilitySummary struct {
	TotalVendors              int    `json:"total_vendors"`
	AuthSuccessCount          int    `json:"auth_success_count"`
	AuthFailureCount          int    `json:"auth_failure_count"`
	VSAParsedCount            int    `json:"vsa_parsed_count"`
	VSAParseFailureCount      int    `json:"vsa_parse_failure_count"`
	UnsupportedAttributeCount int    `json:"unsupported_attribute_count"`
	CoASuccessCount           int    `json:"coa_success_count"`
	CoAFailureCount           int    `json:"coa_failure_count"`
	DisconnectSuccessCount    int    `json:"disconnect_success_count"`
	DisconnectFailureCount    int    `json:"disconnect_failure_count"`
	CompatibilityScore        int    `json:"compatibility_score"`
	WorstVendorKey            string `json:"worst_vendor_key,omitempty"`
	LastEventAt               string `json:"last_event_at,omitempty"`
}

func RecordVendorObservability(delta VendorObservabilityDelta) error {
	if DB == nil {
		return nil
	}
	delta.VendorKey = normalizeVendorObservabilityKey(delta.VendorKey)
	delta.NASType = normalizeVendorObservabilityNASType(delta.NASType)
	if delta.VendorKey == "" {
		return nil
	}
	if delta.AuthSuccessDelta == 0 &&
		delta.AuthFailureDelta == 0 &&
		delta.VSAParsedDelta == 0 &&
		delta.VSAParseFailureDelta == 0 &&
		delta.UnsupportedAttributeDelta == 0 &&
		delta.CoASuccessDelta == 0 &&
		delta.CoAFailureDelta == 0 &&
		delta.DisconnectSuccessDelta == 0 &&
		delta.DisconnectFailureDelta == 0 {
		return nil
	}

	_, err := DB.Exec(`INSERT INTO vendor_observability (
			vendor_key, nas_type, auth_success_count, auth_failure_count,
			vsa_parsed_count, vsa_parse_failure_count, unsupported_attribute_count,
			coa_success_count, coa_failure_count, disconnect_success_count, disconnect_failure_count,
			last_message, last_event_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(vendor_key, nas_type) DO UPDATE SET
			auth_success_count = auth_success_count + excluded.auth_success_count,
			auth_failure_count = auth_failure_count + excluded.auth_failure_count,
			vsa_parsed_count = vsa_parsed_count + excluded.vsa_parsed_count,
			vsa_parse_failure_count = vsa_parse_failure_count + excluded.vsa_parse_failure_count,
			unsupported_attribute_count = unsupported_attribute_count + excluded.unsupported_attribute_count,
			coa_success_count = coa_success_count + excluded.coa_success_count,
			coa_failure_count = coa_failure_count + excluded.coa_failure_count,
			disconnect_success_count = disconnect_success_count + excluded.disconnect_success_count,
			disconnect_failure_count = disconnect_failure_count + excluded.disconnect_failure_count,
			last_message = excluded.last_message,
			last_event_at = CURRENT_TIMESTAMP`,
		delta.VendorKey,
		delta.NASType,
		positiveDelta(delta.AuthSuccessDelta),
		positiveDelta(delta.AuthFailureDelta),
		positiveDelta(delta.VSAParsedDelta),
		positiveDelta(delta.VSAParseFailureDelta),
		positiveDelta(delta.UnsupportedAttributeDelta),
		positiveDelta(delta.CoASuccessDelta),
		positiveDelta(delta.CoAFailureDelta),
		positiveDelta(delta.DisconnectSuccessDelta),
		positiveDelta(delta.DisconnectFailureDelta),
		strings.TrimSpace(delta.Message),
	)
	if err != nil {
		return fmt.Errorf("record vendor observability: %w", err)
	}
	return nil
}

func ListVendorObservability(limit int) ([]VendorObservabilityRecord, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	rows, err := DB.Query(`SELECT vendor_key, nas_type,
			COALESCE(auth_success_count, 0), COALESCE(auth_failure_count, 0),
			COALESCE(vsa_parsed_count, 0), COALESCE(vsa_parse_failure_count, 0),
			COALESCE(unsupported_attribute_count, 0),
			COALESCE(coa_success_count, 0), COALESCE(coa_failure_count, 0),
			COALESCE(disconnect_success_count, 0), COALESCE(disconnect_failure_count, 0),
			COALESCE(last_message, ''), COALESCE(last_event_at, '')
		FROM vendor_observability
		ORDER BY datetime(last_event_at) DESC, vendor_key, nas_type
		LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list vendor observability: %w", err)
	}
	defer rows.Close()

	records := []VendorObservabilityRecord{}
	for rows.Next() {
		var item VendorObservabilityRecord
		if err := rows.Scan(
			&item.VendorKey,
			&item.NASType,
			&item.AuthSuccessCount,
			&item.AuthFailureCount,
			&item.VSAParsedCount,
			&item.VSAParseFailureCount,
			&item.UnsupportedAttributeCount,
			&item.CoASuccessCount,
			&item.CoAFailureCount,
			&item.DisconnectSuccessCount,
			&item.DisconnectFailureCount,
			&item.LastMessage,
			&item.LastEventAt,
		); err != nil {
			return nil, fmt.Errorf("scan vendor observability: %w", err)
		}
		item.CompatibilityScore = vendorCompatibilityScore(item)
		records = append(records, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate vendor observability: %w", err)
	}
	return records, nil
}

func GetVendorObservabilitySummary() (VendorObservabilitySummary, error) {
	records, err := ListVendorObservability(1000)
	if err != nil {
		return VendorObservabilitySummary{}, err
	}
	summary := VendorObservabilitySummary{}
	if len(records) == 0 {
		summary.CompatibilityScore = 100
		return summary, nil
	}

	worstScore := 101
	totalScore := 0
	for _, item := range records {
		summary.TotalVendors++
		summary.AuthSuccessCount += item.AuthSuccessCount
		summary.AuthFailureCount += item.AuthFailureCount
		summary.VSAParsedCount += item.VSAParsedCount
		summary.VSAParseFailureCount += item.VSAParseFailureCount
		summary.UnsupportedAttributeCount += item.UnsupportedAttributeCount
		summary.CoASuccessCount += item.CoASuccessCount
		summary.CoAFailureCount += item.CoAFailureCount
		summary.DisconnectSuccessCount += item.DisconnectSuccessCount
		summary.DisconnectFailureCount += item.DisconnectFailureCount
		totalScore += item.CompatibilityScore
		if item.CompatibilityScore < worstScore {
			worstScore = item.CompatibilityScore
			summary.WorstVendorKey = item.VendorKey
		}
		if summary.LastEventAt == "" || item.LastEventAt > summary.LastEventAt {
			summary.LastEventAt = item.LastEventAt
		}
	}
	summary.CompatibilityScore = totalScore / len(records)
	return summary, nil
}

func vendorCompatibilityScore(item VendorObservabilityRecord) int {
	successes := item.AuthSuccessCount + item.VSAParsedCount + item.CoASuccessCount + item.DisconnectSuccessCount
	failures := item.AuthFailureCount + item.VSAParseFailureCount + item.UnsupportedAttributeCount + item.CoAFailureCount + item.DisconnectFailureCount
	total := successes + failures
	if total == 0 {
		return 100
	}
	score := 100 - ((failures * 100) / total)
	if item.UnsupportedAttributeCount > 0 {
		score -= 5
	}
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

func normalizeVendorObservabilityKey(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, " ", "-")
	return value
}

func normalizeVendorObservabilityNASType(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "global"
	}
	return value
}

func positiveDelta(value int) int {
	if value < 0 {
		return 0
	}
	return value
}
