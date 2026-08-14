package db

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

type VLANPolicyEventInput struct {
	EventID         string
	Operation       string
	Status          string
	Role            string
	PoolName        string
	EffectiveVLAN   int
	DataVLAN        int
	VoiceVLAN       int
	TaggedVLANCount int
	QinQOuterVLAN   int
	QinQInnerVLAN   int
	FallbackVLAN    int
	AuthFailVLAN    int
	AttributeCount  int
	DiagnosticCount int
	Fingerprint     string
	RequestJSON     string
	ResponseJSON    string
	DiagnosticsJSON string
	Actor           string
}

type VLANPolicyEvent struct {
	ID              int    `json:"id"`
	EventID         string `json:"event_id"`
	Operation       string `json:"operation"`
	Status          string `json:"status"`
	Role            string `json:"role,omitempty"`
	PoolName        string `json:"pool_name,omitempty"`
	EffectiveVLAN   int    `json:"effective_vlan"`
	DataVLAN        int    `json:"data_vlan"`
	VoiceVLAN       int    `json:"voice_vlan"`
	TaggedVLANCount int    `json:"tagged_vlan_count"`
	QinQOuterVLAN   int    `json:"qinq_outer_vlan"`
	QinQInnerVLAN   int    `json:"qinq_inner_vlan"`
	FallbackVLAN    int    `json:"fallback_vlan"`
	AuthFailVLAN    int    `json:"auth_fail_vlan"`
	AttributeCount  int    `json:"attribute_count"`
	DiagnosticCount int    `json:"diagnostic_count"`
	Fingerprint     string `json:"fingerprint,omitempty"`
	RequestJSON     string `json:"request_json"`
	ResponseJSON    string `json:"response_json"`
	DiagnosticsJSON string `json:"diagnostics_json"`
	Actor           string `json:"actor,omitempty"`
	CreatedAt       string `json:"created_at"`
}

type VLANPolicyEventSummary struct {
	TotalEvents         int    `json:"total_events"`
	CompiledCount       int    `json:"compiled_count"`
	PreviewedCount      int    `json:"previewed_count"`
	DecompiledCount     int    `json:"decompiled_count"`
	BlockedCount        int    `json:"blocked_count"`
	DegradedCount       int    `json:"degraded_count"`
	FailedCount         int    `json:"failed_count"`
	LastEventAt         string `json:"last_event_at,omitempty"`
	LastStatus          string `json:"last_status,omitempty"`
	LastRole            string `json:"last_role,omitempty"`
	LastEffectiveVLAN   int    `json:"last_effective_vlan"`
	LastAttributeCount  int    `json:"last_attribute_count"`
	LastDiagnosticCount int    `json:"last_diagnostic_count"`
}

func RecordVLANPolicyEvent(input VLANPolicyEventInput) (string, error) {
	if DB == nil {
		return "", nil
	}
	input.Operation = normalizeVLANPolicyOperation(input.Operation)
	input.Status = normalizeVLANPolicyStatus(input.Status)
	if input.Operation == "" || input.Status == "" {
		return "", fmt.Errorf("VLAN policy operation and status are required")
	}
	input.EventID = strings.TrimSpace(input.EventID)
	if input.EventID == "" {
		input.EventID = newVLANPolicyEventID(input.Operation, input.Status, input.ResponseJSON)
	}
	if strings.TrimSpace(input.RequestJSON) == "" {
		input.RequestJSON = "{}"
	}
	if strings.TrimSpace(input.ResponseJSON) == "" {
		input.ResponseJSON = "{}"
	}
	if strings.TrimSpace(input.DiagnosticsJSON) == "" {
		input.DiagnosticsJSON = "[]"
	}
	_, err := DB.Exec(`INSERT INTO vlan_policy_events (
			event_id, operation, status, role, pool_name, effective_vlan, data_vlan, voice_vlan,
			tagged_vlan_count, qinq_outer_vlan, qinq_inner_vlan, fallback_vlan, auth_fail_vlan,
			attribute_count, diagnostic_count, fingerprint, request_json, response_json,
			diagnostics_json, actor, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		input.EventID,
		input.Operation,
		input.Status,
		nullString(strings.TrimSpace(input.Role)),
		nullString(strings.TrimSpace(input.PoolName)),
		nonNegativeInt(input.EffectiveVLAN),
		nonNegativeInt(input.DataVLAN),
		nonNegativeInt(input.VoiceVLAN),
		nonNegativeInt(input.TaggedVLANCount),
		nonNegativeInt(input.QinQOuterVLAN),
		nonNegativeInt(input.QinQInnerVLAN),
		nonNegativeInt(input.FallbackVLAN),
		nonNegativeInt(input.AuthFailVLAN),
		nonNegativeInt(input.AttributeCount),
		nonNegativeInt(input.DiagnosticCount),
		nullString(strings.TrimSpace(input.Fingerprint)),
		input.RequestJSON,
		input.ResponseJSON,
		input.DiagnosticsJSON,
		nullString(strings.TrimSpace(input.Actor)),
	)
	if err != nil {
		return "", fmt.Errorf("record VLAN policy event: %w", err)
	}
	return input.EventID, nil
}

func ListVLANPolicyEvents(limit int) ([]VLANPolicyEvent, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := DB.Query(`SELECT id, event_id, operation, status, COALESCE(role, ''), COALESCE(pool_name, ''),
			effective_vlan, data_vlan, voice_vlan, tagged_vlan_count, qinq_outer_vlan, qinq_inner_vlan,
			fallback_vlan, auth_fail_vlan, attribute_count, diagnostic_count, COALESCE(fingerprint, ''),
			request_json, response_json, diagnostics_json, COALESCE(actor, ''), COALESCE(CAST(created_at AS TEXT), '')
		FROM vlan_policy_events
		ORDER BY datetime(created_at) DESC, id DESC
		LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list VLAN policy events: %w", err)
	}
	defer rows.Close()
	var events []VLANPolicyEvent
	for rows.Next() {
		var event VLANPolicyEvent
		if err := rows.Scan(
			&event.ID,
			&event.EventID,
			&event.Operation,
			&event.Status,
			&event.Role,
			&event.PoolName,
			&event.EffectiveVLAN,
			&event.DataVLAN,
			&event.VoiceVLAN,
			&event.TaggedVLANCount,
			&event.QinQOuterVLAN,
			&event.QinQInnerVLAN,
			&event.FallbackVLAN,
			&event.AuthFailVLAN,
			&event.AttributeCount,
			&event.DiagnosticCount,
			&event.Fingerprint,
			&event.RequestJSON,
			&event.ResponseJSON,
			&event.DiagnosticsJSON,
			&event.Actor,
			&event.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan VLAN policy event: %w", err)
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func GetVLANPolicyEventSummary() (VLANPolicyEventSummary, error) {
	events, err := ListVLANPolicyEvents(1000)
	if err != nil {
		return VLANPolicyEventSummary{}, err
	}
	summary := VLANPolicyEventSummary{}
	for _, event := range events {
		summary.TotalEvents++
		switch event.Status {
		case "compiled":
			summary.CompiledCount++
		case "previewed":
			summary.PreviewedCount++
		case "decompiled":
			summary.DecompiledCount++
		case "blocked":
			summary.BlockedCount++
		case "degraded":
			summary.DegradedCount++
		case "failed":
			summary.FailedCount++
		}
		if summary.LastEventAt == "" || event.CreatedAt > summary.LastEventAt {
			summary.LastEventAt = event.CreatedAt
			summary.LastStatus = event.Status
			summary.LastRole = event.Role
			summary.LastEffectiveVLAN = event.EffectiveVLAN
			summary.LastAttributeCount = event.AttributeCount
			summary.LastDiagnosticCount = event.DiagnosticCount
		}
	}
	return summary, nil
}

func normalizeVLANPolicyOperation(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "compile", "preview", "decompile":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeVLANPolicyStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "compiled", "previewed", "decompiled", "blocked", "degraded", "failed":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func newVLANPolicyEventID(operation, status, responseJSON string) string {
	var nonce [8]byte
	_, _ = rand.Read(nonce[:])
	sum := sha256.Sum256([]byte(fmt.Sprintf("vlan-policy:%s:%s:%s:%d:%x",
		operation,
		status,
		responseJSON,
		time.Now().UTC().UnixNano(),
		nonce,
	)))
	return "vlan-policy-" + hex.EncodeToString(sum[:12])
}
