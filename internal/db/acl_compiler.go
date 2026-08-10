package db

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

type ACLCompilerEventInput struct {
	Operation           string
	Status              string
	PackKey             string
	PolicyName          string
	ASTFingerprint      string
	ArtifactFingerprint string
	ArtifactCount       int
	RuleCount           int
	Lossless            bool
	DiagnosticsJSON     string
	DetailsJSON         string
	Actor               string
}

type ACLCompilerEvent struct {
	ID                  int    `json:"id"`
	EventID             string `json:"event_id"`
	Operation           string `json:"operation"`
	Status              string `json:"status"`
	PackKey             string `json:"pack_key"`
	PolicyName          string `json:"policy_name,omitempty"`
	ASTFingerprint      string `json:"ast_fingerprint,omitempty"`
	ArtifactFingerprint string `json:"artifact_fingerprint,omitempty"`
	ArtifactCount       int    `json:"artifact_count"`
	RuleCount           int    `json:"rule_count"`
	Lossless            bool   `json:"lossless"`
	DiagnosticsJSON     string `json:"diagnostics_json"`
	DetailsJSON         string `json:"details_json"`
	Actor               string `json:"actor,omitempty"`
	CreatedAt           string `json:"created_at"`
}

type ACLCompilerEventSummary struct {
	TotalEvents           int    `json:"total_events"`
	CompileEvents         int    `json:"compile_events"`
	DecompileEvents       int    `json:"decompile_events"`
	CompiledCount         int    `json:"compiled_count"`
	ProfileReferenceCount int    `json:"profile_reference_count"`
	DegradedCount         int    `json:"degraded_count"`
	BlockedCount          int    `json:"blocked_count"`
	UnsupportedCount      int    `json:"unsupported_count"`
	LosslessCount         int    `json:"lossless_count"`
	ArtifactCount         int    `json:"artifact_count"`
	LastEventAt           string `json:"last_event_at,omitempty"`
}

func RecordACLCompilerEvent(input ACLCompilerEventInput) (string, error) {
	if DB == nil {
		return "", nil
	}
	input.Operation = normalizeACLCompilerOperation(input.Operation)
	input.Status = normalizeACLCompilerStatus(input.Status)
	input.PackKey = strings.TrimSpace(input.PackKey)
	if input.Operation == "" || input.Status == "" || input.PackKey == "" {
		return "", fmt.Errorf("operation, status, and pack_key are required")
	}
	if strings.TrimSpace(input.DiagnosticsJSON) == "" {
		input.DiagnosticsJSON = "[]"
	}
	if strings.TrimSpace(input.DetailsJSON) == "" {
		input.DetailsJSON = "{}"
	}
	eventID := newACLCompilerEventID(input)
	_, err := DB.Exec(`INSERT INTO acl_compiler_events (
			event_id, operation, status, pack_key, policy_name, ast_fingerprint,
			artifact_fingerprint, artifact_count, rule_count, lossless,
			diagnostics_json, details_json, actor, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		eventID,
		input.Operation,
		input.Status,
		input.PackKey,
		nullString(strings.TrimSpace(input.PolicyName)),
		nullString(strings.TrimSpace(input.ASTFingerprint)),
		nullString(strings.TrimSpace(input.ArtifactFingerprint)),
		nonNegativeInt(input.ArtifactCount),
		nonNegativeInt(input.RuleCount),
		input.Lossless,
		input.DiagnosticsJSON,
		input.DetailsJSON,
		nullString(strings.TrimSpace(input.Actor)),
	)
	if err != nil {
		return "", fmt.Errorf("record ACL compiler event: %w", err)
	}
	return eventID, nil
}

func ListACLCompilerEvents(limit int) ([]ACLCompilerEvent, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	rows, err := DB.Query(`SELECT id, event_id, operation, status, pack_key,
			COALESCE(policy_name, ''), COALESCE(ast_fingerprint, ''),
			COALESCE(artifact_fingerprint, ''), artifact_count, rule_count,
			lossless, diagnostics_json, details_json, COALESCE(actor, ''),
			COALESCE(CAST(created_at AS TEXT), '')
		FROM acl_compiler_events
		ORDER BY datetime(created_at) DESC, id DESC
		LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list ACL compiler events: %w", err)
	}
	defer rows.Close()

	events := []ACLCompilerEvent{}
	for rows.Next() {
		var event ACLCompilerEvent
		if err := rows.Scan(
			&event.ID,
			&event.EventID,
			&event.Operation,
			&event.Status,
			&event.PackKey,
			&event.PolicyName,
			&event.ASTFingerprint,
			&event.ArtifactFingerprint,
			&event.ArtifactCount,
			&event.RuleCount,
			&event.Lossless,
			&event.DiagnosticsJSON,
			&event.DetailsJSON,
			&event.Actor,
			&event.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan ACL compiler event: %w", err)
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func GetACLCompilerEventSummary() (ACLCompilerEventSummary, error) {
	events, err := ListACLCompilerEvents(1000)
	if err != nil {
		return ACLCompilerEventSummary{}, err
	}
	summary := ACLCompilerEventSummary{}
	for _, event := range events {
		summary.TotalEvents++
		summary.ArtifactCount += event.ArtifactCount
		if event.Lossless {
			summary.LosslessCount++
		}
		switch event.Operation {
		case "compile":
			summary.CompileEvents++
		case "decompile":
			summary.DecompileEvents++
		}
		switch event.Status {
		case "compiled", "ready":
			summary.CompiledCount++
		case "profile_reference":
			summary.ProfileReferenceCount++
		case "degraded":
			summary.DegradedCount++
		case "blocked":
			summary.BlockedCount++
		case "unsupported":
			summary.UnsupportedCount++
		}
		if summary.LastEventAt == "" || event.CreatedAt > summary.LastEventAt {
			summary.LastEventAt = event.CreatedAt
		}
	}
	return summary, nil
}

func normalizeACLCompilerOperation(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "compile", "decompile":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeACLCompilerStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "compiled", "profile_reference", "degraded", "blocked", "unsupported", "ready":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "blocked"
	}
}

func newACLCompilerEventID(input ACLCompilerEventInput) string {
	var nonce [8]byte
	_, _ = rand.Read(nonce[:])
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%s:%s:%s:%d:%x",
		input.Operation,
		input.Status,
		input.PackKey,
		input.ASTFingerprint,
		input.ArtifactFingerprint,
		time.Now().UTC().UnixNano(),
		nonce,
	)))
	return "aclcmp-" + hex.EncodeToString(sum[:12])
}

func nonNegativeInt(value int) int {
	if value < 0 {
		return 0
	}
	return value
}
