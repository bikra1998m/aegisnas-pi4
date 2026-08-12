package db

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

type RateCompilerEventInput struct {
	EventID          string
	Operation        string
	Status           string
	PackKeysJSON     string
	DownloadRateKbps int
	UploadRateKbps   int
	AttributeCount   int
	DiagnosticCount  int
	RequestJSON      string
	ResponseJSON     string
	DiagnosticsJSON  string
	Actor            string
}

type RateCompilerEvent struct {
	ID               int    `json:"id"`
	EventID          string `json:"event_id"`
	Operation        string `json:"operation"`
	Status           string `json:"status"`
	PackKeysJSON     string `json:"pack_keys_json"`
	DownloadRateKbps int    `json:"download_rate_kbps"`
	UploadRateKbps   int    `json:"upload_rate_kbps"`
	AttributeCount   int    `json:"attribute_count"`
	DiagnosticCount  int    `json:"diagnostic_count"`
	RequestJSON      string `json:"request_json"`
	ResponseJSON     string `json:"response_json"`
	DiagnosticsJSON  string `json:"diagnostics_json"`
	Actor            string `json:"actor,omitempty"`
	CreatedAt        string `json:"created_at"`
}

type RateCompilerEventSummary struct {
	TotalEvents        int    `json:"total_events"`
	CompiledCount      int    `json:"compiled_count"`
	DecompiledCount    int    `json:"decompiled_count"`
	BlockedCount       int    `json:"blocked_count"`
	FailedCount        int    `json:"failed_count"`
	LastEventAt        string `json:"last_event_at,omitempty"`
	LastStatus         string `json:"last_status,omitempty"`
	LastAttributeCount int    `json:"last_attribute_count"`
}

func RecordRateCompilerEvent(input RateCompilerEventInput) (string, error) {
	if DB == nil {
		return "", nil
	}
	input.Operation = normalizeRateCompilerOperation(input.Operation)
	input.Status = normalizeRateCompilerStatus(input.Status)
	if input.Operation == "" || input.Status == "" {
		return "", fmt.Errorf("rate compiler operation and status are required")
	}
	input.EventID = strings.TrimSpace(input.EventID)
	if input.EventID == "" {
		input.EventID = newRateCompilerEventID(input.Operation, input.Status, input.ResponseJSON)
	}
	if strings.TrimSpace(input.PackKeysJSON) == "" {
		input.PackKeysJSON = "[]"
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
	_, err := DB.Exec(`INSERT INTO rate_compiler_events (
			event_id, operation, status, pack_keys_json, download_rate_kbps, upload_rate_kbps,
			attribute_count, diagnostic_count, request_json, response_json, diagnostics_json, actor, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		input.EventID,
		input.Operation,
		input.Status,
		input.PackKeysJSON,
		nonNegativeInt(input.DownloadRateKbps),
		nonNegativeInt(input.UploadRateKbps),
		nonNegativeInt(input.AttributeCount),
		nonNegativeInt(input.DiagnosticCount),
		input.RequestJSON,
		input.ResponseJSON,
		input.DiagnosticsJSON,
		nullString(strings.TrimSpace(input.Actor)),
	)
	if err != nil {
		return "", fmt.Errorf("record rate compiler event: %w", err)
	}
	return input.EventID, nil
}

func ListRateCompilerEvents(limit int) ([]RateCompilerEvent, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := DB.Query(`SELECT id, event_id, operation, status, pack_keys_json, download_rate_kbps, upload_rate_kbps,
			attribute_count, diagnostic_count, request_json, response_json, diagnostics_json, COALESCE(actor, ''),
			COALESCE(CAST(created_at AS TEXT), '')
		FROM rate_compiler_events
		ORDER BY datetime(created_at) DESC, id DESC
		LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list rate compiler events: %w", err)
	}
	defer rows.Close()
	var events []RateCompilerEvent
	for rows.Next() {
		var event RateCompilerEvent
		if err := rows.Scan(
			&event.ID,
			&event.EventID,
			&event.Operation,
			&event.Status,
			&event.PackKeysJSON,
			&event.DownloadRateKbps,
			&event.UploadRateKbps,
			&event.AttributeCount,
			&event.DiagnosticCount,
			&event.RequestJSON,
			&event.ResponseJSON,
			&event.DiagnosticsJSON,
			&event.Actor,
			&event.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan rate compiler event: %w", err)
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func GetRateCompilerEventSummary() (RateCompilerEventSummary, error) {
	events, err := ListRateCompilerEvents(1000)
	if err != nil {
		return RateCompilerEventSummary{}, err
	}
	summary := RateCompilerEventSummary{}
	for _, event := range events {
		summary.TotalEvents++
		switch event.Status {
		case "compiled":
			summary.CompiledCount++
		case "decompiled":
			summary.DecompiledCount++
		case "blocked":
			summary.BlockedCount++
		case "failed":
			summary.FailedCount++
		}
		if summary.LastEventAt == "" || event.CreatedAt > summary.LastEventAt {
			summary.LastEventAt = event.CreatedAt
			summary.LastStatus = event.Status
			summary.LastAttributeCount = event.AttributeCount
		}
	}
	return summary, nil
}

func normalizeRateCompilerOperation(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "compile", "decompile", "preview":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeRateCompilerStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "compiled", "decompiled", "blocked", "failed":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func newRateCompilerEventID(operation, status, responseJSON string) string {
	var nonce [8]byte
	_, _ = rand.Read(nonce[:])
	sum := sha256.Sum256([]byte(fmt.Sprintf("rate-compiler:%s:%s:%s:%d:%x",
		operation,
		status,
		responseJSON,
		time.Now().UTC().UnixNano(),
		nonce,
	)))
	return "rate-compiler-" + hex.EncodeToString(sum[:12])
}
