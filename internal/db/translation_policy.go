package db

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

type TranslationPolicyOwnershipInput struct {
	OwnershipKey         string
	SessionID            string
	AcctSessionID        string
	Role                 string
	Owner                string
	Revision             string
	TranslationMode      string
	PublicPool           string
	PublicIPv4           string
	PrivateIPv4Prefix    string
	SubscriberIPv6Prefix string
	NAT64Prefix          string
	PortBlockStart       int
	PortBlockEnd         int
	PortBlockSize        int
	Status               string
}

type TranslationPolicyEventInput struct {
	EventID              string
	Operation            string
	Status               string
	Role                 string
	SessionID            string
	AcctSessionID        string
	Owner                string
	Revision             string
	TranslationMode      string
	PublicPool           string
	PublicIPv4           string
	PrivateIPv4Prefix    string
	SubscriberIPv6Prefix string
	NAT64Prefix          string
	PortBlockStart       int
	PortBlockEnd         int
	PortBlockSize        int
	MappingCount         int
	PortBlockCount       int
	WithdrawCount        int
	AttributeCount       int
	DiagnosticCount      int
	Fingerprint          string
	RequestJSON          string
	ResponseJSON         string
	DiagnosticsJSON      string
	Actor                string
	Ownership            []TranslationPolicyOwnershipInput
}

type TranslationPolicyEvent struct {
	ID                   int    `json:"id"`
	EventID              string `json:"event_id"`
	Operation            string `json:"operation"`
	Status               string `json:"status"`
	Role                 string `json:"role,omitempty"`
	SessionID            string `json:"session_id,omitempty"`
	AcctSessionID        string `json:"acct_session_id,omitempty"`
	Owner                string `json:"owner,omitempty"`
	Revision             string `json:"revision,omitempty"`
	TranslationMode      string `json:"translation_mode,omitempty"`
	PublicPool           string `json:"public_pool,omitempty"`
	PublicIPv4           string `json:"public_ipv4,omitempty"`
	PrivateIPv4Prefix    string `json:"private_ipv4_prefix,omitempty"`
	SubscriberIPv6Prefix string `json:"subscriber_ipv6_prefix,omitempty"`
	NAT64Prefix          string `json:"nat64_prefix,omitempty"`
	PortBlockStart       int    `json:"port_block_start"`
	PortBlockEnd         int    `json:"port_block_end"`
	PortBlockSize        int    `json:"port_block_size"`
	MappingCount         int    `json:"mapping_count"`
	PortBlockCount       int    `json:"port_block_count"`
	WithdrawCount        int    `json:"withdraw_count"`
	AttributeCount       int    `json:"attribute_count"`
	DiagnosticCount      int    `json:"diagnostic_count"`
	Fingerprint          string `json:"fingerprint,omitempty"`
	RequestJSON          string `json:"request_json"`
	ResponseJSON         string `json:"response_json"`
	DiagnosticsJSON      string `json:"diagnostics_json"`
	Actor                string `json:"actor,omitempty"`
	CreatedAt            string `json:"created_at"`
}

type TranslationPolicyOwnershipRecord struct {
	ID                   int    `json:"id"`
	MappingKey           string `json:"mapping_key"`
	OwnershipKey         string `json:"ownership_key"`
	EventID              string `json:"event_id"`
	SessionID            string `json:"session_id,omitempty"`
	AcctSessionID        string `json:"acct_session_id,omitempty"`
	Role                 string `json:"role,omitempty"`
	Owner                string `json:"owner"`
	Revision             string `json:"revision"`
	TranslationMode      string `json:"translation_mode"`
	PublicPool           string `json:"public_pool,omitempty"`
	PublicIPv4           string `json:"public_ipv4,omitempty"`
	PrivateIPv4Prefix    string `json:"private_ipv4_prefix,omitempty"`
	SubscriberIPv6Prefix string `json:"subscriber_ipv6_prefix,omitempty"`
	NAT64Prefix          string `json:"nat64_prefix,omitempty"`
	PortBlockStart       int    `json:"port_block_start"`
	PortBlockEnd         int    `json:"port_block_end"`
	PortBlockSize        int    `json:"port_block_size"`
	Status               string `json:"status"`
	CompiledFingerprint  string `json:"compiled_fingerprint,omitempty"`
	InstalledAt          string `json:"installed_at,omitempty"`
	WithdrawnAt          string `json:"withdrawn_at,omitempty"`
	LastSeenAt           string `json:"last_seen_at,omitempty"`
	CreatedAt            string `json:"created_at,omitempty"`
	UpdatedAt            string `json:"updated_at,omitempty"`
}

type TranslationPolicyEventSummary struct {
	TotalEvents         int    `json:"total_events"`
	CompiledCount       int    `json:"compiled_count"`
	PreviewedCount      int    `json:"previewed_count"`
	DecompiledCount     int    `json:"decompiled_count"`
	BlockedCount        int    `json:"blocked_count"`
	DegradedCount       int    `json:"degraded_count"`
	FailedCount         int    `json:"failed_count"`
	ActiveMappings      int    `json:"active_mappings"`
	WithdrawnMappings   int    `json:"withdrawn_mappings"`
	ActivePortBlocks    int    `json:"active_port_blocks"`
	ActiveNAT64Mappings int    `json:"active_nat64_mappings"`
	ActiveCGNATMappings int    `json:"active_cgnat_mappings"`
	LastEventAt         string `json:"last_event_at,omitempty"`
	LastStatus          string `json:"last_status,omitempty"`
	LastRole            string `json:"last_role,omitempty"`
	LastTranslationMode string `json:"last_translation_mode,omitempty"`
	LastMappingCount    int    `json:"last_mapping_count"`
	LastAttributeCount  int    `json:"last_attribute_count"`
	LastDiagnosticCount int    `json:"last_diagnostic_count"`
}

func RecordTranslationPolicyEvent(input TranslationPolicyEventInput) (string, error) {
	if DB == nil {
		return "", nil
	}
	input.Operation = normalizeTranslationPolicyOperation(input.Operation)
	input.Status = normalizeTranslationPolicyStatus(input.Status)
	if input.Operation == "" || input.Status == "" {
		return "", fmt.Errorf("translation policy operation and status are required")
	}
	input.EventID = strings.TrimSpace(input.EventID)
	if input.EventID == "" {
		input.EventID = newTranslationPolicyEventID(input.Operation, input.Status, input.ResponseJSON)
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
	_, err := DB.Exec(`INSERT INTO translation_policy_events (
			event_id, operation, status, role, session_id, acct_session_id, owner, revision,
			translation_mode, public_pool, public_ipv4, private_ipv4_prefix, subscriber_ipv6_prefix, nat64_prefix,
			port_block_start, port_block_end, port_block_size, mapping_count, port_block_count,
			withdraw_count, attribute_count, diagnostic_count, fingerprint,
			request_json, response_json, diagnostics_json, actor, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		input.EventID,
		input.Operation,
		input.Status,
		nullString(strings.TrimSpace(input.Role)),
		nullString(strings.TrimSpace(input.SessionID)),
		nullString(strings.TrimSpace(input.AcctSessionID)),
		nullString(strings.TrimSpace(input.Owner)),
		nullString(strings.TrimSpace(input.Revision)),
		nullString(normalizeTranslationPolicyDBMode(input.TranslationMode)),
		nullString(strings.TrimSpace(input.PublicPool)),
		nullString(strings.TrimSpace(input.PublicIPv4)),
		nullString(strings.TrimSpace(input.PrivateIPv4Prefix)),
		nullString(strings.TrimSpace(input.SubscriberIPv6Prefix)),
		nullString(strings.TrimSpace(input.NAT64Prefix)),
		nonNegativeInt(input.PortBlockStart),
		nonNegativeInt(input.PortBlockEnd),
		nonNegativeInt(input.PortBlockSize),
		nonNegativeInt(input.MappingCount),
		nonNegativeInt(input.PortBlockCount),
		nonNegativeInt(input.WithdrawCount),
		nonNegativeInt(input.AttributeCount),
		nonNegativeInt(input.DiagnosticCount),
		nullString(strings.TrimSpace(input.Fingerprint)),
		input.RequestJSON,
		input.ResponseJSON,
		input.DiagnosticsJSON,
		nullString(strings.TrimSpace(input.Actor)),
	)
	if err != nil {
		return "", fmt.Errorf("record translation policy event: %w", err)
	}
	for _, ownership := range input.Ownership {
		if err := upsertTranslationPolicyOwnership(input, ownership); err != nil {
			return "", err
		}
	}
	return input.EventID, nil
}

func ListTranslationPolicyEvents(limit int) ([]TranslationPolicyEvent, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := DB.Query(`SELECT id, event_id, operation, status, COALESCE(role, ''), COALESCE(session_id, ''),
			COALESCE(acct_session_id, ''), COALESCE(owner, ''), COALESCE(revision, ''),
			COALESCE(translation_mode, ''), COALESCE(public_pool, ''), COALESCE(public_ipv4, ''),
			COALESCE(private_ipv4_prefix, ''), COALESCE(subscriber_ipv6_prefix, ''), COALESCE(nat64_prefix, ''),
			port_block_start, port_block_end, port_block_size, mapping_count, port_block_count,
			withdraw_count, attribute_count, diagnostic_count, COALESCE(fingerprint, ''),
			request_json, response_json, diagnostics_json, COALESCE(actor, ''),
			COALESCE(CAST(created_at AS TEXT), '')
		FROM translation_policy_events
		ORDER BY datetime(created_at) DESC, id DESC
		LIMIT ?`, limit)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list translation policy events: %w", err)
	}
	defer rows.Close()
	var events []TranslationPolicyEvent
	for rows.Next() {
		var event TranslationPolicyEvent
		if err := rows.Scan(
			&event.ID,
			&event.EventID,
			&event.Operation,
			&event.Status,
			&event.Role,
			&event.SessionID,
			&event.AcctSessionID,
			&event.Owner,
			&event.Revision,
			&event.TranslationMode,
			&event.PublicPool,
			&event.PublicIPv4,
			&event.PrivateIPv4Prefix,
			&event.SubscriberIPv6Prefix,
			&event.NAT64Prefix,
			&event.PortBlockStart,
			&event.PortBlockEnd,
			&event.PortBlockSize,
			&event.MappingCount,
			&event.PortBlockCount,
			&event.WithdrawCount,
			&event.AttributeCount,
			&event.DiagnosticCount,
			&event.Fingerprint,
			&event.RequestJSON,
			&event.ResponseJSON,
			&event.DiagnosticsJSON,
			&event.Actor,
			&event.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan translation policy event: %w", err)
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func ListTranslationPolicyOwnership(limit int, status string) ([]TranslationPolicyOwnershipRecord, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	query := translationPolicyOwnershipSelectSQL()
	args := []any{}
	status = strings.ToLower(strings.TrimSpace(status))
	if status != "" {
		query += " WHERE status = ?"
		args = append(args, status)
	}
	query += " ORDER BY datetime(updated_at) DESC, id DESC LIMIT ?"
	args = append(args, limit)
	rows, err := DB.Query(query, args...)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list translation policy ownership: %w", err)
	}
	defer rows.Close()
	var out []TranslationPolicyOwnershipRecord
	for rows.Next() {
		record, err := scanTranslationPolicyOwnership(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, rows.Err()
}

func GetTranslationPolicyEventSummary() (TranslationPolicyEventSummary, error) {
	events, err := ListTranslationPolicyEvents(1000)
	if err != nil {
		return TranslationPolicyEventSummary{}, err
	}
	summary := TranslationPolicyEventSummary{}
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
			summary.LastTranslationMode = event.TranslationMode
			summary.LastMappingCount = event.MappingCount
			summary.LastAttributeCount = event.AttributeCount
			summary.LastDiagnosticCount = event.DiagnosticCount
		}
	}
	if DB == nil {
		return summary, nil
	}
	_ = DB.QueryRow(`SELECT COUNT(*) FROM translation_policy_ownership WHERE status = 'active'`).Scan(&summary.ActiveMappings)
	_ = DB.QueryRow(`SELECT COUNT(*) FROM translation_policy_ownership WHERE status = 'withdrawn'`).Scan(&summary.WithdrawnMappings)
	_ = DB.QueryRow(`SELECT COUNT(*) FROM translation_policy_ownership WHERE status = 'active' AND port_block_start > 0 AND port_block_end > 0`).Scan(&summary.ActivePortBlocks)
	_ = DB.QueryRow(`SELECT COUNT(*) FROM translation_policy_ownership WHERE status = 'active' AND nat64_prefix IS NOT NULL AND nat64_prefix <> ''`).Scan(&summary.ActiveNAT64Mappings)
	_ = DB.QueryRow(`SELECT COUNT(*) FROM translation_policy_ownership WHERE status = 'active' AND public_ipv4 IS NOT NULL AND public_ipv4 <> ''`).Scan(&summary.ActiveCGNATMappings)
	return summary, nil
}

func WithdrawTranslationPolicyOwnershipForSession(ctx context.Context, sessionID, acctSessionID, eventID, actor string) (int64, error) {
	if DB == nil {
		return 0, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	sessionID = strings.TrimSpace(sessionID)
	acctSessionID = strings.TrimSpace(acctSessionID)
	if sessionID == "" && acctSessionID == "" {
		return 0, nil
	}
	now := formatAccountingTime(time.Now().UTC())
	result, err := DB.ExecContext(ctx, `UPDATE translation_policy_ownership
		SET status = 'withdrawn', withdrawn_at = ?, last_seen_at = ?, updated_at = CURRENT_TIMESTAMP,
			event_id = CASE WHEN ? <> '' THEN ? ELSE event_id END
		WHERE status = 'active' AND ((? <> '' AND session_id = ?) OR (? <> '' AND acct_session_id = ?))`,
		now, now, strings.TrimSpace(eventID), strings.TrimSpace(eventID),
		sessionID, sessionID, acctSessionID, acctSessionID)
	if err != nil {
		if tableMissing(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("withdraw translation policy ownership: %w", err)
	}
	affected, _ := result.RowsAffected()
	if affected > 0 {
		_, _ = RecordTranslationPolicyEvent(TranslationPolicyEventInput{
			Operation:       "compile",
			Status:          "compiled",
			Role:            "accounting-stop",
			SessionID:       sessionID,
			AcctSessionID:   acctSessionID,
			TranslationMode: "unknown",
			WithdrawCount:   int(affected),
			RequestJSON:     "{}",
			ResponseJSON:    fmt.Sprintf(`{"withdrawn":%d}`, affected),
			DiagnosticsJSON: "[]",
			Actor:           firstNonEmptyDBString(actor, "accounting-stop"),
		})
	}
	return affected, nil
}

func upsertTranslationPolicyOwnership(event TranslationPolicyEventInput, input TranslationPolicyOwnershipInput) error {
	input = normalizeTranslationPolicyOwnershipInput(event, input)
	if input.TranslationMode == "" || (input.PublicPool == "" && input.PublicIPv4 == "" && input.PrivateIPv4Prefix == "" && input.SubscriberIPv6Prefix == "" && input.NAT64Prefix == "" && input.PortBlockStart == 0 && input.PortBlockEnd == 0) {
		return nil
	}
	mappingKey := translationPolicyMappingKey(input)
	now := formatAccountingTime(time.Now().UTC())
	status := input.Status
	if status == "" {
		status = "active"
	}
	installedAt := now
	withdrawnAt := ""
	if status == "withdrawn" {
		installedAt = ""
		withdrawnAt = now
	}
	_, err := DB.Exec(`INSERT INTO translation_policy_ownership (
			mapping_key, ownership_key, event_id, session_id, acct_session_id, role, owner, revision,
			translation_mode, public_pool, public_ipv4, private_ipv4_prefix, subscriber_ipv6_prefix, nat64_prefix,
			port_block_start, port_block_end, port_block_size, status, compiled_fingerprint,
			installed_at, withdrawn_at, last_seen_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(mapping_key) DO UPDATE SET
			ownership_key = excluded.ownership_key,
			event_id = excluded.event_id,
			session_id = excluded.session_id,
			acct_session_id = excluded.acct_session_id,
			role = excluded.role,
			owner = excluded.owner,
			revision = excluded.revision,
			translation_mode = excluded.translation_mode,
			public_pool = excluded.public_pool,
			public_ipv4 = excluded.public_ipv4,
			private_ipv4_prefix = excluded.private_ipv4_prefix,
			subscriber_ipv6_prefix = excluded.subscriber_ipv6_prefix,
			nat64_prefix = excluded.nat64_prefix,
			port_block_start = excluded.port_block_start,
			port_block_end = excluded.port_block_end,
			port_block_size = excluded.port_block_size,
			status = excluded.status,
			compiled_fingerprint = excluded.compiled_fingerprint,
			installed_at = COALESCE(excluded.installed_at, translation_policy_ownership.installed_at),
			withdrawn_at = excluded.withdrawn_at,
			last_seen_at = excluded.last_seen_at,
			updated_at = CURRENT_TIMESTAMP`,
		mappingKey,
		input.OwnershipKey,
		event.EventID,
		nullString(input.SessionID),
		nullString(input.AcctSessionID),
		nullString(input.Role),
		input.Owner,
		input.Revision,
		input.TranslationMode,
		nullString(input.PublicPool),
		nullString(input.PublicIPv4),
		nullString(input.PrivateIPv4Prefix),
		nullString(input.SubscriberIPv6Prefix),
		nullString(input.NAT64Prefix),
		nonNegativeInt(input.PortBlockStart),
		nonNegativeInt(input.PortBlockEnd),
		nonNegativeInt(input.PortBlockSize),
		status,
		nullString(event.Fingerprint),
		nullString(installedAt),
		nullString(withdrawnAt),
		now)
	if err != nil {
		return fmt.Errorf("upsert translation policy ownership: %w", err)
	}
	return nil
}

func normalizeTranslationPolicyOwnershipInput(event TranslationPolicyEventInput, input TranslationPolicyOwnershipInput) TranslationPolicyOwnershipInput {
	input.SessionID = firstNonEmptyDBString(input.SessionID, event.SessionID)
	input.AcctSessionID = firstNonEmptyDBString(input.AcctSessionID, event.AcctSessionID)
	input.Role = firstNonEmptyDBString(input.Role, event.Role)
	input.Owner = firstNonEmptyDBString(input.Owner, event.Owner, "aegisnas")
	input.Revision = firstNonEmptyDBString(input.Revision, event.Revision, "unknown")
	input.OwnershipKey = firstNonEmptyDBString(input.OwnershipKey, translationPolicyOwnerFallback(input))
	input.TranslationMode = normalizeTranslationPolicyDBMode(firstNonEmptyDBString(input.TranslationMode, event.TranslationMode, "unknown"))
	input.PublicPool = strings.TrimSpace(firstNonEmptyDBString(input.PublicPool, event.PublicPool))
	input.PublicIPv4 = strings.TrimSpace(firstNonEmptyDBString(input.PublicIPv4, event.PublicIPv4))
	input.PrivateIPv4Prefix = strings.TrimSpace(firstNonEmptyDBString(input.PrivateIPv4Prefix, event.PrivateIPv4Prefix))
	input.SubscriberIPv6Prefix = strings.TrimSpace(firstNonEmptyDBString(input.SubscriberIPv6Prefix, event.SubscriberIPv6Prefix))
	input.NAT64Prefix = strings.TrimSpace(firstNonEmptyDBString(input.NAT64Prefix, event.NAT64Prefix))
	if input.PortBlockStart == 0 {
		input.PortBlockStart = event.PortBlockStart
	}
	if input.PortBlockEnd == 0 {
		input.PortBlockEnd = event.PortBlockEnd
	}
	if input.PortBlockSize == 0 {
		input.PortBlockSize = event.PortBlockSize
	}
	input.Status = normalizeTranslationPolicyOwnershipStatus(input.Status)
	return input
}

func translationPolicyOwnershipSelectSQL() string {
	return `SELECT id, mapping_key, ownership_key, event_id, COALESCE(session_id, ''), COALESCE(acct_session_id, ''),
		COALESCE(role, ''), owner, revision, translation_mode, COALESCE(public_pool, ''),
		COALESCE(public_ipv4, ''), COALESCE(private_ipv4_prefix, ''), COALESCE(subscriber_ipv6_prefix, ''),
		COALESCE(nat64_prefix, ''), port_block_start, port_block_end, port_block_size,
		status, COALESCE(compiled_fingerprint, ''),
		COALESCE(CAST(installed_at AS TEXT), ''), COALESCE(CAST(withdrawn_at AS TEXT), ''),
		COALESCE(CAST(last_seen_at AS TEXT), ''), COALESCE(CAST(created_at AS TEXT), ''),
		COALESCE(CAST(updated_at AS TEXT), '')
		FROM translation_policy_ownership`
}

func scanTranslationPolicyOwnership(scanner interface {
	Scan(dest ...any) error
}) (TranslationPolicyOwnershipRecord, error) {
	var record TranslationPolicyOwnershipRecord
	err := scanner.Scan(
		&record.ID,
		&record.MappingKey,
		&record.OwnershipKey,
		&record.EventID,
		&record.SessionID,
		&record.AcctSessionID,
		&record.Role,
		&record.Owner,
		&record.Revision,
		&record.TranslationMode,
		&record.PublicPool,
		&record.PublicIPv4,
		&record.PrivateIPv4Prefix,
		&record.SubscriberIPv6Prefix,
		&record.NAT64Prefix,
		&record.PortBlockStart,
		&record.PortBlockEnd,
		&record.PortBlockSize,
		&record.Status,
		&record.CompiledFingerprint,
		&record.InstalledAt,
		&record.WithdrawnAt,
		&record.LastSeenAt,
		&record.CreatedAt,
		&record.UpdatedAt,
	)
	if err != nil {
		return TranslationPolicyOwnershipRecord{}, fmt.Errorf("scan translation policy ownership: %w", err)
	}
	return record, nil
}

func normalizeTranslationPolicyOperation(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "compile", "preview", "decompile":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeTranslationPolicyStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "compiled", "previewed", "decompiled", "blocked", "degraded", "failed":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeTranslationPolicyOwnershipStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "withdrawn", "replaced", "stale", "observed":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "active"
	}
}

func normalizeTranslationPolicyDBMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "cgnat", "nat44", "nat64", "dual-stack", "ds-lite", "map-t":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "unknown"
	}
}

func translationPolicyMappingKey(input TranslationPolicyOwnershipInput) string {
	payload := strings.Join([]string{
		firstNonEmptyDBString(input.SessionID, input.AcctSessionID, input.Role),
		input.Owner,
		input.TranslationMode,
		input.PublicPool,
		input.PublicIPv4,
		input.PrivateIPv4Prefix,
		input.SubscriberIPv6Prefix,
		input.NAT64Prefix,
		fmt.Sprintf("%d-%d-%d", input.PortBlockStart, input.PortBlockEnd, input.PortBlockSize),
	}, "|")
	sum := sha256.Sum256([]byte(payload))
	return "trans-" + hex.EncodeToString(sum[:12])
}

func translationPolicyOwnerFallback(input TranslationPolicyOwnershipInput) string {
	payload := strings.Join([]string{
		firstNonEmptyDBString(input.SessionID, input.AcctSessionID, input.Role),
		input.Owner,
		input.Revision,
	}, "|")
	sum := sha256.Sum256([]byte(payload))
	return "translation-owner-" + hex.EncodeToString(sum[:12])
}

func newTranslationPolicyEventID(operation, status, responseJSON string) string {
	var nonce [8]byte
	_, _ = rand.Read(nonce[:])
	sum := sha256.Sum256([]byte(fmt.Sprintf("translation-policy:%s:%s:%s:%d:%x",
		operation,
		status,
		responseJSON,
		time.Now().UTC().UnixNano(),
		nonce,
	)))
	return "translation-policy-" + hex.EncodeToString(sum[:12])
}
