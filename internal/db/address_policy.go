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

type AddressPolicyOwnershipInput struct {
	OwnershipKey   string
	SessionID      string
	AcctSessionID  string
	Role           string
	Owner          string
	Revision       string
	Family         string
	AssignmentType string
	PoolName       string
	Address        string
	Prefix         string
	Status         string
}

type AddressPolicyEventInput struct {
	EventID              string
	Operation            string
	Status               string
	Role                 string
	SessionID            string
	AcctSessionID        string
	Owner                string
	Revision             string
	IPv4AssignmentCount  int
	IPv6AssignmentCount  int
	DelegatedPrefixCount int
	RAPrefixCount        int
	WithdrawCount        int
	AttributeCount       int
	DiagnosticCount      int
	Fingerprint          string
	RequestJSON          string
	ResponseJSON         string
	DiagnosticsJSON      string
	Actor                string
	Ownership            []AddressPolicyOwnershipInput
}

type AddressPolicyEvent struct {
	ID                   int    `json:"id"`
	EventID              string `json:"event_id"`
	Operation            string `json:"operation"`
	Status               string `json:"status"`
	Role                 string `json:"role,omitempty"`
	SessionID            string `json:"session_id,omitempty"`
	AcctSessionID        string `json:"acct_session_id,omitempty"`
	Owner                string `json:"owner,omitempty"`
	Revision             string `json:"revision,omitempty"`
	IPv4AssignmentCount  int    `json:"ipv4_assignment_count"`
	IPv6AssignmentCount  int    `json:"ipv6_assignment_count"`
	DelegatedPrefixCount int    `json:"delegated_prefix_count"`
	RAPrefixCount        int    `json:"ra_prefix_count"`
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

type AddressPolicyOwnershipRecord struct {
	ID                  int    `json:"id"`
	AssignmentKey       string `json:"assignment_key"`
	OwnershipKey        string `json:"ownership_key"`
	EventID             string `json:"event_id"`
	SessionID           string `json:"session_id,omitempty"`
	AcctSessionID       string `json:"acct_session_id,omitempty"`
	Role                string `json:"role,omitempty"`
	Owner               string `json:"owner"`
	Revision            string `json:"revision"`
	Family              string `json:"family"`
	AssignmentType      string `json:"assignment_type"`
	PoolName            string `json:"pool_name,omitempty"`
	Address             string `json:"address,omitempty"`
	Prefix              string `json:"prefix,omitempty"`
	Status              string `json:"status"`
	CompiledFingerprint string `json:"compiled_fingerprint,omitempty"`
	InstalledAt         string `json:"installed_at,omitempty"`
	WithdrawnAt         string `json:"withdrawn_at,omitempty"`
	LastSeenAt          string `json:"last_seen_at,omitempty"`
	CreatedAt           string `json:"created_at,omitempty"`
	UpdatedAt           string `json:"updated_at,omitempty"`
}

type AddressPolicyEventSummary struct {
	TotalEvents           int    `json:"total_events"`
	CompiledCount         int    `json:"compiled_count"`
	PreviewedCount        int    `json:"previewed_count"`
	DecompiledCount       int    `json:"decompiled_count"`
	BlockedCount          int    `json:"blocked_count"`
	DegradedCount         int    `json:"degraded_count"`
	FailedCount           int    `json:"failed_count"`
	ActiveAssignments     int    `json:"active_assignments"`
	WithdrawnAssignments  int    `json:"withdrawn_assignments"`
	IPv4ActiveAssignments int    `json:"ipv4_active_assignments"`
	IPv6ActiveAssignments int    `json:"ipv6_active_assignments"`
	DelegatedPrefixes     int    `json:"delegated_prefixes"`
	RAPrefixes            int    `json:"ra_prefixes"`
	LastEventAt           string `json:"last_event_at,omitempty"`
	LastStatus            string `json:"last_status,omitempty"`
	LastRole              string `json:"last_role,omitempty"`
	LastAssignmentCount   int    `json:"last_assignment_count"`
	LastAttributeCount    int    `json:"last_attribute_count"`
	LastDiagnosticCount   int    `json:"last_diagnostic_count"`
}

func RecordAddressPolicyEvent(input AddressPolicyEventInput) (string, error) {
	if DB == nil {
		return "", nil
	}
	input.Operation = normalizeAddressPolicyOperation(input.Operation)
	input.Status = normalizeAddressPolicyStatus(input.Status)
	if input.Operation == "" || input.Status == "" {
		return "", fmt.Errorf("address policy operation and status are required")
	}
	input.EventID = strings.TrimSpace(input.EventID)
	if input.EventID == "" {
		input.EventID = newAddressPolicyEventID(input.Operation, input.Status, input.ResponseJSON)
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
	_, err := DB.Exec(`INSERT INTO address_policy_events (
			event_id, operation, status, role, session_id, acct_session_id, owner, revision,
			ipv4_assignment_count, ipv6_assignment_count, delegated_prefix_count, ra_prefix_count,
			withdraw_count, attribute_count, diagnostic_count, fingerprint,
			request_json, response_json, diagnostics_json, actor, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		input.EventID,
		input.Operation,
		input.Status,
		nullString(strings.TrimSpace(input.Role)),
		nullString(strings.TrimSpace(input.SessionID)),
		nullString(strings.TrimSpace(input.AcctSessionID)),
		nullString(strings.TrimSpace(input.Owner)),
		nullString(strings.TrimSpace(input.Revision)),
		nonNegativeInt(input.IPv4AssignmentCount),
		nonNegativeInt(input.IPv6AssignmentCount),
		nonNegativeInt(input.DelegatedPrefixCount),
		nonNegativeInt(input.RAPrefixCount),
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
		return "", fmt.Errorf("record address policy event: %w", err)
	}
	for _, ownership := range input.Ownership {
		if err := upsertAddressPolicyOwnership(input, ownership); err != nil {
			return "", err
		}
	}
	return input.EventID, nil
}

func ListAddressPolicyEvents(limit int) ([]AddressPolicyEvent, error) {
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
			ipv4_assignment_count, ipv6_assignment_count, delegated_prefix_count, ra_prefix_count,
			withdraw_count, attribute_count, diagnostic_count, COALESCE(fingerprint, ''),
			request_json, response_json, diagnostics_json, COALESCE(actor, ''),
			COALESCE(CAST(created_at AS TEXT), '')
		FROM address_policy_events
		ORDER BY datetime(created_at) DESC, id DESC
		LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list address policy events: %w", err)
	}
	defer rows.Close()
	var events []AddressPolicyEvent
	for rows.Next() {
		var event AddressPolicyEvent
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
			&event.IPv4AssignmentCount,
			&event.IPv6AssignmentCount,
			&event.DelegatedPrefixCount,
			&event.RAPrefixCount,
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
			return nil, fmt.Errorf("scan address policy event: %w", err)
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func ListAddressPolicyOwnership(limit int, status string) ([]AddressPolicyOwnershipRecord, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	query := addressPolicyOwnershipSelectSQL()
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
		return nil, fmt.Errorf("list address policy ownership: %w", err)
	}
	defer rows.Close()
	var out []AddressPolicyOwnershipRecord
	for rows.Next() {
		record, err := scanAddressPolicyOwnership(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, rows.Err()
}

func GetAddressPolicyEventSummary() (AddressPolicyEventSummary, error) {
	events, err := ListAddressPolicyEvents(1000)
	if err != nil {
		return AddressPolicyEventSummary{}, err
	}
	summary := AddressPolicyEventSummary{}
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
			summary.LastAssignmentCount = event.IPv4AssignmentCount + event.IPv6AssignmentCount + event.DelegatedPrefixCount + event.RAPrefixCount
			summary.LastAttributeCount = event.AttributeCount
			summary.LastDiagnosticCount = event.DiagnosticCount
		}
	}
	if DB == nil {
		return summary, nil
	}
	_ = DB.QueryRow(`SELECT COUNT(*) FROM address_policy_ownership WHERE status = 'active'`).Scan(&summary.ActiveAssignments)
	_ = DB.QueryRow(`SELECT COUNT(*) FROM address_policy_ownership WHERE status = 'withdrawn'`).Scan(&summary.WithdrawnAssignments)
	_ = DB.QueryRow(`SELECT COUNT(*) FROM address_policy_ownership WHERE status = 'active' AND family = 'ipv4'`).Scan(&summary.IPv4ActiveAssignments)
	_ = DB.QueryRow(`SELECT COUNT(*) FROM address_policy_ownership WHERE status = 'active' AND family = 'ipv6'`).Scan(&summary.IPv6ActiveAssignments)
	_ = DB.QueryRow(`SELECT COUNT(*) FROM address_policy_ownership WHERE status = 'active' AND assignment_type = 'delegated_prefix'`).Scan(&summary.DelegatedPrefixes)
	_ = DB.QueryRow(`SELECT COUNT(*) FROM address_policy_ownership WHERE status = 'active' AND assignment_type = 'ra_prefix'`).Scan(&summary.RAPrefixes)
	return summary, nil
}

func WithdrawAddressPolicyOwnershipForSession(ctx context.Context, sessionID, acctSessionID, eventID, actor string) (int64, error) {
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
	result, err := DB.ExecContext(ctx, `UPDATE address_policy_ownership
		SET status = 'withdrawn', withdrawn_at = ?, last_seen_at = ?, updated_at = CURRENT_TIMESTAMP,
			event_id = CASE WHEN ? <> '' THEN ? ELSE event_id END
		WHERE status = 'active' AND ((? <> '' AND session_id = ?) OR (? <> '' AND acct_session_id = ?))`,
		now, now, strings.TrimSpace(eventID), strings.TrimSpace(eventID),
		sessionID, sessionID, acctSessionID, acctSessionID)
	if err != nil {
		return 0, fmt.Errorf("withdraw address policy ownership: %w", err)
	}
	affected, _ := result.RowsAffected()
	if affected > 0 {
		_, _ = RecordAddressPolicyEvent(AddressPolicyEventInput{
			Operation:       "compile",
			Status:          "compiled",
			Role:            "accounting-stop",
			SessionID:       sessionID,
			AcctSessionID:   acctSessionID,
			WithdrawCount:   int(affected),
			RequestJSON:     "{}",
			ResponseJSON:    fmt.Sprintf(`{"withdrawn":%d}`, affected),
			DiagnosticsJSON: "[]",
			Actor:           firstNonEmptyDBString(actor, "accounting-stop"),
		})
	}
	return affected, nil
}

func upsertAddressPolicyOwnership(event AddressPolicyEventInput, input AddressPolicyOwnershipInput) error {
	input = normalizeAddressPolicyOwnershipInput(event, input)
	if input.Family == "" || input.AssignmentType == "" || (input.Address == "" && input.Prefix == "" && input.PoolName == "") {
		return nil
	}
	assignmentKey := addressPolicyAssignmentKey(input)
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
	_, err := DB.Exec(`INSERT INTO address_policy_ownership (
			assignment_key, ownership_key, event_id, session_id, acct_session_id, role, owner, revision,
			family, assignment_type, pool_name, address, prefix, status, compiled_fingerprint,
			installed_at, withdrawn_at, last_seen_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(assignment_key) DO UPDATE SET
			ownership_key = excluded.ownership_key,
			event_id = excluded.event_id,
			session_id = excluded.session_id,
			acct_session_id = excluded.acct_session_id,
			role = excluded.role,
			owner = excluded.owner,
			revision = excluded.revision,
			pool_name = excluded.pool_name,
			address = excluded.address,
			prefix = excluded.prefix,
			status = excluded.status,
			compiled_fingerprint = excluded.compiled_fingerprint,
			installed_at = COALESCE(excluded.installed_at, address_policy_ownership.installed_at),
			withdrawn_at = excluded.withdrawn_at,
			last_seen_at = excluded.last_seen_at,
			updated_at = CURRENT_TIMESTAMP`,
		assignmentKey,
		input.OwnershipKey,
		event.EventID,
		nullString(input.SessionID),
		nullString(input.AcctSessionID),
		nullString(input.Role),
		input.Owner,
		input.Revision,
		input.Family,
		input.AssignmentType,
		nullString(input.PoolName),
		nullString(input.Address),
		nullString(input.Prefix),
		status,
		nullString(event.Fingerprint),
		nullString(installedAt),
		nullString(withdrawnAt),
		now)
	if err != nil {
		return fmt.Errorf("upsert address policy ownership: %w", err)
	}
	return nil
}

func normalizeAddressPolicyOwnershipInput(event AddressPolicyEventInput, input AddressPolicyOwnershipInput) AddressPolicyOwnershipInput {
	input.SessionID = firstNonEmptyDBString(input.SessionID, event.SessionID)
	input.AcctSessionID = firstNonEmptyDBString(input.AcctSessionID, event.AcctSessionID)
	input.Role = firstNonEmptyDBString(input.Role, event.Role)
	input.Owner = firstNonEmptyDBString(input.Owner, event.Owner, "aegisnas")
	input.Revision = firstNonEmptyDBString(input.Revision, event.Revision, "unknown")
	input.OwnershipKey = firstNonEmptyDBString(input.OwnershipKey, addressPolicyOwnerFallback(input))
	input.Family = strings.ToLower(strings.TrimSpace(input.Family))
	input.AssignmentType = normalizeAddressPolicyAssignmentType(input.AssignmentType)
	input.PoolName = strings.TrimSpace(input.PoolName)
	input.Address = strings.TrimSpace(input.Address)
	input.Prefix = strings.TrimSpace(input.Prefix)
	input.Status = normalizeAddressPolicyOwnershipStatus(input.Status)
	return input
}

func addressPolicyOwnershipSelectSQL() string {
	return `SELECT id, assignment_key, ownership_key, event_id, COALESCE(session_id, ''), COALESCE(acct_session_id, ''),
		COALESCE(role, ''), owner, revision, family, assignment_type, COALESCE(pool_name, ''),
		COALESCE(address, ''), COALESCE(prefix, ''), status, COALESCE(compiled_fingerprint, ''),
		COALESCE(CAST(installed_at AS TEXT), ''), COALESCE(CAST(withdrawn_at AS TEXT), ''),
		COALESCE(CAST(last_seen_at AS TEXT), ''), COALESCE(CAST(created_at AS TEXT), ''),
		COALESCE(CAST(updated_at AS TEXT), '')
		FROM address_policy_ownership`
}

func scanAddressPolicyOwnership(scanner interface {
	Scan(dest ...any) error
}) (AddressPolicyOwnershipRecord, error) {
	var record AddressPolicyOwnershipRecord
	err := scanner.Scan(
		&record.ID,
		&record.AssignmentKey,
		&record.OwnershipKey,
		&record.EventID,
		&record.SessionID,
		&record.AcctSessionID,
		&record.Role,
		&record.Owner,
		&record.Revision,
		&record.Family,
		&record.AssignmentType,
		&record.PoolName,
		&record.Address,
		&record.Prefix,
		&record.Status,
		&record.CompiledFingerprint,
		&record.InstalledAt,
		&record.WithdrawnAt,
		&record.LastSeenAt,
		&record.CreatedAt,
		&record.UpdatedAt,
	)
	if err != nil {
		return AddressPolicyOwnershipRecord{}, fmt.Errorf("scan address policy ownership: %w", err)
	}
	return record, nil
}

func normalizeAddressPolicyOperation(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "compile", "preview", "decompile":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeAddressPolicyStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "compiled", "previewed", "decompiled", "blocked", "degraded", "failed":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeAddressPolicyOwnershipStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "withdrawn", "replaced", "stale", "observed":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "active"
	}
}

func normalizeAddressPolicyAssignmentType(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "pool", "prefix", "delegated_prefix", "ra_prefix":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "address"
	}
}

func addressPolicyAssignmentKey(input AddressPolicyOwnershipInput) string {
	payload := strings.Join([]string{
		firstNonEmptyDBString(input.SessionID, input.AcctSessionID, input.Role),
		input.Owner,
		input.Family,
		input.AssignmentType,
		input.PoolName,
		input.Address,
		input.Prefix,
	}, "|")
	sum := sha256.Sum256([]byte(payload))
	return "addr-" + hex.EncodeToString(sum[:12])
}

func addressPolicyOwnerFallback(input AddressPolicyOwnershipInput) string {
	payload := strings.Join([]string{
		firstNonEmptyDBString(input.SessionID, input.AcctSessionID, input.Role),
		input.Owner,
		input.Revision,
	}, "|")
	sum := sha256.Sum256([]byte(payload))
	return "address-owner-" + hex.EncodeToString(sum[:12])
}

func newAddressPolicyEventID(operation, status, responseJSON string) string {
	var nonce [8]byte
	_, _ = rand.Read(nonce[:])
	sum := sha256.Sum256([]byte(fmt.Sprintf("address-policy:%s:%s:%s:%d:%x",
		operation,
		status,
		responseJSON,
		time.Now().UTC().UnixNano(),
		nonce,
	)))
	return "address-policy-" + hex.EncodeToString(sum[:12])
}
