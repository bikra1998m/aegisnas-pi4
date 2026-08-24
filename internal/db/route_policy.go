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

type RoutePolicyOwnershipInput struct {
	OwnershipKey  string
	SessionID     string
	AcctSessionID string
	Role          string
	VRF           string
	Owner         string
	Revision      string
	Family        string
	Destination   string
	Gateway       string
	Metric        int
	Preference    int
	Interface     string
	Tag           string
	Source        string
	Status        string
}

type RoutePolicyEventInput struct {
	EventID         string
	Operation       string
	Status          string
	Role            string
	SessionID       string
	AcctSessionID   string
	VRF             string
	Owner           string
	Revision        string
	IPv4RouteCount  int
	IPv6RouteCount  int
	WithdrawCount   int
	AttributeCount  int
	DiagnosticCount int
	Fingerprint     string
	RequestJSON     string
	ResponseJSON    string
	DiagnosticsJSON string
	Actor           string
	Ownership       []RoutePolicyOwnershipInput
}

type RoutePolicyEvent struct {
	ID              int    `json:"id"`
	EventID         string `json:"event_id"`
	Operation       string `json:"operation"`
	Status          string `json:"status"`
	Role            string `json:"role,omitempty"`
	SessionID       string `json:"session_id,omitempty"`
	AcctSessionID   string `json:"acct_session_id,omitempty"`
	VRF             string `json:"vrf,omitempty"`
	Owner           string `json:"owner,omitempty"`
	Revision        string `json:"revision,omitempty"`
	IPv4RouteCount  int    `json:"ipv4_route_count"`
	IPv6RouteCount  int    `json:"ipv6_route_count"`
	WithdrawCount   int    `json:"withdraw_count"`
	AttributeCount  int    `json:"attribute_count"`
	DiagnosticCount int    `json:"diagnostic_count"`
	Fingerprint     string `json:"fingerprint,omitempty"`
	RequestJSON     string `json:"request_json"`
	ResponseJSON    string `json:"response_json"`
	DiagnosticsJSON string `json:"diagnostics_json"`
	Actor           string `json:"actor,omitempty"`
	CreatedAt       string `json:"created_at"`
}

type RoutePolicyOwnershipRecord struct {
	ID                  int    `json:"id"`
	RouteKey            string `json:"route_key"`
	OwnershipKey        string `json:"ownership_key"`
	EventID             string `json:"event_id"`
	SessionID           string `json:"session_id,omitempty"`
	AcctSessionID       string `json:"acct_session_id,omitempty"`
	Role                string `json:"role,omitempty"`
	VRF                 string `json:"vrf"`
	Owner               string `json:"owner"`
	Revision            string `json:"revision"`
	Family              string `json:"family"`
	Destination         string `json:"destination"`
	Gateway             string `json:"gateway,omitempty"`
	Metric              int    `json:"metric"`
	Preference          int    `json:"preference"`
	Interface           string `json:"interface,omitempty"`
	Tag                 string `json:"tag,omitempty"`
	Source              string `json:"source,omitempty"`
	Status              string `json:"status"`
	CompiledFingerprint string `json:"compiled_fingerprint,omitempty"`
	InstalledAt         string `json:"installed_at,omitempty"`
	WithdrawnAt         string `json:"withdrawn_at,omitempty"`
	LastSeenAt          string `json:"last_seen_at,omitempty"`
	CreatedAt           string `json:"created_at,omitempty"`
	UpdatedAt           string `json:"updated_at,omitempty"`
}

type RoutePolicyEventSummary struct {
	TotalEvents         int    `json:"total_events"`
	CompiledCount       int    `json:"compiled_count"`
	PreviewedCount      int    `json:"previewed_count"`
	DecompiledCount     int    `json:"decompiled_count"`
	BlockedCount        int    `json:"blocked_count"`
	DegradedCount       int    `json:"degraded_count"`
	FailedCount         int    `json:"failed_count"`
	ActiveRoutes        int    `json:"active_routes"`
	WithdrawnRoutes     int    `json:"withdrawn_routes"`
	IPv4ActiveRoutes    int    `json:"ipv4_active_routes"`
	IPv6ActiveRoutes    int    `json:"ipv6_active_routes"`
	VRFCount            int    `json:"vrf_count"`
	LastEventAt         string `json:"last_event_at,omitempty"`
	LastStatus          string `json:"last_status,omitempty"`
	LastRole            string `json:"last_role,omitempty"`
	LastVRF             string `json:"last_vrf,omitempty"`
	LastRouteCount      int    `json:"last_route_count"`
	LastAttributeCount  int    `json:"last_attribute_count"`
	LastDiagnosticCount int    `json:"last_diagnostic_count"`
}

func RecordRoutePolicyEvent(input RoutePolicyEventInput) (string, error) {
	if DB == nil {
		return "", nil
	}
	input.Operation = normalizeRoutePolicyOperation(input.Operation)
	input.Status = normalizeRoutePolicyStatus(input.Status)
	if input.Operation == "" || input.Status == "" {
		return "", fmt.Errorf("route policy operation and status are required")
	}
	input.EventID = strings.TrimSpace(input.EventID)
	if input.EventID == "" {
		input.EventID = newRoutePolicyEventID(input.Operation, input.Status, input.ResponseJSON)
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
	_, err := DB.Exec(`INSERT INTO route_policy_events (
			event_id, operation, status, role, session_id, acct_session_id, vrf, owner, revision,
			ipv4_route_count, ipv6_route_count, withdraw_count, attribute_count, diagnostic_count,
			fingerprint, request_json, response_json, diagnostics_json, actor, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		input.EventID,
		input.Operation,
		input.Status,
		nullString(strings.TrimSpace(input.Role)),
		nullString(strings.TrimSpace(input.SessionID)),
		nullString(strings.TrimSpace(input.AcctSessionID)),
		nullString(strings.TrimSpace(input.VRF)),
		nullString(strings.TrimSpace(input.Owner)),
		nullString(strings.TrimSpace(input.Revision)),
		nonNegativeInt(input.IPv4RouteCount),
		nonNegativeInt(input.IPv6RouteCount),
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
		return "", fmt.Errorf("record route policy event: %w", err)
	}
	for _, ownership := range input.Ownership {
		if err := upsertRoutePolicyOwnership(input, ownership); err != nil {
			return "", err
		}
	}
	return input.EventID, nil
}

func ListRoutePolicyEvents(limit int) ([]RoutePolicyEvent, error) {
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
			COALESCE(acct_session_id, ''), COALESCE(vrf, ''), COALESCE(owner, ''), COALESCE(revision, ''),
			ipv4_route_count, ipv6_route_count, withdraw_count, attribute_count, diagnostic_count,
			COALESCE(fingerprint, ''), request_json, response_json, diagnostics_json, COALESCE(actor, ''),
			COALESCE(CAST(created_at AS TEXT), '')
		FROM route_policy_events
		ORDER BY datetime(created_at) DESC, id DESC
		LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list route policy events: %w", err)
	}
	defer rows.Close()
	var events []RoutePolicyEvent
	for rows.Next() {
		var event RoutePolicyEvent
		if err := rows.Scan(
			&event.ID,
			&event.EventID,
			&event.Operation,
			&event.Status,
			&event.Role,
			&event.SessionID,
			&event.AcctSessionID,
			&event.VRF,
			&event.Owner,
			&event.Revision,
			&event.IPv4RouteCount,
			&event.IPv6RouteCount,
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
			return nil, fmt.Errorf("scan route policy event: %w", err)
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func ListRoutePolicyOwnership(limit int, status string) ([]RoutePolicyOwnershipRecord, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	query := routePolicyOwnershipSelectSQL()
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
		return nil, fmt.Errorf("list route policy ownership: %w", err)
	}
	defer rows.Close()
	var out []RoutePolicyOwnershipRecord
	for rows.Next() {
		record, err := scanRoutePolicyOwnership(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, rows.Err()
}

func ListRoutePolicyOwnershipForExport(limit int, statuses ...string) ([]RoutePolicyOwnershipRecord, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 4096
	}
	if limit > 100000 {
		limit = 100000
	}
	query := routePolicyOwnershipSelectSQL()
	args := []any{}
	normalizedStatuses := make([]string, 0, len(statuses))
	for _, status := range statuses {
		status = strings.ToLower(strings.TrimSpace(status))
		if status != "" {
			normalizedStatuses = append(normalizedStatuses, status)
		}
	}
	if len(normalizedStatuses) > 0 {
		placeholders := make([]string, 0, len(normalizedStatuses))
		for _, status := range normalizedStatuses {
			placeholders = append(placeholders, "?")
			args = append(args, status)
		}
		query += " WHERE status IN (" + strings.Join(placeholders, ",") + ")"
	}
	query += " ORDER BY vrf, family, destination, owner, updated_at DESC, id DESC LIMIT ?"
	args = append(args, limit)
	rows, err := DB.Query(query, args...)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list route policy ownership for export: %w", err)
	}
	defer rows.Close()
	var out []RoutePolicyOwnershipRecord
	for rows.Next() {
		record, err := scanRoutePolicyOwnership(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, rows.Err()
}

func GetRoutePolicyEventSummary() (RoutePolicyEventSummary, error) {
	events, err := ListRoutePolicyEvents(1000)
	if err != nil {
		return RoutePolicyEventSummary{}, err
	}
	summary := RoutePolicyEventSummary{}
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
			summary.LastVRF = event.VRF
			summary.LastRouteCount = event.IPv4RouteCount + event.IPv6RouteCount
			summary.LastAttributeCount = event.AttributeCount
			summary.LastDiagnosticCount = event.DiagnosticCount
		}
	}
	if DB == nil {
		return summary, nil
	}
	_ = DB.QueryRow(`SELECT COUNT(*), COUNT(DISTINCT vrf) FROM route_policy_ownership WHERE status = 'active'`).Scan(&summary.ActiveRoutes, &summary.VRFCount)
	_ = DB.QueryRow(`SELECT COUNT(*) FROM route_policy_ownership WHERE status = 'withdrawn'`).Scan(&summary.WithdrawnRoutes)
	_ = DB.QueryRow(`SELECT COUNT(*) FROM route_policy_ownership WHERE status = 'active' AND family = 'ipv4'`).Scan(&summary.IPv4ActiveRoutes)
	_ = DB.QueryRow(`SELECT COUNT(*) FROM route_policy_ownership WHERE status = 'active' AND family = 'ipv6'`).Scan(&summary.IPv6ActiveRoutes)
	return summary, nil
}

func WithdrawRoutePolicyOwnershipForSession(ctx context.Context, sessionID, acctSessionID, eventID, actor string) (int64, error) {
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
	result, err := DB.ExecContext(ctx, `UPDATE route_policy_ownership
		SET status = 'withdrawn', withdrawn_at = ?, last_seen_at = ?, updated_at = CURRENT_TIMESTAMP,
			event_id = CASE WHEN ? <> '' THEN ? ELSE event_id END
		WHERE status = 'active' AND ((? <> '' AND session_id = ?) OR (? <> '' AND acct_session_id = ?))`,
		now, now, strings.TrimSpace(eventID), strings.TrimSpace(eventID),
		sessionID, sessionID, acctSessionID, acctSessionID)
	if err != nil {
		return 0, fmt.Errorf("withdraw route policy ownership: %w", err)
	}
	affected, _ := result.RowsAffected()
	if affected > 0 {
		_, _ = RecordRoutePolicyEvent(RoutePolicyEventInput{
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

func upsertRoutePolicyOwnership(event RoutePolicyEventInput, input RoutePolicyOwnershipInput) error {
	input = normalizeRoutePolicyOwnershipInput(event, input)
	if input.Destination == "" || input.Family == "" {
		return nil
	}
	routeKey := routePolicyRouteKey(input)
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
	_, err := DB.Exec(`INSERT INTO route_policy_ownership (
			route_key, ownership_key, event_id, session_id, acct_session_id, role, vrf, owner, revision,
			family, destination, gateway, metric, preference, interface_name, tag, source, status,
			compiled_fingerprint, installed_at, withdrawn_at, last_seen_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(route_key) DO UPDATE SET
			ownership_key = excluded.ownership_key,
			event_id = excluded.event_id,
			session_id = excluded.session_id,
			acct_session_id = excluded.acct_session_id,
			role = excluded.role,
			vrf = excluded.vrf,
			owner = excluded.owner,
			revision = excluded.revision,
			gateway = excluded.gateway,
			metric = excluded.metric,
			preference = excluded.preference,
			interface_name = excluded.interface_name,
			tag = excluded.tag,
			source = excluded.source,
			status = excluded.status,
			compiled_fingerprint = excluded.compiled_fingerprint,
			installed_at = COALESCE(excluded.installed_at, route_policy_ownership.installed_at),
			withdrawn_at = excluded.withdrawn_at,
			last_seen_at = excluded.last_seen_at,
			updated_at = CURRENT_TIMESTAMP`,
		routeKey,
		input.OwnershipKey,
		event.EventID,
		nullString(input.SessionID),
		nullString(input.AcctSessionID),
		nullString(input.Role),
		input.VRF,
		input.Owner,
		input.Revision,
		input.Family,
		input.Destination,
		nullString(input.Gateway),
		nonNegativeInt(input.Metric),
		nonNegativeInt(input.Preference),
		nullString(input.Interface),
		nullString(input.Tag),
		nullString(input.Source),
		status,
		nullString(event.Fingerprint),
		nullString(installedAt),
		nullString(withdrawnAt),
		now)
	if err != nil {
		return fmt.Errorf("upsert route policy ownership: %w", err)
	}
	return nil
}

func normalizeRoutePolicyOwnershipInput(event RoutePolicyEventInput, input RoutePolicyOwnershipInput) RoutePolicyOwnershipInput {
	input.SessionID = firstNonEmptyDBString(input.SessionID, event.SessionID)
	input.AcctSessionID = firstNonEmptyDBString(input.AcctSessionID, event.AcctSessionID)
	input.Role = firstNonEmptyDBString(input.Role, event.Role)
	input.VRF = firstNonEmptyDBString(input.VRF, event.VRF, "default")
	input.Owner = firstNonEmptyDBString(input.Owner, event.Owner, "aegisnas")
	input.Revision = firstNonEmptyDBString(input.Revision, event.Revision, "unknown")
	input.OwnershipKey = firstNonEmptyDBString(input.OwnershipKey, routePolicyRouteOwnerFallback(input))
	input.Family = strings.ToLower(strings.TrimSpace(input.Family))
	input.Destination = strings.TrimSpace(input.Destination)
	input.Gateway = strings.TrimSpace(input.Gateway)
	input.Interface = strings.TrimSpace(input.Interface)
	input.Tag = strings.TrimSpace(input.Tag)
	input.Source = strings.TrimSpace(input.Source)
	input.Status = normalizeRoutePolicyOwnershipStatus(input.Status)
	return input
}

func routePolicyOwnershipSelectSQL() string {
	return `SELECT id, route_key, ownership_key, event_id, COALESCE(session_id, ''), COALESCE(acct_session_id, ''),
		COALESCE(role, ''), vrf, owner, revision, family, destination, COALESCE(gateway, ''), metric, preference,
		COALESCE(interface_name, ''), COALESCE(tag, ''), COALESCE(source, ''), status,
		COALESCE(compiled_fingerprint, ''), COALESCE(CAST(installed_at AS TEXT), ''),
		COALESCE(CAST(withdrawn_at AS TEXT), ''), COALESCE(CAST(last_seen_at AS TEXT), ''),
		COALESCE(CAST(created_at AS TEXT), ''), COALESCE(CAST(updated_at AS TEXT), '')
		FROM route_policy_ownership`
}

func scanRoutePolicyOwnership(scanner interface {
	Scan(dest ...any) error
}) (RoutePolicyOwnershipRecord, error) {
	var record RoutePolicyOwnershipRecord
	err := scanner.Scan(
		&record.ID,
		&record.RouteKey,
		&record.OwnershipKey,
		&record.EventID,
		&record.SessionID,
		&record.AcctSessionID,
		&record.Role,
		&record.VRF,
		&record.Owner,
		&record.Revision,
		&record.Family,
		&record.Destination,
		&record.Gateway,
		&record.Metric,
		&record.Preference,
		&record.Interface,
		&record.Tag,
		&record.Source,
		&record.Status,
		&record.CompiledFingerprint,
		&record.InstalledAt,
		&record.WithdrawnAt,
		&record.LastSeenAt,
		&record.CreatedAt,
		&record.UpdatedAt,
	)
	if err != nil {
		return RoutePolicyOwnershipRecord{}, fmt.Errorf("scan route policy ownership: %w", err)
	}
	return record, nil
}

func normalizeRoutePolicyOperation(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "compile", "preview", "decompile":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeRoutePolicyStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "compiled", "previewed", "decompiled", "blocked", "degraded", "failed":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeRoutePolicyOwnershipStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "withdrawn", "replaced", "stale", "observed":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "active"
	}
}

func routePolicyRouteKey(input RoutePolicyOwnershipInput) string {
	payload := strings.Join([]string{
		firstNonEmptyDBString(input.SessionID, input.AcctSessionID, input.Role),
		input.VRF,
		input.Owner,
		input.Family,
		input.Destination,
	}, "|")
	sum := sha256.Sum256([]byte(payload))
	return "route-" + hex.EncodeToString(sum[:12])
}

func routePolicyRouteOwnerFallback(input RoutePolicyOwnershipInput) string {
	payload := strings.Join([]string{
		firstNonEmptyDBString(input.SessionID, input.AcctSessionID, input.Role),
		input.VRF,
		input.Owner,
		input.Revision,
	}, "|")
	sum := sha256.Sum256([]byte(payload))
	return "route-owner-" + hex.EncodeToString(sum[:12])
}

func newRoutePolicyEventID(operation, status, responseJSON string) string {
	var nonce [8]byte
	_, _ = rand.Read(nonce[:])
	sum := sha256.Sum256([]byte(fmt.Sprintf("route-policy:%s:%s:%s:%d:%x",
		operation,
		status,
		responseJSON,
		time.Now().UTC().UnixNano(),
		nonce,
	)))
	return "route-policy-" + hex.EncodeToString(sum[:12])
}

func firstNonEmptyDBString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
