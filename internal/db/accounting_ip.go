package db

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

type AccountingIPFields struct {
	FramedIPAddress     string `json:"framed_ip_address,omitempty"`
	FramedIPv6Address   string `json:"framed_ipv6_address,omitempty"`
	FramedIPv6Prefix    string `json:"framed_ipv6_prefix,omitempty"`
	DelegatedIPv6Prefix string `json:"delegated_ipv6_prefix,omitempty"`
	FramedInterfaceID   string `json:"framed_interface_id,omitempty"`
	FramedRoute         string `json:"framed_route,omitempty"`
	FramedIPv6Route     string `json:"framed_ipv6_route,omitempty"`
	ValidationStatus    string `json:"validation_status"`
	ValidationError     string `json:"validation_error,omitempty"`
}

type AccountingIPAssignmentRecord struct {
	ID                  int    `json:"id"`
	SessionKey          string `json:"session_key"`
	EventID             string `json:"event_id"`
	AcctUniqueID        string `json:"acct_unique_id,omitempty"`
	AcctSessionID       string `json:"acct_session_id,omitempty"`
	StatusType          string `json:"status_type"`
	EventTime           string `json:"event_time"`
	Username            string `json:"username,omitempty"`
	NASIPAddress        string `json:"nas_ip_address,omitempty"`
	FramedIPAddress     string `json:"framed_ip_address,omitempty"`
	FramedIPv6Address   string `json:"framed_ipv6_address,omitempty"`
	FramedIPv6Prefix    string `json:"framed_ipv6_prefix,omitempty"`
	DelegatedIPv6Prefix string `json:"delegated_ipv6_prefix,omitempty"`
	FramedInterfaceID   string `json:"framed_interface_id,omitempty"`
	FramedRoute         string `json:"framed_route,omitempty"`
	FramedIPv6Route     string `json:"framed_ipv6_route,omitempty"`
	AssignmentStatus    string `json:"assignment_status"`
	ValidationStatus    string `json:"validation_status"`
	ValidationError     string `json:"validation_error,omitempty"`
	CreatedAt           string `json:"created_at,omitempty"`
	UpdatedAt           string `json:"updated_at,omitempty"`
}

type AccountingIPAssignmentSummary struct {
	AssignmentRows                 int    `json:"assignment_rows"`
	ActiveAssignments              int    `json:"active_assignments"`
	ClosedAssignments              int    `json:"closed_assignments"`
	IPv4AddressRows                int    `json:"ipv4_address_rows"`
	IPv6AddressRows                int    `json:"ipv6_address_rows"`
	IPv6PrefixRows                 int    `json:"ipv6_prefix_rows"`
	DelegatedPrefixRows            int    `json:"delegated_prefix_rows"`
	IPv4RouteRows                  int    `json:"ipv4_route_rows"`
	IPv6RouteRows                  int    `json:"ipv6_route_rows"`
	InvalidRows                    int    `json:"invalid_rows"`
	RadAcctRowsWithIPv6            int    `json:"radacct_rows_with_ipv6"`
	RadAcctRowsWithDelegatedPrefix int    `json:"radacct_rows_with_delegated_prefix"`
	RadAcctRowsWithRoute           int    `json:"radacct_rows_with_route"`
	SessionRowsWithIPv6            int    `json:"session_rows_with_ipv6"`
	SessionRowsWithDelegatedPrefix int    `json:"session_rows_with_delegated_prefix"`
	SessionRowsWithRoute           int    `json:"session_rows_with_route"`
	LastAssignmentAt               string `json:"last_assignment_at,omitempty"`
	LastValidationStatus           string `json:"last_validation_status,omitempty"`
	LastValidationError            string `json:"last_validation_error,omitempty"`
}

func NormalizeAccountingIPFields(fields AccountingIPFields) AccountingIPFields {
	fields.FramedIPAddress = strings.TrimSpace(fields.FramedIPAddress)
	fields.FramedIPv6Address = strings.TrimSpace(fields.FramedIPv6Address)
	fields.FramedIPv6Prefix = strings.TrimSpace(fields.FramedIPv6Prefix)
	fields.DelegatedIPv6Prefix = strings.TrimSpace(fields.DelegatedIPv6Prefix)
	fields.FramedInterfaceID = strings.ToLower(strings.TrimSpace(fields.FramedInterfaceID))
	fields.FramedRoute = strings.TrimSpace(fields.FramedRoute)
	fields.FramedIPv6Route = strings.TrimSpace(fields.FramedIPv6Route)

	var errors []string
	if fields.FramedIPAddress != "" {
		if normalized, err := canonicalIP(fields.FramedIPAddress, 4); err != nil {
			errors = append(errors, "Framed-IP-Address: "+err.Error())
		} else {
			fields.FramedIPAddress = normalized
		}
	}
	if fields.FramedIPv6Address != "" {
		if strings.Contains(fields.FramedIPv6Address, "/") {
			prefix, err := canonicalPrefix(fields.FramedIPv6Address, 6)
			if err != nil {
				errors = append(errors, "Framed-IPv6-Address: "+err.Error())
			} else {
				parsed, _ := netip.ParsePrefix(prefix)
				fields.FramedIPv6Address = parsed.Addr().String()
				if fields.FramedIPv6Prefix == "" {
					fields.FramedIPv6Prefix = prefix
				}
			}
		} else if normalized, err := canonicalIP(fields.FramedIPv6Address, 6); err != nil {
			errors = append(errors, "Framed-IPv6-Address: "+err.Error())
		} else {
			fields.FramedIPv6Address = normalized
		}
	}
	if fields.FramedIPv6Prefix != "" {
		if normalized, err := canonicalPrefix(fields.FramedIPv6Prefix, 6); err != nil {
			errors = append(errors, "Framed-IPv6-Prefix: "+err.Error())
		} else {
			fields.FramedIPv6Prefix = normalized
		}
	}
	if fields.DelegatedIPv6Prefix != "" {
		if normalized, err := canonicalPrefix(fields.DelegatedIPv6Prefix, 6); err != nil {
			errors = append(errors, "Delegated-IPv6-Prefix: "+err.Error())
		} else {
			fields.DelegatedIPv6Prefix = normalized
		}
	}
	if fields.FramedRoute != "" {
		normalized, routeErrors := canonicalRouteList(fields.FramedRoute, 4)
		fields.FramedRoute = normalized
		errors = append(errors, routeErrors...)
	}
	if fields.FramedIPv6Route != "" {
		normalized, routeErrors := canonicalRouteList(fields.FramedIPv6Route, 6)
		fields.FramedIPv6Route = normalized
		errors = append(errors, routeErrors...)
	}

	fields.ValidationStatus = "ok"
	fields.ValidationError = ""
	if len(errors) > 0 {
		fields.ValidationStatus = "invalid"
		fields.ValidationError = strings.Join(errors, "; ")
	}
	return fields
}

func RecordAccountingIPAssignment(ctx context.Context, event AccountingEventRecord) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	event = normalizeAccountingEventRecord(event)
	fields := accountingIPFieldsFromEvent(event)
	assignmentStatus := accountingAssignmentStatusForEvent(event.StatusType)
	if assignmentStatus == "closed" {
		if _, err := DB.ExecContext(ctx, `UPDATE radius_accounting_ip_assignments
			SET assignment_status = 'closed', updated_at = ?
			WHERE session_key = ? AND assignment_status = 'active'`,
			formatAccountingTime(time.Now().UTC()), event.SessionKey); err != nil && !tableMissing(err) {
			return fmt.Errorf("close accounting IP assignments: %w", err)
		}
	}
	if !accountingIPFieldsPresent(fields) && assignmentStatus != "closed" {
		return nil
	}

	now := formatAccountingTime(time.Now().UTC())
	if event.EventTime == "" {
		event.EventTime = now
	}
	_, err := DB.ExecContext(ctx, `INSERT INTO radius_accounting_ip_assignments (
		session_key, event_id, acct_unique_id, acct_session_id, status_type, event_time,
		username, nas_ip_address, framed_ip_address, framed_ipv6_address,
		framed_ipv6_prefix, delegated_ipv6_prefix, framed_interface_id,
		framed_route, framed_ipv6_route, assignment_status, validation_status,
		validation_error, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(event_id) DO UPDATE SET
		session_key = excluded.session_key,
		acct_unique_id = excluded.acct_unique_id,
		acct_session_id = excluded.acct_session_id,
		status_type = excluded.status_type,
		event_time = excluded.event_time,
		username = excluded.username,
		nas_ip_address = excluded.nas_ip_address,
		framed_ip_address = excluded.framed_ip_address,
		framed_ipv6_address = excluded.framed_ipv6_address,
		framed_ipv6_prefix = excluded.framed_ipv6_prefix,
		delegated_ipv6_prefix = excluded.delegated_ipv6_prefix,
		framed_interface_id = excluded.framed_interface_id,
		framed_route = excluded.framed_route,
		framed_ipv6_route = excluded.framed_ipv6_route,
		assignment_status = excluded.assignment_status,
		validation_status = excluded.validation_status,
		validation_error = excluded.validation_error,
		updated_at = excluded.updated_at`,
		event.SessionKey, event.EventID, event.AcctUniqueID, event.AcctSessionID, event.StatusType,
		event.EventTime, nullIfEmpty(event.Username), nullIfEmpty(event.NASIPAddress), nullIfEmpty(fields.FramedIPAddress),
		nullIfEmpty(fields.FramedIPv6Address), nullIfEmpty(fields.FramedIPv6Prefix), nullIfEmpty(fields.DelegatedIPv6Prefix),
		nullIfEmpty(fields.FramedInterfaceID), nullIfEmpty(fields.FramedRoute), nullIfEmpty(fields.FramedIPv6Route),
		assignmentStatus, fields.ValidationStatus, nullIfEmpty(fields.ValidationError), now, now)
	if err != nil {
		return fmt.Errorf("record accounting IP assignment: %w", err)
	}
	return nil
}

func ListAccountingIPAssignments(limit int, validationStatus, sessionKey string) ([]AccountingIPAssignmentRecord, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	query := `SELECT id, session_key, event_id, acct_unique_id, acct_session_id, status_type,
		COALESCE(CAST(event_time AS TEXT), ''), COALESCE(username, ''), COALESCE(nas_ip_address, ''),
		COALESCE(framed_ip_address, ''), COALESCE(framed_ipv6_address, ''),
		COALESCE(framed_ipv6_prefix, ''), COALESCE(delegated_ipv6_prefix, ''),
		COALESCE(framed_interface_id, ''), COALESCE(framed_route, ''),
		COALESCE(framed_ipv6_route, ''), assignment_status, validation_status,
		COALESCE(validation_error, ''), COALESCE(CAST(created_at AS TEXT), ''),
		COALESCE(CAST(updated_at AS TEXT), '')
		FROM radius_accounting_ip_assignments`
	args := []any{}
	filters := []string{}
	if validationStatus = strings.TrimSpace(validationStatus); validationStatus != "" {
		filters = append(filters, "validation_status = ?")
		args = append(args, validationStatus)
	}
	if sessionKey = strings.TrimSpace(sessionKey); sessionKey != "" {
		filters = append(filters, "session_key = ?")
		args = append(args, sessionKey)
	}
	if len(filters) > 0 {
		query += " WHERE " + strings.Join(filters, " AND ")
	}
	query += " ORDER BY event_time DESC, id DESC LIMIT ?"
	args = append(args, limit)

	rows, err := DB.Query(query, args...)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list accounting IP assignments: %w", err)
	}
	defer rows.Close()
	records := []AccountingIPAssignmentRecord{}
	for rows.Next() {
		var record AccountingIPAssignmentRecord
		if err := rows.Scan(&record.ID, &record.SessionKey, &record.EventID, &record.AcctUniqueID,
			&record.AcctSessionID, &record.StatusType, &record.EventTime, &record.Username,
			&record.NASIPAddress, &record.FramedIPAddress, &record.FramedIPv6Address,
			&record.FramedIPv6Prefix, &record.DelegatedIPv6Prefix, &record.FramedInterfaceID,
			&record.FramedRoute, &record.FramedIPv6Route, &record.AssignmentStatus,
			&record.ValidationStatus, &record.ValidationError, &record.CreatedAt, &record.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan accounting IP assignment: %w", err)
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func GetAccountingIPAssignmentSummary() (AccountingIPAssignmentSummary, error) {
	if DB == nil {
		return AccountingIPAssignmentSummary{}, fmt.Errorf("database not initialized")
	}
	var summary AccountingIPAssignmentSummary
	err := DB.QueryRow(`SELECT
		COUNT(*),
		COALESCE(SUM(CASE WHEN assignment_status = 'active' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN assignment_status = 'closed' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN framed_ip_address IS NOT NULL AND framed_ip_address <> '' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN framed_ipv6_address IS NOT NULL AND framed_ipv6_address <> '' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN framed_ipv6_prefix IS NOT NULL AND framed_ipv6_prefix <> '' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN delegated_ipv6_prefix IS NOT NULL AND delegated_ipv6_prefix <> '' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN framed_route IS NOT NULL AND framed_route <> '' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN framed_ipv6_route IS NOT NULL AND framed_ipv6_route <> '' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN validation_status = 'invalid' THEN 1 ELSE 0 END), 0),
		COALESCE(MAX(event_time), ''),
		COALESCE((SELECT validation_status FROM radius_accounting_ip_assignments ORDER BY event_time DESC, id DESC LIMIT 1), ''),
		COALESCE((SELECT validation_error FROM radius_accounting_ip_assignments WHERE validation_error IS NOT NULL AND validation_error <> '' ORDER BY updated_at DESC, id DESC LIMIT 1), '')
		FROM radius_accounting_ip_assignments`).Scan(&summary.AssignmentRows, &summary.ActiveAssignments,
		&summary.ClosedAssignments, &summary.IPv4AddressRows, &summary.IPv6AddressRows,
		&summary.IPv6PrefixRows, &summary.DelegatedPrefixRows, &summary.IPv4RouteRows,
		&summary.IPv6RouteRows, &summary.InvalidRows, &summary.LastAssignmentAt,
		&summary.LastValidationStatus, &summary.LastValidationError)
	if err != nil {
		if tableMissing(err) {
			return summary, nil
		}
		return AccountingIPAssignmentSummary{}, fmt.Errorf("summarize accounting IP assignments: %w", err)
	}
	_ = DB.QueryRow(`SELECT
		COALESCE(SUM(CASE WHEN framedipv6address IS NOT NULL AND framedipv6address <> '' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN delegatedipv6prefix IS NOT NULL AND delegatedipv6prefix <> '' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN framedroute IS NOT NULL AND framedroute <> '' OR framedipv6route IS NOT NULL AND framedipv6route <> '' THEN 1 ELSE 0 END), 0)
		FROM radacct`).Scan(&summary.RadAcctRowsWithIPv6, &summary.RadAcctRowsWithDelegatedPrefix, &summary.RadAcctRowsWithRoute)
	_ = DB.QueryRow(`SELECT
		COALESCE(SUM(CASE WHEN ipv6_address IS NOT NULL AND ipv6_address <> '' OR framed_ipv6_prefix IS NOT NULL AND framed_ipv6_prefix <> '' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN delegated_ipv6_prefix IS NOT NULL AND delegated_ipv6_prefix <> '' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN framed_route IS NOT NULL AND framed_route <> '' OR framed_ipv6_route IS NOT NULL AND framed_ipv6_route <> '' THEN 1 ELSE 0 END), 0)
		FROM sessions`).Scan(&summary.SessionRowsWithIPv6, &summary.SessionRowsWithDelegatedPrefix, &summary.SessionRowsWithRoute)
	return summary, nil
}

func PruneAccountingIPAssignments(retention time.Duration, now time.Time) error {
	if DB == nil || retention <= 0 {
		return nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	cutoff := formatAccountingTime(now.Add(-retention))
	_, err := DB.Exec(`DELETE FROM radius_accounting_ip_assignments
		WHERE assignment_status <> 'active' AND event_time < ?`, cutoff)
	if err != nil && !tableMissing(err) {
		return fmt.Errorf("prune accounting IP assignments: %w", err)
	}
	_, err = DB.Exec(`UPDATE radius_accounting_events
		SET ip_assignment_error = NULL
		WHERE ip_assignment_error IS NOT NULL AND event_time < ?`, cutoff)
	if err != nil && !tableMissing(err) {
		return fmt.Errorf("prune accounting IP validation evidence: %w", err)
	}
	return nil
}

func accountingIPFieldsFromEvent(event AccountingEventRecord) AccountingIPFields {
	return NormalizeAccountingIPFields(AccountingIPFields{
		FramedIPAddress:     event.FramedIPAddress,
		FramedIPv6Address:   event.FramedIPv6Address,
		FramedIPv6Prefix:    event.FramedIPv6Prefix,
		DelegatedIPv6Prefix: event.DelegatedIPv6Prefix,
		FramedInterfaceID:   event.FramedInterfaceID,
		FramedRoute:         event.FramedRoute,
		FramedIPv6Route:     event.FramedIPv6Route,
	})
}

func accountingIPFieldsPresent(fields AccountingIPFields) bool {
	return strings.TrimSpace(fields.FramedIPAddress) != "" ||
		strings.TrimSpace(fields.FramedIPv6Address) != "" ||
		strings.TrimSpace(fields.FramedIPv6Prefix) != "" ||
		strings.TrimSpace(fields.DelegatedIPv6Prefix) != "" ||
		strings.TrimSpace(fields.FramedInterfaceID) != "" ||
		strings.TrimSpace(fields.FramedRoute) != "" ||
		strings.TrimSpace(fields.FramedIPv6Route) != ""
}

func accountingAssignmentStatusForEvent(status string) string {
	switch canonicalAccountingStatus(status) {
	case "Stop", "Accounting-Off":
		return "closed"
	case "Unknown":
		return "unknown"
	default:
		return "active"
	}
}

func canonicalIP(value string, family int) (string, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return "", err
	}
	if family == 4 {
		addr = addr.Unmap()
		if !addr.Is4() {
			return "", fmt.Errorf("expected IPv4 address")
		}
		return addr.String(), nil
	}
	if !addr.Is6() || addr.Is4In6() {
		return "", fmt.Errorf("expected IPv6 address")
	}
	return addr.String(), nil
}

func canonicalPrefix(value string, family int) (string, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
	if err != nil {
		return "", err
	}
	addr := prefix.Addr()
	if family == 4 {
		addr = addr.Unmap()
		if !addr.Is4() {
			return "", fmt.Errorf("expected IPv4 prefix")
		}
		return netip.PrefixFrom(addr, prefix.Bits()).Masked().String(), nil
	}
	if !addr.Is6() || addr.Is4In6() {
		return "", fmt.Errorf("expected IPv6 prefix")
	}
	return prefix.Masked().String(), nil
}

func canonicalRouteList(value string, family int) (string, []string) {
	routes := splitAccountingRoutes(value)
	out := make([]string, 0, len(routes))
	var errors []string
	for _, route := range routes {
		tokens := strings.Fields(route)
		if len(tokens) == 0 {
			continue
		}
		destination, err := canonicalRouteDestination(tokens[0], family)
		if err != nil {
			name := "Framed-Route"
			if family == 6 {
				name = "Framed-IPv6-Route"
			}
			errors = append(errors, fmt.Sprintf("%s %q: %s", name, route, err))
			out = append(out, route)
			continue
		}
		tokens[0] = destination
		out = append(out, strings.Join(tokens, " "))
	}
	return strings.Join(out, "\n"), errors
}

func canonicalRouteDestination(value string, family int) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("empty route destination")
	}
	if strings.Contains(value, "/") {
		return canonicalPrefix(value, family)
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return "", err
	}
	if family == 4 {
		addr = addr.Unmap()
		if !addr.Is4() {
			return "", fmt.Errorf("expected IPv4 route destination")
		}
		return netip.PrefixFrom(addr, 32).String(), nil
	}
	if !addr.Is6() || addr.Is4In6() {
		return "", fmt.Errorf("expected IPv6 route destination")
	}
	return netip.PrefixFrom(addr, 128).String(), nil
}

func splitAccountingRoutes(value string) []string {
	return strings.FieldsFunc(value, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ';' || r == ','
	})
}
