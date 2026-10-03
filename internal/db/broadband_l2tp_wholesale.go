package db

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
)

type BroadbandL2TPWholesaleEventInput struct {
	EventID                  string
	Operation                string
	Status                   string
	PlanFingerprint          string
	Mode                     string
	RealmCount               int
	TunnelProfileCount       int
	FailoverPolicyCount      int
	ProxyRouteCount          int
	AccountingRouteCount     int
	CompiledAttributeCount   int
	ComplianceCheckCount     int
	PassedCheckCount         int
	WarningCount             int
	BlockerCount             int
	ExternalRequirementCount int
	SummaryJSON              string
	ReportJSON               string
	Actor                    string
	Bindings                 []BroadbandL2TPWholesaleBindingInput
}

type BroadbandL2TPWholesaleBindingInput struct {
	BindingKey             string
	RealmName              string
	Realm                  string
	Tenant                 string
	Partner                string
	AccessMethod           string
	TunnelProfile          string
	TunnelMode             string
	ProxyRoute             string
	AccountingRoute        string
	AddressPool            string
	QoSProfile             string
	Product                string
	Status                 string
	CompiledAttributesJSON string
	FailoverPolicy         string
	SourceEventID          string
	PlanFingerprint        string
	InstalledAt            string
	WithdrawnAt            string
}

type BroadbandL2TPWholesaleEvent struct {
	ID                       int    `json:"id"`
	EventID                  string `json:"event_id"`
	Operation                string `json:"operation"`
	Status                   string `json:"status"`
	PlanFingerprint          string `json:"plan_fingerprint"`
	Mode                     string `json:"mode,omitempty"`
	RealmCount               int    `json:"realm_count"`
	TunnelProfileCount       int    `json:"tunnel_profile_count"`
	FailoverPolicyCount      int    `json:"failover_policy_count"`
	ProxyRouteCount          int    `json:"proxy_route_count"`
	AccountingRouteCount     int    `json:"accounting_route_count"`
	CompiledAttributeCount   int    `json:"compiled_attribute_count"`
	ComplianceCheckCount     int    `json:"compliance_check_count"`
	PassedCheckCount         int    `json:"passed_check_count"`
	WarningCount             int    `json:"warning_count"`
	BlockerCount             int    `json:"blocker_count"`
	ExternalRequirementCount int    `json:"external_requirement_count"`
	SummaryJSON              string `json:"summary_json"`
	ReportJSON               string `json:"report_json,omitempty"`
	Actor                    string `json:"actor,omitempty"`
	CreatedAt                string `json:"created_at"`
}

type BroadbandL2TPWholesaleBindingRecord struct {
	ID                     int    `json:"id"`
	BindingKey             string `json:"binding_key"`
	RealmName              string `json:"realm_name"`
	Realm                  string `json:"realm"`
	Tenant                 string `json:"tenant,omitempty"`
	Partner                string `json:"partner,omitempty"`
	AccessMethod           string `json:"access_method"`
	TunnelProfile          string `json:"tunnel_profile"`
	TunnelMode             string `json:"tunnel_mode"`
	ProxyRoute             string `json:"proxy_route,omitempty"`
	AccountingRoute        string `json:"accounting_route,omitempty"`
	AddressPool            string `json:"address_pool,omitempty"`
	QoSProfile             string `json:"qos_profile,omitempty"`
	Product                string `json:"product,omitempty"`
	Status                 string `json:"status"`
	CompiledAttributesJSON string `json:"compiled_attributes_json"`
	FailoverPolicy         string `json:"failover_policy,omitempty"`
	SourceEventID          string `json:"source_event_id,omitempty"`
	PlanFingerprint        string `json:"plan_fingerprint"`
	InstalledAt            string `json:"installed_at,omitempty"`
	WithdrawnAt            string `json:"withdrawn_at,omitempty"`
	LastSeenAt             string `json:"last_seen_at"`
	CreatedAt              string `json:"created_at"`
	UpdatedAt              string `json:"updated_at"`
}

type BroadbandL2TPWholesaleSummary struct {
	TotalEvents                int    `json:"total_events"`
	PreviewEvents              int    `json:"preview_events"`
	ApplyEvents                int    `json:"apply_events"`
	PreviewedCount             int    `json:"previewed_count"`
	AppliedCount               int    `json:"applied_count"`
	BlockedCount               int    `json:"blocked_count"`
	DegradedCount              int    `json:"degraded_count"`
	SkippedCount               int    `json:"skipped_count"`
	FailedCount                int    `json:"failed_count"`
	ActiveBindings             int    `json:"active_bindings"`
	PlannedBindings            int    `json:"planned_bindings"`
	DegradedBindings           int    `json:"degraded_bindings"`
	BlockedBindings            int    `json:"blocked_bindings"`
	WithdrawnBindings          int    `json:"withdrawn_bindings"`
	LastEventAt                string `json:"last_event_at,omitempty"`
	LastFingerprint            string `json:"last_fingerprint,omitempty"`
	LastRealmCount             int    `json:"last_realm_count"`
	LastTunnelProfileCount     int    `json:"last_tunnel_profile_count"`
	LastFailoverPolicyCount    int    `json:"last_failover_policy_count"`
	LastCompiledAttributeCount int    `json:"last_compiled_attribute_count"`
}

func RecordBroadbandL2TPWholesaleEvent(input BroadbandL2TPWholesaleEventInput) (string, error) {
	if DB == nil {
		return "", nil
	}
	input.Operation = normalizeBroadbandL2TPWholesaleOperation(input.Operation)
	input.Status = normalizeBroadbandL2TPWholesaleStatus(input.Status)
	input.EventID = strings.TrimSpace(input.EventID)
	if input.EventID == "" {
		input.EventID = newBroadbandL2TPWholesaleEventID(input)
	}
	if input.Operation == "" || input.Status == "" {
		return "", fmt.Errorf("broadband L2TP wholesale operation and status are required")
	}
	if strings.TrimSpace(input.PlanFingerprint) == "" {
		return "", fmt.Errorf("broadband L2TP wholesale plan fingerprint is required")
	}
	if strings.TrimSpace(input.SummaryJSON) == "" {
		input.SummaryJSON = "{}"
	}
	if strings.TrimSpace(input.ReportJSON) == "" {
		input.ReportJSON = "{}"
	}
	tx, err := DB.Begin()
	if err != nil {
		return "", fmt.Errorf("begin broadband L2TP wholesale event: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO broadband_l2tp_wholesale_events (
			event_id, operation, status, plan_fingerprint, mode,
			realm_count, tunnel_profile_count, failover_policy_count, proxy_route_count, accounting_route_count,
			compiled_attribute_count, compliance_check_count, passed_check_count, warning_count, blocker_count,
			external_requirement_count, summary_json, report_json, actor, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(event_id) DO UPDATE SET
			operation = excluded.operation,
			status = excluded.status,
			plan_fingerprint = excluded.plan_fingerprint,
			mode = excluded.mode,
			realm_count = excluded.realm_count,
			tunnel_profile_count = excluded.tunnel_profile_count,
			failover_policy_count = excluded.failover_policy_count,
			proxy_route_count = excluded.proxy_route_count,
			accounting_route_count = excluded.accounting_route_count,
			compiled_attribute_count = excluded.compiled_attribute_count,
			compliance_check_count = excluded.compliance_check_count,
			passed_check_count = excluded.passed_check_count,
			warning_count = excluded.warning_count,
			blocker_count = excluded.blocker_count,
			external_requirement_count = excluded.external_requirement_count,
			summary_json = excluded.summary_json,
			report_json = excluded.report_json,
			actor = excluded.actor`,
		input.EventID,
		input.Operation,
		input.Status,
		strings.TrimSpace(input.PlanFingerprint),
		nullString(strings.TrimSpace(input.Mode)),
		nonNegativeInt(input.RealmCount),
		nonNegativeInt(input.TunnelProfileCount),
		nonNegativeInt(input.FailoverPolicyCount),
		nonNegativeInt(input.ProxyRouteCount),
		nonNegativeInt(input.AccountingRouteCount),
		nonNegativeInt(input.CompiledAttributeCount),
		nonNegativeInt(input.ComplianceCheckCount),
		nonNegativeInt(input.PassedCheckCount),
		nonNegativeInt(input.WarningCount),
		nonNegativeInt(input.BlockerCount),
		nonNegativeInt(input.ExternalRequirementCount),
		input.SummaryJSON,
		input.ReportJSON,
		nullString(strings.TrimSpace(input.Actor)),
	)
	if err != nil {
		return "", fmt.Errorf("record broadband L2TP wholesale event: %w", err)
	}
	for _, binding := range input.Bindings {
		binding.SourceEventID = firstNonEmptyString(binding.SourceEventID, input.EventID)
		if err := upsertBroadbandL2TPWholesaleBinding(tx, binding); err != nil {
			return "", err
		}
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit broadband L2TP wholesale event: %w", err)
	}
	return input.EventID, nil
}

func ListBroadbandL2TPWholesaleEvents(limit int) ([]BroadbandL2TPWholesaleEvent, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := DB.Query(broadbandL2TPWholesaleEventSelectSQL()+` ORDER BY datetime(created_at) DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list broadband L2TP wholesale events: %w", err)
	}
	defer rows.Close()
	var events []BroadbandL2TPWholesaleEvent
	for rows.Next() {
		event, err := scanBroadbandL2TPWholesaleEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func ListBroadbandL2TPWholesaleBindings(limit int, status string) ([]BroadbandL2TPWholesaleBindingRecord, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	query := broadbandL2TPWholesaleBindingSelectSQL()
	var args []any
	if strings.TrimSpace(status) != "" {
		query += ` WHERE status = ?`
		args = append(args, strings.ToLower(strings.TrimSpace(status)))
	}
	query += ` ORDER BY datetime(updated_at) DESC, id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := DB.Query(query, args...)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list broadband L2TP wholesale bindings: %w", err)
	}
	defer rows.Close()
	var bindings []BroadbandL2TPWholesaleBindingRecord
	for rows.Next() {
		binding, err := scanBroadbandL2TPWholesaleBinding(rows)
		if err != nil {
			return nil, err
		}
		bindings = append(bindings, binding)
	}
	return bindings, rows.Err()
}

func GetBroadbandL2TPWholesaleSummary() (BroadbandL2TPWholesaleSummary, error) {
	events, err := ListBroadbandL2TPWholesaleEvents(1000)
	if err != nil {
		return BroadbandL2TPWholesaleSummary{}, err
	}
	bindings, err := ListBroadbandL2TPWholesaleBindings(1000, "")
	if err != nil {
		return BroadbandL2TPWholesaleSummary{}, err
	}
	summary := BroadbandL2TPWholesaleSummary{}
	for _, event := range events {
		summary.TotalEvents++
		if summary.LastEventAt == "" {
			summary.LastEventAt = event.CreatedAt
			summary.LastFingerprint = event.PlanFingerprint
			summary.LastRealmCount = event.RealmCount
			summary.LastTunnelProfileCount = event.TunnelProfileCount
			summary.LastFailoverPolicyCount = event.FailoverPolicyCount
			summary.LastCompiledAttributeCount = event.CompiledAttributeCount
		}
		switch event.Operation {
		case "preview":
			summary.PreviewEvents++
		case "apply":
			summary.ApplyEvents++
		}
		switch event.Status {
		case "previewed":
			summary.PreviewedCount++
		case "applied":
			summary.AppliedCount++
		case "blocked":
			summary.BlockedCount++
		case "degraded":
			summary.DegradedCount++
		case "skipped":
			summary.SkippedCount++
		case "failed":
			summary.FailedCount++
		}
	}
	for _, binding := range bindings {
		switch binding.Status {
		case "active":
			summary.ActiveBindings++
		case "planned":
			summary.PlannedBindings++
		case "degraded":
			summary.DegradedBindings++
		case "blocked":
			summary.BlockedBindings++
		case "withdrawn":
			summary.WithdrawnBindings++
		}
	}
	return summary, nil
}

func upsertBroadbandL2TPWholesaleBinding(tx *sql.Tx, input BroadbandL2TPWholesaleBindingInput) error {
	input.BindingKey = strings.TrimSpace(input.BindingKey)
	if input.BindingKey == "" {
		return fmt.Errorf("broadband L2TP wholesale binding key is required")
	}
	if strings.TrimSpace(input.RealmName) == "" || strings.TrimSpace(input.Realm) == "" || strings.TrimSpace(input.TunnelProfile) == "" {
		return fmt.Errorf("broadband L2TP wholesale realm, realm_name, and tunnel_profile are required")
	}
	input.Status = normalizeBroadbandL2TPWholesaleBindingStatus(input.Status)
	if strings.TrimSpace(input.CompiledAttributesJSON) == "" {
		input.CompiledAttributesJSON = "[]"
	}
	_, err := tx.Exec(`INSERT INTO broadband_l2tp_wholesale_bindings (
			binding_key, realm_name, realm, tenant, partner, access_method, tunnel_profile, tunnel_mode,
			proxy_route, accounting_route, address_pool, qos_profile, product, status,
			compiled_attributes_json, failover_policy, source_event_id, plan_fingerprint,
			installed_at, withdrawn_at, last_seen_at, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT(binding_key) DO UPDATE SET
			realm_name = excluded.realm_name,
			realm = excluded.realm,
			tenant = excluded.tenant,
			partner = excluded.partner,
			access_method = excluded.access_method,
			tunnel_profile = excluded.tunnel_profile,
			tunnel_mode = excluded.tunnel_mode,
			proxy_route = excluded.proxy_route,
			accounting_route = excluded.accounting_route,
			address_pool = excluded.address_pool,
			qos_profile = excluded.qos_profile,
			product = excluded.product,
			status = excluded.status,
			compiled_attributes_json = excluded.compiled_attributes_json,
			failover_policy = excluded.failover_policy,
			source_event_id = excluded.source_event_id,
			plan_fingerprint = excluded.plan_fingerprint,
			installed_at = excluded.installed_at,
			withdrawn_at = excluded.withdrawn_at,
			last_seen_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP`,
		input.BindingKey,
		strings.TrimSpace(input.RealmName),
		strings.TrimSpace(input.Realm),
		nullString(strings.TrimSpace(input.Tenant)),
		nullString(strings.TrimSpace(input.Partner)),
		firstNonEmptyString(strings.TrimSpace(input.AccessMethod), "pppoe"),
		strings.TrimSpace(input.TunnelProfile),
		firstNonEmptyString(strings.TrimSpace(input.TunnelMode), "lns"),
		nullString(strings.TrimSpace(input.ProxyRoute)),
		nullString(strings.TrimSpace(input.AccountingRoute)),
		nullString(strings.TrimSpace(input.AddressPool)),
		nullString(strings.TrimSpace(input.QoSProfile)),
		nullString(strings.TrimSpace(input.Product)),
		input.Status,
		input.CompiledAttributesJSON,
		nullString(strings.TrimSpace(input.FailoverPolicy)),
		nullString(strings.TrimSpace(input.SourceEventID)),
		strings.TrimSpace(input.PlanFingerprint),
		nullString(strings.TrimSpace(input.InstalledAt)),
		nullString(strings.TrimSpace(input.WithdrawnAt)),
	)
	if err != nil {
		return fmt.Errorf("upsert broadband L2TP wholesale binding %q: %w", input.BindingKey, err)
	}
	return nil
}

func broadbandL2TPWholesaleEventSelectSQL() string {
	return `SELECT id, event_id, operation, status, plan_fingerprint, COALESCE(mode, ''),
		realm_count, tunnel_profile_count, failover_policy_count, proxy_route_count, accounting_route_count,
		compiled_attribute_count, compliance_check_count, passed_check_count, warning_count, blocker_count,
		external_requirement_count, summary_json, report_json, COALESCE(actor, ''), created_at
		FROM broadband_l2tp_wholesale_events`
}

func broadbandL2TPWholesaleBindingSelectSQL() string {
	return `SELECT id, binding_key, realm_name, realm, COALESCE(tenant, ''), COALESCE(partner, ''),
		access_method, tunnel_profile, tunnel_mode, COALESCE(proxy_route, ''), COALESCE(accounting_route, ''),
		COALESCE(address_pool, ''), COALESCE(qos_profile, ''), COALESCE(product, ''), status,
		compiled_attributes_json, COALESCE(failover_policy, ''), COALESCE(source_event_id, ''),
		plan_fingerprint, COALESCE(installed_at, ''), COALESCE(withdrawn_at, ''), last_seen_at, created_at, updated_at
		FROM broadband_l2tp_wholesale_bindings`
}

func scanBroadbandL2TPWholesaleEvent(row interface{ Scan(dest ...any) error }) (BroadbandL2TPWholesaleEvent, error) {
	var event BroadbandL2TPWholesaleEvent
	if err := row.Scan(
		&event.ID, &event.EventID, &event.Operation, &event.Status, &event.PlanFingerprint, &event.Mode,
		&event.RealmCount, &event.TunnelProfileCount, &event.FailoverPolicyCount, &event.ProxyRouteCount, &event.AccountingRouteCount,
		&event.CompiledAttributeCount, &event.ComplianceCheckCount, &event.PassedCheckCount, &event.WarningCount,
		&event.BlockerCount, &event.ExternalRequirementCount, &event.SummaryJSON, &event.ReportJSON, &event.Actor, &event.CreatedAt,
	); err != nil {
		return BroadbandL2TPWholesaleEvent{}, fmt.Errorf("scan broadband L2TP wholesale event: %w", err)
	}
	return event, nil
}

func scanBroadbandL2TPWholesaleBinding(row interface{ Scan(dest ...any) error }) (BroadbandL2TPWholesaleBindingRecord, error) {
	var binding BroadbandL2TPWholesaleBindingRecord
	if err := row.Scan(
		&binding.ID, &binding.BindingKey, &binding.RealmName, &binding.Realm, &binding.Tenant, &binding.Partner,
		&binding.AccessMethod, &binding.TunnelProfile, &binding.TunnelMode, &binding.ProxyRoute, &binding.AccountingRoute,
		&binding.AddressPool, &binding.QoSProfile, &binding.Product, &binding.Status, &binding.CompiledAttributesJSON,
		&binding.FailoverPolicy, &binding.SourceEventID, &binding.PlanFingerprint, &binding.InstalledAt,
		&binding.WithdrawnAt, &binding.LastSeenAt, &binding.CreatedAt, &binding.UpdatedAt,
	); err != nil {
		return BroadbandL2TPWholesaleBindingRecord{}, fmt.Errorf("scan broadband L2TP wholesale binding: %w", err)
	}
	return binding, nil
}

func normalizeBroadbandL2TPWholesaleOperation(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "preview", "apply", "status", "reconcile":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "preview"
	}
}

func normalizeBroadbandL2TPWholesaleStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "previewed", "applied", "blocked", "degraded", "skipped", "failed", "reconciled":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "previewed"
	}
}

func normalizeBroadbandL2TPWholesaleBindingStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "planned", "active", "degraded", "blocked", "withdrawn":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "planned"
	}
}

func newBroadbandL2TPWholesaleEventID(input BroadbandL2TPWholesaleEventInput) string {
	random := make([]byte, 16)
	_, _ = rand.Read(random)
	sum := sha256.Sum256([]byte(strings.Join([]string{input.Operation, input.Status, input.PlanFingerprint, hex.EncodeToString(random)}, "|")))
	return "bng-l2tp-" + input.Operation + "-" + hex.EncodeToString(sum[:8])
}
