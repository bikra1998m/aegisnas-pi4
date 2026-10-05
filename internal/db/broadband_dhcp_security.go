package db

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
)

type BroadbandDHCPSecurityEventInput struct {
	EventID                  string
	Operation                string
	Status                   string
	PlanFingerprint          string
	Mode                     string
	RelayAgentCount          int
	PortCount                int
	TrustedPortCount         int
	Option82RuleCount        int
	SourceGuardPolicyCount   int
	RADIUSCorrelationCount   int
	CompiledOptionCount      int
	ComplianceCheckCount     int
	PassedCheckCount         int
	WarningCount             int
	BlockerCount             int
	ExternalRequirementCount int
	SummaryJSON              string
	ReportJSON               string
	Actor                    string
	Bindings                 []BroadbandDHCPSecurityBindingInput
}

type BroadbandDHCPSecurityBindingInput struct {
	BindingKey          string
	PortName            string
	Interface           string
	VLAN                int
	Role                string
	Trusted             bool
	CircuitID           string
	RemoteID            string
	SubscriberProduct   string
	Tenant              string
	RelayAgent          string
	SourceGuardPolicy   string
	Status              string
	CompiledOptionsJSON string
	SourceEventID       string
	PlanFingerprint     string
	InstalledAt         string
	WithdrawnAt         string
}

type BroadbandDHCPSecurityEvent struct {
	ID                       int    `json:"id"`
	EventID                  string `json:"event_id"`
	Operation                string `json:"operation"`
	Status                   string `json:"status"`
	PlanFingerprint          string `json:"plan_fingerprint"`
	Mode                     string `json:"mode,omitempty"`
	RelayAgentCount          int    `json:"relay_agent_count"`
	PortCount                int    `json:"port_count"`
	TrustedPortCount         int    `json:"trusted_port_count"`
	Option82RuleCount        int    `json:"option82_rule_count"`
	SourceGuardPolicyCount   int    `json:"source_guard_policy_count"`
	RADIUSCorrelationCount   int    `json:"radius_correlation_count"`
	CompiledOptionCount      int    `json:"compiled_option_count"`
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

type BroadbandDHCPSecurityBindingRecord struct {
	ID                  int    `json:"id"`
	BindingKey          string `json:"binding_key"`
	PortName            string `json:"port_name"`
	Interface           string `json:"interface"`
	VLAN                int    `json:"vlan"`
	Role                string `json:"role"`
	Trusted             bool   `json:"trusted"`
	CircuitID           string `json:"circuit_id,omitempty"`
	RemoteID            string `json:"remote_id,omitempty"`
	SubscriberProduct   string `json:"subscriber_product,omitempty"`
	Tenant              string `json:"tenant,omitempty"`
	RelayAgent          string `json:"relay_agent,omitempty"`
	SourceGuardPolicy   string `json:"source_guard_policy,omitempty"`
	Status              string `json:"status"`
	CompiledOptionsJSON string `json:"compiled_options_json"`
	SourceEventID       string `json:"source_event_id,omitempty"`
	PlanFingerprint     string `json:"plan_fingerprint"`
	InstalledAt         string `json:"installed_at,omitempty"`
	WithdrawnAt         string `json:"withdrawn_at,omitempty"`
	LastSeenAt          string `json:"last_seen_at"`
	CreatedAt           string `json:"created_at"`
	UpdatedAt           string `json:"updated_at"`
}

type BroadbandDHCPSecuritySummary struct {
	TotalEvents             int    `json:"total_events"`
	PreviewEvents           int    `json:"preview_events"`
	ApplyEvents             int    `json:"apply_events"`
	PreviewedCount          int    `json:"previewed_count"`
	AppliedCount            int    `json:"applied_count"`
	BlockedCount            int    `json:"blocked_count"`
	DegradedCount           int    `json:"degraded_count"`
	SkippedCount            int    `json:"skipped_count"`
	FailedCount             int    `json:"failed_count"`
	ActiveBindings          int    `json:"active_bindings"`
	PlannedBindings         int    `json:"planned_bindings"`
	DegradedBindings        int    `json:"degraded_bindings"`
	BlockedBindings         int    `json:"blocked_bindings"`
	WithdrawnBindings       int    `json:"withdrawn_bindings"`
	LastEventAt             string `json:"last_event_at,omitempty"`
	LastFingerprint         string `json:"last_fingerprint,omitempty"`
	LastRelayAgentCount     int    `json:"last_relay_agent_count"`
	LastPortCount           int    `json:"last_port_count"`
	LastTrustedPortCount    int    `json:"last_trusted_port_count"`
	LastOption82RuleCount   int    `json:"last_option82_rule_count"`
	LastSourceGuardCount    int    `json:"last_source_guard_policy_count"`
	LastCompiledOptionCount int    `json:"last_compiled_option_count"`
}

func RecordBroadbandDHCPSecurityEvent(input BroadbandDHCPSecurityEventInput) (string, error) {
	if DB == nil {
		return "", nil
	}
	input.Operation = normalizeBroadbandDHCPSecurityOperation(input.Operation)
	input.Status = normalizeBroadbandDHCPSecurityStatus(input.Status)
	input.EventID = strings.TrimSpace(input.EventID)
	if input.EventID == "" {
		input.EventID = newBroadbandDHCPSecurityEventID(input)
	}
	if input.Operation == "" || input.Status == "" {
		return "", fmt.Errorf("broadband DHCP security operation and status are required")
	}
	if strings.TrimSpace(input.PlanFingerprint) == "" {
		return "", fmt.Errorf("broadband DHCP security plan fingerprint is required")
	}
	if strings.TrimSpace(input.SummaryJSON) == "" {
		input.SummaryJSON = "{}"
	}
	if strings.TrimSpace(input.ReportJSON) == "" {
		input.ReportJSON = "{}"
	}
	tx, err := DB.Begin()
	if err != nil {
		return "", fmt.Errorf("begin broadband DHCP security event: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO broadband_dhcp_security_events (
			event_id, operation, status, plan_fingerprint, mode,
			relay_agent_count, port_count, trusted_port_count, option82_rule_count, source_guard_policy_count,
			radius_correlation_count, compiled_option_count, compliance_check_count, passed_check_count,
			warning_count, blocker_count, external_requirement_count, summary_json, report_json, actor, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(event_id) DO UPDATE SET
			operation = excluded.operation,
			status = excluded.status,
			plan_fingerprint = excluded.plan_fingerprint,
			mode = excluded.mode,
			relay_agent_count = excluded.relay_agent_count,
			port_count = excluded.port_count,
			trusted_port_count = excluded.trusted_port_count,
			option82_rule_count = excluded.option82_rule_count,
			source_guard_policy_count = excluded.source_guard_policy_count,
			radius_correlation_count = excluded.radius_correlation_count,
			compiled_option_count = excluded.compiled_option_count,
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
		nonNegativeInt(input.RelayAgentCount),
		nonNegativeInt(input.PortCount),
		nonNegativeInt(input.TrustedPortCount),
		nonNegativeInt(input.Option82RuleCount),
		nonNegativeInt(input.SourceGuardPolicyCount),
		nonNegativeInt(input.RADIUSCorrelationCount),
		nonNegativeInt(input.CompiledOptionCount),
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
		return "", fmt.Errorf("record broadband DHCP security event: %w", err)
	}
	for _, binding := range input.Bindings {
		binding.SourceEventID = firstNonEmptyString(binding.SourceEventID, input.EventID)
		if err := upsertBroadbandDHCPSecurityBinding(tx, binding); err != nil {
			return "", err
		}
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit broadband DHCP security event: %w", err)
	}
	return input.EventID, nil
}

func ListBroadbandDHCPSecurityEvents(limit int) ([]BroadbandDHCPSecurityEvent, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := DB.Query(`SELECT id, event_id, operation, status, plan_fingerprint, COALESCE(mode, ''),
		relay_agent_count, port_count, trusted_port_count, option82_rule_count, source_guard_policy_count,
		radius_correlation_count, compiled_option_count, compliance_check_count, passed_check_count,
		warning_count, blocker_count, external_requirement_count, summary_json, report_json, COALESCE(actor, ''), created_at
		FROM broadband_dhcp_security_events ORDER BY created_at DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list broadband DHCP security events: %w", err)
	}
	defer rows.Close()
	events := []BroadbandDHCPSecurityEvent{}
	for rows.Next() {
		var event BroadbandDHCPSecurityEvent
		if err := rows.Scan(&event.ID, &event.EventID, &event.Operation, &event.Status, &event.PlanFingerprint, &event.Mode,
			&event.RelayAgentCount, &event.PortCount, &event.TrustedPortCount, &event.Option82RuleCount, &event.SourceGuardPolicyCount,
			&event.RADIUSCorrelationCount, &event.CompiledOptionCount, &event.ComplianceCheckCount, &event.PassedCheckCount,
			&event.WarningCount, &event.BlockerCount, &event.ExternalRequirementCount, &event.SummaryJSON, &event.ReportJSON,
			&event.Actor, &event.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan broadband DHCP security event: %w", err)
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func ListBroadbandDHCPSecurityBindings(limit int, status string) ([]BroadbandDHCPSecurityBindingRecord, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	status = strings.ToLower(strings.TrimSpace(status))
	query := `SELECT id, binding_key, port_name, interface, vlan, role, trusted, COALESCE(circuit_id, ''), COALESCE(remote_id, ''),
		COALESCE(subscriber_product, ''), COALESCE(tenant, ''), COALESCE(relay_agent, ''), COALESCE(source_guard_policy, ''),
		status, compiled_options_json, COALESCE(source_event_id, ''), plan_fingerprint, COALESCE(installed_at, ''),
		COALESCE(withdrawn_at, ''), last_seen_at, created_at, updated_at
		FROM broadband_dhcp_security_bindings`
	args := []any{}
	if status != "" {
		query += " WHERE status = ?"
		args = append(args, status)
	}
	query += " ORDER BY updated_at DESC, id DESC LIMIT ?"
	args = append(args, limit)
	rows, err := DB.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list broadband DHCP security bindings: %w", err)
	}
	defer rows.Close()
	bindings := []BroadbandDHCPSecurityBindingRecord{}
	for rows.Next() {
		var binding BroadbandDHCPSecurityBindingRecord
		if err := rows.Scan(&binding.ID, &binding.BindingKey, &binding.PortName, &binding.Interface, &binding.VLAN, &binding.Role,
			&binding.Trusted, &binding.CircuitID, &binding.RemoteID, &binding.SubscriberProduct, &binding.Tenant, &binding.RelayAgent,
			&binding.SourceGuardPolicy, &binding.Status, &binding.CompiledOptionsJSON, &binding.SourceEventID, &binding.PlanFingerprint,
			&binding.InstalledAt, &binding.WithdrawnAt, &binding.LastSeenAt, &binding.CreatedAt, &binding.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan broadband DHCP security binding: %w", err)
		}
		bindings = append(bindings, binding)
	}
	return bindings, rows.Err()
}

func GetBroadbandDHCPSecuritySummary() (BroadbandDHCPSecuritySummary, error) {
	if DB == nil {
		return BroadbandDHCPSecuritySummary{}, nil
	}
	var summary BroadbandDHCPSecuritySummary
	err := DB.QueryRow(`SELECT COUNT(*),
		COALESCE(SUM(CASE WHEN operation = 'preview' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN operation = 'apply' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'previewed' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'applied' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'degraded' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'skipped' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END), 0),
		COALESCE(MAX(created_at), '')
		FROM broadband_dhcp_security_events`).Scan(&summary.TotalEvents, &summary.PreviewEvents, &summary.ApplyEvents,
		&summary.PreviewedCount, &summary.AppliedCount, &summary.BlockedCount, &summary.DegradedCount,
		&summary.SkippedCount, &summary.FailedCount, &summary.LastEventAt)
	if err != nil {
		return BroadbandDHCPSecuritySummary{}, fmt.Errorf("summarize broadband DHCP security events: %w", err)
	}
	_ = DB.QueryRow(`SELECT
		COALESCE(SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'planned' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'degraded' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'withdrawn' THEN 1 ELSE 0 END), 0)
		FROM broadband_dhcp_security_bindings`).Scan(&summary.ActiveBindings, &summary.PlannedBindings, &summary.DegradedBindings, &summary.BlockedBindings, &summary.WithdrawnBindings)
	var last struct {
		Fingerprint       string
		RelayAgentCount   int
		PortCount         int
		TrustedPortCount  int
		Option82RuleCount int
		SourceGuardCount  int
		CompiledOptions   int
	}
	err = DB.QueryRow(`SELECT plan_fingerprint, relay_agent_count, port_count, trusted_port_count, option82_rule_count,
		source_guard_policy_count, compiled_option_count FROM broadband_dhcp_security_events ORDER BY created_at DESC, id DESC LIMIT 1`).
		Scan(&last.Fingerprint, &last.RelayAgentCount, &last.PortCount, &last.TrustedPortCount, &last.Option82RuleCount, &last.SourceGuardCount, &last.CompiledOptions)
	if err != nil && err != sql.ErrNoRows {
		return BroadbandDHCPSecuritySummary{}, fmt.Errorf("summarize last broadband DHCP security event: %w", err)
	}
	summary.LastFingerprint = last.Fingerprint
	summary.LastRelayAgentCount = last.RelayAgentCount
	summary.LastPortCount = last.PortCount
	summary.LastTrustedPortCount = last.TrustedPortCount
	summary.LastOption82RuleCount = last.Option82RuleCount
	summary.LastSourceGuardCount = last.SourceGuardCount
	summary.LastCompiledOptionCount = last.CompiledOptions
	return summary, nil
}

func upsertBroadbandDHCPSecurityBinding(tx *sql.Tx, input BroadbandDHCPSecurityBindingInput) error {
	input.BindingKey = strings.TrimSpace(input.BindingKey)
	input.Status = normalizeBroadbandDHCPSecurityBindingStatus(input.Status)
	if input.BindingKey == "" || strings.TrimSpace(input.PortName) == "" || strings.TrimSpace(input.Interface) == "" {
		return fmt.Errorf("broadband DHCP security binding key, port, and interface are required")
	}
	if strings.TrimSpace(input.PlanFingerprint) == "" {
		return fmt.Errorf("broadband DHCP security binding plan fingerprint is required")
	}
	if strings.TrimSpace(input.CompiledOptionsJSON) == "" {
		input.CompiledOptionsJSON = "[]"
	}
	_, err := tx.Exec(`INSERT INTO broadband_dhcp_security_bindings (
		binding_key, port_name, interface, vlan, role, trusted, circuit_id, remote_id, subscriber_product, tenant,
		relay_agent, source_guard_policy, status, compiled_options_json, source_event_id, plan_fingerprint,
		installed_at, withdrawn_at, last_seen_at, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
	ON CONFLICT(binding_key) DO UPDATE SET
		port_name = excluded.port_name,
		interface = excluded.interface,
		vlan = excluded.vlan,
		role = excluded.role,
		trusted = excluded.trusted,
		circuit_id = excluded.circuit_id,
		remote_id = excluded.remote_id,
		subscriber_product = excluded.subscriber_product,
		tenant = excluded.tenant,
		relay_agent = excluded.relay_agent,
		source_guard_policy = excluded.source_guard_policy,
		status = excluded.status,
		compiled_options_json = excluded.compiled_options_json,
		source_event_id = excluded.source_event_id,
		plan_fingerprint = excluded.plan_fingerprint,
		installed_at = COALESCE(excluded.installed_at, broadband_dhcp_security_bindings.installed_at),
		withdrawn_at = excluded.withdrawn_at,
		last_seen_at = CURRENT_TIMESTAMP,
		updated_at = CURRENT_TIMESTAMP`,
		input.BindingKey,
		strings.TrimSpace(input.PortName),
		strings.TrimSpace(input.Interface),
		nonNegativeInt(input.VLAN),
		firstNonEmptyString(strings.TrimSpace(input.Role), "access"),
		input.Trusted,
		nullString(strings.TrimSpace(input.CircuitID)),
		nullString(strings.TrimSpace(input.RemoteID)),
		nullString(strings.TrimSpace(input.SubscriberProduct)),
		nullString(strings.TrimSpace(input.Tenant)),
		nullString(strings.TrimSpace(input.RelayAgent)),
		nullString(strings.TrimSpace(input.SourceGuardPolicy)),
		input.Status,
		input.CompiledOptionsJSON,
		nullString(strings.TrimSpace(input.SourceEventID)),
		strings.TrimSpace(input.PlanFingerprint),
		nullString(strings.TrimSpace(input.InstalledAt)),
		nullString(strings.TrimSpace(input.WithdrawnAt)),
	)
	if err != nil {
		return fmt.Errorf("upsert broadband DHCP security binding %q: %w", input.BindingKey, err)
	}
	return nil
}

func newBroadbandDHCPSecurityEventID(input BroadbandDHCPSecurityEventInput) string {
	var entropy [8]byte
	_, _ = rand.Read(entropy[:])
	sum := sha256.Sum256([]byte(strings.Join([]string{input.Operation, input.Status, input.PlanFingerprint, hex.EncodeToString(entropy[:])}, "|")))
	return "bdhcp-" + hex.EncodeToString(sum[:])[:24]
}

func normalizeBroadbandDHCPSecurityOperation(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "preview", "apply", "status", "reconcile":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeBroadbandDHCPSecurityStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "previewed", "applied", "blocked", "degraded", "skipped", "failed", "reconciled":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeBroadbandDHCPSecurityBindingStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "active", "planned", "degraded", "blocked", "withdrawn":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "planned"
	}
}
