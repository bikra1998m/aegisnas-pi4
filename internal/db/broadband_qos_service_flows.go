package db

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
)

type BroadbandQoSServiceFlowEventInput struct {
	EventID                  string
	Operation                string
	Status                   string
	PlanFingerprint          string
	Mode                     string
	ProfileCount             int
	ServiceFlowCount         int
	AggregatePolicyCount     int
	CompiledAttributeCount   int
	DiagnosticCount          int
	ComplianceCheckCount     int
	PassedCheckCount         int
	WarningCount             int
	BlockerCount             int
	ExternalRequirementCount int
	SummaryJSON              string
	ReportJSON               string
	Actor                    string
	Flows                    []BroadbandQoSServiceFlowInput
}

type BroadbandQoSServiceFlowInput struct {
	FlowKey                string
	Name                   string
	SubscriberID           string
	Username               string
	SessionID              string
	AcctSessionID          string
	Product                string
	ServiceLeg             string
	Role                   string
	Tenant                 string
	Direction              string
	Profile                string
	ParentProfile          string
	AggregatePolicy        string
	TrafficClass           string
	Scheduler              string
	Priority               int
	DSCPMark               int
	DownloadMinRateKbps    int
	DownloadRateKbps       int
	DownloadPeakRateKbps   int
	UploadMinRateKbps      int
	UploadRateKbps         int
	UploadPeakRateKbps     int
	AggregateLimitKbps     int
	Status                 string
	VendorPacksJSON        string
	CompiledAttributesJSON string
	DiagnosticsJSON        string
	SourceEventID          string
	PlanFingerprint        string
	InstalledAt            string
	WithdrawnAt            string
}

type BroadbandQoSServiceFlowEvent struct {
	ID                       int    `json:"id"`
	EventID                  string `json:"event_id"`
	Operation                string `json:"operation"`
	Status                   string `json:"status"`
	PlanFingerprint          string `json:"plan_fingerprint"`
	Mode                     string `json:"mode,omitempty"`
	ProfileCount             int    `json:"profile_count"`
	ServiceFlowCount         int    `json:"service_flow_count"`
	AggregatePolicyCount     int    `json:"aggregate_policy_count"`
	CompiledAttributeCount   int    `json:"compiled_attribute_count"`
	DiagnosticCount          int    `json:"diagnostic_count"`
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

type BroadbandQoSServiceFlowRecord struct {
	ID                     int    `json:"id"`
	FlowKey                string `json:"flow_key"`
	Name                   string `json:"name"`
	SubscriberID           string `json:"subscriber_id,omitempty"`
	Username               string `json:"username,omitempty"`
	SessionID              string `json:"session_id,omitempty"`
	AcctSessionID          string `json:"acct_session_id,omitempty"`
	Product                string `json:"product,omitempty"`
	ServiceLeg             string `json:"service_leg,omitempty"`
	Role                   string `json:"role,omitempty"`
	Tenant                 string `json:"tenant,omitempty"`
	Direction              string `json:"direction"`
	Profile                string `json:"profile"`
	ParentProfile          string `json:"parent_profile,omitempty"`
	AggregatePolicy        string `json:"aggregate_policy,omitempty"`
	TrafficClass           string `json:"traffic_class"`
	Scheduler              string `json:"scheduler"`
	Priority               int    `json:"priority"`
	DSCPMark               int    `json:"dscp_mark"`
	DownloadMinRateKbps    int    `json:"download_min_rate_kbps"`
	DownloadRateKbps       int    `json:"download_rate_kbps"`
	DownloadPeakRateKbps   int    `json:"download_peak_rate_kbps"`
	UploadMinRateKbps      int    `json:"upload_min_rate_kbps"`
	UploadRateKbps         int    `json:"upload_rate_kbps"`
	UploadPeakRateKbps     int    `json:"upload_peak_rate_kbps"`
	AggregateLimitKbps     int    `json:"aggregate_limit_kbps"`
	Status                 string `json:"status"`
	VendorPacksJSON        string `json:"vendor_packs_json"`
	CompiledAttributesJSON string `json:"compiled_attributes_json"`
	DiagnosticsJSON        string `json:"diagnostics_json"`
	SourceEventID          string `json:"source_event_id,omitempty"`
	PlanFingerprint        string `json:"plan_fingerprint"`
	InstalledAt            string `json:"installed_at,omitempty"`
	WithdrawnAt            string `json:"withdrawn_at,omitempty"`
	LastSeenAt             string `json:"last_seen_at"`
	CreatedAt              string `json:"created_at"`
	UpdatedAt              string `json:"updated_at"`
}

type BroadbandQoSServiceFlowSummary struct {
	TotalEvents                int    `json:"total_events"`
	PreviewEvents              int    `json:"preview_events"`
	ApplyEvents                int    `json:"apply_events"`
	PreviewedCount             int    `json:"previewed_count"`
	AppliedCount               int    `json:"applied_count"`
	BlockedCount               int    `json:"blocked_count"`
	DegradedCount              int    `json:"degraded_count"`
	SkippedCount               int    `json:"skipped_count"`
	FailedCount                int    `json:"failed_count"`
	ActiveFlows                int    `json:"active_flows"`
	PlannedFlows               int    `json:"planned_flows"`
	DegradedFlows              int    `json:"degraded_flows"`
	BlockedFlows               int    `json:"blocked_flows"`
	WithdrawnFlows             int    `json:"withdrawn_flows"`
	LastEventAt                string `json:"last_event_at,omitempty"`
	LastFingerprint            string `json:"last_fingerprint,omitempty"`
	LastProfileCount           int    `json:"last_profile_count"`
	LastServiceFlowCount       int    `json:"last_service_flow_count"`
	LastAggregatePolicyCount   int    `json:"last_aggregate_policy_count"`
	LastCompiledAttributeCount int    `json:"last_compiled_attribute_count"`
}

func RecordBroadbandQoSServiceFlowEvent(input BroadbandQoSServiceFlowEventInput) (string, error) {
	if DB == nil {
		return "", nil
	}
	input.Operation = normalizeBroadbandQoSOperation(input.Operation)
	input.Status = normalizeBroadbandQoSStatus(input.Status)
	input.EventID = strings.TrimSpace(input.EventID)
	if input.EventID == "" {
		input.EventID = newBroadbandQoSEventID(input)
	}
	if input.Operation == "" || input.Status == "" {
		return "", fmt.Errorf("broadband QoS operation and status are required")
	}
	if strings.TrimSpace(input.PlanFingerprint) == "" {
		return "", fmt.Errorf("broadband QoS plan fingerprint is required")
	}
	if strings.TrimSpace(input.SummaryJSON) == "" {
		input.SummaryJSON = "{}"
	}
	if strings.TrimSpace(input.ReportJSON) == "" {
		input.ReportJSON = "{}"
	}
	tx, err := DB.Begin()
	if err != nil {
		return "", fmt.Errorf("begin broadband QoS event: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO broadband_qos_service_flow_events (
			event_id, operation, status, plan_fingerprint, mode,
			profile_count, service_flow_count, aggregate_policy_count, compiled_attribute_count,
			diagnostic_count, compliance_check_count, passed_check_count, warning_count, blocker_count,
			external_requirement_count, summary_json, report_json, actor, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(event_id) DO UPDATE SET
			operation = excluded.operation,
			status = excluded.status,
			plan_fingerprint = excluded.plan_fingerprint,
			mode = excluded.mode,
			profile_count = excluded.profile_count,
			service_flow_count = excluded.service_flow_count,
			aggregate_policy_count = excluded.aggregate_policy_count,
			compiled_attribute_count = excluded.compiled_attribute_count,
			diagnostic_count = excluded.diagnostic_count,
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
		nonNegativeInt(input.ProfileCount),
		nonNegativeInt(input.ServiceFlowCount),
		nonNegativeInt(input.AggregatePolicyCount),
		nonNegativeInt(input.CompiledAttributeCount),
		nonNegativeInt(input.DiagnosticCount),
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
		return "", fmt.Errorf("record broadband QoS event: %w", err)
	}
	for _, flow := range input.Flows {
		flow.SourceEventID = firstNonEmptyString(flow.SourceEventID, input.EventID)
		if err := upsertBroadbandQoSServiceFlow(tx, flow); err != nil {
			return "", err
		}
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit broadband QoS event: %w", err)
	}
	return input.EventID, nil
}

func ListBroadbandQoSServiceFlowEvents(limit int) ([]BroadbandQoSServiceFlowEvent, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := DB.Query(broadbandQoSEventSelectSQL()+` ORDER BY datetime(created_at) DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list broadband QoS events: %w", err)
	}
	defer rows.Close()
	var events []BroadbandQoSServiceFlowEvent
	for rows.Next() {
		event, err := scanBroadbandQoSEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func ListBroadbandQoSServiceFlows(limit int, status string) ([]BroadbandQoSServiceFlowRecord, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	query := broadbandQoSFlowSelectSQL()
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
		return nil, fmt.Errorf("list broadband QoS service flows: %w", err)
	}
	defer rows.Close()
	var flows []BroadbandQoSServiceFlowRecord
	for rows.Next() {
		flow, err := scanBroadbandQoSFlow(rows)
		if err != nil {
			return nil, err
		}
		flows = append(flows, flow)
	}
	return flows, rows.Err()
}

func GetBroadbandQoSServiceFlowSummary() (BroadbandQoSServiceFlowSummary, error) {
	events, err := ListBroadbandQoSServiceFlowEvents(1000)
	if err != nil {
		return BroadbandQoSServiceFlowSummary{}, err
	}
	flows, err := ListBroadbandQoSServiceFlows(1000, "")
	if err != nil {
		return BroadbandQoSServiceFlowSummary{}, err
	}
	summary := BroadbandQoSServiceFlowSummary{}
	for _, event := range events {
		summary.TotalEvents++
		if summary.LastEventAt == "" {
			summary.LastEventAt = event.CreatedAt
			summary.LastFingerprint = event.PlanFingerprint
			summary.LastProfileCount = event.ProfileCount
			summary.LastServiceFlowCount = event.ServiceFlowCount
			summary.LastAggregatePolicyCount = event.AggregatePolicyCount
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
	for _, flow := range flows {
		switch flow.Status {
		case "active":
			summary.ActiveFlows++
		case "planned":
			summary.PlannedFlows++
		case "degraded":
			summary.DegradedFlows++
		case "blocked":
			summary.BlockedFlows++
		case "withdrawn":
			summary.WithdrawnFlows++
		}
	}
	return summary, nil
}

func upsertBroadbandQoSServiceFlow(tx *sql.Tx, input BroadbandQoSServiceFlowInput) error {
	input.FlowKey = strings.TrimSpace(input.FlowKey)
	if input.FlowKey == "" {
		return fmt.Errorf("broadband QoS flow key is required")
	}
	if strings.TrimSpace(input.Name) == "" || strings.TrimSpace(input.Profile) == "" {
		return fmt.Errorf("broadband QoS flow name and profile are required")
	}
	input.Status = normalizeBroadbandQoSFlowStatus(input.Status)
	if strings.TrimSpace(input.VendorPacksJSON) == "" {
		input.VendorPacksJSON = "[]"
	}
	if strings.TrimSpace(input.CompiledAttributesJSON) == "" {
		input.CompiledAttributesJSON = "[]"
	}
	if strings.TrimSpace(input.DiagnosticsJSON) == "" {
		input.DiagnosticsJSON = "[]"
	}
	_, err := tx.Exec(`INSERT INTO broadband_qos_service_flows (
			flow_key, name, subscriber_id, username, session_id, acct_session_id,
			product, service_leg, role, tenant, direction, profile, parent_profile,
			aggregate_policy, traffic_class, scheduler, priority, dscp_mark,
			download_min_rate_kbps, download_rate_kbps, download_peak_rate_kbps,
			upload_min_rate_kbps, upload_rate_kbps, upload_peak_rate_kbps,
			aggregate_limit_kbps, status, vendor_packs_json, compiled_attributes_json,
			diagnostics_json, source_event_id, plan_fingerprint, installed_at, withdrawn_at,
			last_seen_at, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT(flow_key) DO UPDATE SET
			name = excluded.name,
			subscriber_id = excluded.subscriber_id,
			username = excluded.username,
			session_id = excluded.session_id,
			acct_session_id = excluded.acct_session_id,
			product = excluded.product,
			service_leg = excluded.service_leg,
			role = excluded.role,
			tenant = excluded.tenant,
			direction = excluded.direction,
			profile = excluded.profile,
			parent_profile = excluded.parent_profile,
			aggregate_policy = excluded.aggregate_policy,
			traffic_class = excluded.traffic_class,
			scheduler = excluded.scheduler,
			priority = excluded.priority,
			dscp_mark = excluded.dscp_mark,
			download_min_rate_kbps = excluded.download_min_rate_kbps,
			download_rate_kbps = excluded.download_rate_kbps,
			download_peak_rate_kbps = excluded.download_peak_rate_kbps,
			upload_min_rate_kbps = excluded.upload_min_rate_kbps,
			upload_rate_kbps = excluded.upload_rate_kbps,
			upload_peak_rate_kbps = excluded.upload_peak_rate_kbps,
			aggregate_limit_kbps = excluded.aggregate_limit_kbps,
			status = excluded.status,
			vendor_packs_json = excluded.vendor_packs_json,
			compiled_attributes_json = excluded.compiled_attributes_json,
			diagnostics_json = excluded.diagnostics_json,
			source_event_id = excluded.source_event_id,
			plan_fingerprint = excluded.plan_fingerprint,
			installed_at = excluded.installed_at,
			withdrawn_at = excluded.withdrawn_at,
			last_seen_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP`,
		input.FlowKey,
		strings.TrimSpace(input.Name),
		nullString(strings.TrimSpace(input.SubscriberID)),
		nullString(strings.TrimSpace(input.Username)),
		nullString(strings.TrimSpace(input.SessionID)),
		nullString(strings.TrimSpace(input.AcctSessionID)),
		nullString(strings.TrimSpace(input.Product)),
		nullString(strings.TrimSpace(input.ServiceLeg)),
		nullString(strings.TrimSpace(input.Role)),
		nullString(strings.TrimSpace(input.Tenant)),
		firstNonEmptyString(strings.TrimSpace(input.Direction), "bidirectional"),
		strings.TrimSpace(input.Profile),
		nullString(strings.TrimSpace(input.ParentProfile)),
		nullString(strings.TrimSpace(input.AggregatePolicy)),
		firstNonEmptyString(strings.TrimSpace(input.TrafficClass), "best_effort"),
		firstNonEmptyString(strings.TrimSpace(input.Scheduler), "htb"),
		nonNegativeInt(input.Priority),
		nonNegativeInt(input.DSCPMark),
		nonNegativeInt(input.DownloadMinRateKbps),
		nonNegativeInt(input.DownloadRateKbps),
		nonNegativeInt(input.DownloadPeakRateKbps),
		nonNegativeInt(input.UploadMinRateKbps),
		nonNegativeInt(input.UploadRateKbps),
		nonNegativeInt(input.UploadPeakRateKbps),
		nonNegativeInt(input.AggregateLimitKbps),
		input.Status,
		input.VendorPacksJSON,
		input.CompiledAttributesJSON,
		input.DiagnosticsJSON,
		nullString(strings.TrimSpace(input.SourceEventID)),
		strings.TrimSpace(input.PlanFingerprint),
		nullString(strings.TrimSpace(input.InstalledAt)),
		nullString(strings.TrimSpace(input.WithdrawnAt)),
	)
	if err != nil {
		return fmt.Errorf("upsert broadband QoS service flow %q: %w", input.FlowKey, err)
	}
	return nil
}

func broadbandQoSEventSelectSQL() string {
	return `SELECT id, event_id, operation, status, plan_fingerprint, COALESCE(mode, ''),
		profile_count, service_flow_count, aggregate_policy_count, compiled_attribute_count,
		diagnostic_count, compliance_check_count, passed_check_count, warning_count, blocker_count,
		external_requirement_count, summary_json, report_json, COALESCE(actor, ''), created_at
		FROM broadband_qos_service_flow_events`
}

func broadbandQoSFlowSelectSQL() string {
	return `SELECT id, flow_key, name, COALESCE(subscriber_id, ''), COALESCE(username, ''),
		COALESCE(session_id, ''), COALESCE(acct_session_id, ''), COALESCE(product, ''),
		COALESCE(service_leg, ''), COALESCE(role, ''), COALESCE(tenant, ''), direction, profile,
		COALESCE(parent_profile, ''), COALESCE(aggregate_policy, ''), traffic_class, scheduler,
		priority, dscp_mark, download_min_rate_kbps, download_rate_kbps, download_peak_rate_kbps,
		upload_min_rate_kbps, upload_rate_kbps, upload_peak_rate_kbps, aggregate_limit_kbps,
		status, vendor_packs_json, compiled_attributes_json, diagnostics_json, COALESCE(source_event_id, ''),
		plan_fingerprint, COALESCE(installed_at, ''), COALESCE(withdrawn_at, ''), last_seen_at, created_at, updated_at
		FROM broadband_qos_service_flows`
}

func scanBroadbandQoSEvent(row interface{ Scan(dest ...any) error }) (BroadbandQoSServiceFlowEvent, error) {
	var event BroadbandQoSServiceFlowEvent
	if err := row.Scan(
		&event.ID, &event.EventID, &event.Operation, &event.Status, &event.PlanFingerprint, &event.Mode,
		&event.ProfileCount, &event.ServiceFlowCount, &event.AggregatePolicyCount, &event.CompiledAttributeCount,
		&event.DiagnosticCount, &event.ComplianceCheckCount, &event.PassedCheckCount, &event.WarningCount,
		&event.BlockerCount, &event.ExternalRequirementCount, &event.SummaryJSON, &event.ReportJSON,
		&event.Actor, &event.CreatedAt,
	); err != nil {
		return BroadbandQoSServiceFlowEvent{}, fmt.Errorf("scan broadband QoS event: %w", err)
	}
	return event, nil
}

func scanBroadbandQoSFlow(row interface{ Scan(dest ...any) error }) (BroadbandQoSServiceFlowRecord, error) {
	var flow BroadbandQoSServiceFlowRecord
	if err := row.Scan(
		&flow.ID, &flow.FlowKey, &flow.Name, &flow.SubscriberID, &flow.Username,
		&flow.SessionID, &flow.AcctSessionID, &flow.Product, &flow.ServiceLeg,
		&flow.Role, &flow.Tenant, &flow.Direction, &flow.Profile, &flow.ParentProfile,
		&flow.AggregatePolicy, &flow.TrafficClass, &flow.Scheduler, &flow.Priority,
		&flow.DSCPMark, &flow.DownloadMinRateKbps, &flow.DownloadRateKbps, &flow.DownloadPeakRateKbps,
		&flow.UploadMinRateKbps, &flow.UploadRateKbps, &flow.UploadPeakRateKbps,
		&flow.AggregateLimitKbps, &flow.Status, &flow.VendorPacksJSON, &flow.CompiledAttributesJSON,
		&flow.DiagnosticsJSON, &flow.SourceEventID, &flow.PlanFingerprint, &flow.InstalledAt,
		&flow.WithdrawnAt, &flow.LastSeenAt, &flow.CreatedAt, &flow.UpdatedAt,
	); err != nil {
		return BroadbandQoSServiceFlowRecord{}, fmt.Errorf("scan broadband QoS service flow: %w", err)
	}
	return flow, nil
}

func normalizeBroadbandQoSOperation(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "preview", "apply", "status", "reconcile":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "preview"
	}
}

func normalizeBroadbandQoSStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "previewed", "applied", "blocked", "degraded", "skipped", "failed", "reconciled":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "previewed"
	}
}

func normalizeBroadbandQoSFlowStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "planned", "active", "degraded", "blocked", "withdrawn":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "planned"
	}
}

func newBroadbandQoSEventID(input BroadbandQoSServiceFlowEventInput) string {
	random := make([]byte, 16)
	_, _ = rand.Read(random)
	sum := sha256.Sum256([]byte(strings.Join([]string{input.Operation, input.Status, input.PlanFingerprint, hex.EncodeToString(random)}, "|")))
	return "bng-qos-" + input.Operation + "-" + hex.EncodeToString(sum[:8])
}
