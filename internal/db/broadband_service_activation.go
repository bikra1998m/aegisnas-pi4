package db

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
)

type BroadbandServiceActivationEventInput struct {
	EventID                  string
	Operation                string
	Status                   string
	PlanFingerprint          string
	Mode                     string
	ServiceCount             int
	RoutePolicyCount         int
	MulticastProfileCount    int
	ActivationPolicyCount    int
	RouteAttributeCount      int
	MulticastAttributeCount  int
	RadiusAttributeCount     int
	ComplianceCheckCount     int
	PassedCheckCount         int
	WarningCount             int
	BlockerCount             int
	ExternalRequirementCount int
	SummaryJSON              string
	ReportJSON               string
	Actor                    string
	Transactions             []BroadbandServiceActivationTransactionInput
}

type BroadbandServiceActivationTransactionInput struct {
	TransactionKey          string
	ServiceName             string
	Product                 string
	SubscriberID            string
	Username                string
	Tenant                  string
	ServiceChain            string
	RoutePolicy             string
	MulticastProfile        string
	AddressPool             string
	QoSProfile              string
	AccountingClass         string
	Status                  string
	VendorPacksJSON         string
	RouteAttributesJSON     string
	MulticastAttributesJSON string
	RadiusAttributesJSON    string
	RollbackRequired        bool
	SourceEventID           string
	PlanFingerprint         string
	InstalledAt             string
	WithdrawnAt             string
}

type BroadbandServiceActivationEvent struct {
	ID                       int    `json:"id"`
	EventID                  string `json:"event_id"`
	Operation                string `json:"operation"`
	Status                   string `json:"status"`
	PlanFingerprint          string `json:"plan_fingerprint"`
	Mode                     string `json:"mode,omitempty"`
	ServiceCount             int    `json:"service_count"`
	RoutePolicyCount         int    `json:"route_policy_count"`
	MulticastProfileCount    int    `json:"multicast_profile_count"`
	ActivationPolicyCount    int    `json:"activation_policy_count"`
	RouteAttributeCount      int    `json:"route_attribute_count"`
	MulticastAttributeCount  int    `json:"multicast_attribute_count"`
	RadiusAttributeCount     int    `json:"radius_attribute_count"`
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

type BroadbandServiceActivationTransactionRecord struct {
	ID                      int    `json:"id"`
	TransactionKey          string `json:"transaction_key"`
	ServiceName             string `json:"service_name"`
	Product                 string `json:"product,omitempty"`
	SubscriberID            string `json:"subscriber_id,omitempty"`
	Username                string `json:"username,omitempty"`
	Tenant                  string `json:"tenant,omitempty"`
	ServiceChain            string `json:"service_chain,omitempty"`
	RoutePolicy             string `json:"route_policy,omitempty"`
	MulticastProfile        string `json:"multicast_profile,omitempty"`
	AddressPool             string `json:"address_pool,omitempty"`
	QoSProfile              string `json:"qos_profile,omitempty"`
	AccountingClass         string `json:"accounting_class,omitempty"`
	Status                  string `json:"status"`
	VendorPacksJSON         string `json:"vendor_packs_json"`
	RouteAttributesJSON     string `json:"route_attributes_json"`
	MulticastAttributesJSON string `json:"multicast_attributes_json"`
	RadiusAttributesJSON    string `json:"radius_attributes_json"`
	RollbackRequired        bool   `json:"rollback_required"`
	SourceEventID           string `json:"source_event_id,omitempty"`
	PlanFingerprint         string `json:"plan_fingerprint"`
	InstalledAt             string `json:"installed_at,omitempty"`
	WithdrawnAt             string `json:"withdrawn_at,omitempty"`
	LastSeenAt              string `json:"last_seen_at"`
	CreatedAt               string `json:"created_at"`
	UpdatedAt               string `json:"updated_at"`
}

type BroadbandServiceActivationSummary struct {
	TotalEvents                  int    `json:"total_events"`
	PreviewEvents                int    `json:"preview_events"`
	ApplyEvents                  int    `json:"apply_events"`
	PreviewedCount               int    `json:"previewed_count"`
	AppliedCount                 int    `json:"applied_count"`
	BlockedCount                 int    `json:"blocked_count"`
	DegradedCount                int    `json:"degraded_count"`
	SkippedCount                 int    `json:"skipped_count"`
	FailedCount                  int    `json:"failed_count"`
	ActiveTransactions           int    `json:"active_transactions"`
	PlannedTransactions          int    `json:"planned_transactions"`
	DegradedTransactions         int    `json:"degraded_transactions"`
	BlockedTransactions          int    `json:"blocked_transactions"`
	WithdrawnTransactions        int    `json:"withdrawn_transactions"`
	RollbackRequiredTransactions int    `json:"rollback_required_transactions"`
	LastEventAt                  string `json:"last_event_at,omitempty"`
	LastFingerprint              string `json:"last_fingerprint,omitempty"`
	LastServiceCount             int    `json:"last_service_count"`
	LastRoutePolicyCount         int    `json:"last_route_policy_count"`
	LastMulticastProfileCount    int    `json:"last_multicast_profile_count"`
	LastRadiusAttributeCount     int    `json:"last_radius_attribute_count"`
}

func RecordBroadbandServiceActivationEvent(input BroadbandServiceActivationEventInput) (string, error) {
	if DB == nil {
		return "", nil
	}
	input.Operation = normalizeBroadbandServiceActivationOperation(input.Operation)
	input.Status = normalizeBroadbandServiceActivationEventStatus(input.Status)
	input.EventID = strings.TrimSpace(input.EventID)
	if input.EventID == "" {
		input.EventID = newBroadbandServiceActivationEventID(input)
	}
	if input.Operation == "" || input.Status == "" {
		return "", fmt.Errorf("broadband service activation operation and status are required")
	}
	if strings.TrimSpace(input.PlanFingerprint) == "" {
		return "", fmt.Errorf("broadband service activation plan fingerprint is required")
	}
	if strings.TrimSpace(input.SummaryJSON) == "" {
		input.SummaryJSON = "{}"
	}
	if strings.TrimSpace(input.ReportJSON) == "" {
		input.ReportJSON = "{}"
	}
	tx, err := DB.Begin()
	if err != nil {
		return "", fmt.Errorf("begin broadband service activation event: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO broadband_service_activation_events (
			event_id, operation, status, plan_fingerprint, mode,
			service_count, route_policy_count, multicast_profile_count, activation_policy_count,
			route_attribute_count, multicast_attribute_count, radius_attribute_count,
			compliance_check_count, passed_check_count, warning_count, blocker_count,
			external_requirement_count, summary_json, report_json, actor, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(event_id) DO UPDATE SET
			operation = excluded.operation,
			status = excluded.status,
			plan_fingerprint = excluded.plan_fingerprint,
			mode = excluded.mode,
			service_count = excluded.service_count,
			route_policy_count = excluded.route_policy_count,
			multicast_profile_count = excluded.multicast_profile_count,
			activation_policy_count = excluded.activation_policy_count,
			route_attribute_count = excluded.route_attribute_count,
			multicast_attribute_count = excluded.multicast_attribute_count,
			radius_attribute_count = excluded.radius_attribute_count,
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
		nonNegativeInt(input.ServiceCount),
		nonNegativeInt(input.RoutePolicyCount),
		nonNegativeInt(input.MulticastProfileCount),
		nonNegativeInt(input.ActivationPolicyCount),
		nonNegativeInt(input.RouteAttributeCount),
		nonNegativeInt(input.MulticastAttributeCount),
		nonNegativeInt(input.RadiusAttributeCount),
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
		return "", fmt.Errorf("record broadband service activation event: %w", err)
	}
	for _, transaction := range input.Transactions {
		transaction.SourceEventID = firstNonEmptyString(transaction.SourceEventID, input.EventID)
		if err := upsertBroadbandServiceActivationTransaction(tx, transaction); err != nil {
			return "", err
		}
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit broadband service activation event: %w", err)
	}
	return input.EventID, nil
}

func ListBroadbandServiceActivationEvents(limit int) ([]BroadbandServiceActivationEvent, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := DB.Query(broadbandServiceActivationEventSelectSQL()+` ORDER BY datetime(created_at) DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list broadband service activation events: %w", err)
	}
	defer rows.Close()
	var events []BroadbandServiceActivationEvent
	for rows.Next() {
		event, err := scanBroadbandServiceActivationEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func ListBroadbandServiceActivationTransactions(limit int, status string) ([]BroadbandServiceActivationTransactionRecord, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	query := broadbandServiceActivationTransactionSelectSQL()
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
		return nil, fmt.Errorf("list broadband service activation transactions: %w", err)
	}
	defer rows.Close()
	var transactions []BroadbandServiceActivationTransactionRecord
	for rows.Next() {
		transaction, err := scanBroadbandServiceActivationTransaction(rows)
		if err != nil {
			return nil, err
		}
		transactions = append(transactions, transaction)
	}
	return transactions, rows.Err()
}

func GetBroadbandServiceActivationSummary() (BroadbandServiceActivationSummary, error) {
	events, err := ListBroadbandServiceActivationEvents(1000)
	if err != nil {
		return BroadbandServiceActivationSummary{}, err
	}
	transactions, err := ListBroadbandServiceActivationTransactions(1000, "")
	if err != nil {
		return BroadbandServiceActivationSummary{}, err
	}
	summary := BroadbandServiceActivationSummary{}
	for _, event := range events {
		summary.TotalEvents++
		if summary.LastEventAt == "" {
			summary.LastEventAt = event.CreatedAt
			summary.LastFingerprint = event.PlanFingerprint
			summary.LastServiceCount = event.ServiceCount
			summary.LastRoutePolicyCount = event.RoutePolicyCount
			summary.LastMulticastProfileCount = event.MulticastProfileCount
			summary.LastRadiusAttributeCount = event.RadiusAttributeCount
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
	for _, transaction := range transactions {
		switch transaction.Status {
		case "active":
			summary.ActiveTransactions++
		case "planned":
			summary.PlannedTransactions++
		case "degraded":
			summary.DegradedTransactions++
		case "blocked":
			summary.BlockedTransactions++
		case "withdrawn":
			summary.WithdrawnTransactions++
		}
		if transaction.RollbackRequired {
			summary.RollbackRequiredTransactions++
		}
	}
	return summary, nil
}

func upsertBroadbandServiceActivationTransaction(tx *sql.Tx, input BroadbandServiceActivationTransactionInput) error {
	input.TransactionKey = strings.TrimSpace(input.TransactionKey)
	if input.TransactionKey == "" {
		return fmt.Errorf("broadband service activation transaction key is required")
	}
	if strings.TrimSpace(input.ServiceName) == "" {
		return fmt.Errorf("broadband service activation service name is required")
	}
	input.Status = normalizeBroadbandServiceActivationTransactionStatus(input.Status)
	if strings.TrimSpace(input.VendorPacksJSON) == "" {
		input.VendorPacksJSON = "[]"
	}
	if strings.TrimSpace(input.RouteAttributesJSON) == "" {
		input.RouteAttributesJSON = "[]"
	}
	if strings.TrimSpace(input.MulticastAttributesJSON) == "" {
		input.MulticastAttributesJSON = "[]"
	}
	if strings.TrimSpace(input.RadiusAttributesJSON) == "" {
		input.RadiusAttributesJSON = "[]"
	}
	_, err := tx.Exec(`INSERT INTO broadband_service_activation_transactions (
			transaction_key, service_name, product, subscriber_id, username, tenant,
			service_chain, route_policy, multicast_profile, address_pool, qos_profile,
			accounting_class, status, vendor_packs_json, route_attributes_json,
			multicast_attributes_json, radius_attributes_json, rollback_required,
			source_event_id, plan_fingerprint, installed_at, withdrawn_at,
			last_seen_at, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT(transaction_key) DO UPDATE SET
			service_name = excluded.service_name,
			product = excluded.product,
			subscriber_id = excluded.subscriber_id,
			username = excluded.username,
			tenant = excluded.tenant,
			service_chain = excluded.service_chain,
			route_policy = excluded.route_policy,
			multicast_profile = excluded.multicast_profile,
			address_pool = excluded.address_pool,
			qos_profile = excluded.qos_profile,
			accounting_class = excluded.accounting_class,
			status = excluded.status,
			vendor_packs_json = excluded.vendor_packs_json,
			route_attributes_json = excluded.route_attributes_json,
			multicast_attributes_json = excluded.multicast_attributes_json,
			radius_attributes_json = excluded.radius_attributes_json,
			rollback_required = excluded.rollback_required,
			source_event_id = excluded.source_event_id,
			plan_fingerprint = excluded.plan_fingerprint,
			installed_at = excluded.installed_at,
			withdrawn_at = excluded.withdrawn_at,
			last_seen_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP`,
		input.TransactionKey,
		strings.TrimSpace(input.ServiceName),
		nullString(strings.TrimSpace(input.Product)),
		nullString(strings.TrimSpace(input.SubscriberID)),
		nullString(strings.TrimSpace(input.Username)),
		nullString(strings.TrimSpace(input.Tenant)),
		nullString(strings.TrimSpace(input.ServiceChain)),
		nullString(strings.TrimSpace(input.RoutePolicy)),
		nullString(strings.TrimSpace(input.MulticastProfile)),
		nullString(strings.TrimSpace(input.AddressPool)),
		nullString(strings.TrimSpace(input.QoSProfile)),
		nullString(strings.TrimSpace(input.AccountingClass)),
		input.Status,
		input.VendorPacksJSON,
		input.RouteAttributesJSON,
		input.MulticastAttributesJSON,
		input.RadiusAttributesJSON,
		boolToInt(input.RollbackRequired),
		nullString(strings.TrimSpace(input.SourceEventID)),
		strings.TrimSpace(input.PlanFingerprint),
		nullString(strings.TrimSpace(input.InstalledAt)),
		nullString(strings.TrimSpace(input.WithdrawnAt)),
	)
	if err != nil {
		return fmt.Errorf("upsert broadband service activation transaction %q: %w", input.TransactionKey, err)
	}
	return nil
}

func broadbandServiceActivationEventSelectSQL() string {
	return `SELECT id, event_id, operation, status, plan_fingerprint, COALESCE(mode, ''),
		service_count, route_policy_count, multicast_profile_count, activation_policy_count,
		route_attribute_count, multicast_attribute_count, radius_attribute_count,
		compliance_check_count, passed_check_count, warning_count, blocker_count,
		external_requirement_count, summary_json, report_json, COALESCE(actor, ''), created_at
		FROM broadband_service_activation_events`
}

func broadbandServiceActivationTransactionSelectSQL() string {
	return `SELECT id, transaction_key, service_name, COALESCE(product, ''), COALESCE(subscriber_id, ''),
		COALESCE(username, ''), COALESCE(tenant, ''), COALESCE(service_chain, ''),
		COALESCE(route_policy, ''), COALESCE(multicast_profile, ''), COALESCE(address_pool, ''),
		COALESCE(qos_profile, ''), COALESCE(accounting_class, ''), status,
		vendor_packs_json, route_attributes_json, multicast_attributes_json, radius_attributes_json,
		rollback_required, COALESCE(source_event_id, ''), plan_fingerprint,
		COALESCE(installed_at, ''), COALESCE(withdrawn_at, ''), last_seen_at, created_at, updated_at
		FROM broadband_service_activation_transactions`
}

func scanBroadbandServiceActivationEvent(row interface{ Scan(dest ...any) error }) (BroadbandServiceActivationEvent, error) {
	var event BroadbandServiceActivationEvent
	if err := row.Scan(
		&event.ID, &event.EventID, &event.Operation, &event.Status, &event.PlanFingerprint, &event.Mode,
		&event.ServiceCount, &event.RoutePolicyCount, &event.MulticastProfileCount, &event.ActivationPolicyCount,
		&event.RouteAttributeCount, &event.MulticastAttributeCount, &event.RadiusAttributeCount,
		&event.ComplianceCheckCount, &event.PassedCheckCount, &event.WarningCount, &event.BlockerCount,
		&event.ExternalRequirementCount, &event.SummaryJSON, &event.ReportJSON, &event.Actor, &event.CreatedAt,
	); err != nil {
		return BroadbandServiceActivationEvent{}, fmt.Errorf("scan broadband service activation event: %w", err)
	}
	return event, nil
}

func scanBroadbandServiceActivationTransaction(row interface{ Scan(dest ...any) error }) (BroadbandServiceActivationTransactionRecord, error) {
	var record BroadbandServiceActivationTransactionRecord
	if err := row.Scan(
		&record.ID, &record.TransactionKey, &record.ServiceName, &record.Product, &record.SubscriberID,
		&record.Username, &record.Tenant, &record.ServiceChain, &record.RoutePolicy,
		&record.MulticastProfile, &record.AddressPool, &record.QoSProfile, &record.AccountingClass,
		&record.Status, &record.VendorPacksJSON, &record.RouteAttributesJSON, &record.MulticastAttributesJSON,
		&record.RadiusAttributesJSON, &record.RollbackRequired, &record.SourceEventID,
		&record.PlanFingerprint, &record.InstalledAt, &record.WithdrawnAt, &record.LastSeenAt,
		&record.CreatedAt, &record.UpdatedAt,
	); err != nil {
		return BroadbandServiceActivationTransactionRecord{}, fmt.Errorf("scan broadband service activation transaction: %w", err)
	}
	return record, nil
}

func normalizeBroadbandServiceActivationOperation(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "preview", "apply", "status", "reconcile":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "preview"
	}
}

func normalizeBroadbandServiceActivationEventStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "previewed", "applied", "blocked", "degraded", "skipped", "failed", "reconciled":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "previewed"
	}
}

func normalizeBroadbandServiceActivationTransactionStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "planned", "active", "degraded", "blocked", "withdrawn":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "planned"
	}
}

func newBroadbandServiceActivationEventID(input BroadbandServiceActivationEventInput) string {
	random := make([]byte, 16)
	_, _ = rand.Read(random)
	sum := sha256.Sum256([]byte(strings.Join([]string{input.Operation, input.Status, input.PlanFingerprint, hex.EncodeToString(random)}, "|")))
	return "bng-service-" + input.Operation + "-" + hex.EncodeToString(sum[:8])
}
