package db

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
)

type BroadbandCommercialCatalogEventInput struct {
	EventID                  string
	Operation                string
	Status                   string
	PlanFingerprint          string
	Mode                     string
	AccountCount             int
	PlanCount                int
	BundleCount              int
	SubscriptionCount        int
	ConcurrencyPolicyCount   int
	ActiveSubscriptionCount  int
	ActiveSessionCount       int
	OverLimitCount           int
	ComplianceCheckCount     int
	PassedCheckCount         int
	WarningCount             int
	BlockerCount             int
	ExternalRequirementCount int
	SummaryJSON              string
	ReportJSON               string
	Actor                    string
	Accounts                 []BroadbandCommercialAccountInput
	Plans                    []BroadbandCommercialPlanInput
	Bundles                  []BroadbandCommercialBundleInput
	Subscriptions            []BroadbandCommercialSubscriptionInput
	ConcurrencyPolicies      []BroadbandCommercialConcurrencyPolicyInput
}

type BroadbandCommercialAccountInput struct {
	AccountID        string
	ParentAccountID  string
	Tenant           string
	Status           string
	BillingMode      string
	OwnerName        string
	Contact          string
	MaxSubscriptions int
	MaxSessions      int
	TagsJSON         string
	MetadataJSON     string
	SourceEventID    string
}

type BroadbandCommercialPlanInput struct {
	Name                  string
	Product               string
	Status                string
	DisplayName           string
	BillingPeriod         string
	PriceMicros           int64
	Currency              string
	MaxSessions           int
	MaxDevices            int
	DownstreamKbps        int
	UpstreamKbps          int
	QuotaProfile          string
	ServiceChain          string
	AddressPool           string
	IPv6Pool              string
	DelegatedIPv6Pool     string
	RoutePolicy           string
	QoSProfile            string
	TranslationPool       string
	PortalProfile         string
	GraceSeconds          int
	SuspensionRole        string
	SessionTimeoutSeconds int
	IdleTimeoutSeconds    int
	VendorPacksJSON       string
	MetadataJSON          string
	SourceEventID         string
}

type BroadbandCommercialBundleInput struct {
	Name                       string
	Status                     string
	DisplayName                string
	PlansJSON                  string
	RequiredPlansJSON          string
	MutuallyExclusivePlansJSON string
	MaxConcurrentSubscriptions int
	SharedConcurrency          bool
	Priority                   int
	EligibilityTagsJSON        string
	MetadataJSON               string
	SourceEventID              string
}

type BroadbandCommercialSubscriptionInput struct {
	SubscriptionID      string
	AccountID           string
	SubscriberID        string
	Username            string
	PlanName            string
	BundleName          string
	Status              string
	StartsAt            string
	EndsAt              string
	AutoRenew           bool
	MaxSessions         int
	DeviceLimit         int
	EligibilityTagsJSON string
	ActiveSessionCount  int
	MetadataJSON        string
	SourceEventID       string
}

type BroadbandCommercialConcurrencyPolicyInput struct {
	PolicyKey                string
	Name                     string
	Scope                    string
	Target                   string
	AccountID                string
	Tenant                   string
	PlanName                 string
	BundleName               string
	MaxSessions              int
	MaxSessionsPerSubscriber int
	BurstSessions            int
	GraceSeconds             int
	Action                   string
	CoAAction                string
	Status                   string
	MetadataJSON             string
	SourceEventID            string
}

type BroadbandCommercialCatalogEvent struct {
	ID                       int    `json:"id"`
	EventID                  string `json:"event_id"`
	Operation                string `json:"operation"`
	Status                   string `json:"status"`
	PlanFingerprint          string `json:"plan_fingerprint"`
	Mode                     string `json:"mode,omitempty"`
	AccountCount             int    `json:"account_count"`
	PlanCount                int    `json:"plan_count"`
	BundleCount              int    `json:"bundle_count"`
	SubscriptionCount        int    `json:"subscription_count"`
	ConcurrencyPolicyCount   int    `json:"concurrency_policy_count"`
	ActiveSubscriptionCount  int    `json:"active_subscription_count"`
	ActiveSessionCount       int    `json:"active_session_count"`
	OverLimitCount           int    `json:"over_limit_count"`
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

type BroadbandCommercialAccountRecord struct {
	ID               int    `json:"id"`
	AccountID        string `json:"account_id"`
	ParentAccountID  string `json:"parent_account_id,omitempty"`
	Tenant           string `json:"tenant,omitempty"`
	Status           string `json:"status"`
	BillingMode      string `json:"billing_mode,omitempty"`
	OwnerName        string `json:"owner_name,omitempty"`
	Contact          string `json:"contact,omitempty"`
	MaxSubscriptions int    `json:"max_subscriptions"`
	MaxSessions      int    `json:"max_sessions"`
	TagsJSON         string `json:"tags_json"`
	MetadataJSON     string `json:"metadata_json"`
	SourceEventID    string `json:"source_event_id,omitempty"`
	LastSeenAt       string `json:"last_seen_at"`
	CreatedAt        string `json:"created_at"`
	UpdatedAt        string `json:"updated_at"`
}

type BroadbandCommercialPlanRecord struct {
	ID                    int    `json:"id"`
	Name                  string `json:"name"`
	Product               string `json:"product,omitempty"`
	Status                string `json:"status"`
	DisplayName           string `json:"display_name,omitempty"`
	BillingPeriod         string `json:"billing_period,omitempty"`
	PriceMicros           int64  `json:"price_micros"`
	Currency              string `json:"currency,omitempty"`
	MaxSessions           int    `json:"max_sessions"`
	MaxDevices            int    `json:"max_devices"`
	DownstreamKbps        int    `json:"downstream_kbps"`
	UpstreamKbps          int    `json:"upstream_kbps"`
	QuotaProfile          string `json:"quota_profile,omitempty"`
	ServiceChain          string `json:"service_chain,omitempty"`
	AddressPool           string `json:"address_pool,omitempty"`
	IPv6Pool              string `json:"ipv6_pool,omitempty"`
	DelegatedIPv6Pool     string `json:"delegated_ipv6_pool,omitempty"`
	RoutePolicy           string `json:"route_policy,omitempty"`
	QoSProfile            string `json:"qos_profile,omitempty"`
	TranslationPool       string `json:"translation_pool,omitempty"`
	PortalProfile         string `json:"portal_profile,omitempty"`
	GraceSeconds          int    `json:"grace_seconds"`
	SuspensionRole        string `json:"suspension_role,omitempty"`
	SessionTimeoutSeconds int    `json:"session_timeout_seconds"`
	IdleTimeoutSeconds    int    `json:"idle_timeout_seconds"`
	VendorPacksJSON       string `json:"vendor_packs_json"`
	MetadataJSON          string `json:"metadata_json"`
	SourceEventID         string `json:"source_event_id,omitempty"`
	LastSeenAt            string `json:"last_seen_at"`
	CreatedAt             string `json:"created_at"`
	UpdatedAt             string `json:"updated_at"`
}

type BroadbandCommercialBundleRecord struct {
	ID                         int    `json:"id"`
	Name                       string `json:"name"`
	Status                     string `json:"status"`
	DisplayName                string `json:"display_name,omitempty"`
	PlansJSON                  string `json:"plans_json"`
	RequiredPlansJSON          string `json:"required_plans_json"`
	MutuallyExclusivePlansJSON string `json:"mutually_exclusive_plans_json"`
	MaxConcurrentSubscriptions int    `json:"max_concurrent_subscriptions"`
	SharedConcurrency          bool   `json:"shared_concurrency"`
	Priority                   int    `json:"priority"`
	EligibilityTagsJSON        string `json:"eligibility_tags_json"`
	MetadataJSON               string `json:"metadata_json"`
	SourceEventID              string `json:"source_event_id,omitempty"`
	LastSeenAt                 string `json:"last_seen_at"`
	CreatedAt                  string `json:"created_at"`
	UpdatedAt                  string `json:"updated_at"`
}

type BroadbandCommercialSubscriptionRecord struct {
	ID                  int    `json:"id"`
	SubscriptionID      string `json:"subscription_id"`
	AccountID           string `json:"account_id"`
	SubscriberID        string `json:"subscriber_id,omitempty"`
	Username            string `json:"username,omitempty"`
	PlanName            string `json:"plan_name"`
	BundleName          string `json:"bundle_name,omitempty"`
	Status              string `json:"status"`
	StartsAt            string `json:"starts_at,omitempty"`
	EndsAt              string `json:"ends_at,omitempty"`
	AutoRenew           bool   `json:"auto_renew"`
	MaxSessions         int    `json:"max_sessions"`
	DeviceLimit         int    `json:"device_limit"`
	EligibilityTagsJSON string `json:"eligibility_tags_json"`
	ActiveSessionCount  int    `json:"active_session_count"`
	MetadataJSON        string `json:"metadata_json"`
	SourceEventID       string `json:"source_event_id,omitempty"`
	LastSeenAt          string `json:"last_seen_at"`
	CreatedAt           string `json:"created_at"`
	UpdatedAt           string `json:"updated_at"`
}

type BroadbandCommercialConcurrencyPolicyRecord struct {
	ID                       int    `json:"id"`
	PolicyKey                string `json:"policy_key"`
	Name                     string `json:"name"`
	Scope                    string `json:"scope"`
	Target                   string `json:"target,omitempty"`
	AccountID                string `json:"account_id,omitempty"`
	Tenant                   string `json:"tenant,omitempty"`
	PlanName                 string `json:"plan_name,omitempty"`
	BundleName               string `json:"bundle_name,omitempty"`
	MaxSessions              int    `json:"max_sessions"`
	MaxSessionsPerSubscriber int    `json:"max_sessions_per_subscriber"`
	BurstSessions            int    `json:"burst_sessions"`
	GraceSeconds             int    `json:"grace_seconds"`
	Action                   string `json:"action"`
	CoAAction                string `json:"coa_action,omitempty"`
	Status                   string `json:"status"`
	MetadataJSON             string `json:"metadata_json"`
	SourceEventID            string `json:"source_event_id,omitempty"`
	LastSeenAt               string `json:"last_seen_at"`
	CreatedAt                string `json:"created_at"`
	UpdatedAt                string `json:"updated_at"`
}

type BroadbandCommercialCatalogSummary struct {
	TotalEvents                int    `json:"total_events"`
	PreviewEvents              int    `json:"preview_events"`
	ApplyEvents                int    `json:"apply_events"`
	StatusEvents               int    `json:"status_events"`
	ReconcileEvents            int    `json:"reconcile_events"`
	PreviewedCount             int    `json:"previewed_count"`
	AppliedCount               int    `json:"applied_count"`
	BlockedCount               int    `json:"blocked_count"`
	DegradedCount              int    `json:"degraded_count"`
	SkippedCount               int    `json:"skipped_count"`
	FailedCount                int    `json:"failed_count"`
	ReconciledCount            int    `json:"reconciled_count"`
	ActiveAccounts             int    `json:"active_accounts"`
	SuspendedAccounts          int    `json:"suspended_accounts"`
	ActivePlans                int    `json:"active_plans"`
	ActiveBundles              int    `json:"active_bundles"`
	ActiveSubscriptions        int    `json:"active_subscriptions"`
	SuspendedSubscriptions     int    `json:"suspended_subscriptions"`
	ActiveConcurrencyPolicies  int    `json:"active_concurrency_policies"`
	ActiveSessions             int    `json:"active_sessions"`
	OverLimitRecords           int    `json:"over_limit_records"`
	LastEventAt                string `json:"last_event_at,omitempty"`
	LastFingerprint            string `json:"last_fingerprint,omitempty"`
	LastAccountCount           int    `json:"last_account_count"`
	LastPlanCount              int    `json:"last_plan_count"`
	LastBundleCount            int    `json:"last_bundle_count"`
	LastSubscriptionCount      int    `json:"last_subscription_count"`
	LastConcurrencyPolicyCount int    `json:"last_concurrency_policy_count"`
	LastComplianceCheckCount   int    `json:"last_compliance_check_count"`
}

func RecordBroadbandCommercialCatalogEvent(input BroadbandCommercialCatalogEventInput) (string, error) {
	if DB == nil {
		return "", nil
	}
	input.Operation = normalizeBroadbandCommercialCatalogOperation(input.Operation)
	input.Status = normalizeBroadbandCommercialCatalogEventStatus(input.Status)
	input.EventID = strings.TrimSpace(input.EventID)
	if input.EventID == "" {
		input.EventID = newBroadbandCommercialCatalogEventID(input)
	}
	if input.Operation == "" || input.Status == "" {
		return "", fmt.Errorf("broadband commercial catalog operation and status are required")
	}
	if strings.TrimSpace(input.PlanFingerprint) == "" {
		return "", fmt.Errorf("broadband commercial catalog plan fingerprint is required")
	}
	if strings.TrimSpace(input.SummaryJSON) == "" {
		input.SummaryJSON = "{}"
	}
	if strings.TrimSpace(input.ReportJSON) == "" {
		input.ReportJSON = "{}"
	}

	tx, err := DB.Begin()
	if err != nil {
		return "", fmt.Errorf("begin broadband commercial catalog event: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.Exec(`INSERT INTO broadband_commercial_catalog_events (
			event_id, operation, status, plan_fingerprint, mode,
			account_count, plan_count, bundle_count, subscription_count, concurrency_policy_count,
			active_subscription_count, active_session_count, over_limit_count,
			compliance_check_count, passed_check_count, warning_count, blocker_count,
			external_requirement_count, summary_json, report_json, actor, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(event_id) DO UPDATE SET
			operation = excluded.operation,
			status = excluded.status,
			plan_fingerprint = excluded.plan_fingerprint,
			mode = excluded.mode,
			account_count = excluded.account_count,
			plan_count = excluded.plan_count,
			bundle_count = excluded.bundle_count,
			subscription_count = excluded.subscription_count,
			concurrency_policy_count = excluded.concurrency_policy_count,
			active_subscription_count = excluded.active_subscription_count,
			active_session_count = excluded.active_session_count,
			over_limit_count = excluded.over_limit_count,
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
		nonNegativeInt(input.AccountCount),
		nonNegativeInt(input.PlanCount),
		nonNegativeInt(input.BundleCount),
		nonNegativeInt(input.SubscriptionCount),
		nonNegativeInt(input.ConcurrencyPolicyCount),
		nonNegativeInt(input.ActiveSubscriptionCount),
		nonNegativeInt(input.ActiveSessionCount),
		nonNegativeInt(input.OverLimitCount),
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
		return "", fmt.Errorf("record broadband commercial catalog event: %w", err)
	}
	for _, account := range input.Accounts {
		account.SourceEventID = firstNonEmptyString(account.SourceEventID, input.EventID)
		if err := upsertBroadbandCommercialAccount(tx, account); err != nil {
			return "", err
		}
	}
	for _, plan := range input.Plans {
		plan.SourceEventID = firstNonEmptyString(plan.SourceEventID, input.EventID)
		if err := upsertBroadbandCommercialPlan(tx, plan); err != nil {
			return "", err
		}
	}
	for _, bundle := range input.Bundles {
		bundle.SourceEventID = firstNonEmptyString(bundle.SourceEventID, input.EventID)
		if err := upsertBroadbandCommercialBundle(tx, bundle); err != nil {
			return "", err
		}
	}
	for _, subscription := range input.Subscriptions {
		subscription.SourceEventID = firstNonEmptyString(subscription.SourceEventID, input.EventID)
		if err := upsertBroadbandCommercialSubscription(tx, subscription); err != nil {
			return "", err
		}
	}
	for _, policy := range input.ConcurrencyPolicies {
		policy.SourceEventID = firstNonEmptyString(policy.SourceEventID, input.EventID)
		if err := upsertBroadbandCommercialConcurrencyPolicy(tx, policy); err != nil {
			return "", err
		}
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit broadband commercial catalog event: %w", err)
	}
	return input.EventID, nil
}

func ListBroadbandCommercialCatalogEvents(limit int) ([]BroadbandCommercialCatalogEvent, error) {
	if DB == nil {
		return nil, nil
	}
	limit = boundedBroadbandCommercialLimit(limit)
	rows, err := DB.Query(broadbandCommercialCatalogEventSelectSQL()+` ORDER BY datetime(created_at) DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list broadband commercial catalog events: %w", err)
	}
	defer rows.Close()
	events := []BroadbandCommercialCatalogEvent{}
	for rows.Next() {
		event, scanErr := scanBroadbandCommercialCatalogEvent(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func ListBroadbandCommercialAccounts(limit int) ([]BroadbandCommercialAccountRecord, error) {
	if DB == nil {
		return nil, nil
	}
	rows, err := DB.Query(broadbandCommercialAccountSelectSQL()+` ORDER BY tenant, account_id LIMIT ?`, boundedBroadbandCommercialLimit(limit))
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list broadband commercial accounts: %w", err)
	}
	defer rows.Close()
	records := []BroadbandCommercialAccountRecord{}
	for rows.Next() {
		record, scanErr := scanBroadbandCommercialAccount(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func ListBroadbandCommercialPlans(limit int) ([]BroadbandCommercialPlanRecord, error) {
	if DB == nil {
		return nil, nil
	}
	rows, err := DB.Query(broadbandCommercialPlanSelectSQL()+` ORDER BY plan_name LIMIT ?`, boundedBroadbandCommercialLimit(limit))
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list broadband commercial plans: %w", err)
	}
	defer rows.Close()
	records := []BroadbandCommercialPlanRecord{}
	for rows.Next() {
		record, scanErr := scanBroadbandCommercialPlan(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func ListBroadbandCommercialBundles(limit int) ([]BroadbandCommercialBundleRecord, error) {
	if DB == nil {
		return nil, nil
	}
	rows, err := DB.Query(broadbandCommercialBundleSelectSQL()+` ORDER BY priority DESC, bundle_name LIMIT ?`, boundedBroadbandCommercialLimit(limit))
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list broadband commercial bundles: %w", err)
	}
	defer rows.Close()
	records := []BroadbandCommercialBundleRecord{}
	for rows.Next() {
		record, scanErr := scanBroadbandCommercialBundle(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func ListBroadbandCommercialSubscriptions(limit int) ([]BroadbandCommercialSubscriptionRecord, error) {
	if DB == nil {
		return nil, nil
	}
	rows, err := DB.Query(broadbandCommercialSubscriptionSelectSQL()+` ORDER BY account_id, subscription_id LIMIT ?`, boundedBroadbandCommercialLimit(limit))
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list broadband commercial subscriptions: %w", err)
	}
	defer rows.Close()
	records := []BroadbandCommercialSubscriptionRecord{}
	for rows.Next() {
		record, scanErr := scanBroadbandCommercialSubscription(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func ListBroadbandCommercialConcurrencyPolicies(limit int) ([]BroadbandCommercialConcurrencyPolicyRecord, error) {
	if DB == nil {
		return nil, nil
	}
	rows, err := DB.Query(broadbandCommercialConcurrencyPolicySelectSQL()+` ORDER BY scope, target, name LIMIT ?`, boundedBroadbandCommercialLimit(limit))
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list broadband commercial concurrency policies: %w", err)
	}
	defer rows.Close()
	records := []BroadbandCommercialConcurrencyPolicyRecord{}
	for rows.Next() {
		record, scanErr := scanBroadbandCommercialConcurrencyPolicy(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func GetBroadbandCommercialCatalogSummary() (BroadbandCommercialCatalogSummary, error) {
	if DB == nil {
		return BroadbandCommercialCatalogSummary{}, nil
	}
	var summary BroadbandCommercialCatalogSummary
	err := DB.QueryRow(`SELECT
			COUNT(*),
			COALESCE(SUM(CASE WHEN operation = 'preview' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN operation = 'apply' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN operation = 'status' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN operation = 'reconcile' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'previewed' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'applied' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'degraded' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'skipped' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'reconciled' THEN 1 ELSE 0 END), 0),
			COALESCE(MAX(created_at), '')
		FROM broadband_commercial_catalog_events`).Scan(
		&summary.TotalEvents,
		&summary.PreviewEvents,
		&summary.ApplyEvents,
		&summary.StatusEvents,
		&summary.ReconcileEvents,
		&summary.PreviewedCount,
		&summary.AppliedCount,
		&summary.BlockedCount,
		&summary.DegradedCount,
		&summary.SkippedCount,
		&summary.FailedCount,
		&summary.ReconciledCount,
		&summary.LastEventAt,
	)
	if err != nil {
		if tableMissing(err) {
			return BroadbandCommercialCatalogSummary{}, nil
		}
		return BroadbandCommercialCatalogSummary{}, fmt.Errorf("summarize broadband commercial catalog events: %w", err)
	}
	_ = DB.QueryRow(`SELECT plan_fingerprint, account_count, plan_count, bundle_count, subscription_count, concurrency_policy_count, compliance_check_count
		FROM broadband_commercial_catalog_events
		ORDER BY datetime(created_at) DESC, id DESC LIMIT 1`).Scan(
		&summary.LastFingerprint,
		&summary.LastAccountCount,
		&summary.LastPlanCount,
		&summary.LastBundleCount,
		&summary.LastSubscriptionCount,
		&summary.LastConcurrencyPolicyCount,
		&summary.LastComplianceCheckCount,
	)
	_ = DB.QueryRow(`SELECT
			COALESCE(SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'suspended' THEN 1 ELSE 0 END), 0)
		FROM broadband_commercial_accounts`).Scan(&summary.ActiveAccounts, &summary.SuspendedAccounts)
	_ = DB.QueryRow(`SELECT COALESCE(SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END), 0) FROM broadband_commercial_plans`).Scan(&summary.ActivePlans)
	_ = DB.QueryRow(`SELECT COALESCE(SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END), 0) FROM broadband_commercial_bundles`).Scan(&summary.ActiveBundles)
	_ = DB.QueryRow(`SELECT
			COALESCE(SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'suspended' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(active_session_count), 0)
		FROM broadband_commercial_subscriptions`).Scan(&summary.ActiveSubscriptions, &summary.SuspendedSubscriptions, &summary.ActiveSessions)
	_ = DB.QueryRow(`SELECT COALESCE(SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END), 0) FROM broadband_commercial_concurrency_policies`).Scan(&summary.ActiveConcurrencyPolicies)
	_ = DB.QueryRow(`SELECT COALESCE(SUM(CASE WHEN max_sessions > 0 AND active_session_count > max_sessions THEN 1 ELSE 0 END), 0) FROM broadband_commercial_subscriptions`).Scan(&summary.OverLimitRecords)
	return summary, nil
}

func upsertBroadbandCommercialAccount(tx *sql.Tx, input BroadbandCommercialAccountInput) error {
	input = normalizeBroadbandCommercialAccountInput(input)
	if input.AccountID == "" || input.Status == "" {
		return fmt.Errorf("broadband commercial account id and status are required")
	}
	_, err := tx.Exec(`INSERT INTO broadband_commercial_accounts (
			account_id, parent_account_id, tenant, status, billing_mode, owner_name, contact,
			max_subscriptions, max_sessions, tags_json, metadata_json, source_event_id,
			last_seen_at, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT(account_id) DO UPDATE SET
			parent_account_id = excluded.parent_account_id,
			tenant = excluded.tenant,
			status = excluded.status,
			billing_mode = excluded.billing_mode,
			owner_name = excluded.owner_name,
			contact = excluded.contact,
			max_subscriptions = excluded.max_subscriptions,
			max_sessions = excluded.max_sessions,
			tags_json = excluded.tags_json,
			metadata_json = excluded.metadata_json,
			source_event_id = excluded.source_event_id,
			last_seen_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP`,
		input.AccountID,
		nullString(input.ParentAccountID),
		nullString(input.Tenant),
		input.Status,
		nullString(input.BillingMode),
		nullString(input.OwnerName),
		nullString(input.Contact),
		nonNegativeInt(input.MaxSubscriptions),
		nonNegativeInt(input.MaxSessions),
		input.TagsJSON,
		input.MetadataJSON,
		nullString(input.SourceEventID),
	)
	if err != nil {
		return fmt.Errorf("upsert broadband commercial account %q: %w", input.AccountID, err)
	}
	return nil
}

func upsertBroadbandCommercialPlan(tx *sql.Tx, input BroadbandCommercialPlanInput) error {
	input = normalizeBroadbandCommercialPlanInput(input)
	if input.Name == "" || input.Status == "" {
		return fmt.Errorf("broadband commercial plan name and status are required")
	}
	_, err := tx.Exec(`INSERT INTO broadband_commercial_plans (
			plan_name, product, status, display_name, billing_period, price_micros, currency,
			max_sessions, max_devices, downstream_kbps, upstream_kbps, quota_profile, service_chain,
			address_pool, ipv6_pool, delegated_ipv6_pool, route_policy, qos_profile, translation_pool,
			portal_profile, grace_seconds, suspension_role, session_timeout_seconds, idle_timeout_seconds,
			vendor_packs_json, metadata_json, source_event_id, last_seen_at, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT(plan_name) DO UPDATE SET
			product = excluded.product,
			status = excluded.status,
			display_name = excluded.display_name,
			billing_period = excluded.billing_period,
			price_micros = excluded.price_micros,
			currency = excluded.currency,
			max_sessions = excluded.max_sessions,
			max_devices = excluded.max_devices,
			downstream_kbps = excluded.downstream_kbps,
			upstream_kbps = excluded.upstream_kbps,
			quota_profile = excluded.quota_profile,
			service_chain = excluded.service_chain,
			address_pool = excluded.address_pool,
			ipv6_pool = excluded.ipv6_pool,
			delegated_ipv6_pool = excluded.delegated_ipv6_pool,
			route_policy = excluded.route_policy,
			qos_profile = excluded.qos_profile,
			translation_pool = excluded.translation_pool,
			portal_profile = excluded.portal_profile,
			grace_seconds = excluded.grace_seconds,
			suspension_role = excluded.suspension_role,
			session_timeout_seconds = excluded.session_timeout_seconds,
			idle_timeout_seconds = excluded.idle_timeout_seconds,
			vendor_packs_json = excluded.vendor_packs_json,
			metadata_json = excluded.metadata_json,
			source_event_id = excluded.source_event_id,
			last_seen_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP`,
		input.Name,
		nullString(input.Product),
		input.Status,
		nullString(input.DisplayName),
		nullString(input.BillingPeriod),
		input.PriceMicros,
		nullString(input.Currency),
		nonNegativeInt(input.MaxSessions),
		nonNegativeInt(input.MaxDevices),
		nonNegativeInt(input.DownstreamKbps),
		nonNegativeInt(input.UpstreamKbps),
		nullString(input.QuotaProfile),
		nullString(input.ServiceChain),
		nullString(input.AddressPool),
		nullString(input.IPv6Pool),
		nullString(input.DelegatedIPv6Pool),
		nullString(input.RoutePolicy),
		nullString(input.QoSProfile),
		nullString(input.TranslationPool),
		nullString(input.PortalProfile),
		nonNegativeInt(input.GraceSeconds),
		nullString(input.SuspensionRole),
		nonNegativeInt(input.SessionTimeoutSeconds),
		nonNegativeInt(input.IdleTimeoutSeconds),
		input.VendorPacksJSON,
		input.MetadataJSON,
		nullString(input.SourceEventID),
	)
	if err != nil {
		return fmt.Errorf("upsert broadband commercial plan %q: %w", input.Name, err)
	}
	return nil
}

func upsertBroadbandCommercialBundle(tx *sql.Tx, input BroadbandCommercialBundleInput) error {
	input = normalizeBroadbandCommercialBundleInput(input)
	if input.Name == "" || input.Status == "" {
		return fmt.Errorf("broadband commercial bundle name and status are required")
	}
	_, err := tx.Exec(`INSERT INTO broadband_commercial_bundles (
			bundle_name, status, display_name, plans_json, required_plans_json,
			mutually_exclusive_plans_json, max_concurrent_subscriptions, shared_concurrency,
			priority, eligibility_tags_json, metadata_json, source_event_id,
			last_seen_at, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT(bundle_name) DO UPDATE SET
			status = excluded.status,
			display_name = excluded.display_name,
			plans_json = excluded.plans_json,
			required_plans_json = excluded.required_plans_json,
			mutually_exclusive_plans_json = excluded.mutually_exclusive_plans_json,
			max_concurrent_subscriptions = excluded.max_concurrent_subscriptions,
			shared_concurrency = excluded.shared_concurrency,
			priority = excluded.priority,
			eligibility_tags_json = excluded.eligibility_tags_json,
			metadata_json = excluded.metadata_json,
			source_event_id = excluded.source_event_id,
			last_seen_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP`,
		input.Name,
		input.Status,
		nullString(input.DisplayName),
		input.PlansJSON,
		input.RequiredPlansJSON,
		input.MutuallyExclusivePlansJSON,
		nonNegativeInt(input.MaxConcurrentSubscriptions),
		boolToInt(input.SharedConcurrency),
		input.Priority,
		input.EligibilityTagsJSON,
		input.MetadataJSON,
		nullString(input.SourceEventID),
	)
	if err != nil {
		return fmt.Errorf("upsert broadband commercial bundle %q: %w", input.Name, err)
	}
	return nil
}

func upsertBroadbandCommercialSubscription(tx *sql.Tx, input BroadbandCommercialSubscriptionInput) error {
	input = normalizeBroadbandCommercialSubscriptionInput(input)
	if input.SubscriptionID == "" || input.AccountID == "" || input.PlanName == "" || input.Status == "" {
		return fmt.Errorf("broadband commercial subscription id, account, plan, and status are required")
	}
	_, err := tx.Exec(`INSERT INTO broadband_commercial_subscriptions (
			subscription_id, account_id, subscriber_id, username, plan_name, bundle_name, status,
			starts_at, ends_at, auto_renew, max_sessions, device_limit, eligibility_tags_json,
			active_session_count, metadata_json, source_event_id, last_seen_at, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT(subscription_id) DO UPDATE SET
			account_id = excluded.account_id,
			subscriber_id = excluded.subscriber_id,
			username = excluded.username,
			plan_name = excluded.plan_name,
			bundle_name = excluded.bundle_name,
			status = excluded.status,
			starts_at = excluded.starts_at,
			ends_at = excluded.ends_at,
			auto_renew = excluded.auto_renew,
			max_sessions = excluded.max_sessions,
			device_limit = excluded.device_limit,
			eligibility_tags_json = excluded.eligibility_tags_json,
			active_session_count = excluded.active_session_count,
			metadata_json = excluded.metadata_json,
			source_event_id = excluded.source_event_id,
			last_seen_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP`,
		input.SubscriptionID,
		input.AccountID,
		nullString(input.SubscriberID),
		nullString(input.Username),
		input.PlanName,
		nullString(input.BundleName),
		input.Status,
		nullString(input.StartsAt),
		nullString(input.EndsAt),
		boolToInt(input.AutoRenew),
		nonNegativeInt(input.MaxSessions),
		nonNegativeInt(input.DeviceLimit),
		input.EligibilityTagsJSON,
		nonNegativeInt(input.ActiveSessionCount),
		input.MetadataJSON,
		nullString(input.SourceEventID),
	)
	if err != nil {
		return fmt.Errorf("upsert broadband commercial subscription %q: %w", input.SubscriptionID, err)
	}
	return nil
}

func upsertBroadbandCommercialConcurrencyPolicy(tx *sql.Tx, input BroadbandCommercialConcurrencyPolicyInput) error {
	input = normalizeBroadbandCommercialConcurrencyPolicyInput(input)
	if input.PolicyKey == "" || input.Name == "" || input.Scope == "" || input.Action == "" || input.Status == "" {
		return fmt.Errorf("broadband commercial concurrency policy key, name, scope, action, and status are required")
	}
	_, err := tx.Exec(`INSERT INTO broadband_commercial_concurrency_policies (
			policy_key, name, scope, target, account_id, tenant, plan_name, bundle_name,
			max_sessions, max_sessions_per_subscriber, burst_sessions, grace_seconds,
			action, coa_action, status, metadata_json, source_event_id, last_seen_at, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT(policy_key) DO UPDATE SET
			name = excluded.name,
			scope = excluded.scope,
			target = excluded.target,
			account_id = excluded.account_id,
			tenant = excluded.tenant,
			plan_name = excluded.plan_name,
			bundle_name = excluded.bundle_name,
			max_sessions = excluded.max_sessions,
			max_sessions_per_subscriber = excluded.max_sessions_per_subscriber,
			burst_sessions = excluded.burst_sessions,
			grace_seconds = excluded.grace_seconds,
			action = excluded.action,
			coa_action = excluded.coa_action,
			status = excluded.status,
			metadata_json = excluded.metadata_json,
			source_event_id = excluded.source_event_id,
			last_seen_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP`,
		input.PolicyKey,
		input.Name,
		input.Scope,
		nullString(input.Target),
		nullString(input.AccountID),
		nullString(input.Tenant),
		nullString(input.PlanName),
		nullString(input.BundleName),
		nonNegativeInt(input.MaxSessions),
		nonNegativeInt(input.MaxSessionsPerSubscriber),
		nonNegativeInt(input.BurstSessions),
		nonNegativeInt(input.GraceSeconds),
		input.Action,
		nullString(input.CoAAction),
		input.Status,
		input.MetadataJSON,
		nullString(input.SourceEventID),
	)
	if err != nil {
		return fmt.Errorf("upsert broadband commercial concurrency policy %q: %w", input.PolicyKey, err)
	}
	return nil
}

func scanBroadbandCommercialCatalogEvent(scanner interface{ Scan(dest ...any) error }) (BroadbandCommercialCatalogEvent, error) {
	var event BroadbandCommercialCatalogEvent
	var mode, actor sql.NullString
	err := scanner.Scan(
		&event.ID,
		&event.EventID,
		&event.Operation,
		&event.Status,
		&event.PlanFingerprint,
		&mode,
		&event.AccountCount,
		&event.PlanCount,
		&event.BundleCount,
		&event.SubscriptionCount,
		&event.ConcurrencyPolicyCount,
		&event.ActiveSubscriptionCount,
		&event.ActiveSessionCount,
		&event.OverLimitCount,
		&event.ComplianceCheckCount,
		&event.PassedCheckCount,
		&event.WarningCount,
		&event.BlockerCount,
		&event.ExternalRequirementCount,
		&event.SummaryJSON,
		&event.ReportJSON,
		&actor,
		&event.CreatedAt,
	)
	if err != nil {
		return BroadbandCommercialCatalogEvent{}, fmt.Errorf("scan broadband commercial catalog event: %w", err)
	}
	event.Mode = mode.String
	event.Actor = actor.String
	return event, nil
}

func scanBroadbandCommercialAccount(scanner interface{ Scan(dest ...any) error }) (BroadbandCommercialAccountRecord, error) {
	var record BroadbandCommercialAccountRecord
	var parent, tenant, billing, owner, contact, source sql.NullString
	err := scanner.Scan(
		&record.ID, &record.AccountID, &parent, &tenant, &record.Status, &billing,
		&owner, &contact, &record.MaxSubscriptions, &record.MaxSessions,
		&record.TagsJSON, &record.MetadataJSON, &source, &record.LastSeenAt,
		&record.CreatedAt, &record.UpdatedAt,
	)
	if err != nil {
		return BroadbandCommercialAccountRecord{}, fmt.Errorf("scan broadband commercial account: %w", err)
	}
	record.ParentAccountID = parent.String
	record.Tenant = tenant.String
	record.BillingMode = billing.String
	record.OwnerName = owner.String
	record.Contact = contact.String
	record.SourceEventID = source.String
	return record, nil
}

func scanBroadbandCommercialPlan(scanner interface{ Scan(dest ...any) error }) (BroadbandCommercialPlanRecord, error) {
	var record BroadbandCommercialPlanRecord
	var product, displayName, period, currency, quota, service, address, ipv6Pool, delegatedPool sql.NullString
	var route, qos, translation, portal, suspension, source sql.NullString
	err := scanner.Scan(
		&record.ID, &record.Name, &product, &record.Status, &displayName, &period,
		&record.PriceMicros, &currency, &record.MaxSessions, &record.MaxDevices,
		&record.DownstreamKbps, &record.UpstreamKbps, &quota, &service, &address,
		&ipv6Pool, &delegatedPool, &route, &qos, &translation, &portal,
		&record.GraceSeconds, &suspension, &record.SessionTimeoutSeconds,
		&record.IdleTimeoutSeconds, &record.VendorPacksJSON, &record.MetadataJSON,
		&source, &record.LastSeenAt, &record.CreatedAt, &record.UpdatedAt,
	)
	if err != nil {
		return BroadbandCommercialPlanRecord{}, fmt.Errorf("scan broadband commercial plan: %w", err)
	}
	record.Product = product.String
	record.DisplayName = displayName.String
	record.BillingPeriod = period.String
	record.Currency = currency.String
	record.QuotaProfile = quota.String
	record.ServiceChain = service.String
	record.AddressPool = address.String
	record.IPv6Pool = ipv6Pool.String
	record.DelegatedIPv6Pool = delegatedPool.String
	record.RoutePolicy = route.String
	record.QoSProfile = qos.String
	record.TranslationPool = translation.String
	record.PortalProfile = portal.String
	record.SuspensionRole = suspension.String
	record.SourceEventID = source.String
	return record, nil
}

func scanBroadbandCommercialBundle(scanner interface{ Scan(dest ...any) error }) (BroadbandCommercialBundleRecord, error) {
	var record BroadbandCommercialBundleRecord
	var displayName, source sql.NullString
	var shared int
	err := scanner.Scan(
		&record.ID, &record.Name, &record.Status, &displayName, &record.PlansJSON,
		&record.RequiredPlansJSON, &record.MutuallyExclusivePlansJSON,
		&record.MaxConcurrentSubscriptions, &shared, &record.Priority,
		&record.EligibilityTagsJSON, &record.MetadataJSON, &source, &record.LastSeenAt,
		&record.CreatedAt, &record.UpdatedAt,
	)
	if err != nil {
		return BroadbandCommercialBundleRecord{}, fmt.Errorf("scan broadband commercial bundle: %w", err)
	}
	record.DisplayName = displayName.String
	record.SharedConcurrency = shared != 0
	record.SourceEventID = source.String
	return record, nil
}

func scanBroadbandCommercialSubscription(scanner interface{ Scan(dest ...any) error }) (BroadbandCommercialSubscriptionRecord, error) {
	var record BroadbandCommercialSubscriptionRecord
	var subscriberID, username, bundle, startsAt, endsAt, source sql.NullString
	var autoRenew int
	err := scanner.Scan(
		&record.ID, &record.SubscriptionID, &record.AccountID, &subscriberID, &username,
		&record.PlanName, &bundle, &record.Status, &startsAt, &endsAt, &autoRenew,
		&record.MaxSessions, &record.DeviceLimit, &record.EligibilityTagsJSON,
		&record.ActiveSessionCount, &record.MetadataJSON, &source, &record.LastSeenAt,
		&record.CreatedAt, &record.UpdatedAt,
	)
	if err != nil {
		return BroadbandCommercialSubscriptionRecord{}, fmt.Errorf("scan broadband commercial subscription: %w", err)
	}
	record.SubscriberID = subscriberID.String
	record.Username = username.String
	record.BundleName = bundle.String
	record.StartsAt = startsAt.String
	record.EndsAt = endsAt.String
	record.AutoRenew = autoRenew != 0
	record.SourceEventID = source.String
	return record, nil
}

func scanBroadbandCommercialConcurrencyPolicy(scanner interface{ Scan(dest ...any) error }) (BroadbandCommercialConcurrencyPolicyRecord, error) {
	var record BroadbandCommercialConcurrencyPolicyRecord
	var target, accountID, tenant, planName, bundleName, coaAction, source sql.NullString
	err := scanner.Scan(
		&record.ID, &record.PolicyKey, &record.Name, &record.Scope, &target,
		&accountID, &tenant, &planName, &bundleName, &record.MaxSessions,
		&record.MaxSessionsPerSubscriber, &record.BurstSessions, &record.GraceSeconds,
		&record.Action, &coaAction, &record.Status, &record.MetadataJSON, &source,
		&record.LastSeenAt, &record.CreatedAt, &record.UpdatedAt,
	)
	if err != nil {
		return BroadbandCommercialConcurrencyPolicyRecord{}, fmt.Errorf("scan broadband commercial concurrency policy: %w", err)
	}
	record.Target = target.String
	record.AccountID = accountID.String
	record.Tenant = tenant.String
	record.PlanName = planName.String
	record.BundleName = bundleName.String
	record.CoAAction = coaAction.String
	record.SourceEventID = source.String
	return record, nil
}

func broadbandCommercialCatalogEventSelectSQL() string {
	return `SELECT id, event_id, operation, status, plan_fingerprint, mode,
		account_count, plan_count, bundle_count, subscription_count, concurrency_policy_count,
		active_subscription_count, active_session_count, over_limit_count,
		compliance_check_count, passed_check_count, warning_count, blocker_count,
		external_requirement_count, summary_json, report_json, actor, created_at
		FROM broadband_commercial_catalog_events`
}

func broadbandCommercialAccountSelectSQL() string {
	return `SELECT id, account_id, parent_account_id, tenant, status, billing_mode,
		owner_name, contact, max_subscriptions, max_sessions, tags_json, metadata_json,
		source_event_id, last_seen_at, created_at, updated_at
		FROM broadband_commercial_accounts`
}

func broadbandCommercialPlanSelectSQL() string {
	return `SELECT id, plan_name, product, status, display_name, billing_period,
		price_micros, currency, max_sessions, max_devices, downstream_kbps, upstream_kbps,
		quota_profile, service_chain, address_pool, ipv6_pool, delegated_ipv6_pool,
		route_policy, qos_profile, translation_pool, portal_profile, grace_seconds,
		suspension_role, session_timeout_seconds, idle_timeout_seconds, vendor_packs_json,
		metadata_json, source_event_id, last_seen_at, created_at, updated_at
		FROM broadband_commercial_plans`
}

func broadbandCommercialBundleSelectSQL() string {
	return `SELECT id, bundle_name, status, display_name, plans_json, required_plans_json,
		mutually_exclusive_plans_json, max_concurrent_subscriptions, shared_concurrency,
		priority, eligibility_tags_json, metadata_json, source_event_id, last_seen_at,
		created_at, updated_at
		FROM broadband_commercial_bundles`
}

func broadbandCommercialSubscriptionSelectSQL() string {
	return `SELECT id, subscription_id, account_id, subscriber_id, username, plan_name,
		bundle_name, status, starts_at, ends_at, auto_renew, max_sessions, device_limit,
		eligibility_tags_json, active_session_count, metadata_json, source_event_id,
		last_seen_at, created_at, updated_at
		FROM broadband_commercial_subscriptions`
}

func broadbandCommercialConcurrencyPolicySelectSQL() string {
	return `SELECT id, policy_key, name, scope, target, account_id, tenant, plan_name,
		bundle_name, max_sessions, max_sessions_per_subscriber, burst_sessions,
		grace_seconds, action, coa_action, status, metadata_json, source_event_id,
		last_seen_at, created_at, updated_at
		FROM broadband_commercial_concurrency_policies`
}

func normalizeBroadbandCommercialAccountInput(input BroadbandCommercialAccountInput) BroadbandCommercialAccountInput {
	input.AccountID = strings.TrimSpace(input.AccountID)
	input.ParentAccountID = strings.TrimSpace(input.ParentAccountID)
	input.Tenant = strings.TrimSpace(input.Tenant)
	input.Status = normalizeBroadbandCommercialAccountStatus(input.Status)
	input.BillingMode = strings.ToLower(strings.TrimSpace(input.BillingMode))
	input.OwnerName = strings.TrimSpace(input.OwnerName)
	input.Contact = strings.TrimSpace(input.Contact)
	input.TagsJSON = nonEmptyJSON(input.TagsJSON, "[]")
	input.MetadataJSON = nonEmptyJSON(input.MetadataJSON, "{}")
	input.SourceEventID = strings.TrimSpace(input.SourceEventID)
	return input
}

func normalizeBroadbandCommercialPlanInput(input BroadbandCommercialPlanInput) BroadbandCommercialPlanInput {
	input.Name = strings.TrimSpace(input.Name)
	input.Product = strings.TrimSpace(input.Product)
	input.Status = normalizeBroadbandCommercialEnabledStatus(input.Status)
	input.DisplayName = strings.TrimSpace(input.DisplayName)
	input.BillingPeriod = strings.ToLower(strings.TrimSpace(input.BillingPeriod))
	input.Currency = strings.ToUpper(strings.TrimSpace(input.Currency))
	input.QuotaProfile = strings.TrimSpace(input.QuotaProfile)
	input.ServiceChain = strings.TrimSpace(input.ServiceChain)
	input.AddressPool = strings.TrimSpace(input.AddressPool)
	input.IPv6Pool = strings.TrimSpace(input.IPv6Pool)
	input.DelegatedIPv6Pool = strings.TrimSpace(input.DelegatedIPv6Pool)
	input.RoutePolicy = strings.TrimSpace(input.RoutePolicy)
	input.QoSProfile = strings.TrimSpace(input.QoSProfile)
	input.TranslationPool = strings.TrimSpace(input.TranslationPool)
	input.PortalProfile = strings.TrimSpace(input.PortalProfile)
	input.SuspensionRole = strings.TrimSpace(input.SuspensionRole)
	input.VendorPacksJSON = nonEmptyJSON(input.VendorPacksJSON, "[]")
	input.MetadataJSON = nonEmptyJSON(input.MetadataJSON, "{}")
	input.SourceEventID = strings.TrimSpace(input.SourceEventID)
	return input
}

func normalizeBroadbandCommercialBundleInput(input BroadbandCommercialBundleInput) BroadbandCommercialBundleInput {
	input.Name = strings.TrimSpace(input.Name)
	input.Status = normalizeBroadbandCommercialEnabledStatus(input.Status)
	input.DisplayName = strings.TrimSpace(input.DisplayName)
	input.PlansJSON = nonEmptyJSON(input.PlansJSON, "[]")
	input.RequiredPlansJSON = nonEmptyJSON(input.RequiredPlansJSON, "[]")
	input.MutuallyExclusivePlansJSON = nonEmptyJSON(input.MutuallyExclusivePlansJSON, "[]")
	input.EligibilityTagsJSON = nonEmptyJSON(input.EligibilityTagsJSON, "[]")
	input.MetadataJSON = nonEmptyJSON(input.MetadataJSON, "{}")
	input.SourceEventID = strings.TrimSpace(input.SourceEventID)
	return input
}

func normalizeBroadbandCommercialSubscriptionInput(input BroadbandCommercialSubscriptionInput) BroadbandCommercialSubscriptionInput {
	input.SubscriptionID = strings.TrimSpace(input.SubscriptionID)
	input.AccountID = strings.TrimSpace(input.AccountID)
	input.SubscriberID = strings.TrimSpace(input.SubscriberID)
	input.Username = strings.TrimSpace(input.Username)
	input.PlanName = strings.TrimSpace(input.PlanName)
	input.BundleName = strings.TrimSpace(input.BundleName)
	input.Status = normalizeBroadbandCommercialSubscriptionStatus(input.Status)
	input.StartsAt = strings.TrimSpace(input.StartsAt)
	input.EndsAt = strings.TrimSpace(input.EndsAt)
	input.EligibilityTagsJSON = nonEmptyJSON(input.EligibilityTagsJSON, "[]")
	input.MetadataJSON = nonEmptyJSON(input.MetadataJSON, "{}")
	input.SourceEventID = strings.TrimSpace(input.SourceEventID)
	return input
}

func normalizeBroadbandCommercialConcurrencyPolicyInput(input BroadbandCommercialConcurrencyPolicyInput) BroadbandCommercialConcurrencyPolicyInput {
	input.PolicyKey = strings.TrimSpace(input.PolicyKey)
	input.Name = strings.TrimSpace(input.Name)
	input.Scope = normalizeBroadbandCommercialConcurrencyScope(input.Scope)
	input.Target = strings.TrimSpace(input.Target)
	input.AccountID = strings.TrimSpace(input.AccountID)
	input.Tenant = strings.TrimSpace(input.Tenant)
	input.PlanName = strings.TrimSpace(input.PlanName)
	input.BundleName = strings.TrimSpace(input.BundleName)
	input.Action = normalizeBroadbandCommercialConcurrencyAction(input.Action)
	input.CoAAction = strings.TrimSpace(input.CoAAction)
	input.Status = normalizeBroadbandCommercialEnabledStatus(input.Status)
	input.MetadataJSON = nonEmptyJSON(input.MetadataJSON, "{}")
	input.SourceEventID = strings.TrimSpace(input.SourceEventID)
	if input.PolicyKey == "" {
		input.PolicyKey = "bccp_" + sha256Text(input.Name + "|" + input.Scope + "|" + input.Target + "|" + input.PlanName + "|" + input.BundleName)[:20]
	}
	return input
}

func normalizeBroadbandCommercialCatalogOperation(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "preview", "apply", "status", "reconcile":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeBroadbandCommercialCatalogEventStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "previewed", "applied", "blocked", "degraded", "skipped", "failed", "reconciled":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeBroadbandCommercialAccountStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "active":
		return "active"
	case "suspended", "closed", "pending":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeBroadbandCommercialEnabledStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "active", "enabled", "ready":
		return "active"
	case "disabled":
		return "disabled"
	default:
		return ""
	}
}

func normalizeBroadbandCommercialSubscriptionStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "active":
		return "active"
	case "pending", "suspended", "expired", "cancelled":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeBroadbandCommercialConcurrencyScope(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "subscriber":
		return "subscriber"
	case "subscription", "account", "bundle", "plan", "tenant":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeBroadbandCommercialConcurrencyAction(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "reject":
		return "reject"
	case "suspend", "quarantine", "degrade", "monitor":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func boundedBroadbandCommercialLimit(limit int) int {
	if limit <= 0 {
		return 100
	}
	if limit > 1000 {
		return 1000
	}
	return limit
}

func nonEmptyJSON(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func sha256Text(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func newBroadbandCommercialCatalogEventID(input BroadbandCommercialCatalogEventInput) string {
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%s", input.Operation, input.Status, input.PlanFingerprint, input.Actor)))
		return "bcc_" + hex.EncodeToString(sum[:8])
	}
	return "bcc_" + hex.EncodeToString(random)
}
