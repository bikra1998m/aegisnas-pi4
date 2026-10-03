package db

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
)

type BroadbandQuotaBalanceEventInput struct {
	EventID                  string
	Operation                string
	Status                   string
	PlanFingerprint          string
	Mode                     string
	WalletCount              int
	QuotaProfileCount        int
	TopUpCount               int
	RatingRuleCount          int
	ResetPolicyCount         int
	ActiveWalletCount        int
	PrepaidWalletCount       int
	PostpaidWalletCount      int
	ExhaustedWalletCount     int
	TotalBalanceMicros       int64
	TotalCreditLimitMicros   int64
	TotalTopUpMicros         int64
	ComplianceCheckCount     int
	PassedCheckCount         int
	WarningCount             int
	BlockerCount             int
	ExternalRequirementCount int
	SummaryJSON              string
	ReportJSON               string
	Actor                    string
	Wallets                  []BroadbandQuotaWalletInput
	QuotaProfiles            []BroadbandQuotaProfileInput
	TopUps                   []BroadbandTopUpGrantInput
	RatingRules              []BroadbandQuotaRatingRuleInput
	ResetPolicies            []BroadbandQuotaResetPolicyInput
}

type BroadbandQuotaWalletInput struct {
	WalletID          string
	AccountID         string
	SubscriptionID    string
	SubscriberID      string
	Username          string
	BillingMode       string
	Status            string
	Currency          string
	BalanceMicros     int64
	CreditLimitMicros int64
	ReservedMicros    int64
	QuotaProfile      string
	PeriodStart       string
	PeriodEnd         string
	AutoRecharge      bool
	TagsJSON          string
	MetadataJSON      string
}

type BroadbandQuotaProfileInput struct {
	Name                    string
	Status                  string
	Period                  string
	IncludedInputOctets     int64
	IncludedOutputOctets    int64
	IncludedTotalOctets     int64
	OverageRateMicrosPerMB  int64
	WarningThresholdPercent int
	HardLimit               bool
	ThrottleProfile         string
	ExhaustedRole           string
	ResetPolicy             string
	VendorPacksJSON         string
	MetadataJSON            string
}

type BroadbandTopUpGrantInput struct {
	TopUpID        string
	WalletID       string
	Status         string
	AmountMicros   int64
	BonusMicros    int64
	Currency       string
	QuotaOctets    int64
	ExpiresAt      string
	PaymentRef     string
	IdempotencyKey string
	Source         string
	MetadataJSON   string
}

type BroadbandQuotaRatingRuleInput struct {
	Name                string
	Status              string
	PlanName            string
	QuotaProfile        string
	Unit                string
	PriceMicros         int64
	Rounding            string
	MinimumChargeMicros int64
	TaxPercent          int
	MetadataJSON        string
}

type BroadbandQuotaResetPolicyInput struct {
	Name                   string
	Status                 string
	Period                 string
	ResetDay               int
	ResetHour              int
	CarryOverOctets        int64
	CarryOverBalanceMicros int64
	MetadataJSON           string
}

type BroadbandQuotaBalanceEvent struct {
	EventID                  string `json:"event_id"`
	Operation                string `json:"operation"`
	Status                   string `json:"status"`
	PlanFingerprint          string `json:"plan_fingerprint"`
	Mode                     string `json:"mode,omitempty"`
	WalletCount              int    `json:"wallet_count"`
	QuotaProfileCount        int    `json:"quota_profile_count"`
	TopUpCount               int    `json:"top_up_count"`
	RatingRuleCount          int    `json:"rating_rule_count"`
	ResetPolicyCount         int    `json:"reset_policy_count"`
	ActiveWalletCount        int    `json:"active_wallet_count"`
	PrepaidWalletCount       int    `json:"prepaid_wallet_count"`
	PostpaidWalletCount      int    `json:"postpaid_wallet_count"`
	ExhaustedWalletCount     int    `json:"exhausted_wallet_count"`
	TotalBalanceMicros       int64  `json:"total_balance_micros"`
	TotalCreditLimitMicros   int64  `json:"total_credit_limit_micros"`
	TotalTopUpMicros         int64  `json:"total_top_up_micros"`
	ComplianceCheckCount     int    `json:"compliance_check_count"`
	PassedCheckCount         int    `json:"passed_check_count"`
	WarningCount             int    `json:"warning_count"`
	BlockerCount             int    `json:"blocker_count"`
	ExternalRequirementCount int    `json:"external_requirement_count"`
	SummaryJSON              string `json:"summary_json"`
	ReportJSON               string `json:"report_json"`
	Actor                    string `json:"actor,omitempty"`
	CreatedAt                string `json:"created_at"`
}

type BroadbandQuotaWalletRecord struct {
	WalletID          string `json:"wallet_id"`
	AccountID         string `json:"account_id,omitempty"`
	SubscriptionID    string `json:"subscription_id,omitempty"`
	SubscriberID      string `json:"subscriber_id,omitempty"`
	Username          string `json:"username,omitempty"`
	BillingMode       string `json:"billing_mode"`
	Status            string `json:"status"`
	Currency          string `json:"currency"`
	BalanceMicros     int64  `json:"balance_micros"`
	CreditLimitMicros int64  `json:"credit_limit_micros"`
	ReservedMicros    int64  `json:"reserved_micros"`
	QuotaProfile      string `json:"quota_profile,omitempty"`
	PeriodStart       string `json:"period_start,omitempty"`
	PeriodEnd         string `json:"period_end,omitempty"`
	AutoRecharge      bool   `json:"auto_recharge"`
	TagsJSON          string `json:"tags_json"`
	MetadataJSON      string `json:"metadata_json"`
	LastSeenAt        string `json:"last_seen_at"`
}

type BroadbandQuotaProfileRecord struct {
	Name                    string `json:"name"`
	Status                  string `json:"status"`
	Period                  string `json:"period"`
	IncludedInputOctets     int64  `json:"included_input_octets"`
	IncludedOutputOctets    int64  `json:"included_output_octets"`
	IncludedTotalOctets     int64  `json:"included_total_octets"`
	OverageRateMicrosPerMB  int64  `json:"overage_rate_micros_per_mb"`
	WarningThresholdPercent int    `json:"warning_threshold_percent"`
	HardLimit               bool   `json:"hard_limit"`
	ThrottleProfile         string `json:"throttle_profile,omitempty"`
	ExhaustedRole           string `json:"exhausted_role,omitempty"`
	ResetPolicy             string `json:"reset_policy,omitempty"`
	VendorPacksJSON         string `json:"vendor_packs_json"`
	MetadataJSON            string `json:"metadata_json"`
	LastSeenAt              string `json:"last_seen_at"`
}

type BroadbandTopUpGrantRecord struct {
	TopUpID        string `json:"top_up_id"`
	WalletID       string `json:"wallet_id"`
	Status         string `json:"status"`
	AmountMicros   int64  `json:"amount_micros"`
	BonusMicros    int64  `json:"bonus_micros"`
	Currency       string `json:"currency"`
	QuotaOctets    int64  `json:"quota_octets"`
	ExpiresAt      string `json:"expires_at,omitempty"`
	PaymentRef     string `json:"payment_ref,omitempty"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
	Source         string `json:"source,omitempty"`
	MetadataJSON   string `json:"metadata_json"`
	LastSeenAt     string `json:"last_seen_at"`
}

type BroadbandQuotaRatingRuleRecord struct {
	Name                string `json:"name"`
	Status              string `json:"status"`
	PlanName            string `json:"plan_name,omitempty"`
	QuotaProfile        string `json:"quota_profile,omitempty"`
	Unit                string `json:"unit"`
	PriceMicros         int64  `json:"price_micros"`
	Rounding            string `json:"rounding"`
	MinimumChargeMicros int64  `json:"minimum_charge_micros"`
	TaxPercent          int    `json:"tax_percent"`
	MetadataJSON        string `json:"metadata_json"`
	LastSeenAt          string `json:"last_seen_at"`
}

type BroadbandQuotaResetPolicyRecord struct {
	Name                   string `json:"name"`
	Status                 string `json:"status"`
	Period                 string `json:"period"`
	ResetDay               int    `json:"reset_day"`
	ResetHour              int    `json:"reset_hour"`
	CarryOverOctets        int64  `json:"carry_over_octets"`
	CarryOverBalanceMicros int64  `json:"carry_over_balance_micros"`
	MetadataJSON           string `json:"metadata_json"`
	LastSeenAt             string `json:"last_seen_at"`
}

type BroadbandQuotaBalanceSummary struct {
	TotalEvents            int    `json:"total_events"`
	PreviewEvents          int    `json:"preview_events"`
	AppliedCount           int    `json:"applied_count"`
	BlockedCount           int    `json:"blocked_count"`
	LastStatus             string `json:"last_status,omitempty"`
	LastFingerprint        string `json:"last_fingerprint,omitempty"`
	LastAppliedAt          string `json:"last_applied_at,omitempty"`
	ActiveWallets          int    `json:"active_wallets"`
	ExhaustedWallets       int    `json:"exhausted_wallets"`
	PrepaidWallets         int    `json:"prepaid_wallets"`
	PostpaidWallets        int    `json:"postpaid_wallets"`
	ActiveQuotaProfiles    int    `json:"active_quota_profiles"`
	AppliedTopUps          int    `json:"applied_top_ups"`
	ActiveRatingRules      int    `json:"active_rating_rules"`
	ActiveResetPolicies    int    `json:"active_reset_policies"`
	TotalBalanceMicros     int64  `json:"total_balance_micros"`
	TotalCreditLimitMicros int64  `json:"total_credit_limit_micros"`
	TotalTopUpMicros       int64  `json:"total_top_up_micros"`
}

func RecordBroadbandQuotaBalanceEvent(input BroadbandQuotaBalanceEventInput) (string, error) {
	if DB == nil {
		return "", fmt.Errorf("database is not initialized")
	}
	input.Operation = normalizeBroadbandQuotaBalanceOperation(input.Operation)
	input.Status = normalizeBroadbandQuotaBalanceEventStatus(input.Status)
	if strings.TrimSpace(input.EventID) == "" {
		input.EventID = newBroadbandQuotaBalanceEventID(input)
	}
	if input.Operation == "" || input.Status == "" {
		return "", fmt.Errorf("broadband quota balance operation and status are required")
	}
	if strings.TrimSpace(input.PlanFingerprint) == "" {
		return "", fmt.Errorf("broadband quota balance plan fingerprint is required")
	}
	tx, err := DB.Begin()
	if err != nil {
		return "", fmt.Errorf("begin broadband quota balance event: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	_, err = tx.Exec(`INSERT INTO broadband_quota_balance_events (
		event_id, operation, status, plan_fingerprint, mode, wallet_count,
		quota_profile_count, top_up_count, rating_rule_count, reset_policy_count,
		active_wallet_count, prepaid_wallet_count, postpaid_wallet_count,
		exhausted_wallet_count, total_balance_micros, total_credit_limit_micros,
		total_top_up_micros, compliance_check_count, passed_check_count,
		warning_count, blocker_count, external_requirement_count, summary_json,
		report_json, actor
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		input.EventID, input.Operation, input.Status, input.PlanFingerprint,
		strings.TrimSpace(input.Mode), nonNegativeInt(input.WalletCount), nonNegativeInt(input.QuotaProfileCount),
		nonNegativeInt(input.TopUpCount), nonNegativeInt(input.RatingRuleCount), nonNegativeInt(input.ResetPolicyCount),
		nonNegativeInt(input.ActiveWalletCount), nonNegativeInt(input.PrepaidWalletCount), nonNegativeInt(input.PostpaidWalletCount),
		nonNegativeInt(input.ExhaustedWalletCount), input.TotalBalanceMicros, input.TotalCreditLimitMicros,
		input.TotalTopUpMicros, nonNegativeInt(input.ComplianceCheckCount), nonNegativeInt(input.PassedCheckCount),
		nonNegativeInt(input.WarningCount), nonNegativeInt(input.BlockerCount), nonNegativeInt(input.ExternalRequirementCount),
		quotaNonEmptyJSON(input.SummaryJSON), quotaNonEmptyJSON(input.ReportJSON), nullString(input.Actor))
	if err != nil {
		return "", fmt.Errorf("record broadband quota balance event: %w", err)
	}
	if err := upsertBroadbandQuotaWallets(tx, input.EventID, input.Wallets); err != nil {
		return "", err
	}
	if err := upsertBroadbandQuotaProfiles(tx, input.EventID, input.QuotaProfiles); err != nil {
		return "", err
	}
	if err := upsertBroadbandTopUpGrants(tx, input.EventID, input.TopUps); err != nil {
		return "", err
	}
	if err := upsertBroadbandQuotaRatingRules(tx, input.EventID, input.RatingRules); err != nil {
		return "", err
	}
	if err := upsertBroadbandQuotaResetPolicies(tx, input.EventID, input.ResetPolicies); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit broadband quota balance event: %w", err)
	}
	committed = true
	return input.EventID, nil
}

func ListBroadbandQuotaBalanceEvents(limit int) ([]BroadbandQuotaBalanceEvent, error) {
	if DB == nil {
		return []BroadbandQuotaBalanceEvent{}, nil
	}
	rows, err := DB.Query(broadbandQuotaBalanceEventSelectSQL()+` ORDER BY datetime(created_at) DESC, id DESC LIMIT ?`, positiveInt(limit, 100))
	if err != nil {
		if tableMissing(err) {
			return []BroadbandQuotaBalanceEvent{}, nil
		}
		return nil, fmt.Errorf("list broadband quota balance events: %w", err)
	}
	defer rows.Close()
	events := []BroadbandQuotaBalanceEvent{}
	for rows.Next() {
		event, scanErr := scanBroadbandQuotaBalanceEvent(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func ListBroadbandQuotaWallets(limit int) ([]BroadbandQuotaWalletRecord, error) {
	if DB == nil {
		return []BroadbandQuotaWalletRecord{}, nil
	}
	rows, err := DB.Query(`SELECT wallet_id, account_id, subscription_id, subscriber_id, username, billing_mode,
		status, currency, balance_micros, credit_limit_micros, reserved_micros, quota_profile,
		period_start, period_end, auto_recharge, tags_json, metadata_json, last_seen_at
		FROM broadband_quota_wallets ORDER BY datetime(last_seen_at) DESC, id DESC LIMIT ?`, positiveInt(limit, 100))
	if err != nil {
		if tableMissing(err) {
			return []BroadbandQuotaWalletRecord{}, nil
		}
		return nil, fmt.Errorf("list broadband quota wallets: %w", err)
	}
	defer rows.Close()
	out := []BroadbandQuotaWalletRecord{}
	for rows.Next() {
		var r BroadbandQuotaWalletRecord
		var accountID, subscriptionID, subscriberID, username, quotaProfile, periodStart, periodEnd sql.NullString
		var autoRecharge int
		if err := rows.Scan(&r.WalletID, &accountID, &subscriptionID, &subscriberID, &username, &r.BillingMode,
			&r.Status, &r.Currency, &r.BalanceMicros, &r.CreditLimitMicros, &r.ReservedMicros, &quotaProfile,
			&periodStart, &periodEnd, &autoRecharge, &r.TagsJSON, &r.MetadataJSON, &r.LastSeenAt); err != nil {
			return nil, fmt.Errorf("scan broadband quota wallet: %w", err)
		}
		r.AccountID = accountID.String
		r.SubscriptionID = subscriptionID.String
		r.SubscriberID = subscriberID.String
		r.Username = username.String
		r.QuotaProfile = quotaProfile.String
		r.PeriodStart = periodStart.String
		r.PeriodEnd = periodEnd.String
		r.AutoRecharge = autoRecharge != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

func ListBroadbandQuotaProfiles(limit int) ([]BroadbandQuotaProfileRecord, error) {
	if DB == nil {
		return []BroadbandQuotaProfileRecord{}, nil
	}
	rows, err := DB.Query(`SELECT profile_name, status, period, included_input_octets, included_output_octets,
		included_total_octets, overage_rate_micros_per_mb, warning_threshold_percent, hard_limit,
		throttle_profile, exhausted_role, reset_policy, vendor_packs_json, metadata_json, last_seen_at
		FROM broadband_quota_profiles ORDER BY datetime(last_seen_at) DESC, id DESC LIMIT ?`, positiveInt(limit, 100))
	if err != nil {
		if tableMissing(err) {
			return []BroadbandQuotaProfileRecord{}, nil
		}
		return nil, fmt.Errorf("list broadband quota profiles: %w", err)
	}
	defer rows.Close()
	out := []BroadbandQuotaProfileRecord{}
	for rows.Next() {
		var r BroadbandQuotaProfileRecord
		var hardLimit int
		var throttle, exhausted, reset sql.NullString
		if err := rows.Scan(&r.Name, &r.Status, &r.Period, &r.IncludedInputOctets, &r.IncludedOutputOctets,
			&r.IncludedTotalOctets, &r.OverageRateMicrosPerMB, &r.WarningThresholdPercent, &hardLimit,
			&throttle, &exhausted, &reset, &r.VendorPacksJSON, &r.MetadataJSON, &r.LastSeenAt); err != nil {
			return nil, fmt.Errorf("scan broadband quota profile: %w", err)
		}
		r.HardLimit = hardLimit != 0
		r.ThrottleProfile = throttle.String
		r.ExhaustedRole = exhausted.String
		r.ResetPolicy = reset.String
		out = append(out, r)
	}
	return out, rows.Err()
}

func ListBroadbandTopUpGrants(limit int) ([]BroadbandTopUpGrantRecord, error) {
	if DB == nil {
		return []BroadbandTopUpGrantRecord{}, nil
	}
	rows, err := DB.Query(`SELECT top_up_id, wallet_id, status, amount_micros, bonus_micros, currency,
		quota_octets, expires_at, payment_ref, idempotency_key, source, metadata_json, last_seen_at
		FROM broadband_topup_grants ORDER BY datetime(last_seen_at) DESC, id DESC LIMIT ?`, positiveInt(limit, 100))
	if err != nil {
		if tableMissing(err) {
			return []BroadbandTopUpGrantRecord{}, nil
		}
		return nil, fmt.Errorf("list broadband top-up grants: %w", err)
	}
	defer rows.Close()
	out := []BroadbandTopUpGrantRecord{}
	for rows.Next() {
		var r BroadbandTopUpGrantRecord
		var expiresAt, paymentRef, idempotencyKey, source sql.NullString
		if err := rows.Scan(&r.TopUpID, &r.WalletID, &r.Status, &r.AmountMicros, &r.BonusMicros,
			&r.Currency, &r.QuotaOctets, &expiresAt, &paymentRef, &idempotencyKey, &source,
			&r.MetadataJSON, &r.LastSeenAt); err != nil {
			return nil, fmt.Errorf("scan broadband top-up grant: %w", err)
		}
		r.ExpiresAt = expiresAt.String
		r.PaymentRef = paymentRef.String
		r.IdempotencyKey = idempotencyKey.String
		r.Source = source.String
		out = append(out, r)
	}
	return out, rows.Err()
}

func ListBroadbandQuotaRatingRules(limit int) ([]BroadbandQuotaRatingRuleRecord, error) {
	if DB == nil {
		return []BroadbandQuotaRatingRuleRecord{}, nil
	}
	rows, err := DB.Query(`SELECT rule_name, status, plan_name, quota_profile, unit, price_micros,
		rounding, minimum_charge_micros, tax_percent, metadata_json, last_seen_at
		FROM broadband_quota_rating_rules ORDER BY datetime(last_seen_at) DESC, id DESC LIMIT ?`, positiveInt(limit, 100))
	if err != nil {
		if tableMissing(err) {
			return []BroadbandQuotaRatingRuleRecord{}, nil
		}
		return nil, fmt.Errorf("list broadband quota rating rules: %w", err)
	}
	defer rows.Close()
	out := []BroadbandQuotaRatingRuleRecord{}
	for rows.Next() {
		var r BroadbandQuotaRatingRuleRecord
		var plan, quotaProfile sql.NullString
		if err := rows.Scan(&r.Name, &r.Status, &plan, &quotaProfile, &r.Unit, &r.PriceMicros,
			&r.Rounding, &r.MinimumChargeMicros, &r.TaxPercent, &r.MetadataJSON, &r.LastSeenAt); err != nil {
			return nil, fmt.Errorf("scan broadband quota rating rule: %w", err)
		}
		r.PlanName = plan.String
		r.QuotaProfile = quotaProfile.String
		out = append(out, r)
	}
	return out, rows.Err()
}

func ListBroadbandQuotaResetPolicies(limit int) ([]BroadbandQuotaResetPolicyRecord, error) {
	if DB == nil {
		return []BroadbandQuotaResetPolicyRecord{}, nil
	}
	rows, err := DB.Query(`SELECT policy_name, status, period, reset_day, reset_hour, carry_over_octets,
		carry_over_balance_micros, metadata_json, last_seen_at
		FROM broadband_quota_reset_policies ORDER BY datetime(last_seen_at) DESC, id DESC LIMIT ?`, positiveInt(limit, 100))
	if err != nil {
		if tableMissing(err) {
			return []BroadbandQuotaResetPolicyRecord{}, nil
		}
		return nil, fmt.Errorf("list broadband quota reset policies: %w", err)
	}
	defer rows.Close()
	out := []BroadbandQuotaResetPolicyRecord{}
	for rows.Next() {
		var r BroadbandQuotaResetPolicyRecord
		if err := rows.Scan(&r.Name, &r.Status, &r.Period, &r.ResetDay, &r.ResetHour,
			&r.CarryOverOctets, &r.CarryOverBalanceMicros, &r.MetadataJSON, &r.LastSeenAt); err != nil {
			return nil, fmt.Errorf("scan broadband quota reset policy: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func GetBroadbandQuotaBalanceSummary() (BroadbandQuotaBalanceSummary, error) {
	if DB == nil {
		return BroadbandQuotaBalanceSummary{}, nil
	}
	var summary BroadbandQuotaBalanceSummary
	err := DB.QueryRow(`SELECT
		COUNT(*),
		COALESCE(SUM(CASE WHEN operation = 'preview' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'applied' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'applied' THEN total_top_up_micros ELSE 0 END), 0)
		FROM broadband_quota_balance_events`).Scan(&summary.TotalEvents, &summary.PreviewEvents,
		&summary.AppliedCount, &summary.BlockedCount, &summary.TotalTopUpMicros)
	if err != nil {
		if tableMissing(err) {
			return BroadbandQuotaBalanceSummary{}, nil
		}
		return BroadbandQuotaBalanceSummary{}, fmt.Errorf("summarize broadband quota balance events: %w", err)
	}
	var lastStatus, lastFingerprint, lastAppliedAt sql.NullString
	err = DB.QueryRow(`SELECT status, plan_fingerprint, created_at FROM broadband_quota_balance_events
		WHERE status = 'applied' ORDER BY datetime(created_at) DESC, id DESC LIMIT 1`).Scan(&lastStatus, &lastFingerprint, &lastAppliedAt)
	if err != nil && err != sql.ErrNoRows {
		return BroadbandQuotaBalanceSummary{}, fmt.Errorf("summarize last broadband quota balance apply: %w", err)
	}
	summary.LastStatus = lastStatus.String
	summary.LastFingerprint = lastFingerprint.String
	summary.LastAppliedAt = lastAppliedAt.String
	_ = DB.QueryRow(`SELECT
		COALESCE(SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'exhausted' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN billing_mode IN ('prepaid', 'hybrid') THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN billing_mode IN ('postpaid', 'hybrid') THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(balance_micros), 0),
		COALESCE(SUM(credit_limit_micros), 0)
		FROM broadband_quota_wallets`).Scan(&summary.ActiveWallets, &summary.ExhaustedWallets,
		&summary.PrepaidWallets, &summary.PostpaidWallets, &summary.TotalBalanceMicros, &summary.TotalCreditLimitMicros)
	_ = DB.QueryRow(`SELECT COALESCE(SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END), 0) FROM broadband_quota_profiles`).Scan(&summary.ActiveQuotaProfiles)
	_ = DB.QueryRow(`SELECT COALESCE(SUM(CASE WHEN status = 'applied' THEN 1 ELSE 0 END), 0) FROM broadband_topup_grants`).Scan(&summary.AppliedTopUps)
	_ = DB.QueryRow(`SELECT COALESCE(SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END), 0) FROM broadband_quota_rating_rules`).Scan(&summary.ActiveRatingRules)
	_ = DB.QueryRow(`SELECT COALESCE(SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END), 0) FROM broadband_quota_reset_policies`).Scan(&summary.ActiveResetPolicies)
	return summary, nil
}

func upsertBroadbandQuotaWallets(tx *sql.Tx, eventID string, wallets []BroadbandQuotaWalletInput) error {
	for _, wallet := range wallets {
		if strings.TrimSpace(wallet.WalletID) == "" {
			return fmt.Errorf("broadband quota wallet_id is required")
		}
		status := firstNonEmptyString(strings.ToLower(strings.TrimSpace(wallet.Status)), "active")
		billingMode := firstNonEmptyString(strings.ToLower(strings.TrimSpace(wallet.BillingMode)), "prepaid")
		currency := firstNonEmptyString(strings.ToUpper(strings.TrimSpace(wallet.Currency)), "USD")
		_, err := tx.Exec(`INSERT INTO broadband_quota_wallets (
			wallet_id, account_id, subscription_id, subscriber_id, username, billing_mode, status,
			currency, balance_micros, credit_limit_micros, reserved_micros, quota_profile, period_start,
			period_end, auto_recharge, tags_json, metadata_json, source_event_id, last_seen_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT(wallet_id) DO UPDATE SET
			account_id=excluded.account_id, subscription_id=excluded.subscription_id, subscriber_id=excluded.subscriber_id,
			username=excluded.username, billing_mode=excluded.billing_mode, status=excluded.status, currency=excluded.currency,
			balance_micros=excluded.balance_micros, credit_limit_micros=excluded.credit_limit_micros, reserved_micros=excluded.reserved_micros,
			quota_profile=excluded.quota_profile, period_start=excluded.period_start, period_end=excluded.period_end,
			auto_recharge=excluded.auto_recharge, tags_json=excluded.tags_json, metadata_json=excluded.metadata_json,
			source_event_id=excluded.source_event_id, last_seen_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP`,
			wallet.WalletID, nullString(wallet.AccountID), nullString(wallet.SubscriptionID), nullString(wallet.SubscriberID),
			nullString(wallet.Username), billingMode, status, currency, wallet.BalanceMicros, wallet.CreditLimitMicros,
			wallet.ReservedMicros, nullString(wallet.QuotaProfile), nullString(wallet.PeriodStart), nullString(wallet.PeriodEnd),
			boolToInt(wallet.AutoRecharge), quotaNonEmptyJSONArray(wallet.TagsJSON), quotaNonEmptyJSON(wallet.MetadataJSON), eventID)
		if err != nil {
			return fmt.Errorf("upsert broadband quota wallet %q: %w", wallet.WalletID, err)
		}
	}
	return nil
}

func upsertBroadbandQuotaProfiles(tx *sql.Tx, eventID string, profiles []BroadbandQuotaProfileInput) error {
	for _, profile := range profiles {
		if strings.TrimSpace(profile.Name) == "" {
			return fmt.Errorf("broadband quota profile name is required")
		}
		status := firstNonEmptyString(strings.ToLower(strings.TrimSpace(profile.Status)), "active")
		period := firstNonEmptyString(strings.ToLower(strings.TrimSpace(profile.Period)), "monthly")
		_, err := tx.Exec(`INSERT INTO broadband_quota_profiles (
			profile_name, status, period, included_input_octets, included_output_octets, included_total_octets,
			overage_rate_micros_per_mb, warning_threshold_percent, hard_limit, throttle_profile, exhausted_role,
			reset_policy, vendor_packs_json, metadata_json, source_event_id, last_seen_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT(profile_name) DO UPDATE SET
			status=excluded.status, period=excluded.period, included_input_octets=excluded.included_input_octets,
			included_output_octets=excluded.included_output_octets, included_total_octets=excluded.included_total_octets,
			overage_rate_micros_per_mb=excluded.overage_rate_micros_per_mb,
			warning_threshold_percent=excluded.warning_threshold_percent, hard_limit=excluded.hard_limit,
			throttle_profile=excluded.throttle_profile, exhausted_role=excluded.exhausted_role,
			reset_policy=excluded.reset_policy, vendor_packs_json=excluded.vendor_packs_json,
			metadata_json=excluded.metadata_json, source_event_id=excluded.source_event_id,
			last_seen_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP`,
			profile.Name, status, period, profile.IncludedInputOctets, profile.IncludedOutputOctets,
			profile.IncludedTotalOctets, profile.OverageRateMicrosPerMB, nonNegativeInt(profile.WarningThresholdPercent),
			boolToInt(profile.HardLimit), nullString(profile.ThrottleProfile), nullString(profile.ExhaustedRole),
			nullString(profile.ResetPolicy), quotaNonEmptyJSONArray(profile.VendorPacksJSON), quotaNonEmptyJSON(profile.MetadataJSON), eventID)
		if err != nil {
			return fmt.Errorf("upsert broadband quota profile %q: %w", profile.Name, err)
		}
	}
	return nil
}

func upsertBroadbandTopUpGrants(tx *sql.Tx, eventID string, topUps []BroadbandTopUpGrantInput) error {
	for _, topUp := range topUps {
		if strings.TrimSpace(topUp.TopUpID) == "" || strings.TrimSpace(topUp.WalletID) == "" {
			return fmt.Errorf("broadband top-up id and wallet_id are required")
		}
		status := firstNonEmptyString(strings.ToLower(strings.TrimSpace(topUp.Status)), "pending")
		currency := firstNonEmptyString(strings.ToUpper(strings.TrimSpace(topUp.Currency)), "USD")
		_, err := tx.Exec(`INSERT INTO broadband_topup_grants (
			top_up_id, wallet_id, status, amount_micros, bonus_micros, currency, quota_octets,
			expires_at, payment_ref, idempotency_key, source, metadata_json, source_event_id, last_seen_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT(top_up_id) DO UPDATE SET
			wallet_id=excluded.wallet_id, status=excluded.status, amount_micros=excluded.amount_micros,
			bonus_micros=excluded.bonus_micros, currency=excluded.currency, quota_octets=excluded.quota_octets,
			expires_at=excluded.expires_at, payment_ref=excluded.payment_ref, idempotency_key=excluded.idempotency_key,
			source=excluded.source, metadata_json=excluded.metadata_json, source_event_id=excluded.source_event_id,
			last_seen_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP`,
			topUp.TopUpID, topUp.WalletID, status, topUp.AmountMicros, topUp.BonusMicros, currency,
			topUp.QuotaOctets, nullString(topUp.ExpiresAt), nullString(topUp.PaymentRef), nullString(topUp.IdempotencyKey),
			nullString(topUp.Source), quotaNonEmptyJSON(topUp.MetadataJSON), eventID)
		if err != nil {
			return fmt.Errorf("upsert broadband top-up %q: %w", topUp.TopUpID, err)
		}
	}
	return nil
}

func upsertBroadbandQuotaRatingRules(tx *sql.Tx, eventID string, rules []BroadbandQuotaRatingRuleInput) error {
	for _, rule := range rules {
		if strings.TrimSpace(rule.Name) == "" {
			return fmt.Errorf("broadband quota rating rule name is required")
		}
		status := firstNonEmptyString(strings.ToLower(strings.TrimSpace(rule.Status)), "active")
		unit := firstNonEmptyString(strings.ToLower(strings.TrimSpace(rule.Unit)), "total-octets")
		rounding := firstNonEmptyString(strings.ToLower(strings.TrimSpace(rule.Rounding)), "none")
		_, err := tx.Exec(`INSERT INTO broadband_quota_rating_rules (
			rule_name, status, plan_name, quota_profile, unit, price_micros, rounding,
			minimum_charge_micros, tax_percent, metadata_json, source_event_id, last_seen_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT(rule_name) DO UPDATE SET
			status=excluded.status, plan_name=excluded.plan_name, quota_profile=excluded.quota_profile,
			unit=excluded.unit, price_micros=excluded.price_micros, rounding=excluded.rounding,
			minimum_charge_micros=excluded.minimum_charge_micros, tax_percent=excluded.tax_percent,
			metadata_json=excluded.metadata_json, source_event_id=excluded.source_event_id,
			last_seen_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP`,
			rule.Name, status, nullString(rule.PlanName), nullString(rule.QuotaProfile), unit,
			rule.PriceMicros, rounding, rule.MinimumChargeMicros, nonNegativeInt(rule.TaxPercent),
			quotaNonEmptyJSON(rule.MetadataJSON), eventID)
		if err != nil {
			return fmt.Errorf("upsert broadband quota rating rule %q: %w", rule.Name, err)
		}
	}
	return nil
}

func upsertBroadbandQuotaResetPolicies(tx *sql.Tx, eventID string, policies []BroadbandQuotaResetPolicyInput) error {
	for _, policy := range policies {
		if strings.TrimSpace(policy.Name) == "" {
			return fmt.Errorf("broadband quota reset policy name is required")
		}
		status := firstNonEmptyString(strings.ToLower(strings.TrimSpace(policy.Status)), "active")
		period := firstNonEmptyString(strings.ToLower(strings.TrimSpace(policy.Period)), "monthly")
		_, err := tx.Exec(`INSERT INTO broadband_quota_reset_policies (
			policy_name, status, period, reset_day, reset_hour, carry_over_octets, carry_over_balance_micros,
			metadata_json, source_event_id, last_seen_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT(policy_name) DO UPDATE SET
			status=excluded.status, period=excluded.period, reset_day=excluded.reset_day, reset_hour=excluded.reset_hour,
			carry_over_octets=excluded.carry_over_octets, carry_over_balance_micros=excluded.carry_over_balance_micros,
			metadata_json=excluded.metadata_json, source_event_id=excluded.source_event_id,
			last_seen_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP`,
			policy.Name, status, period, nonNegativeInt(policy.ResetDay), nonNegativeInt(policy.ResetHour),
			policy.CarryOverOctets, policy.CarryOverBalanceMicros, quotaNonEmptyJSON(policy.MetadataJSON), eventID)
		if err != nil {
			return fmt.Errorf("upsert broadband quota reset policy %q: %w", policy.Name, err)
		}
	}
	return nil
}

func scanBroadbandQuotaBalanceEvent(scanner interface{ Scan(dest ...any) error }) (BroadbandQuotaBalanceEvent, error) {
	var event BroadbandQuotaBalanceEvent
	var mode, actor sql.NullString
	if err := scanner.Scan(&event.EventID, &event.Operation, &event.Status, &event.PlanFingerprint,
		&mode, &event.WalletCount, &event.QuotaProfileCount, &event.TopUpCount, &event.RatingRuleCount,
		&event.ResetPolicyCount, &event.ActiveWalletCount, &event.PrepaidWalletCount, &event.PostpaidWalletCount,
		&event.ExhaustedWalletCount, &event.TotalBalanceMicros, &event.TotalCreditLimitMicros,
		&event.TotalTopUpMicros, &event.ComplianceCheckCount, &event.PassedCheckCount, &event.WarningCount,
		&event.BlockerCount, &event.ExternalRequirementCount, &event.SummaryJSON, &event.ReportJSON,
		&actor, &event.CreatedAt); err != nil {
		return BroadbandQuotaBalanceEvent{}, fmt.Errorf("scan broadband quota balance event: %w", err)
	}
	event.Mode = mode.String
	event.Actor = actor.String
	return event, nil
}

func broadbandQuotaBalanceEventSelectSQL() string {
	return `SELECT event_id, operation, status, plan_fingerprint, mode, wallet_count,
		quota_profile_count, top_up_count, rating_rule_count, reset_policy_count,
		active_wallet_count, prepaid_wallet_count, postpaid_wallet_count, exhausted_wallet_count,
		total_balance_micros, total_credit_limit_micros, total_top_up_micros,
		compliance_check_count, passed_check_count, warning_count, blocker_count,
		external_requirement_count, summary_json, report_json, actor, created_at
		FROM broadband_quota_balance_events`
}

func normalizeBroadbandQuotaBalanceOperation(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "preview", "apply", "status", "reconcile":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "status"
	}
}

func normalizeBroadbandQuotaBalanceEventStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "previewed", "applied", "blocked", "degraded", "skipped", "failed", "reconciled":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "failed"
	}
}

func newBroadbandQuotaBalanceEventID(input BroadbandQuotaBalanceEventInput) string {
	random := make([]byte, 8)
	if _, err := rand.Read(random); err == nil {
		return "bqb_" + hex.EncodeToString(random)
	}
	return "bqb_" + sha256Text(strings.Join([]string{input.Operation, input.Status, input.PlanFingerprint, input.Mode, input.Actor}, "|"))[:16]
}

func quotaNonEmptyJSON(value string) string {
	if strings.TrimSpace(value) == "" {
		return "{}"
	}
	return value
}

func quotaNonEmptyJSONArray(value string) string {
	if strings.TrimSpace(value) == "" {
		return "[]"
	}
	return value
}
