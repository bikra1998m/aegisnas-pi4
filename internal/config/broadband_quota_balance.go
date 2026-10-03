package config

import (
	"errors"
	"fmt"
	"strings"
	"time"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
)

type BroadbandQuotaBalanceConfig struct {
	Enabled                       bool                              `mapstructure:"enabled"`
	Mode                          string                            `mapstructure:"mode"`
	FailClosed                    bool                              `mapstructure:"fail_closed"`
	DefaultCurrency               string                            `mapstructure:"default_currency"`
	DefaultQuotaPeriod            string                            `mapstructure:"default_quota_period"`
	RequireCommercialCatalog      bool                              `mapstructure:"require_commercial_catalog"`
	RequireActiveWallet           bool                              `mapstructure:"require_active_wallet"`
	RequireQuotaProfile           bool                              `mapstructure:"require_quota_profile"`
	RatingEnabled                 bool                              `mapstructure:"rating_enabled"`
	TopUpEnabled                  bool                              `mapstructure:"top_up_enabled"`
	PrepaidEnabled                bool                              `mapstructure:"prepaid_enabled"`
	PostpaidEnabled               bool                              `mapstructure:"postpaid_enabled"`
	AccountingCorrelationRequired bool                              `mapstructure:"accounting_correlation_required"`
	AutoSuspendOnExhaustion       bool                              `mapstructure:"auto_suspend_on_exhaustion"`
	CoAOnExhaustion               bool                              `mapstructure:"coa_on_exhaustion"`
	AllowNegativeBalance          bool                              `mapstructure:"allow_negative_balance"`
	BalanceFloorMicros            int64                             `mapstructure:"balance_floor_micros"`
	EventRetentionLimit           int                               `mapstructure:"event_retention_limit"`
	Wallets                       []BroadbandQuotaWalletConfig      `mapstructure:"wallets"`
	QuotaProfiles                 []BroadbandQuotaProfileConfig     `mapstructure:"quota_profiles"`
	TopUps                        []BroadbandTopUpGrantConfig       `mapstructure:"top_ups"`
	RatingRules                   []BroadbandQuotaRatingRuleConfig  `mapstructure:"rating_rules"`
	ResetPolicies                 []BroadbandQuotaResetPolicyConfig `mapstructure:"reset_policies"`
}

type BroadbandQuotaWalletConfig struct {
	WalletID          string   `mapstructure:"wallet_id"`
	AccountID         string   `mapstructure:"account_id"`
	SubscriptionID    string   `mapstructure:"subscription_id"`
	SubscriberID      string   `mapstructure:"subscriber_id"`
	Username          string   `mapstructure:"username"`
	BillingMode       string   `mapstructure:"billing_mode"`
	Status            string   `mapstructure:"status"`
	Currency          string   `mapstructure:"currency"`
	BalanceMicros     int64    `mapstructure:"balance_micros"`
	CreditLimitMicros int64    `mapstructure:"credit_limit_micros"`
	ReservedMicros    int64    `mapstructure:"reserved_micros"`
	QuotaProfile      string   `mapstructure:"quota_profile"`
	PeriodStart       string   `mapstructure:"period_start"`
	PeriodEnd         string   `mapstructure:"period_end"`
	AutoRecharge      bool     `mapstructure:"auto_recharge"`
	Tags              []string `mapstructure:"tags"`
}

type BroadbandQuotaProfileConfig struct {
	Name                    string   `mapstructure:"name"`
	Enabled                 bool     `mapstructure:"enabled"`
	Period                  string   `mapstructure:"period"`
	IncludedInputOctets     int64    `mapstructure:"included_input_octets"`
	IncludedOutputOctets    int64    `mapstructure:"included_output_octets"`
	IncludedTotalOctets     int64    `mapstructure:"included_total_octets"`
	OverageRateMicrosPerMB  int64    `mapstructure:"overage_rate_micros_per_mb"`
	WarningThresholdPercent int      `mapstructure:"warning_threshold_percent"`
	HardLimit               bool     `mapstructure:"hard_limit"`
	ThrottleProfile         string   `mapstructure:"throttle_profile"`
	ExhaustedRole           string   `mapstructure:"exhausted_role"`
	ResetPolicy             string   `mapstructure:"reset_policy"`
	VendorPacks             []string `mapstructure:"vendor_packs"`
}

type BroadbandTopUpGrantConfig struct {
	TopUpID        string `mapstructure:"top_up_id"`
	WalletID       string `mapstructure:"wallet_id"`
	AmountMicros   int64  `mapstructure:"amount_micros"`
	BonusMicros    int64  `mapstructure:"bonus_micros"`
	Currency       string `mapstructure:"currency"`
	QuotaOctets    int64  `mapstructure:"quota_octets"`
	Status         string `mapstructure:"status"`
	ExpiresAt      string `mapstructure:"expires_at"`
	PaymentRef     string `mapstructure:"payment_ref"`
	IdempotencyKey string `mapstructure:"idempotency_key"`
	Source         string `mapstructure:"source"`
}

type BroadbandQuotaRatingRuleConfig struct {
	Name                string `mapstructure:"name"`
	Enabled             bool   `mapstructure:"enabled"`
	Plan                string `mapstructure:"plan"`
	QuotaProfile        string `mapstructure:"quota_profile"`
	Unit                string `mapstructure:"unit"`
	PriceMicros         int64  `mapstructure:"price_micros"`
	Rounding            string `mapstructure:"rounding"`
	MinimumChargeMicros int64  `mapstructure:"minimum_charge_micros"`
	TaxPercent          int    `mapstructure:"tax_percent"`
}

type BroadbandQuotaResetPolicyConfig struct {
	Name                   string `mapstructure:"name"`
	Enabled                bool   `mapstructure:"enabled"`
	Period                 string `mapstructure:"period"`
	ResetDay               int    `mapstructure:"reset_day"`
	ResetHour              int    `mapstructure:"reset_hour"`
	CarryOverOctets        int64  `mapstructure:"carry_over_octets"`
	CarryOverBalanceMicros int64  `mapstructure:"carry_over_balance_micros"`
}

func EffectiveBroadbandQuotaBalanceConfig(raw BroadbandQuotaBalanceConfig) BroadbandQuotaBalanceConfig {
	quota := raw
	quota.Mode = EffectiveBroadbandQuotaBalanceMode(quota.Mode)
	if strings.TrimSpace(quota.DefaultCurrency) == "" {
		quota.DefaultCurrency = "USD"
	}
	if strings.TrimSpace(quota.DefaultQuotaPeriod) == "" {
		quota.DefaultQuotaPeriod = "monthly"
	}
	if quota.EventRetentionLimit == 0 {
		quota.EventRetentionLimit = 10000
	}
	if !raw.RequireCommercialCatalog && !raw.RequireActiveWallet && !raw.RequireQuotaProfile &&
		!raw.RatingEnabled && !raw.TopUpEnabled && !raw.PrepaidEnabled && !raw.PostpaidEnabled &&
		!raw.AccountingCorrelationRequired && !raw.AutoSuspendOnExhaustion && !raw.CoAOnExhaustion {
		quota.RequireCommercialCatalog = true
		quota.RequireActiveWallet = true
		quota.RequireQuotaProfile = true
		quota.RatingEnabled = true
		quota.TopUpEnabled = true
		quota.PrepaidEnabled = true
		quota.PostpaidEnabled = true
		quota.AccountingCorrelationRequired = true
		quota.AutoSuspendOnExhaustion = true
		quota.CoAOnExhaustion = true
	}
	return quota
}

func EffectiveBroadbandQuotaBalanceMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "monitor", "enforce":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "monitor"
	}
}

func validateBroadbandQuotaBalanceConfig(raw BroadbandQuotaBalanceConfig, catalogRaw BroadbandCommercialCatalog, subscriberRaw BroadbandSubscriberStateConfig, radius RadiusConfig, profile string) error {
	quota := EffectiveBroadbandQuotaBalanceConfig(raw)
	if !quota.Enabled && len(quota.Wallets) == 0 && len(quota.QuotaProfiles) == 0 &&
		len(quota.TopUps) == 0 && len(quota.RatingRules) == 0 && len(quota.ResetPolicies) == 0 {
		return nil
	}
	switch quota.Mode {
	case "monitor", "enforce":
	default:
		return fmt.Errorf("broadband.quota_balance.mode %q is invalid", raw.Mode)
	}
	if profile == "lite" && quota.Mode == "enforce" {
		return errors.New("broadband.quota_balance cannot use enforce mode on lite deployment profile")
	}
	if !validBroadbandCommercialCurrency(quota.DefaultCurrency) {
		return fmt.Errorf("broadband.quota_balance.default_currency %q is invalid", quota.DefaultCurrency)
	}
	if !validBroadbandCommercialBillingPeriod(quota.DefaultQuotaPeriod) {
		return fmt.Errorf("broadband.quota_balance.default_quota_period %q is invalid", quota.DefaultQuotaPeriod)
	}
	if quota.EventRetentionLimit < 0 || quota.EventRetentionLimit > 1000000 {
		return errors.New("broadband.quota_balance.event_retention_limit must be between 0 and 1000000")
	}
	if !quota.AllowNegativeBalance && quota.BalanceFloorMicros < 0 {
		return errors.New("broadband.quota_balance.balance_floor_micros cannot be negative unless allow_negative_balance is enabled")
	}
	if quota.BalanceFloorMicros < -1000000000000000 || quota.BalanceFloorMicros > 1000000000000000 {
		return errors.New("broadband.quota_balance.balance_floor_micros is outside the supported range")
	}
	catalog := EffectiveBroadbandCommercialCatalog(catalogRaw)
	subscriber := EffectiveBroadbandSubscriberStateConfig(subscriberRaw)
	if quota.Enabled && !subscriber.Enabled {
		return errors.New("broadband.quota_balance requires broadband.subscriber_state.enabled")
	}
	if quota.Enabled && quota.RequireCommercialCatalog && !catalog.Enabled {
		return errors.New("broadband.quota_balance require_commercial_catalog requires broadband.commercial_catalog.enabled")
	}
	if quota.Enabled && quota.AccountingCorrelationRequired && !radius.SQLAccounting.Enabled {
		return errors.New("broadband.quota_balance accounting correlation requires radius.sql_accounting.enabled")
	}
	if quota.Enabled && quota.AccountingCorrelationRequired && !radius.AccountingServices.Enabled {
		return errors.New("broadband.quota_balance accounting correlation requires radius.accounting_services.enabled")
	}
	charging := EffectiveRadiusAccountingChargingConfig(radius.AccountingCharging)
	if quota.Enabled && quota.RatingEnabled && (!charging.Enabled || !charging.RatingEnabled) {
		return errors.New("broadband.quota_balance rating_enabled requires radius.accounting_charging.enabled and radius.accounting_charging.rating_enabled")
	}
	if quota.Enabled && quota.CoAOnExhaustion && !radius.DynamicAuth.Enabled {
		return errors.New("broadband.quota_balance coa_on_exhaustion requires radius.dynamic_auth.enabled")
	}
	resetPolicies, err := validateBroadbandQuotaResetPolicies(quota)
	if err != nil {
		return err
	}
	quotaProfiles, enabledProfiles, err := validateBroadbandQuotaProfiles(quota, resetPolicies)
	if err != nil {
		return err
	}
	accountIDs, subscriptionIDs, planNames := broadbandCommercialCatalogReferenceMaps(catalog)
	wallets, activeWallets, prepaidWallets, postpaidWallets, err := validateBroadbandQuotaWallets(quota, accountIDs, subscriptionIDs, quotaProfiles)
	if err != nil {
		return err
	}
	if err := validateBroadbandTopUpGrants(quota, wallets); err != nil {
		return err
	}
	enabledRatingRules, err := validateBroadbandQuotaRatingRules(quota, planNames, quotaProfiles)
	if err != nil {
		return err
	}
	if quota.Enabled && quota.Mode == "enforce" {
		if quota.RequireActiveWallet && activeWallets == 0 {
			return errors.New("broadband.quota_balance enforce mode requires at least one active wallet")
		}
		if quota.RequireQuotaProfile && enabledProfiles == 0 {
			return errors.New("broadband.quota_balance enforce mode requires at least one enabled quota profile")
		}
		if quota.RatingEnabled && enabledRatingRules == 0 {
			return errors.New("broadband.quota_balance rating_enabled requires at least one enabled rating rule")
		}
		if prepaidWallets == 0 && postpaidWallets == 0 {
			return errors.New("broadband.quota_balance enforce mode requires at least one prepaid or postpaid wallet")
		}
	}
	return nil
}

func validateBroadbandQuotaResetPolicies(quota BroadbandQuotaBalanceConfig) (map[string]struct{}, error) {
	policies := map[string]struct{}{}
	for i, policy := range quota.ResetPolicies {
		name := strings.TrimSpace(policy.Name)
		if !validBroadbandPPPoEText(name, 128) {
			return nil, fmt.Errorf("broadband.quota_balance.reset_policies[%d].name is invalid", i)
		}
		key := strings.ToLower(name)
		if _, exists := policies[key]; exists {
			return nil, fmt.Errorf("broadband.quota_balance.reset_policies[%d].name %q duplicates an earlier reset policy", i, name)
		}
		policies[key] = struct{}{}
		if strings.TrimSpace(policy.Period) != "" && !validBroadbandCommercialBillingPeriod(policy.Period) {
			return nil, fmt.Errorf("broadband.quota_balance.reset_policies[%d].period %q is invalid", i, policy.Period)
		}
		if policy.ResetDay < 0 || policy.ResetDay > 31 {
			return nil, fmt.Errorf("broadband.quota_balance.reset_policies[%d].reset_day must be between 0 and 31", i)
		}
		if policy.ResetHour < 0 || policy.ResetHour > 23 {
			return nil, fmt.Errorf("broadband.quota_balance.reset_policies[%d].reset_hour must be between 0 and 23", i)
		}
		if policy.CarryOverOctets < 0 || policy.CarryOverBalanceMicros < 0 {
			return nil, fmt.Errorf("broadband.quota_balance.reset_policies[%d] carry-over values cannot be negative", i)
		}
	}
	return policies, nil
}

func validateBroadbandQuotaProfiles(quota BroadbandQuotaBalanceConfig, resetPolicies map[string]struct{}) (map[string]struct{}, int, error) {
	profiles := map[string]struct{}{}
	enabled := 0
	for i, profile := range quota.QuotaProfiles {
		name := strings.TrimSpace(profile.Name)
		if !validBroadbandPPPoEText(name, 128) {
			return nil, 0, fmt.Errorf("broadband.quota_balance.quota_profiles[%d].name is invalid", i)
		}
		key := strings.ToLower(name)
		if _, exists := profiles[key]; exists {
			return nil, 0, fmt.Errorf("broadband.quota_balance.quota_profiles[%d].name %q duplicates an earlier quota profile", i, name)
		}
		profiles[key] = struct{}{}
		if profile.Enabled {
			enabled++
		}
		if strings.TrimSpace(profile.Period) != "" && !validBroadbandCommercialBillingPeriod(profile.Period) {
			return nil, 0, fmt.Errorf("broadband.quota_balance.quota_profiles[%d].period %q is invalid", i, profile.Period)
		}
		for field, value := range map[string]int64{
			"included_input_octets":      profile.IncludedInputOctets,
			"included_output_octets":     profile.IncludedOutputOctets,
			"included_total_octets":      profile.IncludedTotalOctets,
			"overage_rate_micros_per_mb": profile.OverageRateMicrosPerMB,
		} {
			if value < 0 {
				return nil, 0, fmt.Errorf("broadband.quota_balance.quota_profiles[%d].%s cannot be negative", i, field)
			}
		}
		if profile.WarningThresholdPercent < 0 || profile.WarningThresholdPercent > 100 {
			return nil, 0, fmt.Errorf("broadband.quota_balance.quota_profiles[%d].warning_threshold_percent must be between 0 and 100", i)
		}
		if profile.HardLimit && profile.IncludedInputOctets == 0 && profile.IncludedOutputOctets == 0 && profile.IncludedTotalOctets == 0 {
			return nil, 0, fmt.Errorf("broadband.quota_balance.quota_profiles[%d] hard_limit requires a positive quota", i)
		}
		for _, binding := range []struct {
			field string
			value string
			limit int
		}{
			{"throttle_profile", profile.ThrottleProfile, 128},
			{"exhausted_role", profile.ExhaustedRole, 253},
		} {
			if strings.TrimSpace(binding.value) != "" && !validBroadbandPPPoEText(binding.value, binding.limit) {
				return nil, 0, fmt.Errorf("broadband.quota_balance.quota_profiles[%d].%s is invalid", i, binding.field)
			}
		}
		if reset := strings.TrimSpace(profile.ResetPolicy); reset != "" {
			if _, ok := resetPolicies[strings.ToLower(reset)]; !ok {
				return nil, 0, fmt.Errorf("broadband.quota_balance.quota_profiles[%d].reset_policy %q is not configured", i, reset)
			}
		}
		for packIndex, pack := range profile.VendorPacks {
			key := productconfigs.NormalizeVendorCompatibilityPackKey(pack)
			if key == "" || !productconfigs.ValidVendorCompatibilityPackKey(key) {
				return nil, 0, fmt.Errorf("broadband.quota_balance.quota_profiles[%d].vendor_packs[%d] %q is unknown", i, packIndex, pack)
			}
		}
	}
	return profiles, enabled, nil
}

func validateBroadbandQuotaWallets(quota BroadbandQuotaBalanceConfig, accounts, subscriptions, profiles map[string]struct{}) (map[string]struct{}, int, int, int, error) {
	wallets := map[string]struct{}{}
	activeWallets := 0
	prepaidWallets := 0
	postpaidWallets := 0
	for i, wallet := range quota.Wallets {
		walletID := strings.TrimSpace(wallet.WalletID)
		if !validBroadbandPPPoEText(walletID, 128) {
			return nil, 0, 0, 0, fmt.Errorf("broadband.quota_balance.wallets[%d].wallet_id is invalid", i)
		}
		key := strings.ToLower(walletID)
		if _, exists := wallets[key]; exists {
			return nil, 0, 0, 0, fmt.Errorf("broadband.quota_balance.wallets[%d].wallet_id %q duplicates an earlier wallet", i, walletID)
		}
		wallets[key] = struct{}{}
		if strings.TrimSpace(wallet.SubscriberID) == "" && strings.TrimSpace(wallet.Username) == "" {
			return nil, 0, 0, 0, fmt.Errorf("broadband.quota_balance.wallets[%d] requires subscriber_id or username", i)
		}
		mode := strings.ToLower(strings.TrimSpace(wallet.BillingMode))
		switch mode {
		case "", "prepaid", "postpaid", "hybrid", "external":
		default:
			return nil, 0, 0, 0, fmt.Errorf("broadband.quota_balance.wallets[%d].billing_mode %q is invalid", i, wallet.BillingMode)
		}
		if mode == "" {
			mode = "prepaid"
		}
		if mode == "prepaid" && !quota.PrepaidEnabled {
			return nil, 0, 0, 0, fmt.Errorf("broadband.quota_balance.wallets[%d].billing_mode prepaid requires prepaid_enabled", i)
		}
		if mode == "postpaid" && !quota.PostpaidEnabled {
			return nil, 0, 0, 0, fmt.Errorf("broadband.quota_balance.wallets[%d].billing_mode postpaid requires postpaid_enabled", i)
		}
		if mode == "prepaid" || mode == "hybrid" {
			prepaidWallets++
		}
		if mode == "postpaid" || mode == "hybrid" {
			postpaidWallets++
		}
		status := strings.ToLower(strings.TrimSpace(wallet.Status))
		switch status {
		case "", "active", "suspended", "exhausted", "closed", "pending":
		default:
			return nil, 0, 0, 0, fmt.Errorf("broadband.quota_balance.wallets[%d].status %q is invalid", i, wallet.Status)
		}
		if status == "" || status == "active" {
			activeWallets++
		}
		if strings.TrimSpace(wallet.Currency) != "" && !validBroadbandCommercialCurrency(wallet.Currency) {
			return nil, 0, 0, 0, fmt.Errorf("broadband.quota_balance.wallets[%d].currency %q is invalid", i, wallet.Currency)
		}
		if wallet.ReservedMicros < 0 || wallet.CreditLimitMicros < 0 {
			return nil, 0, 0, 0, fmt.Errorf("broadband.quota_balance.wallets[%d] reserved_micros and credit_limit_micros cannot be negative", i)
		}
		if !quota.AllowNegativeBalance && wallet.BalanceMicros < quota.BalanceFloorMicros {
			return nil, 0, 0, 0, fmt.Errorf("broadband.quota_balance.wallets[%d].balance_micros is below balance_floor_micros", i)
		}
		if profile := strings.TrimSpace(wallet.QuotaProfile); profile != "" {
			if _, ok := profiles[strings.ToLower(profile)]; !ok {
				return nil, 0, 0, 0, fmt.Errorf("broadband.quota_balance.wallets[%d].quota_profile %q is not configured", i, profile)
			}
		} else if quota.RequireQuotaProfile {
			return nil, 0, 0, 0, fmt.Errorf("broadband.quota_balance.wallets[%d].quota_profile is required", i)
		}
		for _, ref := range []struct {
			field string
			value string
			table map[string]struct{}
		}{
			{"account_id", wallet.AccountID, accounts},
			{"subscription_id", wallet.SubscriptionID, subscriptions},
		} {
			value := strings.TrimSpace(ref.value)
			if value == "" {
				continue
			}
			if !validBroadbandPPPoEText(value, 128) {
				return nil, 0, 0, 0, fmt.Errorf("broadband.quota_balance.wallets[%d].%s is invalid", i, ref.field)
			}
			if quota.RequireCommercialCatalog {
				if _, ok := ref.table[strings.ToLower(value)]; !ok {
					return nil, 0, 0, 0, fmt.Errorf("broadband.quota_balance.wallets[%d].%s %q is not configured in commercial catalog", i, ref.field, value)
				}
			}
		}
		for _, binding := range []struct {
			field string
			value string
			limit int
		}{
			{"subscriber_id", wallet.SubscriberID, 253},
			{"username", wallet.Username, 253},
		} {
			if strings.TrimSpace(binding.value) != "" && !validBroadbandPPPoEText(binding.value, binding.limit) {
				return nil, 0, 0, 0, fmt.Errorf("broadband.quota_balance.wallets[%d].%s is invalid", i, binding.field)
			}
		}
		for _, binding := range []struct {
			field string
			value string
		}{
			{"period_start", wallet.PeriodStart},
			{"period_end", wallet.PeriodEnd},
		} {
			if strings.TrimSpace(binding.value) != "" {
				if _, err := time.Parse(time.RFC3339, strings.TrimSpace(binding.value)); err != nil {
					return nil, 0, 0, 0, fmt.Errorf("broadband.quota_balance.wallets[%d].%s must be RFC3339: %w", i, binding.field, err)
				}
			}
		}
		for tagIndex, tag := range wallet.Tags {
			if strings.TrimSpace(tag) != "" && !validBroadbandPPPoEText(tag, 64) {
				return nil, 0, 0, 0, fmt.Errorf("broadband.quota_balance.wallets[%d].tags[%d] is invalid", i, tagIndex)
			}
		}
	}
	return wallets, activeWallets, prepaidWallets, postpaidWallets, nil
}

func validateBroadbandTopUpGrants(quota BroadbandQuotaBalanceConfig, wallets map[string]struct{}) error {
	seen := map[string]struct{}{}
	for i, topUp := range quota.TopUps {
		if !quota.TopUpEnabled {
			return fmt.Errorf("broadband.quota_balance.top_ups[%d] requires top_up_enabled", i)
		}
		topUpID := strings.TrimSpace(topUp.TopUpID)
		if !validBroadbandPPPoEText(topUpID, 128) {
			return fmt.Errorf("broadband.quota_balance.top_ups[%d].top_up_id is invalid", i)
		}
		key := strings.ToLower(topUpID)
		if _, exists := seen[key]; exists {
			return fmt.Errorf("broadband.quota_balance.top_ups[%d].top_up_id %q duplicates an earlier top-up", i, topUpID)
		}
		seen[key] = struct{}{}
		walletID := strings.TrimSpace(topUp.WalletID)
		if walletID == "" {
			return fmt.Errorf("broadband.quota_balance.top_ups[%d].wallet_id is required", i)
		}
		if _, ok := wallets[strings.ToLower(walletID)]; !ok {
			return fmt.Errorf("broadband.quota_balance.top_ups[%d].wallet_id %q is not configured", i, walletID)
		}
		if topUp.AmountMicros < 0 || topUp.BonusMicros < 0 || topUp.QuotaOctets < 0 {
			return fmt.Errorf("broadband.quota_balance.top_ups[%d] amount, bonus, and quota cannot be negative", i)
		}
		if topUp.AmountMicros == 0 && topUp.BonusMicros == 0 && topUp.QuotaOctets == 0 {
			return fmt.Errorf("broadband.quota_balance.top_ups[%d] requires positive amount, bonus, or quota", i)
		}
		if strings.TrimSpace(topUp.Currency) != "" && !validBroadbandCommercialCurrency(topUp.Currency) {
			return fmt.Errorf("broadband.quota_balance.top_ups[%d].currency %q is invalid", i, topUp.Currency)
		}
		switch strings.ToLower(strings.TrimSpace(topUp.Status)) {
		case "", "pending", "applied", "reversed", "expired":
		default:
			return fmt.Errorf("broadband.quota_balance.top_ups[%d].status %q is invalid", i, topUp.Status)
		}
		if strings.TrimSpace(topUp.ExpiresAt) != "" {
			if _, err := time.Parse(time.RFC3339, strings.TrimSpace(topUp.ExpiresAt)); err != nil {
				return fmt.Errorf("broadband.quota_balance.top_ups[%d].expires_at must be RFC3339: %w", i, err)
			}
		}
		for _, binding := range []struct {
			field string
			value string
			limit int
		}{
			{"payment_ref", topUp.PaymentRef, 256},
			{"idempotency_key", topUp.IdempotencyKey, 256},
			{"source", topUp.Source, 128},
		} {
			if strings.TrimSpace(binding.value) != "" && !validBroadbandPPPoEText(binding.value, binding.limit) {
				return fmt.Errorf("broadband.quota_balance.top_ups[%d].%s is invalid", i, binding.field)
			}
		}
	}
	return nil
}

func validateBroadbandQuotaRatingRules(quota BroadbandQuotaBalanceConfig, plans, profiles map[string]struct{}) (int, error) {
	seen := map[string]struct{}{}
	enabled := 0
	for i, rule := range quota.RatingRules {
		if !quota.RatingEnabled {
			return 0, fmt.Errorf("broadband.quota_balance.rating_rules[%d] requires rating_enabled", i)
		}
		name := strings.TrimSpace(rule.Name)
		if !validBroadbandPPPoEText(name, 128) {
			return 0, fmt.Errorf("broadband.quota_balance.rating_rules[%d].name is invalid", i)
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			return 0, fmt.Errorf("broadband.quota_balance.rating_rules[%d].name %q duplicates an earlier rating rule", i, name)
		}
		seen[key] = struct{}{}
		if rule.Enabled {
			enabled++
		}
		if plan := strings.TrimSpace(rule.Plan); plan != "" {
			if _, ok := plans[strings.ToLower(plan)]; !ok && quota.RequireCommercialCatalog {
				return 0, fmt.Errorf("broadband.quota_balance.rating_rules[%d].plan %q is not configured in commercial catalog", i, plan)
			}
		}
		if profile := strings.TrimSpace(rule.QuotaProfile); profile != "" {
			if _, ok := profiles[strings.ToLower(profile)]; !ok {
				return 0, fmt.Errorf("broadband.quota_balance.rating_rules[%d].quota_profile %q is not configured", i, profile)
			}
		}
		switch strings.ToLower(strings.TrimSpace(rule.Unit)) {
		case "", "input-octets", "output-octets", "total-octets", "session", "period", "packet":
		default:
			return 0, fmt.Errorf("broadband.quota_balance.rating_rules[%d].unit %q is invalid", i, rule.Unit)
		}
		switch strings.ToLower(strings.TrimSpace(rule.Rounding)) {
		case "", "none", "up", "down", "nearest":
		default:
			return 0, fmt.Errorf("broadband.quota_balance.rating_rules[%d].rounding %q is invalid", i, rule.Rounding)
		}
		if rule.PriceMicros < 0 || rule.MinimumChargeMicros < 0 {
			return 0, fmt.Errorf("broadband.quota_balance.rating_rules[%d] price and minimum charge cannot be negative", i)
		}
		if rule.TaxPercent < 0 || rule.TaxPercent > 100 {
			return 0, fmt.Errorf("broadband.quota_balance.rating_rules[%d].tax_percent must be between 0 and 100", i)
		}
	}
	return enabled, nil
}

func broadbandCommercialCatalogReferenceMaps(catalog BroadbandCommercialCatalog) (map[string]struct{}, map[string]struct{}, map[string]struct{}) {
	accounts := map[string]struct{}{}
	subscriptions := map[string]struct{}{}
	plans := map[string]struct{}{}
	for _, account := range catalog.Accounts {
		if value := strings.TrimSpace(account.AccountID); value != "" {
			accounts[strings.ToLower(value)] = struct{}{}
		}
	}
	for _, subscription := range catalog.Subscriptions {
		if value := strings.TrimSpace(subscription.SubscriptionID); value != "" {
			subscriptions[strings.ToLower(value)] = struct{}{}
		}
	}
	for _, plan := range catalog.Plans {
		if value := strings.TrimSpace(plan.Name); value != "" {
			plans[strings.ToLower(value)] = struct{}{}
		}
	}
	return accounts, subscriptions, plans
}
