package config

import (
	"errors"
	"fmt"
	"strings"
)

type MobileChargingConfig struct {
	Enabled                     bool                         `mapstructure:"enabled"`
	Mode                        string                       `mapstructure:"mode"`
	FailClosed                  bool                         `mapstructure:"fail_closed"`
	RequireDatabase             bool                         `mapstructure:"require_database"`
	RequireMobileSessions       bool                         `mapstructure:"require_mobile_sessions"`
	RequireAccountingCharging   bool                         `mapstructure:"require_accounting_charging"`
	RequireOnlineCharging       bool                         `mapstructure:"require_online_charging"`
	RequireOfflineCharging      bool                         `mapstructure:"require_offline_charging"`
	RequireMediation            bool                         `mapstructure:"require_mediation"`
	QuotaCorrelation            bool                         `mapstructure:"quota_correlation"`
	RedactSubscriberIDs         bool                         `mapstructure:"redact_subscriber_ids"`
	HashSubscriberIDs           bool                         `mapstructure:"hash_subscriber_ids"`
	CorrelationWindowSeconds    int                          `mapstructure:"correlation_window_seconds"`
	MaxCorrelations             int                          `mapstructure:"max_correlations"`
	EventRetentionLimit         int                          `mapstructure:"event_retention_limit"`
	CDRRetentionDays            int                          `mapstructure:"cdr_retention_days"`
	DefaultCurrency             string                       `mapstructure:"default_currency"`
	DefaultOnlineStream         string                       `mapstructure:"default_online_stream"`
	DefaultOfflineStream        string                       `mapstructure:"default_offline_stream"`
	Streams                     []MobileChargingStreamConfig `mapstructure:"streams"`
	RatingGroups                []MobileRatingGroupConfig    `mapstructure:"rating_groups"`
	QuotaPolicies               []MobileQuotaPolicyConfig    `mapstructure:"quota_policies"`
	CorrelationAttributes       []string                     `mapstructure:"correlation_attributes"`
	ExternalMediationReferences []string                     `mapstructure:"external_mediation_references"`
}

type MobileChargingStreamConfig struct {
	Name             string   `mapstructure:"name"`
	Enabled          bool     `mapstructure:"enabled"`
	StreamType       string   `mapstructure:"stream_type"`
	Protocol         string   `mapstructure:"protocol"`
	EndpointRef      string   `mapstructure:"endpoint_ref"`
	ExportFormat     string   `mapstructure:"export_format"`
	RetryPolicy      string   `mapstructure:"retry_policy"`
	Attributes       []string `mapstructure:"attributes"`
	RedactAttributes []string `mapstructure:"redact_attributes"`
}

type MobileRatingGroupConfig struct {
	Name             string   `mapstructure:"name"`
	Enabled          bool     `mapstructure:"enabled"`
	RatingGroup      int      `mapstructure:"rating_group"`
	ServiceID        int      `mapstructure:"service_id"`
	APN              string   `mapstructure:"apn"`
	ChargingProfile  string   `mapstructure:"charging_profile"`
	UnitType         string   `mapstructure:"unit_type"`
	PriceMicros      int64    `mapstructure:"price_micros"`
	Currency         string   `mapstructure:"currency"`
	QuotaPolicy      string   `mapstructure:"quota_policy"`
	RadiusAttributes []string `mapstructure:"radius_attributes"`
}

type MobileQuotaPolicyConfig struct {
	Name               string   `mapstructure:"name"`
	Enabled            bool     `mapstructure:"enabled"`
	GrantUnit          string   `mapstructure:"grant_unit"`
	InitialGrant       int64    `mapstructure:"initial_grant"`
	ThresholdPercent   int      `mapstructure:"threshold_percent"`
	ValiditySeconds    int      `mapstructure:"validity_seconds"`
	ExhaustionAction   string   `mapstructure:"exhaustion_action"`
	InterimTrigger     string   `mapstructure:"interim_trigger"`
	CoAProfile         string   `mapstructure:"coa_profile"`
	RadiusAttributes   []string `mapstructure:"radius_attributes"`
	AccountingCounters []string `mapstructure:"accounting_counters"`
}

func EffectiveMobileChargingConfig(raw MobileChargingConfig) MobileChargingConfig {
	cfg := raw
	cfg.Mode = effectiveMobileChargingMode(cfg.Mode)
	if cfg.CorrelationWindowSeconds == 0 {
		cfg.CorrelationWindowSeconds = 300
	}
	if cfg.MaxCorrelations == 0 {
		cfg.MaxCorrelations = 100000
	}
	if cfg.EventRetentionLimit == 0 {
		cfg.EventRetentionLimit = 10000
	}
	if cfg.CDRRetentionDays == 0 {
		cfg.CDRRetentionDays = 365
	}
	if strings.TrimSpace(cfg.DefaultCurrency) == "" {
		cfg.DefaultCurrency = "USD"
	} else {
		cfg.DefaultCurrency = strings.ToUpper(strings.TrimSpace(cfg.DefaultCurrency))
	}
	if !raw.RequireDatabase && !raw.RequireMobileSessions && !raw.RequireAccountingCharging {
		cfg.RequireDatabase = true
		cfg.RequireMobileSessions = true
		cfg.RequireAccountingCharging = true
	}
	if !raw.RequireOnlineCharging && !raw.RequireOfflineCharging && !raw.RequireMediation {
		cfg.RequireOnlineCharging = true
		cfg.RequireOfflineCharging = true
		cfg.RequireMediation = true
	}
	if !raw.QuotaCorrelation {
		cfg.QuotaCorrelation = true
	}
	if !raw.RedactSubscriberIDs && !raw.HashSubscriberIDs {
		cfg.RedactSubscriberIDs = true
		cfg.HashSubscriberIDs = true
	}
	if strings.TrimSpace(cfg.DefaultOnlineStream) == "" {
		cfg.DefaultOnlineStream = "ocs-online"
	}
	if strings.TrimSpace(cfg.DefaultOfflineStream) == "" {
		cfg.DefaultOfflineStream = "ofcs-offline"
	}
	if len(cfg.Streams) == 0 {
		cfg.Streams = defaultMobileChargingStreams()
	}
	if len(cfg.QuotaPolicies) == 0 {
		cfg.QuotaPolicies = defaultMobileQuotaPolicies()
	}
	if len(cfg.RatingGroups) == 0 {
		cfg.RatingGroups = defaultMobileRatingGroups()
	}
	if len(cfg.CorrelationAttributes) == 0 {
		cfg.CorrelationAttributes = []string{"3GPP-IMSI", "3GPP-Charging-ID", "Acct-Session-Id", "Acct-Unique-Session-Id", "Class", "Called-Station-Id"}
	}
	if len(cfg.ExternalMediationReferences) == 0 {
		cfg.ExternalMediationReferences = []string{"OCS", "OFCS", "billing-mediation", "rating-engine"}
	}
	return cfg
}

func effectiveMobileChargingMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "monitor", "enforce":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "monitor"
	}
}

func validateMobileChargingConfig(raw MobileChargingConfig, sessions MobileSessionConfig, radius RadiusConfig, profile string) error {
	cfg := EffectiveMobileChargingConfig(raw)
	if !cfg.Enabled && len(raw.Streams) == 0 && len(raw.RatingGroups) == 0 && len(raw.QuotaPolicies) == 0 {
		return nil
	}
	if profile == "lite" && cfg.Mode == "enforce" {
		return errors.New("mobile.charging cannot use enforce mode on lite deployment profile")
	}
	if cfg.CorrelationWindowSeconds < 1 || cfg.CorrelationWindowSeconds > 86400 {
		return errors.New("mobile.charging.correlation_window_seconds must be between 1 and 86400")
	}
	if cfg.MaxCorrelations < 1 || cfg.MaxCorrelations > 10000000 {
		return errors.New("mobile.charging.max_correlations must be between 1 and 10000000")
	}
	if cfg.EventRetentionLimit < 0 || cfg.EventRetentionLimit > 1000000 {
		return errors.New("mobile.charging.event_retention_limit must be between 0 and 1000000")
	}
	if cfg.CDRRetentionDays < 1 || cfg.CDRRetentionDays > 3650 {
		return errors.New("mobile.charging.cdr_retention_days must be between 1 and 3650")
	}
	if !validMobileChargingCurrency(cfg.DefaultCurrency) {
		return errors.New("mobile.charging.default_currency is invalid")
	}
	streams, enabledStreams, enabledOnline, enabledOffline, err := validateMobileChargingStreams(cfg.Streams)
	if err != nil {
		return err
	}
	quotaPolicies, enabledQuotaPolicies, err := validateMobileQuotaPolicies(cfg.QuotaPolicies)
	if err != nil {
		return err
	}
	enabledRatingGroups, err := validateMobileRatingGroups(cfg.RatingGroups, quotaPolicies)
	if err != nil {
		return err
	}
	if err := validateMobileRadiusAttributeNames("mobile.charging.correlation_attributes", cfg.CorrelationAttributes); err != nil {
		return err
	}
	for i, ref := range cfg.ExternalMediationReferences {
		if strings.TrimSpace(ref) != "" && !validBroadbandPPPoEText(ref, 128) {
			return fmt.Errorf("mobile.charging.external_mediation_references[%d] is invalid", i)
		}
	}
	if cfg.Enabled && cfg.Mode == "enforce" {
		effectiveSessions := EffectiveMobileSessionConfig(sessions)
		effectiveCharging := EffectiveRadiusAccountingChargingConfig(radius.AccountingCharging)
		if cfg.RequireMobileSessions && !effectiveSessions.Enabled {
			return errors.New("mobile.charging enforce mode requires mobile.sessions.enabled")
		}
		if cfg.RequireAccountingCharging && (!effectiveCharging.Enabled || !effectiveCharging.RatingEnabled || !effectiveCharging.ExportEnabled) {
			return errors.New("mobile.charging enforce mode requires radius.accounting_charging enabled with rating and export")
		}
		if cfg.RequireOnlineCharging && enabledOnline == 0 {
			return errors.New("mobile.charging enforce mode requires an enabled online charging stream")
		}
		if cfg.RequireOfflineCharging && enabledOffline == 0 {
			return errors.New("mobile.charging enforce mode requires an enabled offline charging stream")
		}
		if enabledStreams == 0 {
			return errors.New("mobile.charging enforce mode requires at least one enabled charging stream")
		}
		if enabledRatingGroups == 0 {
			return errors.New("mobile.charging enforce mode requires at least one enabled rating group")
		}
		if cfg.QuotaCorrelation && enabledQuotaPolicies == 0 {
			return errors.New("mobile.charging quota_correlation requires at least one enabled quota policy")
		}
		if cfg.RedactSubscriberIDs && !cfg.HashSubscriberIDs {
			return errors.New("mobile.charging subscriber redaction requires hash_subscriber_ids")
		}
	}
	if _, ok := streams[strings.ToLower(strings.TrimSpace(cfg.DefaultOnlineStream))]; strings.TrimSpace(cfg.DefaultOnlineStream) != "" && !ok {
		return fmt.Errorf("mobile.charging.default_online_stream %q must match a charging stream", cfg.DefaultOnlineStream)
	}
	if _, ok := streams[strings.ToLower(strings.TrimSpace(cfg.DefaultOfflineStream))]; strings.TrimSpace(cfg.DefaultOfflineStream) != "" && !ok {
		return fmt.Errorf("mobile.charging.default_offline_stream %q must match a charging stream", cfg.DefaultOfflineStream)
	}
	return nil
}

func validateMobileChargingStreams(streams []MobileChargingStreamConfig) (map[string]struct{}, int, int, int, error) {
	seen := map[string]struct{}{}
	enabled, online, offline := 0, 0, 0
	for i, stream := range streams {
		name := strings.TrimSpace(stream.Name)
		if !validBroadbandPPPoEText(name, 128) {
			return nil, 0, 0, 0, fmt.Errorf("mobile.charging.streams[%d].name is invalid", i)
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			return nil, 0, 0, 0, fmt.Errorf("mobile.charging.streams[%d] duplicates stream %q", i, key)
		}
		seen[key] = struct{}{}
		streamType := strings.ToLower(strings.TrimSpace(stream.StreamType))
		switch streamType {
		case "online", "offline", "mediation":
		default:
			return nil, 0, 0, 0, fmt.Errorf("mobile.charging.streams[%d].stream_type is invalid", i)
		}
		for _, field := range []struct {
			name  string
			value string
			limit int
		}{
			{"protocol", stream.Protocol, 64},
			{"endpoint_ref", stream.EndpointRef, 253},
			{"export_format", stream.ExportFormat, 64},
			{"retry_policy", stream.RetryPolicy, 128},
		} {
			if strings.TrimSpace(field.value) != "" && !validBroadbandPPPoEText(field.value, field.limit) {
				return nil, 0, 0, 0, fmt.Errorf("mobile.charging.streams[%d].%s is invalid", i, field.name)
			}
		}
		if err := validateMobileRadiusAttributeNames(fmt.Sprintf("mobile.charging.streams[%d].attributes", i), stream.Attributes); err != nil {
			return nil, 0, 0, 0, err
		}
		if err := validateMobileRadiusAttributeNames(fmt.Sprintf("mobile.charging.streams[%d].redact_attributes", i), stream.RedactAttributes); err != nil {
			return nil, 0, 0, 0, err
		}
		if stream.Enabled {
			enabled++
			if streamType == "online" {
				online++
			}
			if streamType == "offline" {
				offline++
			}
		}
	}
	return seen, enabled, online, offline, nil
}

func validateMobileRatingGroups(groups []MobileRatingGroupConfig, quotaPolicies map[string]struct{}) (int, error) {
	seen := map[string]struct{}{}
	enabled := 0
	for i, group := range groups {
		name := strings.TrimSpace(group.Name)
		if !validBroadbandPPPoEText(name, 128) {
			return 0, fmt.Errorf("mobile.charging.rating_groups[%d].name is invalid", i)
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			return 0, fmt.Errorf("mobile.charging.rating_groups[%d] duplicates rating group %q", i, key)
		}
		seen[key] = struct{}{}
		if group.Enabled {
			enabled++
		}
		if group.RatingGroup < 0 || group.RatingGroup > 2147483647 {
			return 0, fmt.Errorf("mobile.charging.rating_groups[%d].rating_group must be non-negative", i)
		}
		if group.ServiceID < 0 || group.ServiceID > 2147483647 {
			return 0, fmt.Errorf("mobile.charging.rating_groups[%d].service_id must be non-negative", i)
		}
		switch strings.ToLower(strings.TrimSpace(group.UnitType)) {
		case "", "octets", "seconds", "events":
		default:
			return 0, fmt.Errorf("mobile.charging.rating_groups[%d].unit_type is invalid", i)
		}
		if group.PriceMicros < 0 {
			return 0, fmt.Errorf("mobile.charging.rating_groups[%d].price_micros must not be negative", i)
		}
		if strings.TrimSpace(group.Currency) != "" && !validMobileChargingCurrency(group.Currency) {
			return 0, fmt.Errorf("mobile.charging.rating_groups[%d].currency is invalid", i)
		}
		for _, field := range []struct {
			name  string
			value string
			limit int
		}{
			{"apn", group.APN, 128},
			{"charging_profile", group.ChargingProfile, 128},
			{"quota_policy", group.QuotaPolicy, 128},
		} {
			if strings.TrimSpace(field.value) != "" && !validBroadbandPPPoEText(field.value, field.limit) {
				return 0, fmt.Errorf("mobile.charging.rating_groups[%d].%s is invalid", i, field.name)
			}
		}
		if strings.TrimSpace(group.QuotaPolicy) != "" {
			if _, ok := quotaPolicies[strings.ToLower(strings.TrimSpace(group.QuotaPolicy))]; !ok {
				return 0, fmt.Errorf("mobile.charging.rating_groups[%d].quota_policy references unknown policy %q", i, group.QuotaPolicy)
			}
		}
		if err := validateMobileRadiusAttributeNames(fmt.Sprintf("mobile.charging.rating_groups[%d].radius_attributes", i), group.RadiusAttributes); err != nil {
			return 0, err
		}
	}
	return enabled, nil
}

func validateMobileQuotaPolicies(policies []MobileQuotaPolicyConfig) (map[string]struct{}, int, error) {
	seen := map[string]struct{}{}
	enabled := 0
	for i, policy := range policies {
		name := strings.TrimSpace(policy.Name)
		if !validBroadbandPPPoEText(name, 128) {
			return nil, 0, fmt.Errorf("mobile.charging.quota_policies[%d].name is invalid", i)
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			return nil, 0, fmt.Errorf("mobile.charging.quota_policies[%d] duplicates policy %q", i, key)
		}
		seen[key] = struct{}{}
		if policy.Enabled {
			enabled++
		}
		switch strings.ToLower(strings.TrimSpace(policy.GrantUnit)) {
		case "", "octets", "seconds", "events":
		default:
			return nil, 0, fmt.Errorf("mobile.charging.quota_policies[%d].grant_unit is invalid", i)
		}
		if policy.InitialGrant < 0 {
			return nil, 0, fmt.Errorf("mobile.charging.quota_policies[%d].initial_grant must not be negative", i)
		}
		if policy.ThresholdPercent < 0 || policy.ThresholdPercent > 100 {
			return nil, 0, fmt.Errorf("mobile.charging.quota_policies[%d].threshold_percent must be between 0 and 100", i)
		}
		if policy.ValiditySeconds < 0 || policy.ValiditySeconds > 31536000 {
			return nil, 0, fmt.Errorf("mobile.charging.quota_policies[%d].validity_seconds is invalid", i)
		}
		for _, field := range []struct {
			name  string
			value string
			limit int
		}{
			{"exhaustion_action", policy.ExhaustionAction, 64},
			{"interim_trigger", policy.InterimTrigger, 64},
			{"coa_profile", policy.CoAProfile, 128},
		} {
			if strings.TrimSpace(field.value) != "" && !validBroadbandPPPoEText(field.value, field.limit) {
				return nil, 0, fmt.Errorf("mobile.charging.quota_policies[%d].%s is invalid", i, field.name)
			}
		}
		if err := validateMobileRadiusAttributeNames(fmt.Sprintf("mobile.charging.quota_policies[%d].radius_attributes", i), policy.RadiusAttributes); err != nil {
			return nil, 0, err
		}
		if err := validateMobileRadiusAttributeNames(fmt.Sprintf("mobile.charging.quota_policies[%d].accounting_counters", i), policy.AccountingCounters); err != nil {
			return nil, 0, err
		}
	}
	return seen, enabled, nil
}

func validMobileChargingCurrency(value string) bool {
	value = strings.ToUpper(strings.TrimSpace(value))
	if len(value) != 3 {
		return false
	}
	for _, r := range value {
		if r < 'A' || r > 'Z' {
			return false
		}
	}
	return true
}

func defaultMobileChargingStreams() []MobileChargingStreamConfig {
	return []MobileChargingStreamConfig{
		{
			Name:             "ocs-online",
			Enabled:          true,
			StreamType:       "online",
			Protocol:         "diameter-gy",
			EndpointRef:      "env:MOBILE_OCS_ENDPOINT",
			ExportFormat:     "jsonl",
			RetryPolicy:      "bounded-exponential",
			Attributes:       []string{"3GPP-Charging-ID", "3GPP-RAT-Type", "Acct-Input-Octets", "Acct-Output-Octets", "Acct-Session-Time"},
			RedactAttributes: []string{"3GPP-IMSI", "User-Name"},
		},
		{
			Name:             "ofcs-offline",
			Enabled:          true,
			StreamType:       "offline",
			Protocol:         "cdr-export",
			EndpointRef:      "file:/var/lib/aegisnas/mobile-cdr",
			ExportFormat:     "jsonl",
			RetryPolicy:      "hash-chain",
			Attributes:       []string{"Acct-Session-Id", "Acct-Unique-Session-Id", "3GPP-Charging-ID", "Class"},
			RedactAttributes: []string{"3GPP-IMSI", "Calling-Station-Id"},
		},
		{
			Name:             "mediation-feed",
			Enabled:          true,
			StreamType:       "mediation",
			Protocol:         "webhook",
			EndpointRef:      "env:MOBILE_MEDIATION_ENDPOINT",
			ExportFormat:     "json",
			RetryPolicy:      "at-least-once",
			Attributes:       []string{"3GPP-Charging-ID", "Acct-Multi-Session-Id", "Acct-Terminate-Cause"},
			RedactAttributes: []string{"3GPP-IMSI", "User-Name"},
		},
	}
}

func defaultMobileRatingGroups() []MobileRatingGroupConfig {
	return []MobileRatingGroupConfig{
		{
			Name:             "internet-data",
			Enabled:          true,
			RatingGroup:      1001,
			ServiceID:        1,
			APN:              "internet",
			ChargingProfile:  "online-offline-default",
			UnitType:         "octets",
			PriceMicros:      0,
			Currency:         "USD",
			QuotaPolicy:      "default-data-quota",
			RadiusAttributes: []string{"3GPP-Charging-ID", "3GPP-GPRS-Negotiated-QoS-profile", "Acct-Input-Octets", "Acct-Output-Octets"},
		},
		{
			Name:             "iot-events",
			Enabled:          true,
			RatingGroup:      2001,
			ServiceID:        2,
			APN:              "iot.private",
			ChargingProfile:  "iot-usage",
			UnitType:         "events",
			PriceMicros:      0,
			Currency:         "USD",
			QuotaPolicy:      "iot-event-quota",
			RadiusAttributes: []string{"3GPP-Charging-ID", "Class", "Acct-Interim-Interval"},
		},
	}
}

func defaultMobileQuotaPolicies() []MobileQuotaPolicyConfig {
	return []MobileQuotaPolicyConfig{
		{
			Name:               "default-data-quota",
			Enabled:            true,
			GrantUnit:          "octets",
			InitialGrant:       1073741824,
			ThresholdPercent:   80,
			ValiditySeconds:    3600,
			ExhaustionAction:   "coa-throttle",
			InterimTrigger:     "threshold",
			CoAProfile:         "mobile-quota-throttle",
			RadiusAttributes:   []string{"Session-Timeout", "Acct-Interim-Interval", "Filter-Id"},
			AccountingCounters: []string{"Acct-Input-Octets", "Acct-Output-Octets", "Acct-Input-Gigawords", "Acct-Output-Gigawords"},
		},
		{
			Name:               "iot-event-quota",
			Enabled:            true,
			GrantUnit:          "events",
			InitialGrant:       10000,
			ThresholdPercent:   90,
			ValiditySeconds:    86400,
			ExhaustionAction:   "deny-new-sessions",
			InterimTrigger:     "daily",
			CoAProfile:         "iot-quarantine",
			RadiusAttributes:   []string{"Class", "Filter-Id"},
			AccountingCounters: []string{"Acct-Status-Type", "Acct-Session-Time"},
		},
	}
}
