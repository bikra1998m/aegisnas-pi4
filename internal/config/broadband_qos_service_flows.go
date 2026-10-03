package config

import (
	"errors"
	"fmt"
	"strings"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
)

type BroadbandQoSServiceFlowConfig struct {
	Enabled                       bool                                  `mapstructure:"enabled"`
	Mode                          string                                `mapstructure:"mode"`
	FailClosed                    bool                                  `mapstructure:"fail_closed"`
	RequireSubscriberState        bool                                  `mapstructure:"require_subscriber_state"`
	RequireCommercialCatalog      bool                                  `mapstructure:"require_commercial_catalog"`
	RequireRuntimeQoS             bool                                  `mapstructure:"require_runtime_qos"`
	RequireRateCompiler           bool                                  `mapstructure:"require_rate_compiler"`
	AccountingCorrelationRequired bool                                  `mapstructure:"accounting_correlation_required"`
	CoAOnChange                   bool                                  `mapstructure:"coa_on_change"`
	AggregateControlEnabled       bool                                  `mapstructure:"aggregate_control_enabled"`
	Scheduler                     string                                `mapstructure:"scheduler"`
	DefaultTrafficClass           string                                `mapstructure:"default_traffic_class"`
	EventRetentionLimit           int                                   `mapstructure:"event_retention_limit"`
	Profiles                      []BroadbandQoSProfileConfig           `mapstructure:"profiles"`
	ServiceFlows                  []BroadbandQoSServiceFlowIntentConfig `mapstructure:"service_flows"`
	AggregatePolicies             []BroadbandQoSAggregatePolicyConfig   `mapstructure:"aggregate_policies"`
}

type BroadbandQoSProfileConfig struct {
	Name                 string   `mapstructure:"name"`
	Enabled              bool     `mapstructure:"enabled"`
	ParentProfile        string   `mapstructure:"parent_profile"`
	TrafficClass         string   `mapstructure:"traffic_class"`
	Scheduler            string   `mapstructure:"scheduler"`
	Priority             int      `mapstructure:"priority"`
	DSCPMark             int      `mapstructure:"dscp_mark"`
	DownloadMinRateKbps  int      `mapstructure:"download_min_rate_kbps"`
	DownloadRateKbps     int      `mapstructure:"download_rate_kbps"`
	DownloadPeakRateKbps int      `mapstructure:"download_peak_rate_kbps"`
	UploadMinRateKbps    int      `mapstructure:"upload_min_rate_kbps"`
	UploadRateKbps       int      `mapstructure:"upload_rate_kbps"`
	UploadPeakRateKbps   int      `mapstructure:"upload_peak_rate_kbps"`
	DownloadBurstKbps    int      `mapstructure:"download_burst_kbps"`
	UploadBurstKbps      int      `mapstructure:"upload_burst_kbps"`
	BurstTimeSeconds     int      `mapstructure:"burst_time_seconds"`
	AggregateLimitKbps   int      `mapstructure:"aggregate_limit_kbps"`
	MaxSubscribers       int      `mapstructure:"max_subscribers"`
	VendorPacks          []string `mapstructure:"vendor_packs"`
	ExternalPolicyName   string   `mapstructure:"external_policy_name"`
}

type BroadbandQoSServiceFlowIntentConfig struct {
	Name          string   `mapstructure:"name"`
	Enabled       bool     `mapstructure:"enabled"`
	Product       string   `mapstructure:"product"`
	ServiceLeg    string   `mapstructure:"service_leg"`
	SubscriberID  string   `mapstructure:"subscriber_id"`
	Username      string   `mapstructure:"username"`
	Role          string   `mapstructure:"role"`
	Tenant        string   `mapstructure:"tenant"`
	Direction     string   `mapstructure:"direction"`
	Profile       string   `mapstructure:"profile"`
	Aggregate     string   `mapstructure:"aggregate"`
	AccountingKey string   `mapstructure:"accounting_key"`
	Precedence    int      `mapstructure:"precedence"`
	CoAAction     string   `mapstructure:"coa_action"`
	VendorPacks   []string `mapstructure:"vendor_packs"`
}

type BroadbandQoSAggregatePolicyConfig struct {
	Name                  string   `mapstructure:"name"`
	Enabled               bool     `mapstructure:"enabled"`
	Scope                 string   `mapstructure:"scope"`
	Tenant                string   `mapstructure:"tenant"`
	Product               string   `mapstructure:"product"`
	Profile               string   `mapstructure:"profile"`
	MaxSubscribers        int      `mapstructure:"max_subscribers"`
	DownloadLimitKbps     int      `mapstructure:"download_limit_kbps"`
	UploadLimitKbps       int      `mapstructure:"upload_limit_kbps"`
	OversubscriptionRatio int      `mapstructure:"oversubscription_ratio"`
	Scheduler             string   `mapstructure:"scheduler"`
	DropPrecedence        string   `mapstructure:"drop_precedence"`
	VendorPacks           []string `mapstructure:"vendor_packs"`
}

func EffectiveBroadbandQoSServiceFlowConfig(raw BroadbandQoSServiceFlowConfig) BroadbandQoSServiceFlowConfig {
	qos := raw
	qos.Mode = EffectiveBroadbandQoSServiceFlowMode(qos.Mode)
	qos.Scheduler = normalizeBroadbandQoSScheduler(qos.Scheduler)
	if strings.TrimSpace(qos.DefaultTrafficClass) == "" {
		qos.DefaultTrafficClass = "best_effort"
	}
	if qos.EventRetentionLimit == 0 {
		qos.EventRetentionLimit = 10000
	}
	if !raw.RequireSubscriberState && !raw.RequireCommercialCatalog && !raw.RequireRuntimeQoS &&
		!raw.RequireRateCompiler && !raw.AccountingCorrelationRequired && !raw.CoAOnChange && !raw.AggregateControlEnabled {
		qos.RequireSubscriberState = true
		qos.RequireCommercialCatalog = true
		qos.RequireRuntimeQoS = true
		qos.RequireRateCompiler = true
		qos.AccountingCorrelationRequired = true
		qos.CoAOnChange = true
		qos.AggregateControlEnabled = true
	}
	return qos
}

func EffectiveBroadbandQoSServiceFlowMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "monitor", "enforce":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "monitor"
	}
}

func validateBroadbandQoSServiceFlowConfig(raw BroadbandQoSServiceFlowConfig, subscriberRaw BroadbandSubscriberStateConfig, catalogRaw BroadbandCommercialCatalog, radius RadiusConfig, profile string) error {
	qos := EffectiveBroadbandQoSServiceFlowConfig(raw)
	if !qos.Enabled && len(qos.Profiles) == 0 && len(qos.ServiceFlows) == 0 && len(qos.AggregatePolicies) == 0 {
		return nil
	}
	if profile == "lite" && qos.Mode == "enforce" {
		return errors.New("broadband.qos_service_flows cannot use enforce mode on lite deployment profile")
	}
	if qos.EventRetentionLimit < 0 || qos.EventRetentionLimit > 1000000 {
		return errors.New("broadband.qos_service_flows.event_retention_limit must be between 0 and 1000000")
	}
	if !validBroadbandQoSTrafficClass(qos.DefaultTrafficClass) {
		return fmt.Errorf("broadband.qos_service_flows.default_traffic_class %q is invalid", qos.DefaultTrafficClass)
	}
	subscriber := EffectiveBroadbandSubscriberStateConfig(subscriberRaw)
	catalog := EffectiveBroadbandCommercialCatalog(catalogRaw)
	if qos.Enabled && qos.RequireSubscriberState && !subscriber.Enabled {
		return errors.New("broadband.qos_service_flows requires broadband.subscriber_state.enabled")
	}
	if qos.Enabled && qos.RequireCommercialCatalog && !catalog.Enabled {
		return errors.New("broadband.qos_service_flows require_commercial_catalog requires broadband.commercial_catalog.enabled")
	}
	if qos.Enabled && qos.AccountingCorrelationRequired && !radius.AccountingServices.Enabled {
		return errors.New("broadband.qos_service_flows accounting correlation requires radius.accounting_services.enabled")
	}
	if qos.Enabled && qos.CoAOnChange && !radius.DynamicAuth.Enabled {
		return errors.New("broadband.qos_service_flows coa_on_change requires radius.dynamic_auth.enabled")
	}
	profiles, enabledProfiles, err := validateBroadbandQoSProfiles(qos)
	if err != nil {
		return err
	}
	aggregates, enabledAggregates, err := validateBroadbandQoSAggregates(qos, profiles)
	if err != nil {
		return err
	}
	productNames := broadbandSubscriberProductNames(subscriber)
	if len(productNames) == 0 {
		_, _, productNames = broadbandCommercialCatalogReferenceMaps(catalog)
	}
	enabledFlows, err := validateBroadbandQoSServiceFlows(qos, profiles, aggregates, productNames)
	if err != nil {
		return err
	}
	if qos.Enabled && qos.Mode == "enforce" {
		if enabledProfiles == 0 {
			return errors.New("broadband.qos_service_flows enforce mode requires at least one enabled QoS profile")
		}
		if enabledFlows == 0 {
			return errors.New("broadband.qos_service_flows enforce mode requires at least one enabled service flow")
		}
		if qos.AggregateControlEnabled && enabledAggregates == 0 {
			return errors.New("broadband.qos_service_flows aggregate_control_enabled requires at least one enabled aggregate policy")
		}
	}
	return nil
}

func validateBroadbandQoSProfiles(qos BroadbandQoSServiceFlowConfig) (map[string]struct{}, int, error) {
	profiles := map[string]struct{}{}
	enabled := 0
	for i, profile := range qos.Profiles {
		name := strings.TrimSpace(profile.Name)
		if !validBroadbandPPPoEText(name, 128) {
			return nil, 0, fmt.Errorf("broadband.qos_service_flows.profiles[%d].name is invalid", i)
		}
		key := strings.ToLower(name)
		if _, exists := profiles[key]; exists {
			return nil, 0, fmt.Errorf("broadband.qos_service_flows.profiles[%d].name %q duplicates an earlier profile", i, name)
		}
		profiles[key] = struct{}{}
		if profile.Enabled {
			enabled++
		}
		if strings.TrimSpace(profile.TrafficClass) != "" && !validBroadbandQoSTrafficClass(profile.TrafficClass) {
			return nil, 0, fmt.Errorf("broadband.qos_service_flows.profiles[%d].traffic_class %q is invalid", i, profile.TrafficClass)
		}
		if strings.TrimSpace(profile.Scheduler) != "" && normalizeBroadbandQoSScheduler(profile.Scheduler) == "" {
			return nil, 0, fmt.Errorf("broadband.qos_service_flows.profiles[%d].scheduler %q is invalid", i, profile.Scheduler)
		}
		if profile.Priority < 0 || profile.Priority > 7 {
			return nil, 0, fmt.Errorf("broadband.qos_service_flows.profiles[%d].priority must be between 0 and 7", i)
		}
		if profile.DSCPMark < 0 || profile.DSCPMark > 63 {
			return nil, 0, fmt.Errorf("broadband.qos_service_flows.profiles[%d].dscp_mark must be between 0 and 63", i)
		}
		if err := validateBroadbandQoSRateSet("broadband.qos_service_flows.profiles", i, profile.DownloadMinRateKbps, profile.DownloadRateKbps, profile.DownloadPeakRateKbps, profile.UploadMinRateKbps, profile.UploadRateKbps, profile.UploadPeakRateKbps); err != nil {
			return nil, 0, err
		}
		if profile.DownloadBurstKbps < 0 || profile.UploadBurstKbps < 0 || profile.BurstTimeSeconds < 0 || profile.AggregateLimitKbps < 0 || profile.MaxSubscribers < 0 {
			return nil, 0, fmt.Errorf("broadband.qos_service_flows.profiles[%d] burst, aggregate, and subscriber limits cannot be negative", i)
		}
		for _, pack := range profile.VendorPacks {
			if productconfigs.NormalizeVendorCompatibilityPackKey(pack) == "" {
				return nil, 0, fmt.Errorf("broadband.qos_service_flows.profiles[%d].vendor_packs contains unsupported pack %q", i, pack)
			}
		}
	}
	for i, profile := range qos.Profiles {
		parent := strings.TrimSpace(profile.ParentProfile)
		if parent != "" {
			if _, ok := profiles[strings.ToLower(parent)]; !ok {
				return nil, 0, fmt.Errorf("broadband.qos_service_flows.profiles[%d].parent_profile %q does not match a profile", i, parent)
			}
		}
	}
	return profiles, enabled, nil
}

func validateBroadbandQoSAggregates(qos BroadbandQoSServiceFlowConfig, profiles map[string]struct{}) (map[string]struct{}, int, error) {
	aggregates := map[string]struct{}{}
	enabled := 0
	for i, aggregate := range qos.AggregatePolicies {
		name := strings.TrimSpace(aggregate.Name)
		if !validBroadbandPPPoEText(name, 128) {
			return nil, 0, fmt.Errorf("broadband.qos_service_flows.aggregate_policies[%d].name is invalid", i)
		}
		key := strings.ToLower(name)
		if _, exists := aggregates[key]; exists {
			return nil, 0, fmt.Errorf("broadband.qos_service_flows.aggregate_policies[%d].name %q duplicates an earlier aggregate", i, name)
		}
		aggregates[key] = struct{}{}
		if aggregate.Enabled {
			enabled++
		}
		if strings.TrimSpace(aggregate.Profile) != "" {
			if _, ok := profiles[strings.ToLower(strings.TrimSpace(aggregate.Profile))]; !ok {
				return nil, 0, fmt.Errorf("broadband.qos_service_flows.aggregate_policies[%d].profile %q does not match a QoS profile", i, aggregate.Profile)
			}
		}
		if aggregate.DownloadLimitKbps < 0 || aggregate.UploadLimitKbps < 0 || aggregate.MaxSubscribers < 0 || aggregate.OversubscriptionRatio < 0 {
			return nil, 0, fmt.Errorf("broadband.qos_service_flows.aggregate_policies[%d] limits cannot be negative", i)
		}
		if strings.TrimSpace(aggregate.Scheduler) != "" && normalizeBroadbandQoSScheduler(aggregate.Scheduler) == "" {
			return nil, 0, fmt.Errorf("broadband.qos_service_flows.aggregate_policies[%d].scheduler %q is invalid", i, aggregate.Scheduler)
		}
		for _, pack := range aggregate.VendorPacks {
			if productconfigs.NormalizeVendorCompatibilityPackKey(pack) == "" {
				return nil, 0, fmt.Errorf("broadband.qos_service_flows.aggregate_policies[%d].vendor_packs contains unsupported pack %q", i, pack)
			}
		}
	}
	return aggregates, enabled, nil
}

func validateBroadbandQoSServiceFlows(qos BroadbandQoSServiceFlowConfig, profiles, aggregates, products map[string]struct{}) (int, error) {
	seen := map[string]struct{}{}
	enabled := 0
	for i, flow := range qos.ServiceFlows {
		name := strings.TrimSpace(flow.Name)
		if !validBroadbandPPPoEText(name, 128) {
			return 0, fmt.Errorf("broadband.qos_service_flows.service_flows[%d].name is invalid", i)
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			return 0, fmt.Errorf("broadband.qos_service_flows.service_flows[%d].name %q duplicates an earlier service flow", i, name)
		}
		seen[key] = struct{}{}
		if flow.Enabled {
			enabled++
		}
		profile := strings.TrimSpace(flow.Profile)
		if profile == "" {
			return 0, fmt.Errorf("broadband.qos_service_flows.service_flows[%d].profile is required", i)
		}
		if _, ok := profiles[strings.ToLower(profile)]; !ok {
			return 0, fmt.Errorf("broadband.qos_service_flows.service_flows[%d].profile %q does not match a QoS profile", i, profile)
		}
		if strings.TrimSpace(flow.Aggregate) != "" {
			if _, ok := aggregates[strings.ToLower(strings.TrimSpace(flow.Aggregate))]; !ok {
				return 0, fmt.Errorf("broadband.qos_service_flows.service_flows[%d].aggregate %q does not match an aggregate policy", i, flow.Aggregate)
			}
		}
		if strings.TrimSpace(flow.Product) != "" && len(products) > 0 {
			if _, ok := products[strings.ToLower(strings.TrimSpace(flow.Product))]; !ok {
				return 0, fmt.Errorf("broadband.qos_service_flows.service_flows[%d].product %q does not match a subscriber product", i, flow.Product)
			}
		}
		if direction := strings.ToLower(strings.TrimSpace(flow.Direction)); direction != "" && direction != "download" && direction != "upload" && direction != "bidirectional" {
			return 0, fmt.Errorf("broadband.qos_service_flows.service_flows[%d].direction %q is invalid", i, flow.Direction)
		}
		if flow.Precedence < 0 || flow.Precedence > 10000 {
			return 0, fmt.Errorf("broadband.qos_service_flows.service_flows[%d].precedence must be between 0 and 10000", i)
		}
		for _, pack := range flow.VendorPacks {
			if productconfigs.NormalizeVendorCompatibilityPackKey(pack) == "" {
				return 0, fmt.Errorf("broadband.qos_service_flows.service_flows[%d].vendor_packs contains unsupported pack %q", i, pack)
			}
		}
	}
	return enabled, nil
}

func validateBroadbandQoSRateSet(prefix string, index, downMin, downRate, downPeak, upMin, upRate, upPeak int) error {
	values := []struct {
		name  string
		value int
	}{
		{"download_min_rate_kbps", downMin},
		{"download_rate_kbps", downRate},
		{"download_peak_rate_kbps", downPeak},
		{"upload_min_rate_kbps", upMin},
		{"upload_rate_kbps", upRate},
		{"upload_peak_rate_kbps", upPeak},
	}
	for _, item := range values {
		if item.value < 0 {
			return fmt.Errorf("%s[%d].%s cannot be negative", prefix, index, item.name)
		}
		if item.value > 4294967 {
			return fmt.Errorf("%s[%d].%s exceeds the supported RADIUS kbps range", prefix, index, item.name)
		}
	}
	if downRate <= 0 || upRate <= 0 {
		return fmt.Errorf("%s[%d] download_rate_kbps and upload_rate_kbps must be greater than zero", prefix, index)
	}
	if downMin > 0 && downMin > downRate {
		return fmt.Errorf("%s[%d].download_min_rate_kbps cannot exceed download_rate_kbps", prefix, index)
	}
	if upMin > 0 && upMin > upRate {
		return fmt.Errorf("%s[%d].upload_min_rate_kbps cannot exceed upload_rate_kbps", prefix, index)
	}
	if downPeak > 0 && downPeak < downRate {
		return fmt.Errorf("%s[%d].download_peak_rate_kbps cannot be lower than download_rate_kbps", prefix, index)
	}
	if upPeak > 0 && upPeak < upRate {
		return fmt.Errorf("%s[%d].upload_peak_rate_kbps cannot be lower than upload_rate_kbps", prefix, index)
	}
	return nil
}

func validBroadbandQoSTrafficClass(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "best_effort", "data", "voice", "video", "control", "management", "critical", "background":
		return true
	default:
		return false
	}
}

func normalizeBroadbandQoSScheduler(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "htb":
		return "htb"
	case "wfq", "fq_codel", "strict-priority", "strict_priority":
		return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(value)), "-", "_")
	default:
		return ""
	}
}
