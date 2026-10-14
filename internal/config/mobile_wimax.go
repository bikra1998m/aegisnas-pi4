package config

import (
	"errors"
	"fmt"
	"strings"
)

type MobileWiMAXConfig struct {
	Enabled                   bool                           `mapstructure:"enabled"`
	Mode                      string                         `mapstructure:"mode"`
	FailClosed                bool                           `mapstructure:"fail_closed"`
	RequireDatabase           bool                           `mapstructure:"require_database"`
	RequireGroupedAVPs        bool                           `mapstructure:"require_grouped_avps"`
	RequireCharging           bool                           `mapstructure:"require_charging"`
	RequireDynamicAuth        bool                           `mapstructure:"require_dynamic_auth"`
	ServiceFlowAuthorization  bool                           `mapstructure:"service_flow_authorization"`
	MobilityTracking          bool                           `mapstructure:"mobility_tracking"`
	AccountingCorrelation     bool                           `mapstructure:"accounting_correlation"`
	RedactSubscriberIDs       bool                           `mapstructure:"redact_subscriber_ids"`
	HashSubscriberIDs         bool                           `mapstructure:"hash_subscriber_ids"`
	ServiceFlowRetentionDays  int                            `mapstructure:"service_flow_retention_days"`
	EventRetentionLimit       int                            `mapstructure:"event_retention_limit"`
	MaxSubscribers            int                            `mapstructure:"max_subscribers"`
	DefaultSubscriberProfile  string                         `mapstructure:"default_subscriber_profile"`
	DefaultServiceFlow        string                         `mapstructure:"default_service_flow"`
	DefaultASNProfile         string                         `mapstructure:"default_asn_profile"`
	SubscriberProfiles        []MobileWiMAXSubscriberProfile `mapstructure:"subscriber_profiles"`
	ServiceFlows              []MobileWiMAXServiceFlow       `mapstructure:"service_flows"`
	ASNProfiles               []MobileWiMAXASNProfile        `mapstructure:"asn_profiles"`
	MobilityPolicies          []MobileWiMAXMobilityPolicy    `mapstructure:"mobility_policies"`
	RadiusAttributes          []string                       `mapstructure:"radius_attributes"`
	ExternalGatewayReferences []string                       `mapstructure:"external_gateway_references"`
}

type MobileWiMAXSubscriberProfile struct {
	Name               string   `mapstructure:"name"`
	Enabled            bool     `mapstructure:"enabled"`
	NAIRealm           string   `mapstructure:"nai_realm"`
	DeviceGroup        string   `mapstructure:"device_group"`
	HomeAgent          string   `mapstructure:"home_agent"`
	ASNProfile         string   `mapstructure:"asn_profile"`
	DefaultServiceFlow string   `mapstructure:"default_service_flow"`
	AccountingClass    string   `mapstructure:"accounting_class"`
	PolicyProfile      string   `mapstructure:"policy_profile"`
	VendorPacks        []string `mapstructure:"vendor_packs"`
	RadiusAttributes   []string `mapstructure:"radius_attributes"`
}

type MobileWiMAXServiceFlow struct {
	Name                 string   `mapstructure:"name"`
	Enabled              bool     `mapstructure:"enabled"`
	Direction            string   `mapstructure:"direction"`
	ServiceClass         string   `mapstructure:"service_class"`
	SchedulingType       string   `mapstructure:"scheduling_type"`
	ServiceFlowID        int      `mapstructure:"service_flow_id"`
	QoSProfile           string   `mapstructure:"qos_profile"`
	TrafficPriority      int      `mapstructure:"traffic_priority"`
	MaxSustainedRateKbps int      `mapstructure:"max_sustained_rate_kbps"`
	MinReservedRateKbps  int      `mapstructure:"min_reserved_rate_kbps"`
	MaxLatencyMs         int      `mapstructure:"max_latency_ms"`
	ToleratedJitterMs    int      `mapstructure:"tolerated_jitter_ms"`
	PacketClassifier     string   `mapstructure:"packet_classifier"`
	RadiusAttributes     []string `mapstructure:"radius_attributes"`
}

type MobileWiMAXASNProfile struct {
	Name               string   `mapstructure:"name"`
	Enabled            bool     `mapstructure:"enabled"`
	ASNID              string   `mapstructure:"asn_id"`
	Realm              string   `mapstructure:"realm"`
	MobilityDomain     string   `mapstructure:"mobility_domain"`
	HomeAgentEndpoint  string   `mapstructure:"home_agent_endpoint"`
	AccountingEndpoint string   `mapstructure:"accounting_endpoint"`
	RadiusAttributes   []string `mapstructure:"radius_attributes"`
}

type MobileWiMAXMobilityPolicy struct {
	Name             string   `mapstructure:"name"`
	Enabled          bool     `mapstructure:"enabled"`
	SourceASN        string   `mapstructure:"source_asn"`
	TargetASN        string   `mapstructure:"target_asn"`
	HandoverMode     string   `mapstructure:"handover_mode"`
	ReauthRequired   bool     `mapstructure:"reauth_required"`
	CoAProfile       string   `mapstructure:"coa_profile"`
	RadiusAttributes []string `mapstructure:"radius_attributes"`
}

func EffectiveMobileWiMAXConfig(raw MobileWiMAXConfig) MobileWiMAXConfig {
	cfg := raw
	cfg.Mode = effectiveMobileWiMAXMode(cfg.Mode)
	if cfg.ServiceFlowRetentionDays == 0 {
		cfg.ServiceFlowRetentionDays = 180
	}
	if cfg.EventRetentionLimit == 0 {
		cfg.EventRetentionLimit = 10000
	}
	if cfg.MaxSubscribers == 0 {
		cfg.MaxSubscribers = 100000
	}
	if !raw.RequireDatabase && !raw.RequireGroupedAVPs && !raw.RequireCharging && !raw.RequireDynamicAuth {
		cfg.RequireDatabase = true
		cfg.RequireGroupedAVPs = true
		cfg.RequireCharging = true
		cfg.RequireDynamicAuth = true
	}
	if !raw.ServiceFlowAuthorization && !raw.MobilityTracking && !raw.AccountingCorrelation {
		cfg.ServiceFlowAuthorization = true
		cfg.MobilityTracking = true
		cfg.AccountingCorrelation = true
	}
	if !raw.RedactSubscriberIDs && !raw.HashSubscriberIDs {
		cfg.RedactSubscriberIDs = true
		cfg.HashSubscriberIDs = true
	}
	if strings.TrimSpace(cfg.DefaultSubscriberProfile) == "" {
		cfg.DefaultSubscriberProfile = "wimax-retail"
	}
	if strings.TrimSpace(cfg.DefaultServiceFlow) == "" {
		cfg.DefaultServiceFlow = "internet-be"
	}
	if strings.TrimSpace(cfg.DefaultASNProfile) == "" {
		cfg.DefaultASNProfile = "asn-primary"
	}
	if len(cfg.SubscriberProfiles) == 0 {
		cfg.SubscriberProfiles = defaultMobileWiMAXSubscriberProfiles()
	}
	if len(cfg.ServiceFlows) == 0 {
		cfg.ServiceFlows = defaultMobileWiMAXServiceFlows()
	}
	if len(cfg.ASNProfiles) == 0 {
		cfg.ASNProfiles = defaultMobileWiMAXASNProfiles()
	}
	if len(cfg.MobilityPolicies) == 0 {
		cfg.MobilityPolicies = defaultMobileWiMAXMobilityPolicies()
	}
	if len(cfg.RadiusAttributes) == 0 {
		cfg.RadiusAttributes = []string{"WiMAX-MN-NAI", "WiMAX-Service-Flow-ID", "WiMAX-QoS-Descriptor", "WiMAX-Packet-Flow-Descriptor", "WiMAX-Session-Id", "WiMAX-Accounting-Capabilities", "Filter-Id", "Class", "Session-Timeout", "Acct-Interim-Interval"}
	}
	if len(cfg.ExternalGatewayReferences) == 0 {
		cfg.ExternalGatewayReferences = []string{"WiMAX ASN gateway", "AAA mobility anchor", "Alvarion ASN-GW", "WiChorus ASN-GW", "Navini BTS lab"}
	}
	return cfg
}

func effectiveMobileWiMAXMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "monitor", "enforce":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "monitor"
	}
}

func validateMobileWiMAXConfig(raw MobileWiMAXConfig, grouped MobileGroupedAVPConfig, charging MobileChargingConfig, radius RadiusConfig, profile string) error {
	cfg := EffectiveMobileWiMAXConfig(raw)
	if !cfg.Enabled && len(raw.SubscriberProfiles) == 0 && len(raw.ServiceFlows) == 0 && len(raw.ASNProfiles) == 0 && len(raw.MobilityPolicies) == 0 {
		return nil
	}
	if profile == "lite" && cfg.Mode == "enforce" {
		return errors.New("mobile.wimax cannot use enforce mode on lite deployment profile")
	}
	if cfg.ServiceFlowRetentionDays < 1 || cfg.ServiceFlowRetentionDays > 3650 {
		return errors.New("mobile.wimax.service_flow_retention_days must be between 1 and 3650")
	}
	if cfg.EventRetentionLimit < 0 || cfg.EventRetentionLimit > 1000000 {
		return errors.New("mobile.wimax.event_retention_limit must be between 0 and 1000000")
	}
	if cfg.MaxSubscribers < 1 || cfg.MaxSubscribers > 10000000 {
		return errors.New("mobile.wimax.max_subscribers must be between 1 and 10000000")
	}
	asnProfiles, enabledASN, err := validateMobileWiMAXASNProfiles(cfg.ASNProfiles)
	if err != nil {
		return err
	}
	serviceFlows, enabledFlows, err := validateMobileWiMAXServiceFlows(cfg.ServiceFlows)
	if err != nil {
		return err
	}
	subscriberProfiles, enabledSubscribers, err := validateMobileWiMAXSubscriberProfiles(cfg.SubscriberProfiles, asnProfiles, serviceFlows)
	if err != nil {
		return err
	}
	enabledMobility, err := validateMobileWiMAXMobilityPolicies(cfg.MobilityPolicies, asnProfiles)
	if err != nil {
		return err
	}
	if err := validateMobileRadiusAttributeNames("mobile.wimax.radius_attributes", cfg.RadiusAttributes); err != nil {
		return err
	}
	for i, ref := range cfg.ExternalGatewayReferences {
		if strings.TrimSpace(ref) != "" && !validBroadbandPPPoEText(ref, 128) {
			return fmt.Errorf("mobile.wimax.external_gateway_references[%d] is invalid", i)
		}
	}
	if _, ok := subscriberProfiles[strings.ToLower(strings.TrimSpace(cfg.DefaultSubscriberProfile))]; strings.TrimSpace(cfg.DefaultSubscriberProfile) != "" && !ok {
		return fmt.Errorf("mobile.wimax.default_subscriber_profile %q must match a subscriber profile", cfg.DefaultSubscriberProfile)
	}
	if _, ok := serviceFlows[strings.ToLower(strings.TrimSpace(cfg.DefaultServiceFlow))]; strings.TrimSpace(cfg.DefaultServiceFlow) != "" && !ok {
		return fmt.Errorf("mobile.wimax.default_service_flow %q must match a service flow", cfg.DefaultServiceFlow)
	}
	if _, ok := asnProfiles[strings.ToLower(strings.TrimSpace(cfg.DefaultASNProfile))]; strings.TrimSpace(cfg.DefaultASNProfile) != "" && !ok {
		return fmt.Errorf("mobile.wimax.default_asn_profile %q must match an ASN profile", cfg.DefaultASNProfile)
	}
	if cfg.Enabled && cfg.Mode == "enforce" {
		effectiveGrouped := EffectiveMobileGroupedAVPConfig(grouped)
		effectiveCharging := EffectiveMobileChargingConfig(charging)
		effectiveDynamicAuth := EffectiveDynamicAuthConfig(radius.DynamicAuth)
		if cfg.RequireGroupedAVPs && !effectiveGrouped.Enabled {
			return errors.New("mobile.wimax enforce mode requires mobile.grouped_avps.enabled")
		}
		if cfg.RequireCharging && !effectiveCharging.Enabled {
			return errors.New("mobile.wimax enforce mode requires mobile.charging.enabled")
		}
		if cfg.RequireDynamicAuth && !effectiveDynamicAuth.Enabled && !effectiveDynamicAuth.OutboundEnabled {
			return errors.New("mobile.wimax enforce mode requires radius.dynamic_auth enabled or outbound_enabled")
		}
		if enabledSubscribers == 0 {
			return errors.New("mobile.wimax enforce mode requires at least one enabled subscriber profile")
		}
		if cfg.ServiceFlowAuthorization && enabledFlows == 0 {
			return errors.New("mobile.wimax service_flow_authorization requires at least one enabled service flow")
		}
		if enabledASN == 0 {
			return errors.New("mobile.wimax enforce mode requires at least one enabled ASN profile")
		}
		if cfg.MobilityTracking && enabledMobility == 0 {
			return errors.New("mobile.wimax mobility_tracking requires at least one enabled mobility policy")
		}
		if cfg.RedactSubscriberIDs && !cfg.HashSubscriberIDs {
			return errors.New("mobile.wimax subscriber redaction requires hash_subscriber_ids")
		}
	}
	return nil
}

func validateMobileWiMAXSubscriberProfiles(profiles []MobileWiMAXSubscriberProfile, asnProfiles, serviceFlows map[string]struct{}) (map[string]struct{}, int, error) {
	seen := map[string]struct{}{}
	enabled := 0
	for i, item := range profiles {
		name := strings.TrimSpace(item.Name)
		if !validBroadbandPPPoEText(name, 128) {
			return nil, 0, fmt.Errorf("mobile.wimax.subscriber_profiles[%d].name is invalid", i)
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			return nil, 0, fmt.Errorf("mobile.wimax.subscriber_profiles[%d] duplicates profile %q", i, key)
		}
		seen[key] = struct{}{}
		if item.Enabled {
			enabled++
		}
		if strings.TrimSpace(item.ASNProfile) != "" {
			if _, ok := asnProfiles[strings.ToLower(strings.TrimSpace(item.ASNProfile))]; !ok {
				return nil, 0, fmt.Errorf("mobile.wimax.subscriber_profiles[%d].asn_profile references unknown ASN profile %q", i, item.ASNProfile)
			}
		}
		if strings.TrimSpace(item.DefaultServiceFlow) != "" {
			if _, ok := serviceFlows[strings.ToLower(strings.TrimSpace(item.DefaultServiceFlow))]; !ok {
				return nil, 0, fmt.Errorf("mobile.wimax.subscriber_profiles[%d].default_service_flow references unknown service flow %q", i, item.DefaultServiceFlow)
			}
		}
		for _, field := range []struct {
			name  string
			value string
			limit int
		}{
			{"nai_realm", item.NAIRealm, 253},
			{"device_group", item.DeviceGroup, 128},
			{"home_agent", item.HomeAgent, 128},
			{"accounting_class", item.AccountingClass, 128},
			{"policy_profile", item.PolicyProfile, 128},
		} {
			if strings.TrimSpace(field.value) != "" && !validBroadbandPPPoEText(field.value, field.limit) {
				return nil, 0, fmt.Errorf("mobile.wimax.subscriber_profiles[%d].%s is invalid", i, field.name)
			}
		}
		for j, value := range item.VendorPacks {
			if strings.TrimSpace(value) != "" && !validBroadbandPPPoEText(value, 128) {
				return nil, 0, fmt.Errorf("mobile.wimax.subscriber_profiles[%d].vendor_packs[%d] is invalid", i, j)
			}
		}
		if err := validateMobileRadiusAttributeNames(fmt.Sprintf("mobile.wimax.subscriber_profiles[%d].radius_attributes", i), item.RadiusAttributes); err != nil {
			return nil, 0, err
		}
	}
	return seen, enabled, nil
}

func validateMobileWiMAXServiceFlows(flows []MobileWiMAXServiceFlow) (map[string]struct{}, int, error) {
	seen := map[string]struct{}{}
	enabled := 0
	for i, item := range flows {
		name := strings.TrimSpace(item.Name)
		if !validBroadbandPPPoEText(name, 128) {
			return nil, 0, fmt.Errorf("mobile.wimax.service_flows[%d].name is invalid", i)
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			return nil, 0, fmt.Errorf("mobile.wimax.service_flows[%d] duplicates service flow %q", i, key)
		}
		seen[key] = struct{}{}
		if item.Enabled {
			enabled++
		}
		switch strings.ToLower(strings.TrimSpace(item.Direction)) {
		case "", "uplink", "downlink", "bidirectional":
		default:
			return nil, 0, fmt.Errorf("mobile.wimax.service_flows[%d].direction must be uplink, downlink, or bidirectional", i)
		}
		switch strings.ToLower(strings.TrimSpace(item.SchedulingType)) {
		case "", "be", "rtps", "ertps", "nrtps", "ugs":
		default:
			return nil, 0, fmt.Errorf("mobile.wimax.service_flows[%d].scheduling_type is invalid", i)
		}
		if item.ServiceFlowID < 0 || item.ServiceFlowID > 16777215 {
			return nil, 0, fmt.Errorf("mobile.wimax.service_flows[%d].service_flow_id must be between 0 and 16777215", i)
		}
		if item.TrafficPriority < 0 || item.TrafficPriority > 7 {
			return nil, 0, fmt.Errorf("mobile.wimax.service_flows[%d].traffic_priority must be between 0 and 7", i)
		}
		for _, field := range []struct {
			name  string
			value int
		}{
			{"max_sustained_rate_kbps", item.MaxSustainedRateKbps},
			{"min_reserved_rate_kbps", item.MinReservedRateKbps},
			{"max_latency_ms", item.MaxLatencyMs},
			{"tolerated_jitter_ms", item.ToleratedJitterMs},
		} {
			if field.value < 0 {
				return nil, 0, fmt.Errorf("mobile.wimax.service_flows[%d].%s must not be negative", i, field.name)
			}
		}
		if item.MinReservedRateKbps > item.MaxSustainedRateKbps && item.MaxSustainedRateKbps > 0 {
			return nil, 0, fmt.Errorf("mobile.wimax.service_flows[%d].min_reserved_rate_kbps cannot exceed max_sustained_rate_kbps", i)
		}
		for _, field := range []struct {
			name  string
			value string
			limit int
		}{
			{"service_class", item.ServiceClass, 128},
			{"qos_profile", item.QoSProfile, 128},
			{"packet_classifier", item.PacketClassifier, 253},
		} {
			if strings.TrimSpace(field.value) != "" && !validBroadbandPPPoEText(field.value, field.limit) {
				return nil, 0, fmt.Errorf("mobile.wimax.service_flows[%d].%s is invalid", i, field.name)
			}
		}
		if err := validateMobileRadiusAttributeNames(fmt.Sprintf("mobile.wimax.service_flows[%d].radius_attributes", i), item.RadiusAttributes); err != nil {
			return nil, 0, err
		}
	}
	return seen, enabled, nil
}

func validateMobileWiMAXASNProfiles(profiles []MobileWiMAXASNProfile) (map[string]struct{}, int, error) {
	seen := map[string]struct{}{}
	enabled := 0
	for i, item := range profiles {
		name := strings.TrimSpace(item.Name)
		if !validBroadbandPPPoEText(name, 128) {
			return nil, 0, fmt.Errorf("mobile.wimax.asn_profiles[%d].name is invalid", i)
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			return nil, 0, fmt.Errorf("mobile.wimax.asn_profiles[%d] duplicates ASN profile %q", i, key)
		}
		seen[key] = struct{}{}
		if item.Enabled {
			enabled++
		}
		for _, field := range []struct {
			name  string
			value string
			limit int
		}{
			{"asn_id", item.ASNID, 64},
			{"realm", item.Realm, 253},
			{"mobility_domain", item.MobilityDomain, 128},
			{"home_agent_endpoint", item.HomeAgentEndpoint, 128},
			{"accounting_endpoint", item.AccountingEndpoint, 128},
		} {
			if strings.TrimSpace(field.value) != "" && !validBroadbandPPPoEText(field.value, field.limit) {
				return nil, 0, fmt.Errorf("mobile.wimax.asn_profiles[%d].%s is invalid", i, field.name)
			}
		}
		if err := validateMobileRadiusAttributeNames(fmt.Sprintf("mobile.wimax.asn_profiles[%d].radius_attributes", i), item.RadiusAttributes); err != nil {
			return nil, 0, err
		}
	}
	return seen, enabled, nil
}

func validateMobileWiMAXMobilityPolicies(policies []MobileWiMAXMobilityPolicy, asnProfiles map[string]struct{}) (int, error) {
	seen := map[string]struct{}{}
	enabled := 0
	for i, item := range policies {
		name := strings.TrimSpace(item.Name)
		if !validBroadbandPPPoEText(name, 128) {
			return 0, fmt.Errorf("mobile.wimax.mobility_policies[%d].name is invalid", i)
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			return 0, fmt.Errorf("mobile.wimax.mobility_policies[%d] duplicates policy %q", i, key)
		}
		seen[key] = struct{}{}
		if item.Enabled {
			enabled++
		}
		if strings.TrimSpace(item.SourceASN) != "" {
			if _, ok := asnProfiles[strings.ToLower(strings.TrimSpace(item.SourceASN))]; !ok {
				return 0, fmt.Errorf("mobile.wimax.mobility_policies[%d].source_asn references unknown ASN profile %q", i, item.SourceASN)
			}
		}
		if strings.TrimSpace(item.TargetASN) != "" {
			if _, ok := asnProfiles[strings.ToLower(strings.TrimSpace(item.TargetASN))]; !ok {
				return 0, fmt.Errorf("mobile.wimax.mobility_policies[%d].target_asn references unknown ASN profile %q", i, item.TargetASN)
			}
		}
		switch strings.ToLower(strings.TrimSpace(item.HandoverMode)) {
		case "", "hard", "optimized", "make-before-break":
		default:
			return 0, fmt.Errorf("mobile.wimax.mobility_policies[%d].handover_mode is invalid", i)
		}
		if strings.TrimSpace(item.CoAProfile) != "" && !validBroadbandPPPoEText(item.CoAProfile, 128) {
			return 0, fmt.Errorf("mobile.wimax.mobility_policies[%d].coa_profile is invalid", i)
		}
		if err := validateMobileRadiusAttributeNames(fmt.Sprintf("mobile.wimax.mobility_policies[%d].radius_attributes", i), item.RadiusAttributes); err != nil {
			return 0, err
		}
	}
	return enabled, nil
}

func defaultMobileWiMAXSubscriberProfiles() []MobileWiMAXSubscriberProfile {
	return []MobileWiMAXSubscriberProfile{
		{Name: "wimax-retail", Enabled: true, NAIRealm: "wimax.example.net", DeviceGroup: "fixed-wireless", HomeAgent: "ha-primary", ASNProfile: "asn-primary", DefaultServiceFlow: "internet-be", AccountingClass: "retail-data", PolicyProfile: "home-default", VendorPacks: []string{"wimax", "alvarion", "wichorus"}, RadiusAttributes: []string{"WiMAX-MN-NAI", "WiMAX-Session-Id", "Filter-Id", "Class"}},
		{Name: "wimax-voice", Enabled: true, NAIRealm: "voice.wimax.example.net", DeviceGroup: "voice-cpe", HomeAgent: "ha-primary", ASNProfile: "asn-primary", DefaultServiceFlow: "voice-ugs", AccountingClass: "voice-qos", PolicyProfile: "voice-priority", VendorPacks: []string{"wimax", "navini"}, RadiusAttributes: []string{"WiMAX-MN-NAI", "WiMAX-QoS-Descriptor", "Acct-Interim-Interval"}},
	}
}

func defaultMobileWiMAXServiceFlows() []MobileWiMAXServiceFlow {
	return []MobileWiMAXServiceFlow{
		{Name: "internet-be", Enabled: true, Direction: "bidirectional", ServiceClass: "best-effort", SchedulingType: "be", ServiceFlowID: 1001, QoSProfile: "internet-default", TrafficPriority: 0, MaxSustainedRateKbps: 50000, MinReservedRateKbps: 0, PacketClassifier: "permit ip any assigned", RadiusAttributes: []string{"WiMAX-Service-Flow-ID", "WiMAX-QoS-Descriptor", "WiMAX-Packet-Flow-Descriptor"}},
		{Name: "voice-ugs", Enabled: true, Direction: "bidirectional", ServiceClass: "voice", SchedulingType: "ugs", ServiceFlowID: 2001, QoSProfile: "voice-low-latency", TrafficPriority: 6, MaxSustainedRateKbps: 128, MinReservedRateKbps: 128, MaxLatencyMs: 50, ToleratedJitterMs: 10, PacketClassifier: "permit udp assigned any eq voice", RadiusAttributes: []string{"WiMAX-Service-Flow-ID", "WiMAX-QoS-Descriptor", "WiMAX-Packet-Flow-Descriptor"}},
		{Name: "iot-nrtps", Enabled: true, Direction: "bidirectional", ServiceClass: "iot-metering", SchedulingType: "nrtps", ServiceFlowID: 3001, QoSProfile: "iot-low-rate", TrafficPriority: 2, MaxSustainedRateKbps: 1024, MinReservedRateKbps: 64, MaxLatencyMs: 500, PacketClassifier: "permit ip assigned any", RadiusAttributes: []string{"WiMAX-Service-Flow-ID", "WiMAX-QoS-Descriptor", "Class"}},
	}
}

func defaultMobileWiMAXASNProfiles() []MobileWiMAXASNProfile {
	return []MobileWiMAXASNProfile{
		{Name: "asn-primary", Enabled: true, ASNID: "asn-001", Realm: "wimax.example.net", MobilityDomain: "metro-primary", HomeAgentEndpoint: "ha-primary", AccountingEndpoint: "acct-primary", RadiusAttributes: []string{"WiMAX-Session-Id", "WiMAX-Accounting-Capabilities"}},
		{Name: "asn-roaming", Enabled: true, ASNID: "asn-roam", Realm: "roaming.example.net", MobilityDomain: "partner-roaming", HomeAgentEndpoint: "ha-roaming", AccountingEndpoint: "acct-roaming", RadiusAttributes: []string{"WiMAX-Session-Id", "Class", "Acct-Interim-Interval"}},
	}
}

func defaultMobileWiMAXMobilityPolicies() []MobileWiMAXMobilityPolicy {
	return []MobileWiMAXMobilityPolicy{
		{Name: "asn-handover", Enabled: true, SourceASN: "asn-primary", TargetASN: "asn-roaming", HandoverMode: "optimized", ReauthRequired: true, CoAProfile: "wimax-handover-update", RadiusAttributes: []string{"WiMAX-Session-Id", "Class", "Acct-Interim-Interval"}},
		{Name: "roaming-reauth", Enabled: true, SourceASN: "asn-roaming", TargetASN: "asn-primary", HandoverMode: "hard", ReauthRequired: true, CoAProfile: "wimax-roaming-reauth", RadiusAttributes: []string{"WiMAX-MN-NAI", "WiMAX-Session-Id", "Session-Timeout"}},
	}
}
