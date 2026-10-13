package config

import (
	"errors"
	"fmt"
	"strings"
)

type MobileSessionConfig struct {
	Enabled              bool                         `mapstructure:"enabled"`
	Mode                 string                       `mapstructure:"mode"`
	FailClosed           bool                         `mapstructure:"fail_closed"`
	RequireDatabase      bool                         `mapstructure:"require_database"`
	RequireGroupedAVPs   bool                         `mapstructure:"require_grouped_avps"`
	RequireAccounting    bool                         `mapstructure:"require_accounting"`
	RequireDynamicAuth   bool                         `mapstructure:"require_dynamic_auth"`
	MaxSessions          int                          `mapstructure:"max_sessions"`
	SessionRetentionDays int                          `mapstructure:"session_retention_days"`
	EventRetentionLimit  int                          `mapstructure:"event_retention_limit"`
	DefaultAPN           string                       `mapstructure:"default_apn"`
	DefaultPDNType       string                       `mapstructure:"default_pdn_type"`
	StateReconciliation  bool                         `mapstructure:"state_reconciliation"`
	HandoverTracking     bool                         `mapstructure:"handover_tracking"`
	RoamingTracking      bool                         `mapstructure:"roaming_tracking"`
	RedactSubscriberIDs  bool                         `mapstructure:"redact_subscriber_ids"`
	HashSubscriberIDs    bool                         `mapstructure:"hash_subscriber_ids"`
	APNProfiles          []MobileAPNProfileConfig     `mapstructure:"apn_profiles"`
	BearerTemplates      []MobileBearerTemplateConfig `mapstructure:"bearer_templates"`
	RoamingPartners      []MobileRoamingPartnerConfig `mapstructure:"roaming_partners"`
}

type MobileAPNProfileConfig struct {
	Name                 string   `mapstructure:"name"`
	Enabled              bool     `mapstructure:"enabled"`
	APN                  string   `mapstructure:"apn"`
	PDNType              string   `mapstructure:"pdn_type"`
	IPv4Pool             string   `mapstructure:"ipv4_pool"`
	IPv6PrefixPool       string   `mapstructure:"ipv6_prefix_pool"`
	QoSProfile           string   `mapstructure:"qos_profile"`
	ChargingProfile      string   `mapstructure:"charging_profile"`
	PolicyProfile        string   `mapstructure:"policy_profile"`
	DefaultBearer        string   `mapstructure:"default_bearer"`
	RoamingAllowed       bool     `mapstructure:"roaming_allowed"`
	LawfulInterceptGroup string   `mapstructure:"lawful_intercept_group"`
	RadiusAttributes     []string `mapstructure:"radius_attributes"`
}

type MobileBearerTemplateConfig struct {
	Name                    string   `mapstructure:"name"`
	Enabled                 bool     `mapstructure:"enabled"`
	BearerType              string   `mapstructure:"bearer_type"`
	QCI                     int      `mapstructure:"qci"`
	ARP                     int      `mapstructure:"arp"`
	Priority                int      `mapstructure:"priority"`
	GBRDownKbps             int      `mapstructure:"gbr_down_kbps"`
	GBRUpKbps               int      `mapstructure:"gbr_up_kbps"`
	MBRDownKbps             int      `mapstructure:"mbr_down_kbps"`
	MBRUpKbps               int      `mapstructure:"mbr_up_kbps"`
	PreemptionCapability    bool     `mapstructure:"preemption_capability"`
	PreemptionVulnerability bool     `mapstructure:"preemption_vulnerability"`
	TrafficFlowTemplates    []string `mapstructure:"traffic_flow_templates"`
	RadiusAttributes        []string `mapstructure:"radius_attributes"`
}

type MobileRoamingPartnerConfig struct {
	Name               string   `mapstructure:"name"`
	Enabled            bool     `mapstructure:"enabled"`
	Realm              string   `mapstructure:"realm"`
	MCCMNC             string   `mapstructure:"mcc_mnc"`
	VisitedPolicy      string   `mapstructure:"visited_policy"`
	HomePolicy         string   `mapstructure:"home_policy"`
	AllowLocalBreakout bool     `mapstructure:"allow_local_breakout"`
	AllowedAPNs        []string `mapstructure:"allowed_apns"`
	RadiusAttributes   []string `mapstructure:"radius_attributes"`
}

func EffectiveMobileSessionConfig(raw MobileSessionConfig) MobileSessionConfig {
	cfg := raw
	cfg.Mode = effectiveMobileSessionMode(cfg.Mode)
	cfg.DefaultPDNType = effectiveMobilePDNType(cfg.DefaultPDNType)
	if cfg.MaxSessions == 0 {
		cfg.MaxSessions = 100000
	}
	if cfg.SessionRetentionDays == 0 {
		cfg.SessionRetentionDays = 90
	}
	if cfg.EventRetentionLimit == 0 {
		cfg.EventRetentionLimit = 10000
	}
	if strings.TrimSpace(cfg.DefaultAPN) == "" {
		cfg.DefaultAPN = "internet"
	}
	if !raw.RequireDatabase && !raw.RequireGroupedAVPs && !raw.RequireAccounting && !raw.RequireDynamicAuth {
		cfg.RequireDatabase = true
		cfg.RequireGroupedAVPs = true
		cfg.RequireAccounting = true
		cfg.RequireDynamicAuth = true
	}
	if !raw.RedactSubscriberIDs && !raw.HashSubscriberIDs {
		cfg.RedactSubscriberIDs = true
		cfg.HashSubscriberIDs = true
	}
	if len(cfg.APNProfiles) == 0 {
		cfg.APNProfiles = defaultMobileAPNProfiles()
	}
	if len(cfg.BearerTemplates) == 0 {
		cfg.BearerTemplates = defaultMobileBearerTemplates()
	}
	if len(cfg.RoamingPartners) == 0 {
		cfg.RoamingPartners = defaultMobileRoamingPartners()
	}
	return cfg
}

func effectiveMobileSessionMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "monitor", "enforce":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "monitor"
	}
}

func effectiveMobilePDNType(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if validMobilePDNType(normalized) && normalized != "" {
		return normalized
	}
	return "ipv4v6"
}

func validMobilePDNType(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "ipv4", "ipv6", "ipv4v6":
		return true
	default:
		return false
	}
}

func validateMobileSessionConfig(raw MobileSessionConfig, profile string) error {
	cfg := EffectiveMobileSessionConfig(raw)
	if !cfg.Enabled && len(raw.APNProfiles) == 0 && len(raw.BearerTemplates) == 0 && len(raw.RoamingPartners) == 0 {
		return nil
	}
	if profile == "lite" && cfg.Mode == "enforce" {
		return errors.New("mobile.sessions cannot use enforce mode on lite deployment profile")
	}
	if cfg.MaxSessions < 1 || cfg.MaxSessions > 10000000 {
		return errors.New("mobile.sessions.max_sessions must be between 1 and 10000000")
	}
	if cfg.SessionRetentionDays < 1 || cfg.SessionRetentionDays > 3650 {
		return errors.New("mobile.sessions.session_retention_days must be between 1 and 3650")
	}
	if cfg.EventRetentionLimit < 0 || cfg.EventRetentionLimit > 1000000 {
		return errors.New("mobile.sessions.event_retention_limit must be between 0 and 1000000")
	}
	if strings.TrimSpace(cfg.DefaultAPN) != "" && !validBroadbandPPPoEText(cfg.DefaultAPN, 128) {
		return errors.New("mobile.sessions.default_apn is invalid")
	}
	apns, enabledAPNs, err := validateMobileAPNProfiles(cfg.APNProfiles)
	if err != nil {
		return err
	}
	bearers, enabledBearers, err := validateMobileBearerTemplates(cfg.BearerTemplates)
	if err != nil {
		return err
	}
	enabledRoaming, err := validateMobileRoamingPartners(cfg.RoamingPartners, apns)
	if err != nil {
		return err
	}
	if cfg.Enabled && cfg.Mode == "enforce" {
		if enabledAPNs == 0 {
			return errors.New("mobile.sessions enforce mode requires at least one enabled APN profile")
		}
		if enabledBearers == 0 {
			return errors.New("mobile.sessions enforce mode requires at least one enabled bearer template")
		}
		if _, ok := apns[strings.ToLower(strings.TrimSpace(cfg.DefaultAPN))]; !ok {
			return fmt.Errorf("mobile.sessions.default_apn %q must match an APN profile", cfg.DefaultAPN)
		}
		if cfg.RequireGroupedAVPs && len(bearers) == 0 {
			return errors.New("mobile.sessions grouped AVP enforcement requires bearer templates")
		}
		if cfg.RoamingTracking && enabledRoaming == 0 {
			return errors.New("mobile.sessions roaming_tracking requires at least one enabled roaming partner")
		}
		if cfg.RedactSubscriberIDs && !cfg.HashSubscriberIDs {
			return errors.New("mobile.sessions subscriber redaction requires hash_subscriber_ids")
		}
	}
	return nil
}

func validateMobileAPNProfiles(profiles []MobileAPNProfileConfig) (map[string]struct{}, int, error) {
	seen := map[string]struct{}{}
	enabled := 0
	for i, profile := range profiles {
		name := strings.TrimSpace(profile.Name)
		if !validBroadbandPPPoEText(name, 128) {
			return nil, 0, fmt.Errorf("mobile.sessions.apn_profiles[%d].name is invalid", i)
		}
		apn := strings.TrimSpace(profile.APN)
		if !validBroadbandPPPoEText(apn, 128) {
			return nil, 0, fmt.Errorf("mobile.sessions.apn_profiles[%d].apn is invalid", i)
		}
		key := strings.ToLower(apn)
		if _, exists := seen[key]; exists {
			return nil, 0, fmt.Errorf("mobile.sessions.apn_profiles[%d] duplicates APN %q", i, key)
		}
		seen[key] = struct{}{}
		if profile.Enabled {
			enabled++
		}
		if !validMobilePDNType(profile.PDNType) {
			return nil, 0, fmt.Errorf("mobile.sessions.apn_profiles[%d].pdn_type is invalid", i)
		}
		for _, field := range []struct {
			name  string
			value string
			limit int
		}{
			{"ipv4_pool", profile.IPv4Pool, 128},
			{"ipv6_prefix_pool", profile.IPv6PrefixPool, 128},
			{"qos_profile", profile.QoSProfile, 128},
			{"charging_profile", profile.ChargingProfile, 128},
			{"policy_profile", profile.PolicyProfile, 128},
			{"default_bearer", profile.DefaultBearer, 128},
			{"lawful_intercept_group", profile.LawfulInterceptGroup, 128},
		} {
			if strings.TrimSpace(field.value) != "" && !validBroadbandPPPoEText(field.value, field.limit) {
				return nil, 0, fmt.Errorf("mobile.sessions.apn_profiles[%d].%s is invalid", i, field.name)
			}
		}
		if err := validateMobileRadiusAttributeNames(fmt.Sprintf("mobile.sessions.apn_profiles[%d].radius_attributes", i), profile.RadiusAttributes); err != nil {
			return nil, 0, err
		}
	}
	return seen, enabled, nil
}

func validateMobileBearerTemplates(templates []MobileBearerTemplateConfig) (map[string]struct{}, int, error) {
	seen := map[string]struct{}{}
	enabled := 0
	for i, item := range templates {
		name := strings.TrimSpace(item.Name)
		if !validBroadbandPPPoEText(name, 128) {
			return nil, 0, fmt.Errorf("mobile.sessions.bearer_templates[%d].name is invalid", i)
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			return nil, 0, fmt.Errorf("mobile.sessions.bearer_templates[%d] duplicates bearer %q", i, key)
		}
		seen[key] = struct{}{}
		if item.Enabled {
			enabled++
		}
		switch strings.ToLower(strings.TrimSpace(item.BearerType)) {
		case "", "default", "dedicated":
		default:
			return nil, 0, fmt.Errorf("mobile.sessions.bearer_templates[%d].bearer_type is invalid", i)
		}
		if item.QCI < 0 || item.QCI > 255 {
			return nil, 0, fmt.Errorf("mobile.sessions.bearer_templates[%d].qci must be between 0 and 255", i)
		}
		if item.ARP < 0 || item.ARP > 15 {
			return nil, 0, fmt.Errorf("mobile.sessions.bearer_templates[%d].arp must be between 0 and 15", i)
		}
		for field, value := range map[string]int{
			"gbr_down_kbps": item.GBRDownKbps,
			"gbr_up_kbps":   item.GBRUpKbps,
			"mbr_down_kbps": item.MBRDownKbps,
			"mbr_up_kbps":   item.MBRUpKbps,
			"priority":      item.Priority,
		} {
			if value < 0 {
				return nil, 0, fmt.Errorf("mobile.sessions.bearer_templates[%d].%s must not be negative", i, field)
			}
		}
		if err := validateMobileRadiusAttributeNames(fmt.Sprintf("mobile.sessions.bearer_templates[%d].radius_attributes", i), item.RadiusAttributes); err != nil {
			return nil, 0, err
		}
		for j, flow := range item.TrafficFlowTemplates {
			if strings.TrimSpace(flow) != "" && !validBroadbandPPPoEText(flow, 253) {
				return nil, 0, fmt.Errorf("mobile.sessions.bearer_templates[%d].traffic_flow_templates[%d] is invalid", i, j)
			}
		}
	}
	return seen, enabled, nil
}

func validateMobileRoamingPartners(partners []MobileRoamingPartnerConfig, apns map[string]struct{}) (int, error) {
	seen := map[string]struct{}{}
	enabled := 0
	for i, partner := range partners {
		name := strings.TrimSpace(partner.Name)
		if !validBroadbandPPPoEText(name, 128) {
			return 0, fmt.Errorf("mobile.sessions.roaming_partners[%d].name is invalid", i)
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			return 0, fmt.Errorf("mobile.sessions.roaming_partners[%d] duplicates partner %q", i, key)
		}
		seen[key] = struct{}{}
		if partner.Enabled {
			enabled++
		}
		for _, field := range []struct {
			name  string
			value string
			limit int
		}{
			{"realm", partner.Realm, 253},
			{"mcc_mnc", partner.MCCMNC, 16},
			{"visited_policy", partner.VisitedPolicy, 128},
			{"home_policy", partner.HomePolicy, 128},
		} {
			if strings.TrimSpace(field.value) != "" && !validBroadbandPPPoEText(field.value, field.limit) {
				return 0, fmt.Errorf("mobile.sessions.roaming_partners[%d].%s is invalid", i, field.name)
			}
		}
		for j, apn := range partner.AllowedAPNs {
			key := strings.ToLower(strings.TrimSpace(apn))
			if key == "" {
				continue
			}
			if _, ok := apns[key]; !ok {
				return 0, fmt.Errorf("mobile.sessions.roaming_partners[%d].allowed_apns[%d] references unknown APN %q", i, j, apn)
			}
		}
		if err := validateMobileRadiusAttributeNames(fmt.Sprintf("mobile.sessions.roaming_partners[%d].radius_attributes", i), partner.RadiusAttributes); err != nil {
			return 0, err
		}
	}
	return enabled, nil
}

func validateMobileRadiusAttributeNames(path string, values []string) error {
	for i, value := range values {
		if strings.TrimSpace(value) != "" && !validBroadbandPPPoEText(strings.TrimSpace(value), 253) {
			return fmt.Errorf("%s[%d] is not a valid RADIUS attribute name", path, i)
		}
	}
	return nil
}

func defaultMobileAPNProfiles() []MobileAPNProfileConfig {
	return []MobileAPNProfileConfig{
		{
			Name:                 "default-internet",
			Enabled:              true,
			APN:                  "internet",
			PDNType:              "ipv4v6",
			IPv4Pool:             "mobile-v4",
			IPv6PrefixPool:       "mobile-v6",
			QoSProfile:           "default-qos",
			ChargingProfile:      "online-offline-default",
			PolicyProfile:        "home-default",
			DefaultBearer:        "default-bearer",
			RoamingAllowed:       true,
			LawfulInterceptGroup: "standard-retention",
			RadiusAttributes:     []string{"3GPP-IMSI", "3GPP-Charging-ID", "3GPP-RAT-Type", "Framed-IP-Address", "Framed-IPv6-Prefix", "Acct-Interim-Interval"},
		},
		{
			Name:                 "iot-private",
			Enabled:              true,
			APN:                  "iot.private",
			PDNType:              "ipv4v6",
			IPv4Pool:             "iot-v4",
			IPv6PrefixPool:       "iot-v6",
			QoSProfile:           "iot-low-bandwidth",
			ChargingProfile:      "iot-usage",
			PolicyProfile:        "iot-isolated",
			DefaultBearer:        "iot-default-bearer",
			RoamingAllowed:       false,
			LawfulInterceptGroup: "iot-retention",
			RadiusAttributes:     []string{"3GPP-IMSI", "3GPP-IMEISV", "3GPP-Selection-Mode", "Class", "Filter-Id"},
		},
	}
}

func defaultMobileBearerTemplates() []MobileBearerTemplateConfig {
	return []MobileBearerTemplateConfig{
		{
			Name:                 "default-bearer",
			Enabled:              true,
			BearerType:           "default",
			QCI:                  9,
			ARP:                  8,
			Priority:             100,
			MBRDownKbps:          50000,
			MBRUpKbps:            10000,
			TrafficFlowTemplates: []string{"permit out ip from any to assigned"},
			RadiusAttributes:     []string{"3GPP-GPRS-Negotiated-QoS-profile", "3GPP-Negotiated-DSCP", "Session-Timeout"},
		},
		{
			Name:                 "dedicated-qos",
			Enabled:              true,
			BearerType:           "dedicated",
			QCI:                  5,
			ARP:                  4,
			Priority:             50,
			GBRDownKbps:          512,
			GBRUpKbps:            512,
			MBRDownKbps:          5000,
			MBRUpKbps:            5000,
			PreemptionCapability: true,
			TrafficFlowTemplates: []string{"permit out udp from any to assigned 5060", "permit in udp from assigned 5060 to any"},
			RadiusAttributes:     []string{"3GPP-GPRS-Negotiated-QoS-profile", "Filter-Id"},
		},
	}
}

func defaultMobileRoamingPartners() []MobileRoamingPartnerConfig {
	return []MobileRoamingPartnerConfig{
		{
			Name:               "home-plmn",
			Enabled:            true,
			Realm:              "mnc001.mcc001.3gppnetwork.org",
			MCCMNC:             "00101",
			VisitedPolicy:      "home-default",
			HomePolicy:         "home-default",
			AllowLocalBreakout: true,
			AllowedAPNs:        []string{"internet", "iot.private"},
			RadiusAttributes:   []string{"3GPP-IMSI-MCC-MNC", "3GPP-Selection-Mode"},
		},
		{
			Name:               "visited-roaming",
			Enabled:            true,
			Realm:              "roaming.example.net",
			MCCMNC:             "99999",
			VisitedPolicy:      "visited-lbo",
			HomePolicy:         "home-roaming",
			AllowLocalBreakout: false,
			AllowedAPNs:        []string{"internet"},
			RadiusAttributes:   []string{"3GPP-RAT-Type", "3GPP-Selection-Mode", "Class"},
		},
	}
}
