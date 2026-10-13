package config

import (
	"errors"
	"fmt"
	"strings"
)

type MobilePolicyControlConfig struct {
	Enabled                      bool                              `mapstructure:"enabled"`
	Mode                         string                            `mapstructure:"mode"`
	FailClosed                   bool                              `mapstructure:"fail_closed"`
	RequireDatabase              bool                              `mapstructure:"require_database"`
	RequireMobileSessions        bool                              `mapstructure:"require_mobile_sessions"`
	RequirePolicyEngine          bool                              `mapstructure:"require_policy_engine"`
	RequireQoS                   bool                              `mapstructure:"require_qos"`
	RequireDynamicAuth           bool                              `mapstructure:"require_dynamic_auth"`
	RequireCharging              bool                              `mapstructure:"require_charging"`
	RoamingControl               bool                              `mapstructure:"roaming_control"`
	EnforcementFeedback          bool                              `mapstructure:"enforcement_feedback"`
	RedactSubscriberIDs          bool                              `mapstructure:"redact_subscriber_ids"`
	HashSubscriberIDs            bool                              `mapstructure:"hash_subscriber_ids"`
	DecisionRetentionDays        int                               `mapstructure:"decision_retention_days"`
	EventRetentionLimit          int                               `mapstructure:"event_retention_limit"`
	MaxPolicyDecisions           int                               `mapstructure:"max_policy_decisions"`
	DefaultPolicyProfile         string                            `mapstructure:"default_policy_profile"`
	DefaultQoSClass              string                            `mapstructure:"default_qos_class"`
	DefaultRoamingPolicy         string                            `mapstructure:"default_roaming_policy"`
	PolicyProfiles               []MobilePolicyProfileConfig       `mapstructure:"policy_profiles"`
	QoSClasses                   []MobilePolicyQoSClassConfig      `mapstructure:"qos_classes"`
	RoamingPolicies              []MobilePolicyRoamingPolicyConfig `mapstructure:"roaming_policies"`
	FeedbackRules                []MobilePolicyFeedbackRuleConfig  `mapstructure:"feedback_rules"`
	PolicyAttributes             []string                          `mapstructure:"policy_attributes"`
	ExternalControllerReferences []string                          `mapstructure:"external_controller_references"`
}

type MobilePolicyProfileConfig struct {
	Name               string   `mapstructure:"name"`
	Enabled            bool     `mapstructure:"enabled"`
	APN                string   `mapstructure:"apn"`
	Role               string   `mapstructure:"role"`
	PolicyProfile      string   `mapstructure:"policy_profile"`
	QoSClass           string   `mapstructure:"qos_class"`
	RoamingPolicy      string   `mapstructure:"roaming_policy"`
	ChargingProfile    string   `mapstructure:"charging_profile"`
	Precedence         int      `mapstructure:"precedence"`
	VendorPacks        []string `mapstructure:"vendor_packs"`
	RadiusAttributes   []string `mapstructure:"radius_attributes"`
	EnforcementActions []string `mapstructure:"enforcement_actions"`
}

type MobilePolicyQoSClassConfig struct {
	Name                    string   `mapstructure:"name"`
	Enabled                 bool     `mapstructure:"enabled"`
	QCI                     int      `mapstructure:"qci"`
	FiveQI                  int      `mapstructure:"five_qi"`
	ARP                     int      `mapstructure:"arp"`
	Priority                int      `mapstructure:"priority"`
	GBRDownKbps             int      `mapstructure:"gbr_down_kbps"`
	GBRUpKbps               int      `mapstructure:"gbr_up_kbps"`
	MBRDownKbps             int      `mapstructure:"mbr_down_kbps"`
	MBRUpKbps               int      `mapstructure:"mbr_up_kbps"`
	PreemptionCapability    bool     `mapstructure:"preemption_capability"`
	PreemptionVulnerability bool     `mapstructure:"preemption_vulnerability"`
	DSCP                    string   `mapstructure:"dscp"`
	TrafficClass            string   `mapstructure:"traffic_class"`
	TrafficFlowTemplates    []string `mapstructure:"traffic_flow_templates"`
	RadiusAttributes        []string `mapstructure:"radius_attributes"`
}

type MobilePolicyRoamingPolicyConfig struct {
	Name             string   `mapstructure:"name"`
	Enabled          bool     `mapstructure:"enabled"`
	HomeRealm        string   `mapstructure:"home_realm"`
	VisitedRealm     string   `mapstructure:"visited_realm"`
	HomeMCCMNC       string   `mapstructure:"home_mcc_mnc"`
	VisitedMCCMNC    string   `mapstructure:"visited_mcc_mnc"`
	HomePolicy       string   `mapstructure:"home_policy"`
	VisitedPolicy    string   `mapstructure:"visited_policy"`
	LocalBreakout    bool     `mapstructure:"local_breakout"`
	SteeringAction   string   `mapstructure:"steering_action"`
	AllowedAPNs      []string `mapstructure:"allowed_apns"`
	RadiusAttributes []string `mapstructure:"radius_attributes"`
}

type MobilePolicyFeedbackRuleConfig struct {
	Name             string   `mapstructure:"name"`
	Enabled          bool     `mapstructure:"enabled"`
	Source           string   `mapstructure:"source"`
	Trigger          string   `mapstructure:"trigger"`
	Action           string   `mapstructure:"action"`
	PolicyProfile    string   `mapstructure:"policy_profile"`
	CoAProfile       string   `mapstructure:"coa_profile"`
	CooldownSeconds  int      `mapstructure:"cooldown_seconds"`
	RadiusAttributes []string `mapstructure:"radius_attributes"`
}

func EffectiveMobilePolicyControlConfig(raw MobilePolicyControlConfig) MobilePolicyControlConfig {
	cfg := raw
	cfg.Mode = effectiveMobilePolicyControlMode(cfg.Mode)
	if cfg.DecisionRetentionDays == 0 {
		cfg.DecisionRetentionDays = 90
	}
	if cfg.EventRetentionLimit == 0 {
		cfg.EventRetentionLimit = 10000
	}
	if cfg.MaxPolicyDecisions == 0 {
		cfg.MaxPolicyDecisions = 100000
	}
	if !raw.RequireDatabase && !raw.RequireMobileSessions && !raw.RequirePolicyEngine &&
		!raw.RequireQoS && !raw.RequireDynamicAuth && !raw.RequireCharging {
		cfg.RequireDatabase = true
		cfg.RequireMobileSessions = true
		cfg.RequirePolicyEngine = true
		cfg.RequireQoS = true
		cfg.RequireDynamicAuth = true
		cfg.RequireCharging = true
	}
	if !raw.RoamingControl && !raw.EnforcementFeedback {
		cfg.RoamingControl = true
		cfg.EnforcementFeedback = true
	}
	if !raw.RedactSubscriberIDs && !raw.HashSubscriberIDs {
		cfg.RedactSubscriberIDs = true
		cfg.HashSubscriberIDs = true
	}
	if strings.TrimSpace(cfg.DefaultPolicyProfile) == "" {
		cfg.DefaultPolicyProfile = "home-default"
	}
	if strings.TrimSpace(cfg.DefaultQoSClass) == "" {
		cfg.DefaultQoSClass = "default-5qi-9"
	}
	if strings.TrimSpace(cfg.DefaultRoamingPolicy) == "" {
		cfg.DefaultRoamingPolicy = "home-plmn"
	}
	if len(cfg.PolicyProfiles) == 0 {
		cfg.PolicyProfiles = defaultMobilePolicyProfiles()
	}
	if len(cfg.QoSClasses) == 0 {
		cfg.QoSClasses = defaultMobilePolicyQoSClasses()
	}
	if len(cfg.RoamingPolicies) == 0 {
		cfg.RoamingPolicies = defaultMobilePolicyRoamingPolicies()
	}
	if len(cfg.FeedbackRules) == 0 {
		cfg.FeedbackRules = defaultMobilePolicyFeedbackRules()
	}
	if len(cfg.PolicyAttributes) == 0 {
		cfg.PolicyAttributes = []string{"3GPP-IMSI", "3GPP-RAT-Type", "3GPP-Selection-Mode", "3GPP-GPRS-Negotiated-QoS-profile", "3GPP-Negotiated-DSCP", "Filter-Id", "Class", "Session-Timeout", "Acct-Interim-Interval"}
	}
	if len(cfg.ExternalControllerReferences) == 0 {
		cfg.ExternalControllerReferences = []string{"PCRF", "PCF", "OCS", "roaming-clearinghouse"}
	}
	return cfg
}

func effectiveMobilePolicyControlMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "monitor", "enforce":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "monitor"
	}
}

func validateMobilePolicyControlConfig(raw MobilePolicyControlConfig, sessions MobileSessionConfig, charging MobileChargingConfig, radius RadiusConfig, policy PolicyConfig, broadbandQoS BroadbandQoSServiceFlowConfig, profile string) error {
	cfg := EffectiveMobilePolicyControlConfig(raw)
	if !cfg.Enabled && len(raw.PolicyProfiles) == 0 && len(raw.QoSClasses) == 0 && len(raw.RoamingPolicies) == 0 && len(raw.FeedbackRules) == 0 {
		return nil
	}
	if profile == "lite" && cfg.Mode == "enforce" {
		return errors.New("mobile.policy_control cannot use enforce mode on lite deployment profile")
	}
	if cfg.DecisionRetentionDays < 1 || cfg.DecisionRetentionDays > 3650 {
		return errors.New("mobile.policy_control.decision_retention_days must be between 1 and 3650")
	}
	if cfg.EventRetentionLimit < 0 || cfg.EventRetentionLimit > 1000000 {
		return errors.New("mobile.policy_control.event_retention_limit must be between 0 and 1000000")
	}
	if cfg.MaxPolicyDecisions < 1 || cfg.MaxPolicyDecisions > 10000000 {
		return errors.New("mobile.policy_control.max_policy_decisions must be between 1 and 10000000")
	}
	qosClasses, enabledQoSClasses, err := validateMobilePolicyQoSClasses(cfg.QoSClasses)
	if err != nil {
		return err
	}
	roamingPolicies, enabledRoamingPolicies, err := validateMobilePolicyRoamingPolicies(cfg.RoamingPolicies)
	if err != nil {
		return err
	}
	policyProfiles, enabledPolicyProfiles, err := validateMobilePolicyProfiles(cfg.PolicyProfiles, qosClasses, roamingPolicies)
	if err != nil {
		return err
	}
	enabledFeedbackRules, err := validateMobilePolicyFeedbackRules(cfg.FeedbackRules, policyProfiles)
	if err != nil {
		return err
	}
	if err := validateMobileRadiusAttributeNames("mobile.policy_control.policy_attributes", cfg.PolicyAttributes); err != nil {
		return err
	}
	for i, ref := range cfg.ExternalControllerReferences {
		if strings.TrimSpace(ref) != "" && !validBroadbandPPPoEText(ref, 128) {
			return fmt.Errorf("mobile.policy_control.external_controller_references[%d] is invalid", i)
		}
	}
	if _, ok := policyProfiles[strings.ToLower(strings.TrimSpace(cfg.DefaultPolicyProfile))]; strings.TrimSpace(cfg.DefaultPolicyProfile) != "" && !ok {
		return fmt.Errorf("mobile.policy_control.default_policy_profile %q must match a policy profile", cfg.DefaultPolicyProfile)
	}
	if _, ok := qosClasses[strings.ToLower(strings.TrimSpace(cfg.DefaultQoSClass))]; strings.TrimSpace(cfg.DefaultQoSClass) != "" && !ok {
		return fmt.Errorf("mobile.policy_control.default_qos_class %q must match a QoS class", cfg.DefaultQoSClass)
	}
	if _, ok := roamingPolicies[strings.ToLower(strings.TrimSpace(cfg.DefaultRoamingPolicy))]; strings.TrimSpace(cfg.DefaultRoamingPolicy) != "" && !ok {
		return fmt.Errorf("mobile.policy_control.default_roaming_policy %q must match a roaming policy", cfg.DefaultRoamingPolicy)
	}
	if cfg.Enabled && cfg.Mode == "enforce" {
		effectiveSessions := EffectiveMobileSessionConfig(sessions)
		effectiveCharging := EffectiveMobileChargingConfig(charging)
		effectiveQoS := EffectiveBroadbandQoSServiceFlowConfig(broadbandQoS)
		effectiveDynamicAuth := EffectiveDynamicAuthConfig(radius.DynamicAuth)
		if cfg.RequireMobileSessions && !effectiveSessions.Enabled {
			return errors.New("mobile.policy_control enforce mode requires mobile.sessions.enabled")
		}
		if cfg.RequireCharging && !effectiveCharging.Enabled {
			return errors.New("mobile.policy_control enforce mode requires mobile.charging.enabled")
		}
		if cfg.RequirePolicyEngine && !policy.TypedEngineEnabled {
			return errors.New("mobile.policy_control enforce mode requires policy.typed_engine_enabled")
		}
		if cfg.RequireQoS && !policy.RuntimeShapingEnabled && !effectiveQoS.Enabled {
			return errors.New("mobile.policy_control enforce mode requires runtime shaping or broadband.qos_service_flows.enabled")
		}
		if cfg.RequireDynamicAuth && !effectiveDynamicAuth.Enabled && !effectiveDynamicAuth.OutboundEnabled {
			return errors.New("mobile.policy_control enforce mode requires radius.dynamic_auth enabled or outbound_enabled")
		}
		if enabledPolicyProfiles == 0 {
			return errors.New("mobile.policy_control enforce mode requires at least one enabled policy profile")
		}
		if enabledQoSClasses == 0 {
			return errors.New("mobile.policy_control enforce mode requires at least one enabled QoS class")
		}
		if cfg.RoamingControl && enabledRoamingPolicies == 0 {
			return errors.New("mobile.policy_control roaming_control requires at least one enabled roaming policy")
		}
		if cfg.EnforcementFeedback && enabledFeedbackRules == 0 {
			return errors.New("mobile.policy_control enforcement_feedback requires at least one enabled feedback rule")
		}
		if cfg.RedactSubscriberIDs && !cfg.HashSubscriberIDs {
			return errors.New("mobile.policy_control subscriber redaction requires hash_subscriber_ids")
		}
	}
	return nil
}

func validateMobilePolicyProfiles(profiles []MobilePolicyProfileConfig, qosClasses, roamingPolicies map[string]struct{}) (map[string]struct{}, int, error) {
	seen := map[string]struct{}{}
	enabled := 0
	for i, item := range profiles {
		name := strings.TrimSpace(item.Name)
		if !validBroadbandPPPoEText(name, 128) {
			return nil, 0, fmt.Errorf("mobile.policy_control.policy_profiles[%d].name is invalid", i)
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			return nil, 0, fmt.Errorf("mobile.policy_control.policy_profiles[%d] duplicates profile %q", i, key)
		}
		seen[key] = struct{}{}
		if item.Enabled {
			enabled++
		}
		if item.Precedence < 0 || item.Precedence > 1000000 {
			return nil, 0, fmt.Errorf("mobile.policy_control.policy_profiles[%d].precedence must be non-negative", i)
		}
		for _, field := range []struct {
			name  string
			value string
			limit int
		}{
			{"apn", item.APN, 128},
			{"role", item.Role, 128},
			{"policy_profile", item.PolicyProfile, 128},
			{"charging_profile", item.ChargingProfile, 128},
		} {
			if strings.TrimSpace(field.value) != "" && !validBroadbandPPPoEText(field.value, field.limit) {
				return nil, 0, fmt.Errorf("mobile.policy_control.policy_profiles[%d].%s is invalid", i, field.name)
			}
		}
		if strings.TrimSpace(item.QoSClass) != "" {
			if _, ok := qosClasses[strings.ToLower(strings.TrimSpace(item.QoSClass))]; !ok {
				return nil, 0, fmt.Errorf("mobile.policy_control.policy_profiles[%d].qos_class references unknown QoS class %q", i, item.QoSClass)
			}
		}
		if strings.TrimSpace(item.RoamingPolicy) != "" {
			if _, ok := roamingPolicies[strings.ToLower(strings.TrimSpace(item.RoamingPolicy))]; !ok {
				return nil, 0, fmt.Errorf("mobile.policy_control.policy_profiles[%d].roaming_policy references unknown roaming policy %q", i, item.RoamingPolicy)
			}
		}
		for name, values := range map[string][]string{
			"vendor_packs":        item.VendorPacks,
			"enforcement_actions": item.EnforcementActions,
		} {
			for j, value := range values {
				if strings.TrimSpace(value) != "" && !validBroadbandPPPoEText(value, 128) {
					return nil, 0, fmt.Errorf("mobile.policy_control.policy_profiles[%d].%s[%d] is invalid", i, name, j)
				}
			}
		}
		if err := validateMobileRadiusAttributeNames(fmt.Sprintf("mobile.policy_control.policy_profiles[%d].radius_attributes", i), item.RadiusAttributes); err != nil {
			return nil, 0, err
		}
	}
	return seen, enabled, nil
}

func validateMobilePolicyQoSClasses(classes []MobilePolicyQoSClassConfig) (map[string]struct{}, int, error) {
	seen := map[string]struct{}{}
	enabled := 0
	for i, item := range classes {
		name := strings.TrimSpace(item.Name)
		if !validBroadbandPPPoEText(name, 128) {
			return nil, 0, fmt.Errorf("mobile.policy_control.qos_classes[%d].name is invalid", i)
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			return nil, 0, fmt.Errorf("mobile.policy_control.qos_classes[%d] duplicates class %q", i, key)
		}
		seen[key] = struct{}{}
		if item.Enabled {
			enabled++
		}
		if item.QCI < 0 || item.QCI > 255 {
			return nil, 0, fmt.Errorf("mobile.policy_control.qos_classes[%d].qci must be between 0 and 255", i)
		}
		if item.FiveQI < 0 || item.FiveQI > 255 {
			return nil, 0, fmt.Errorf("mobile.policy_control.qos_classes[%d].five_qi must be between 0 and 255", i)
		}
		if item.ARP < 0 || item.ARP > 15 {
			return nil, 0, fmt.Errorf("mobile.policy_control.qos_classes[%d].arp must be between 0 and 15", i)
		}
		if item.Priority < 0 || item.Priority > 1000000 {
			return nil, 0, fmt.Errorf("mobile.policy_control.qos_classes[%d].priority must be non-negative", i)
		}
		for _, field := range []struct {
			name  string
			value int
		}{
			{"gbr_down_kbps", item.GBRDownKbps},
			{"gbr_up_kbps", item.GBRUpKbps},
			{"mbr_down_kbps", item.MBRDownKbps},
			{"mbr_up_kbps", item.MBRUpKbps},
		} {
			if field.value < 0 {
				return nil, 0, fmt.Errorf("mobile.policy_control.qos_classes[%d].%s must not be negative", i, field.name)
			}
		}
		for _, field := range []struct {
			name  string
			value string
			limit int
		}{
			{"dscp", item.DSCP, 32},
			{"traffic_class", item.TrafficClass, 64},
		} {
			if strings.TrimSpace(field.value) != "" && !validBroadbandPPPoEText(field.value, field.limit) {
				return nil, 0, fmt.Errorf("mobile.policy_control.qos_classes[%d].%s is invalid", i, field.name)
			}
		}
		for j, value := range item.TrafficFlowTemplates {
			if strings.TrimSpace(value) != "" && !validBroadbandPPPoEText(value, 253) {
				return nil, 0, fmt.Errorf("mobile.policy_control.qos_classes[%d].traffic_flow_templates[%d] is invalid", i, j)
			}
		}
		if err := validateMobileRadiusAttributeNames(fmt.Sprintf("mobile.policy_control.qos_classes[%d].radius_attributes", i), item.RadiusAttributes); err != nil {
			return nil, 0, err
		}
	}
	return seen, enabled, nil
}

func validateMobilePolicyRoamingPolicies(policies []MobilePolicyRoamingPolicyConfig) (map[string]struct{}, int, error) {
	seen := map[string]struct{}{}
	enabled := 0
	for i, item := range policies {
		name := strings.TrimSpace(item.Name)
		if !validBroadbandPPPoEText(name, 128) {
			return nil, 0, fmt.Errorf("mobile.policy_control.roaming_policies[%d].name is invalid", i)
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			return nil, 0, fmt.Errorf("mobile.policy_control.roaming_policies[%d] duplicates policy %q", i, key)
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
			{"home_realm", item.HomeRealm, 253},
			{"visited_realm", item.VisitedRealm, 253},
			{"home_mcc_mnc", item.HomeMCCMNC, 16},
			{"visited_mcc_mnc", item.VisitedMCCMNC, 16},
			{"home_policy", item.HomePolicy, 128},
			{"visited_policy", item.VisitedPolicy, 128},
			{"steering_action", item.SteeringAction, 128},
		} {
			if strings.TrimSpace(field.value) != "" && !validBroadbandPPPoEText(field.value, field.limit) {
				return nil, 0, fmt.Errorf("mobile.policy_control.roaming_policies[%d].%s is invalid", i, field.name)
			}
		}
		for j, apn := range item.AllowedAPNs {
			if strings.TrimSpace(apn) != "" && !validBroadbandPPPoEText(apn, 128) {
				return nil, 0, fmt.Errorf("mobile.policy_control.roaming_policies[%d].allowed_apns[%d] is invalid", i, j)
			}
		}
		if err := validateMobileRadiusAttributeNames(fmt.Sprintf("mobile.policy_control.roaming_policies[%d].radius_attributes", i), item.RadiusAttributes); err != nil {
			return nil, 0, err
		}
	}
	return seen, enabled, nil
}

func validateMobilePolicyFeedbackRules(rules []MobilePolicyFeedbackRuleConfig, profiles map[string]struct{}) (int, error) {
	seen := map[string]struct{}{}
	enabled := 0
	for i, item := range rules {
		name := strings.TrimSpace(item.Name)
		if !validBroadbandPPPoEText(name, 128) {
			return 0, fmt.Errorf("mobile.policy_control.feedback_rules[%d].name is invalid", i)
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			return 0, fmt.Errorf("mobile.policy_control.feedback_rules[%d] duplicates rule %q", i, key)
		}
		seen[key] = struct{}{}
		if item.Enabled {
			enabled++
		}
		if item.CooldownSeconds < 0 || item.CooldownSeconds > 86400 {
			return 0, fmt.Errorf("mobile.policy_control.feedback_rules[%d].cooldown_seconds must be between 0 and 86400", i)
		}
		for _, field := range []struct {
			name  string
			value string
			limit int
		}{
			{"source", item.Source, 64},
			{"trigger", item.Trigger, 128},
			{"action", item.Action, 128},
			{"coa_profile", item.CoAProfile, 128},
		} {
			if strings.TrimSpace(field.value) != "" && !validBroadbandPPPoEText(field.value, field.limit) {
				return 0, fmt.Errorf("mobile.policy_control.feedback_rules[%d].%s is invalid", i, field.name)
			}
		}
		if strings.TrimSpace(item.PolicyProfile) != "" {
			if _, ok := profiles[strings.ToLower(strings.TrimSpace(item.PolicyProfile))]; !ok {
				return 0, fmt.Errorf("mobile.policy_control.feedback_rules[%d].policy_profile references unknown profile %q", i, item.PolicyProfile)
			}
		}
		if err := validateMobileRadiusAttributeNames(fmt.Sprintf("mobile.policy_control.feedback_rules[%d].radius_attributes", i), item.RadiusAttributes); err != nil {
			return 0, err
		}
	}
	return enabled, nil
}

func defaultMobilePolicyProfiles() []MobilePolicyProfileConfig {
	return []MobilePolicyProfileConfig{
		{
			Name:               "home-default",
			Enabled:            true,
			APN:                "internet",
			Role:               "mobile-subscriber",
			PolicyProfile:      "internet-access",
			QoSClass:           "default-5qi-9",
			RoamingPolicy:      "home-plmn",
			ChargingProfile:    "internet-data",
			Precedence:         100,
			VendorPacks:        []string{"3gpp", "starent", "ericsson"},
			RadiusAttributes:   []string{"Filter-Id", "Class", "Session-Timeout", "Acct-Interim-Interval"},
			EnforcementActions: []string{"access-accept", "coa-on-threshold", "disconnect-on-policy-deny"},
		},
		{
			Name:               "visited-lbo",
			Enabled:            true,
			APN:                "internet",
			Role:               "roaming-subscriber",
			PolicyProfile:      "visited-local-breakout",
			QoSClass:           "roaming-5qi-8",
			RoamingPolicy:      "visited-lbo",
			ChargingProfile:    "internet-data",
			Precedence:         200,
			VendorPacks:        []string{"3gpp", "starent", "wimax"},
			RadiusAttributes:   []string{"3GPP-RAT-Type", "3GPP-Selection-Mode", "3GPP-Negotiated-DSCP", "Class"},
			EnforcementActions: []string{"apply-visited-policy", "coa-on-roaming-change", "accounting-correlation"},
		},
		{
			Name:               "iot-isolated",
			Enabled:            true,
			APN:                "iot.private",
			Role:               "mobile-iot",
			PolicyProfile:      "iot-quarantine-ready",
			QoSClass:           "iot-5qi-9",
			RoamingPolicy:      "home-plmn",
			ChargingProfile:    "iot-events",
			Precedence:         300,
			VendorPacks:        []string{"3gpp", "ericsson"},
			RadiusAttributes:   []string{"Filter-Id", "Class", "3GPP-IMSI-MCC-MNC"},
			EnforcementActions: []string{"restricted-acl", "quota-event-count", "auto-quarantine"},
		},
	}
}

func defaultMobilePolicyQoSClasses() []MobilePolicyQoSClassConfig {
	return []MobilePolicyQoSClassConfig{
		{
			Name:                 "default-5qi-9",
			Enabled:              true,
			QCI:                  9,
			FiveQI:               9,
			ARP:                  8,
			Priority:             100,
			MBRDownKbps:          50000,
			MBRUpKbps:            10000,
			DSCP:                 "af21",
			TrafficClass:         "best-effort",
			TrafficFlowTemplates: []string{"permit out ip from any to assigned"},
			RadiusAttributes:     []string{"3GPP-GPRS-Negotiated-QoS-profile", "3GPP-Negotiated-DSCP", "Session-Timeout"},
		},
		{
			Name:                    "roaming-5qi-8",
			Enabled:                 true,
			QCI:                     8,
			FiveQI:                  8,
			ARP:                     7,
			Priority:                80,
			MBRDownKbps:             20000,
			MBRUpKbps:               5000,
			PreemptionVulnerability: true,
			DSCP:                    "af31",
			TrafficClass:            "roaming-data",
			TrafficFlowTemplates:    []string{"permit out ip from any to assigned", "permit in ip from assigned to any"},
			RadiusAttributes:        []string{"3GPP-GPRS-Negotiated-QoS-profile", "3GPP-Negotiated-DSCP", "Filter-Id"},
		},
		{
			Name:                 "iot-5qi-9",
			Enabled:              true,
			QCI:                  9,
			FiveQI:               9,
			ARP:                  10,
			Priority:             200,
			MBRDownKbps:          1024,
			MBRUpKbps:            512,
			DSCP:                 "cs1",
			TrafficClass:         "iot-low-bandwidth",
			TrafficFlowTemplates: []string{"permit out ip from assigned to any"},
			RadiusAttributes:     []string{"Filter-Id", "Class", "Acct-Interim-Interval"},
		},
	}
}

func defaultMobilePolicyRoamingPolicies() []MobilePolicyRoamingPolicyConfig {
	return []MobilePolicyRoamingPolicyConfig{
		{
			Name:             "home-plmn",
			Enabled:          true,
			HomeRealm:        "mnc001.mcc001.3gppnetwork.org",
			VisitedRealm:     "mnc001.mcc001.3gppnetwork.org",
			HomeMCCMNC:       "00101",
			VisitedMCCMNC:    "00101",
			HomePolicy:       "home-default",
			VisitedPolicy:    "home-default",
			LocalBreakout:    true,
			SteeringAction:   "home-policy",
			AllowedAPNs:      []string{"internet", "iot.private"},
			RadiusAttributes: []string{"3GPP-IMSI-MCC-MNC", "3GPP-Selection-Mode"},
		},
		{
			Name:             "visited-lbo",
			Enabled:          true,
			HomeRealm:        "mnc001.mcc001.3gppnetwork.org",
			VisitedRealm:     "roaming.example.net",
			HomeMCCMNC:       "00101",
			VisitedMCCMNC:    "99999",
			HomePolicy:       "home-roaming",
			VisitedPolicy:    "visited-lbo",
			LocalBreakout:    false,
			SteeringAction:   "visited-restrict",
			AllowedAPNs:      []string{"internet"},
			RadiusAttributes: []string{"3GPP-RAT-Type", "3GPP-Selection-Mode", "Class"},
		},
	}
}

func defaultMobilePolicyFeedbackRules() []MobilePolicyFeedbackRuleConfig {
	return []MobilePolicyFeedbackRuleConfig{
		{
			Name:             "quota-threshold-reauthorize",
			Enabled:          true,
			Source:           "charging",
			Trigger:          "quota-threshold",
			Action:           "coa-update-qos",
			PolicyProfile:    "home-default",
			CoAProfile:       "mobile-quota-throttle",
			CooldownSeconds:  60,
			RadiusAttributes: []string{"Session-Timeout", "Acct-Interim-Interval", "Filter-Id"},
		},
		{
			Name:             "roaming-policy-update",
			Enabled:          true,
			Source:           "session",
			Trigger:          "visited-network-change",
			Action:           "coa-apply-visited-policy",
			PolicyProfile:    "visited-lbo",
			CoAProfile:       "mobile-roaming-policy",
			CooldownSeconds:  120,
			RadiusAttributes: []string{"3GPP-RAT-Type", "3GPP-Selection-Mode", "Class"},
		},
	}
}
