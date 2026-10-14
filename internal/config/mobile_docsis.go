package config

import (
	"errors"
	"fmt"
	"strings"
)

type MobileDOCSISConfig struct {
	Enabled                   bool                         `mapstructure:"enabled"`
	Mode                      string                       `mapstructure:"mode"`
	FailClosed                bool                         `mapstructure:"fail_closed"`
	RequireDatabase           bool                         `mapstructure:"require_database"`
	RequireGroupedAVPs        bool                         `mapstructure:"require_grouped_avps"`
	RequireCharging           bool                         `mapstructure:"require_charging"`
	RequireQoSServiceFlows    bool                         `mapstructure:"require_qos_service_flows"`
	RequireDynamicAuth        bool                         `mapstructure:"require_dynamic_auth"`
	CableModemProvisioning    bool                         `mapstructure:"cable_modem_provisioning"`
	ServiceFlowAuthorization  bool                         `mapstructure:"service_flow_authorization"`
	IPDRAccounting            bool                         `mapstructure:"ipdr_accounting"`
	PolicyChargingCorrelation bool                         `mapstructure:"policy_charging_correlation"`
	RedactDeviceIDs           bool                         `mapstructure:"redact_device_ids"`
	HashDeviceIDs             bool                         `mapstructure:"hash_device_ids"`
	ServiceFlowRetentionDays  int                          `mapstructure:"service_flow_retention_days"`
	EventRetentionLimit       int                          `mapstructure:"event_retention_limit"`
	MaxCableModems            int                          `mapstructure:"max_cable_modems"`
	DefaultModemProfile       string                       `mapstructure:"default_modem_profile"`
	DefaultServiceFlow        string                       `mapstructure:"default_service_flow"`
	DefaultCMTSProfile        string                       `mapstructure:"default_cmts_profile"`
	ModemProfiles             []MobileDOCSISModemProfile   `mapstructure:"modem_profiles"`
	ServiceFlows              []MobileDOCSISServiceFlow    `mapstructure:"service_flows"`
	CMTSProfiles              []MobileDOCSISCMTSProfile    `mapstructure:"cmts_profiles"`
	ChargingPolicies          []MobileDOCSISChargingPolicy `mapstructure:"charging_policies"`
	RadiusAttributes          []string                     `mapstructure:"radius_attributes"`
	ExternalCMTSReferences    []string                     `mapstructure:"external_cmts_references"`
}

type MobileDOCSISModemProfile struct {
	Name               string   `mapstructure:"name"`
	Enabled            bool     `mapstructure:"enabled"`
	DOCSISVersion      string   `mapstructure:"docsis_version"`
	DeviceGroup        string   `mapstructure:"device_group"`
	CMTSProfile        string   `mapstructure:"cmts_profile"`
	DefaultServiceFlow string   `mapstructure:"default_service_flow"`
	ProvisioningClass  string   `mapstructure:"provisioning_class"`
	ServiceTier        string   `mapstructure:"service_tier"`
	AccountingClass    string   `mapstructure:"accounting_class"`
	PolicyProfile      string   `mapstructure:"policy_profile"`
	VendorPacks        []string `mapstructure:"vendor_packs"`
	RadiusAttributes   []string `mapstructure:"radius_attributes"`
}

type MobileDOCSISServiceFlow struct {
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
	MaxBurstBytes        int      `mapstructure:"max_burst_bytes"`
	PacketClassifier     string   `mapstructure:"packet_classifier"`
	RadiusAttributes     []string `mapstructure:"radius_attributes"`
}

type MobileDOCSISCMTSProfile struct {
	Name               string   `mapstructure:"name"`
	Enabled            bool     `mapstructure:"enabled"`
	CMTSID             string   `mapstructure:"cmts_id"`
	Vendor             string   `mapstructure:"vendor"`
	ManagementDomain   string   `mapstructure:"management_domain"`
	DHCPRelay          string   `mapstructure:"dhcp_relay"`
	AccountingEndpoint string   `mapstructure:"accounting_endpoint"`
	CoAProfile         string   `mapstructure:"coa_profile"`
	RadiusAttributes   []string `mapstructure:"radius_attributes"`
}

type MobileDOCSISChargingPolicy struct {
	Name             string   `mapstructure:"name"`
	Enabled          bool     `mapstructure:"enabled"`
	BillingModel     string   `mapstructure:"billing_model"`
	RatingGroup      int      `mapstructure:"rating_group"`
	QuotaPolicy      string   `mapstructure:"quota_policy"`
	IPDRExport       string   `mapstructure:"ipdr_export"`
	CoAProfile       string   `mapstructure:"coa_profile"`
	RadiusAttributes []string `mapstructure:"radius_attributes"`
}

func EffectiveMobileDOCSISConfig(raw MobileDOCSISConfig) MobileDOCSISConfig {
	cfg := raw
	cfg.Mode = effectiveMobileDOCSISMode(cfg.Mode)
	if cfg.ServiceFlowRetentionDays == 0 {
		cfg.ServiceFlowRetentionDays = 180
	}
	if cfg.EventRetentionLimit == 0 {
		cfg.EventRetentionLimit = 10000
	}
	if cfg.MaxCableModems == 0 {
		cfg.MaxCableModems = 250000
	}
	if !raw.RequireDatabase && !raw.RequireGroupedAVPs && !raw.RequireCharging && !raw.RequireQoSServiceFlows && !raw.RequireDynamicAuth {
		cfg.RequireDatabase = true
		cfg.RequireGroupedAVPs = true
		cfg.RequireCharging = true
		cfg.RequireQoSServiceFlows = true
		cfg.RequireDynamicAuth = true
	}
	if !raw.CableModemProvisioning && !raw.ServiceFlowAuthorization && !raw.IPDRAccounting && !raw.PolicyChargingCorrelation {
		cfg.CableModemProvisioning = true
		cfg.ServiceFlowAuthorization = true
		cfg.IPDRAccounting = true
		cfg.PolicyChargingCorrelation = true
	}
	if !raw.RedactDeviceIDs && !raw.HashDeviceIDs {
		cfg.RedactDeviceIDs = true
		cfg.HashDeviceIDs = true
	}
	if strings.TrimSpace(cfg.DefaultModemProfile) == "" {
		cfg.DefaultModemProfile = "docsis-retail"
	}
	if strings.TrimSpace(cfg.DefaultServiceFlow) == "" {
		cfg.DefaultServiceFlow = "hsd-best-effort"
	}
	if strings.TrimSpace(cfg.DefaultCMTSProfile) == "" {
		cfg.DefaultCMTSProfile = "cmts-primary"
	}
	if len(cfg.ModemProfiles) == 0 {
		cfg.ModemProfiles = defaultMobileDOCSISModemProfiles()
	}
	if len(cfg.ServiceFlows) == 0 {
		cfg.ServiceFlows = defaultMobileDOCSISServiceFlows()
	}
	if len(cfg.CMTSProfiles) == 0 {
		cfg.CMTSProfiles = defaultMobileDOCSISCMTSProfiles()
	}
	if len(cfg.ChargingPolicies) == 0 {
		cfg.ChargingPolicies = defaultMobileDOCSISChargingPolicies()
	}
	if len(cfg.RadiusAttributes) == 0 {
		cfg.RadiusAttributes = []string{"CableLabs-Subscriber-ID", "CableLabs-SF-ID", "CableLabs-QoS-Descriptor", "CableLabs-Direction-indicator", "CableLabs-Volume-Usage-Limit", "CableLabs-Time-Usage-Limit", "CableLabs-Policy-Decision-Status", "CableLabs-Policy-Update-Reason", "Filter-Id", "Class", "Acct-Interim-Interval"}
	}
	if len(cfg.ExternalCMTSReferences) == 0 {
		cfg.ExternalCMTSReferences = []string{"CableLabs CMTS lab", "DOCSIS provisioning system", "IPDR mediation system", "CMTS dynamic authorization endpoint"}
	}
	return cfg
}

func effectiveMobileDOCSISMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "monitor", "enforce":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "monitor"
	}
}

func validateMobileDOCSISConfig(raw MobileDOCSISConfig, grouped MobileGroupedAVPConfig, charging MobileChargingConfig, broadbandQoS BroadbandQoSServiceFlowConfig, radius RadiusConfig, profile string) error {
	cfg := EffectiveMobileDOCSISConfig(raw)
	if !cfg.Enabled && len(raw.ModemProfiles) == 0 && len(raw.ServiceFlows) == 0 && len(raw.CMTSProfiles) == 0 && len(raw.ChargingPolicies) == 0 {
		return nil
	}
	if profile == "lite" && cfg.Mode == "enforce" {
		return errors.New("mobile.docsis cannot use enforce mode on lite deployment profile")
	}
	if cfg.ServiceFlowRetentionDays < 1 || cfg.ServiceFlowRetentionDays > 3650 {
		return errors.New("mobile.docsis.service_flow_retention_days must be between 1 and 3650")
	}
	if cfg.EventRetentionLimit < 0 || cfg.EventRetentionLimit > 1000000 {
		return errors.New("mobile.docsis.event_retention_limit must be between 0 and 1000000")
	}
	if cfg.MaxCableModems < 1 || cfg.MaxCableModems > 20000000 {
		return errors.New("mobile.docsis.max_cable_modems must be between 1 and 20000000")
	}
	cmtsProfiles, enabledCMTS, err := validateMobileDOCSISCMTSProfiles(cfg.CMTSProfiles)
	if err != nil {
		return err
	}
	serviceFlows, enabledFlows, err := validateMobileDOCSISServiceFlows(cfg.ServiceFlows)
	if err != nil {
		return err
	}
	modemProfiles, enabledModems, err := validateMobileDOCSISModemProfiles(cfg.ModemProfiles, cmtsProfiles, serviceFlows)
	if err != nil {
		return err
	}
	enabledCharging, err := validateMobileDOCSISChargingPolicies(cfg.ChargingPolicies)
	if err != nil {
		return err
	}
	if err := validateMobileRadiusAttributeNames("mobile.docsis.radius_attributes", cfg.RadiusAttributes); err != nil {
		return err
	}
	for i, ref := range cfg.ExternalCMTSReferences {
		if strings.TrimSpace(ref) != "" && !validBroadbandPPPoEText(ref, 128) {
			return fmt.Errorf("mobile.docsis.external_cmts_references[%d] is invalid", i)
		}
	}
	if _, ok := modemProfiles[strings.ToLower(strings.TrimSpace(cfg.DefaultModemProfile))]; strings.TrimSpace(cfg.DefaultModemProfile) != "" && !ok {
		return fmt.Errorf("mobile.docsis.default_modem_profile %q must match a modem profile", cfg.DefaultModemProfile)
	}
	if _, ok := serviceFlows[strings.ToLower(strings.TrimSpace(cfg.DefaultServiceFlow))]; strings.TrimSpace(cfg.DefaultServiceFlow) != "" && !ok {
		return fmt.Errorf("mobile.docsis.default_service_flow %q must match a service flow", cfg.DefaultServiceFlow)
	}
	if _, ok := cmtsProfiles[strings.ToLower(strings.TrimSpace(cfg.DefaultCMTSProfile))]; strings.TrimSpace(cfg.DefaultCMTSProfile) != "" && !ok {
		return fmt.Errorf("mobile.docsis.default_cmts_profile %q must match a CMTS profile", cfg.DefaultCMTSProfile)
	}
	if cfg.Enabled && cfg.Mode == "enforce" {
		effectiveGrouped := EffectiveMobileGroupedAVPConfig(grouped)
		effectiveCharging := EffectiveMobileChargingConfig(charging)
		effectiveQoS := EffectiveBroadbandQoSServiceFlowConfig(broadbandQoS)
		effectiveDynamicAuth := EffectiveDynamicAuthConfig(radius.DynamicAuth)
		if cfg.RequireGroupedAVPs && !effectiveGrouped.Enabled {
			return errors.New("mobile.docsis enforce mode requires mobile.grouped_avps.enabled")
		}
		if cfg.RequireCharging && !effectiveCharging.Enabled {
			return errors.New("mobile.docsis enforce mode requires mobile.charging.enabled")
		}
		if cfg.RequireQoSServiceFlows && !effectiveQoS.Enabled {
			return errors.New("mobile.docsis enforce mode requires broadband.qos_service_flows.enabled")
		}
		if cfg.RequireDynamicAuth && !effectiveDynamicAuth.Enabled && !effectiveDynamicAuth.OutboundEnabled {
			return errors.New("mobile.docsis enforce mode requires radius.dynamic_auth enabled or outbound_enabled")
		}
		if enabledModems == 0 {
			return errors.New("mobile.docsis enforce mode requires at least one enabled modem profile")
		}
		if cfg.ServiceFlowAuthorization && enabledFlows == 0 {
			return errors.New("mobile.docsis service_flow_authorization requires at least one enabled service flow")
		}
		if enabledCMTS == 0 {
			return errors.New("mobile.docsis enforce mode requires at least one enabled CMTS profile")
		}
		if cfg.PolicyChargingCorrelation && enabledCharging == 0 {
			return errors.New("mobile.docsis policy_charging_correlation requires at least one enabled charging policy")
		}
		if cfg.RedactDeviceIDs && !cfg.HashDeviceIDs {
			return errors.New("mobile.docsis device redaction requires hash_device_ids")
		}
	}
	return nil
}

func validateMobileDOCSISModemProfiles(profiles []MobileDOCSISModemProfile, cmtsProfiles, serviceFlows map[string]struct{}) (map[string]struct{}, int, error) {
	seen := map[string]struct{}{}
	enabled := 0
	for i, item := range profiles {
		name := strings.TrimSpace(item.Name)
		if !validBroadbandPPPoEText(name, 128) {
			return nil, 0, fmt.Errorf("mobile.docsis.modem_profiles[%d].name is invalid", i)
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			return nil, 0, fmt.Errorf("mobile.docsis.modem_profiles[%d] duplicates profile %q", i, key)
		}
		seen[key] = struct{}{}
		if item.Enabled {
			enabled++
		}
		if strings.TrimSpace(item.CMTSProfile) != "" {
			if _, ok := cmtsProfiles[strings.ToLower(strings.TrimSpace(item.CMTSProfile))]; !ok {
				return nil, 0, fmt.Errorf("mobile.docsis.modem_profiles[%d].cmts_profile references unknown CMTS profile %q", i, item.CMTSProfile)
			}
		}
		if strings.TrimSpace(item.DefaultServiceFlow) != "" {
			if _, ok := serviceFlows[strings.ToLower(strings.TrimSpace(item.DefaultServiceFlow))]; !ok {
				return nil, 0, fmt.Errorf("mobile.docsis.modem_profiles[%d].default_service_flow references unknown service flow %q", i, item.DefaultServiceFlow)
			}
		}
		for _, field := range []struct {
			name  string
			value string
			limit int
		}{
			{"docsis_version", item.DOCSISVersion, 32},
			{"device_group", item.DeviceGroup, 128},
			{"provisioning_class", item.ProvisioningClass, 128},
			{"service_tier", item.ServiceTier, 128},
			{"accounting_class", item.AccountingClass, 128},
			{"policy_profile", item.PolicyProfile, 128},
		} {
			if strings.TrimSpace(field.value) != "" && !validBroadbandPPPoEText(field.value, field.limit) {
				return nil, 0, fmt.Errorf("mobile.docsis.modem_profiles[%d].%s is invalid", i, field.name)
			}
		}
		for j, value := range item.VendorPacks {
			if strings.TrimSpace(value) != "" && !validBroadbandPPPoEText(value, 128) {
				return nil, 0, fmt.Errorf("mobile.docsis.modem_profiles[%d].vendor_packs[%d] is invalid", i, j)
			}
		}
		if err := validateMobileRadiusAttributeNames(fmt.Sprintf("mobile.docsis.modem_profiles[%d].radius_attributes", i), item.RadiusAttributes); err != nil {
			return nil, 0, err
		}
	}
	return seen, enabled, nil
}

func validateMobileDOCSISServiceFlows(flows []MobileDOCSISServiceFlow) (map[string]struct{}, int, error) {
	seen := map[string]struct{}{}
	enabled := 0
	for i, item := range flows {
		name := strings.TrimSpace(item.Name)
		if !validBroadbandPPPoEText(name, 128) {
			return nil, 0, fmt.Errorf("mobile.docsis.service_flows[%d].name is invalid", i)
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			return nil, 0, fmt.Errorf("mobile.docsis.service_flows[%d] duplicates service flow %q", i, key)
		}
		seen[key] = struct{}{}
		if item.Enabled {
			enabled++
		}
		switch strings.ToLower(strings.TrimSpace(item.Direction)) {
		case "", "upstream", "downstream", "bidirectional":
		default:
			return nil, 0, fmt.Errorf("mobile.docsis.service_flows[%d].direction must be upstream, downstream, or bidirectional", i)
		}
		switch strings.ToLower(strings.TrimSpace(item.SchedulingType)) {
		case "", "best-effort", "ugs", "rtps", "nrtps", "ertps":
		default:
			return nil, 0, fmt.Errorf("mobile.docsis.service_flows[%d].scheduling_type is invalid", i)
		}
		if item.ServiceFlowID < 0 || item.ServiceFlowID > 16777215 {
			return nil, 0, fmt.Errorf("mobile.docsis.service_flows[%d].service_flow_id must be between 0 and 16777215", i)
		}
		if item.TrafficPriority < 0 || item.TrafficPriority > 7 {
			return nil, 0, fmt.Errorf("mobile.docsis.service_flows[%d].traffic_priority must be between 0 and 7", i)
		}
		for _, field := range []struct {
			name  string
			value int
		}{
			{"max_sustained_rate_kbps", item.MaxSustainedRateKbps},
			{"min_reserved_rate_kbps", item.MinReservedRateKbps},
			{"max_burst_bytes", item.MaxBurstBytes},
		} {
			if field.value < 0 {
				return nil, 0, fmt.Errorf("mobile.docsis.service_flows[%d].%s must not be negative", i, field.name)
			}
		}
		if item.MinReservedRateKbps > item.MaxSustainedRateKbps && item.MaxSustainedRateKbps > 0 {
			return nil, 0, fmt.Errorf("mobile.docsis.service_flows[%d].min_reserved_rate_kbps cannot exceed max_sustained_rate_kbps", i)
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
				return nil, 0, fmt.Errorf("mobile.docsis.service_flows[%d].%s is invalid", i, field.name)
			}
		}
		if err := validateMobileRadiusAttributeNames(fmt.Sprintf("mobile.docsis.service_flows[%d].radius_attributes", i), item.RadiusAttributes); err != nil {
			return nil, 0, err
		}
	}
	return seen, enabled, nil
}

func validateMobileDOCSISCMTSProfiles(profiles []MobileDOCSISCMTSProfile) (map[string]struct{}, int, error) {
	seen := map[string]struct{}{}
	enabled := 0
	for i, item := range profiles {
		name := strings.TrimSpace(item.Name)
		if !validBroadbandPPPoEText(name, 128) {
			return nil, 0, fmt.Errorf("mobile.docsis.cmts_profiles[%d].name is invalid", i)
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			return nil, 0, fmt.Errorf("mobile.docsis.cmts_profiles[%d] duplicates CMTS profile %q", i, key)
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
			{"cmts_id", item.CMTSID, 64},
			{"vendor", item.Vendor, 128},
			{"management_domain", item.ManagementDomain, 128},
			{"dhcp_relay", item.DHCPRelay, 128},
			{"accounting_endpoint", item.AccountingEndpoint, 128},
			{"coa_profile", item.CoAProfile, 128},
		} {
			if strings.TrimSpace(field.value) != "" && !validBroadbandPPPoEText(field.value, field.limit) {
				return nil, 0, fmt.Errorf("mobile.docsis.cmts_profiles[%d].%s is invalid", i, field.name)
			}
		}
		if err := validateMobileRadiusAttributeNames(fmt.Sprintf("mobile.docsis.cmts_profiles[%d].radius_attributes", i), item.RadiusAttributes); err != nil {
			return nil, 0, err
		}
	}
	return seen, enabled, nil
}

func validateMobileDOCSISChargingPolicies(policies []MobileDOCSISChargingPolicy) (int, error) {
	seen := map[string]struct{}{}
	enabled := 0
	for i, item := range policies {
		name := strings.TrimSpace(item.Name)
		if !validBroadbandPPPoEText(name, 128) {
			return 0, fmt.Errorf("mobile.docsis.charging_policies[%d].name is invalid", i)
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			return 0, fmt.Errorf("mobile.docsis.charging_policies[%d] duplicates policy %q", i, key)
		}
		seen[key] = struct{}{}
		if item.Enabled {
			enabled++
		}
		if item.RatingGroup < 0 {
			return 0, fmt.Errorf("mobile.docsis.charging_policies[%d].rating_group must not be negative", i)
		}
		for _, field := range []struct {
			name  string
			value string
			limit int
		}{
			{"billing_model", item.BillingModel, 128},
			{"quota_policy", item.QuotaPolicy, 128},
			{"ipdr_export", item.IPDRExport, 128},
			{"coa_profile", item.CoAProfile, 128},
		} {
			if strings.TrimSpace(field.value) != "" && !validBroadbandPPPoEText(field.value, field.limit) {
				return 0, fmt.Errorf("mobile.docsis.charging_policies[%d].%s is invalid", i, field.name)
			}
		}
		if err := validateMobileRadiusAttributeNames(fmt.Sprintf("mobile.docsis.charging_policies[%d].radius_attributes", i), item.RadiusAttributes); err != nil {
			return 0, err
		}
	}
	return enabled, nil
}

func defaultMobileDOCSISModemProfiles() []MobileDOCSISModemProfile {
	return []MobileDOCSISModemProfile{
		{Name: "docsis-retail", Enabled: true, DOCSISVersion: "3.1", DeviceGroup: "retail-cable-modem", CMTSProfile: "cmts-primary", DefaultServiceFlow: "hsd-best-effort", ProvisioningClass: "retail-hsd", ServiceTier: "retail-300m", AccountingClass: "retail-usage", PolicyProfile: "home-default", VendorPacks: []string{"cablelabs", "docsis"}, RadiusAttributes: []string{"CableLabs-Subscriber-ID", "CableLabs-SF-ID", "CableLabs-QoS-Descriptor", "Filter-Id", "Class"}},
		{Name: "docsis-business", Enabled: true, DOCSISVersion: "3.1", DeviceGroup: "business-cable-modem", CMTSProfile: "cmts-primary", DefaultServiceFlow: "business-priority", ProvisioningClass: "business-hsd", ServiceTier: "business-static", AccountingClass: "business-usage", PolicyProfile: "business-sla", VendorPacks: []string{"cablelabs", "docsis"}, RadiusAttributes: []string{"CableLabs-Subscriber-ID", "CableLabs-Volume-Usage-Limit", "Acct-Interim-Interval"}},
	}
}

func defaultMobileDOCSISServiceFlows() []MobileDOCSISServiceFlow {
	return []MobileDOCSISServiceFlow{
		{Name: "hsd-best-effort", Enabled: true, Direction: "bidirectional", ServiceClass: "high-speed-data", SchedulingType: "best-effort", ServiceFlowID: 11001, QoSProfile: "retail-default", TrafficPriority: 0, MaxSustainedRateKbps: 300000, MinReservedRateKbps: 0, MaxBurstBytes: 1048576, PacketClassifier: "permit ip cable-modem any", RadiusAttributes: []string{"CableLabs-SF-ID", "CableLabs-QoS-Descriptor", "CableLabs-Direction-indicator"}},
		{Name: "business-priority", Enabled: true, Direction: "bidirectional", ServiceClass: "business-data", SchedulingType: "rtps", ServiceFlowID: 12001, QoSProfile: "business-sla", TrafficPriority: 5, MaxSustainedRateKbps: 1000000, MinReservedRateKbps: 50000, MaxBurstBytes: 2097152, PacketClassifier: "permit ip business-modem any", RadiusAttributes: []string{"CableLabs-SF-ID", "CableLabs-QoS-Descriptor", "CableLabs-Policy-Decision-Status"}},
		{Name: "packetcable-voice", Enabled: true, Direction: "bidirectional", ServiceClass: "voice", SchedulingType: "ugs", ServiceFlowID: 13001, QoSProfile: "voice-low-latency", TrafficPriority: 6, MaxSustainedRateKbps: 128, MinReservedRateKbps: 128, PacketClassifier: "permit udp mta any eq voice", RadiusAttributes: []string{"CableLabs-SF-ID", "CableLabs-QoS-Descriptor", "CableLabs-MTA-Endpoint-Name"}},
	}
}

func defaultMobileDOCSISCMTSProfiles() []MobileDOCSISCMTSProfile {
	return []MobileDOCSISCMTSProfile{
		{Name: "cmts-primary", Enabled: true, CMTSID: "cmts-001", Vendor: "CableLabs-compatible", ManagementDomain: "metro-primary", DHCPRelay: "relay-primary", AccountingEndpoint: "ipdr-primary", CoAProfile: "docsis-policy-update", RadiusAttributes: []string{"NAS-Identifier", "CableLabs-Policy-Decision-Status", "Acct-Interim-Interval"}},
		{Name: "cmts-backup", Enabled: true, CMTSID: "cmts-002", Vendor: "CableLabs-compatible", ManagementDomain: "metro-secondary", DHCPRelay: "relay-secondary", AccountingEndpoint: "ipdr-secondary", CoAProfile: "docsis-policy-update", RadiusAttributes: []string{"NAS-Identifier", "CableLabs-Policy-Update-Reason", "Class"}},
	}
}

func defaultMobileDOCSISChargingPolicies() []MobileDOCSISChargingPolicy {
	return []MobileDOCSISChargingPolicy{
		{Name: "retail-usage", Enabled: true, BillingModel: "usage-plus-flat", RatingGroup: 7100, QuotaPolicy: "retail-monthly-cap", IPDRExport: "ipdr-retail", CoAProfile: "docsis-quota-update", RadiusAttributes: []string{"CableLabs-Volume-Usage-Limit", "CableLabs-Time-Usage-Limit", "CableLabs-Gate-Usage-Info"}},
		{Name: "business-sla", Enabled: true, BillingModel: "sla-committed", RatingGroup: 7200, QuotaPolicy: "business-sla", IPDRExport: "ipdr-business", CoAProfile: "docsis-sla-update", RadiusAttributes: []string{"CableLabs-Policy-Decision-Status", "CableLabs-Policy-Update-Reason", "Class"}},
	}
}
