package config

import (
	"errors"
	"fmt"
	"strings"
)

type MobileConfig struct {
	GroupedAVPs   MobileGroupedAVPConfig    `mapstructure:"grouped_avps"`
	Sessions      MobileSessionConfig       `mapstructure:"sessions"`
	Charging      MobileChargingConfig      `mapstructure:"charging"`
	PolicyControl MobilePolicyControlConfig `mapstructure:"policy_control"`
	WiMAX         MobileWiMAXConfig         `mapstructure:"wimax"`
}

type MobileGroupedAVPConfig struct {
	Enabled                  bool                                   `mapstructure:"enabled"`
	Mode                     string                                 `mapstructure:"mode"`
	FailClosed               bool                                   `mapstructure:"fail_closed"`
	RequireDatabase          bool                                   `mapstructure:"require_database"`
	RequireVSACodec          bool                                   `mapstructure:"require_vsa_codec"`
	RequireAttributeRegistry bool                                   `mapstructure:"require_attribute_registry"`
	SafeRawEvidence          bool                                   `mapstructure:"safe_raw_evidence"`
	HashRawValues            bool                                   `mapstructure:"hash_raw_values"`
	MaxDepth                 int                                    `mapstructure:"max_depth"`
	MaxPayloadBytes          int                                    `mapstructure:"max_payload_bytes"`
	MaxAttributesPerPacket   int                                    `mapstructure:"max_attributes_per_packet"`
	RawEvidenceRetentionDays int                                    `mapstructure:"raw_evidence_retention_days"`
	EventRetentionLimit      int                                    `mapstructure:"event_retention_limit"`
	VendorScopes             []MobileGroupedAVPVendorScopeConfig    `mapstructure:"vendor_scopes"`
	EvidencePolicies         []MobileGroupedAVPEvidencePolicyConfig `mapstructure:"evidence_policies"`
}

type MobileGroupedAVPVendorScopeConfig struct {
	Name                  string   `mapstructure:"name"`
	Enabled               bool     `mapstructure:"enabled"`
	Vendor                string   `mapstructure:"vendor"`
	VendorID              uint32   `mapstructure:"vendor_id"`
	Dictionary            string   `mapstructure:"dictionary"`
	Domain                string   `mapstructure:"domain"`
	Format                string   `mapstructure:"format"`
	GroupedRootAttributes []string `mapstructure:"grouped_root_attributes"`
	IdentityAttributes    []string `mapstructure:"identity_attributes"`
	ChargingAttributes    []string `mapstructure:"charging_attributes"`
	QoSAttributes         []string `mapstructure:"qos_attributes"`
	PolicyAttributes      []string `mapstructure:"policy_attributes"`
	SafeRawEvidence       bool     `mapstructure:"safe_raw_evidence"`
	HashRawValues         bool     `mapstructure:"hash_raw_values"`
}

type MobileGroupedAVPEvidencePolicyConfig struct {
	Name              string   `mapstructure:"name"`
	Enabled           bool     `mapstructure:"enabled"`
	Scope             string   `mapstructure:"scope"`
	CaptureRaw        bool     `mapstructure:"capture_raw"`
	HashRawValues     bool     `mapstructure:"hash_raw_values"`
	RetentionDays     int      `mapstructure:"retention_days"`
	RedactAttributes  []string `mapstructure:"redact_attributes"`
	AllowedExportRole string   `mapstructure:"allowed_export_role"`
}

func EffectiveMobileGroupedAVPConfig(raw MobileGroupedAVPConfig) MobileGroupedAVPConfig {
	cfg := raw
	cfg.Mode = effectiveMobileGroupedAVPMode(cfg.Mode)
	if cfg.MaxDepth == 0 {
		cfg.MaxDepth = 4
	}
	if cfg.MaxPayloadBytes == 0 {
		cfg.MaxPayloadBytes = 4096
	}
	if cfg.MaxAttributesPerPacket == 0 {
		cfg.MaxAttributesPerPacket = 4096
	}
	if cfg.RawEvidenceRetentionDays == 0 {
		cfg.RawEvidenceRetentionDays = 30
	}
	if cfg.EventRetentionLimit == 0 {
		cfg.EventRetentionLimit = 10000
	}
	if !raw.RequireDatabase && !raw.RequireVSACodec && !raw.RequireAttributeRegistry {
		cfg.RequireDatabase = true
		cfg.RequireVSACodec = true
		cfg.RequireAttributeRegistry = true
	}
	if !raw.SafeRawEvidence && !raw.HashRawValues {
		cfg.SafeRawEvidence = true
		cfg.HashRawValues = true
	}
	if len(cfg.VendorScopes) == 0 {
		cfg.VendorScopes = defaultMobileGroupedAVPVendorScopes()
	}
	if len(cfg.EvidencePolicies) == 0 {
		cfg.EvidencePolicies = []MobileGroupedAVPEvidencePolicyConfig{{
			Name:              "hashed-raw-evidence",
			Enabled:           true,
			Scope:             "all",
			CaptureRaw:        false,
			HashRawValues:     true,
			RetentionDays:     cfg.RawEvidenceRetentionDays,
			RedactAttributes:  []string{"3GPP-IMSI", "3GPP2-IMSI", "WiMAX-MN-NAI"},
			AllowedExportRole: "ops_admin",
		}}
	}
	return cfg
}

func effectiveMobileGroupedAVPMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "monitor", "enforce":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "monitor"
	}
}

func validateMobileGroupedAVPConfig(raw MobileGroupedAVPConfig, profile string) error {
	cfg := EffectiveMobileGroupedAVPConfig(raw)
	if !cfg.Enabled && len(raw.VendorScopes) == 0 && len(raw.EvidencePolicies) == 0 {
		return nil
	}
	if profile == "lite" && cfg.Mode == "enforce" {
		return errors.New("mobile.grouped_avps cannot use enforce mode on lite deployment profile")
	}
	if cfg.MaxDepth < 1 || cfg.MaxDepth > 4 {
		return errors.New("mobile.grouped_avps.max_depth must be between 1 and 4")
	}
	if cfg.MaxPayloadBytes < 256 || cfg.MaxPayloadBytes > 65535 {
		return errors.New("mobile.grouped_avps.max_payload_bytes must be between 256 and 65535")
	}
	if cfg.MaxAttributesPerPacket < 1 || cfg.MaxAttributesPerPacket > 65535 {
		return errors.New("mobile.grouped_avps.max_attributes_per_packet must be between 1 and 65535")
	}
	if cfg.RawEvidenceRetentionDays < 0 || cfg.RawEvidenceRetentionDays > 3650 {
		return errors.New("mobile.grouped_avps.raw_evidence_retention_days must be between 0 and 3650")
	}
	if cfg.EventRetentionLimit < 0 || cfg.EventRetentionLimit > 1000000 {
		return errors.New("mobile.grouped_avps.event_retention_limit must be between 0 and 1000000")
	}
	scopes, enabledScopes, err := validateMobileGroupedAVPVendorScopes(cfg)
	if err != nil {
		return err
	}
	enabledEvidence, err := validateMobileGroupedAVPEvidencePolicies(cfg, scopes)
	if err != nil {
		return err
	}
	if cfg.Enabled && cfg.Mode == "enforce" {
		if enabledScopes == 0 {
			return errors.New("mobile.grouped_avps enforce mode requires at least one enabled vendor scope")
		}
		if enabledEvidence == 0 {
			return errors.New("mobile.grouped_avps enforce mode requires at least one enabled evidence policy")
		}
		if cfg.SafeRawEvidence && !cfg.HashRawValues {
			return errors.New("mobile.grouped_avps safe raw evidence requires hash_raw_values")
		}
	}
	return nil
}

func validateMobileGroupedAVPVendorScopes(cfg MobileGroupedAVPConfig) (map[string]struct{}, int, error) {
	seen := map[string]struct{}{}
	enabled := 0
	for i, scope := range cfg.VendorScopes {
		name := strings.TrimSpace(scope.Name)
		if !validBroadbandPPPoEText(name, 128) {
			return nil, 0, fmt.Errorf("mobile.grouped_avps.vendor_scopes[%d].name is invalid", i)
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			return nil, 0, fmt.Errorf("mobile.grouped_avps.vendor_scopes[%d] duplicates scope %q", i, key)
		}
		seen[key] = struct{}{}
		if scope.Enabled {
			enabled++
		}
		if scope.Enabled && scope.VendorID == 0 {
			return nil, 0, fmt.Errorf("mobile.grouped_avps.vendor_scopes[%d].vendor_id is required when enabled", i)
		}
		for _, field := range []struct {
			name  string
			value string
			limit int
		}{
			{"vendor", scope.Vendor, 128},
			{"dictionary", scope.Dictionary, 128},
			{"domain", scope.Domain, 128},
			{"format", scope.Format, 64},
		} {
			if strings.TrimSpace(field.value) != "" && !validBroadbandPPPoEText(field.value, field.limit) {
				return nil, 0, fmt.Errorf("mobile.grouped_avps.vendor_scopes[%d].%s is invalid", i, field.name)
			}
		}
		for name, values := range map[string][]string{
			"grouped_root_attributes": scope.GroupedRootAttributes,
			"identity_attributes":     scope.IdentityAttributes,
			"charging_attributes":     scope.ChargingAttributes,
			"qos_attributes":          scope.QoSAttributes,
			"policy_attributes":       scope.PolicyAttributes,
		} {
			for j, value := range values {
				if strings.TrimSpace(value) != "" && !validBroadbandPPPoEText(strings.TrimSpace(value), 253) {
					return nil, 0, fmt.Errorf("mobile.grouped_avps.vendor_scopes[%d].%s[%d] is not a valid RADIUS attribute name", i, name, j)
				}
			}
		}
	}
	return seen, enabled, nil
}

func validateMobileGroupedAVPEvidencePolicies(cfg MobileGroupedAVPConfig, scopes map[string]struct{}) (int, error) {
	seen := map[string]struct{}{}
	enabled := 0
	for i, policy := range cfg.EvidencePolicies {
		name := strings.TrimSpace(policy.Name)
		if !validBroadbandPPPoEText(name, 128) {
			return 0, fmt.Errorf("mobile.grouped_avps.evidence_policies[%d].name is invalid", i)
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			return 0, fmt.Errorf("mobile.grouped_avps.evidence_policies[%d] duplicates policy %q", i, key)
		}
		seen[key] = struct{}{}
		if policy.Enabled {
			enabled++
		}
		scope := strings.ToLower(strings.TrimSpace(policy.Scope))
		if scope != "" && scope != "all" {
			if _, ok := scopes[scope]; !ok {
				return 0, fmt.Errorf("mobile.grouped_avps.evidence_policies[%d].scope references unknown vendor scope %q", i, policy.Scope)
			}
		}
		if policy.RetentionDays < 0 || policy.RetentionDays > 3650 {
			return 0, fmt.Errorf("mobile.grouped_avps.evidence_policies[%d].retention_days must be between 0 and 3650", i)
		}
		if policy.CaptureRaw && !policy.HashRawValues {
			return 0, fmt.Errorf("mobile.grouped_avps.evidence_policies[%d] raw capture requires hash_raw_values", i)
		}
		for j, value := range policy.RedactAttributes {
			if strings.TrimSpace(value) != "" && !validBroadbandPPPoEText(strings.TrimSpace(value), 253) {
				return 0, fmt.Errorf("mobile.grouped_avps.evidence_policies[%d].redact_attributes[%d] is not a valid RADIUS attribute name", i, j)
			}
		}
		if strings.TrimSpace(policy.AllowedExportRole) != "" && !validBroadbandPPPoEText(policy.AllowedExportRole, 64) {
			return 0, fmt.Errorf("mobile.grouped_avps.evidence_policies[%d].allowed_export_role is invalid", i)
		}
	}
	return enabled, nil
}

func defaultMobileGroupedAVPVendorScopes() []MobileGroupedAVPVendorScopeConfig {
	return []MobileGroupedAVPVendorScopeConfig{
		{
			Name:                  "3gpp-core",
			Enabled:               true,
			Vendor:                "3GPP",
			VendorID:              10415,
			Dictionary:            "dictionary.3gpp",
			Domain:                "mobile-core-charging",
			Format:                "radius-vsa",
			GroupedRootAttributes: []string{"3GPP-Packet-Filter"},
			IdentityAttributes:    []string{"3GPP-IMSI", "3GPP-IMEISV", "3GPP-IMSI-MCC-MNC"},
			ChargingAttributes:    []string{"3GPP-Charging-ID", "3GPP-Charging-Characteristics", "3GPP-Charging-Gateway-Address"},
			QoSAttributes:         []string{"3GPP-GPRS-Negotiated-QoS-profile", "3GPP-Negotiated-DSCP"},
			PolicyAttributes:      []string{"3GPP-RAT-Type", "3GPP-Selection-Mode", "3GPP-Allocate-IP-Type"},
			SafeRawEvidence:       true,
			HashRawValues:         true,
		},
		{
			Name:                  "3gpp2-core",
			Enabled:               true,
			Vendor:                "3GPP2",
			VendorID:              5535,
			Dictionary:            "dictionary.3gpp2",
			Domain:                "mobile-core-charging",
			Format:                "grouped-tlv",
			GroupedRootAttributes: []string{"3GPP2-Prepaid-Acct-Quota", "3GPP2-Granted-QoS-Params", "3GPP2-Flow-ID"},
			IdentityAttributes:    []string{"3GPP2-IMSI", "3GPP2-AT-Hardware-Identifier-Value"},
			ChargingAttributes:    []string{"3GPP2-Prepaid-Quota-Identifier", "3GPP2-Prepaid-Acct-Quota-VolumeQuota"},
			QoSAttributes:         []string{"3GPP2-Granted-QoS-Params-Flow-Profile-ID", "3GPP2-Allowed-Diffserv-Marking-Max-Class"},
			PolicyAttributes:      []string{"3GPP2-Auth-Flow-Profile-ID-Forward", "3GPP2-Auth-Flow-Profile-ID-Reverse"},
			SafeRawEvidence:       true,
			HashRawValues:         true,
		},
		{
			Name:                  "starent-cisco-packet-core",
			Enabled:               true,
			Vendor:                "Starent",
			VendorID:              8164,
			Dictionary:            "dictionary.starent",
			Domain:                "packet-core-bng",
			Format:                "radius-vsa",
			GroupedRootAttributes: []string{"SN1-Service-Type", "SN1-Subscriber-Profile"},
			IdentityAttributes:    []string{"SN1-Subscriber-ID", "SN1-IMSI"},
			ChargingAttributes:    []string{"SN1-Charging-ID", "SN1-Accounting-Input-Octets", "SN1-Accounting-Output-Octets"},
			QoSAttributes:         []string{"SN1-QoS-Profile", "SN1-Bandwidth-Limit"},
			PolicyAttributes:      []string{"SN1-Policy-Name", "SN1-Rulebase"},
			SafeRawEvidence:       true,
			HashRawValues:         true,
		},
		{
			Name:                  "ericsson-redback",
			Enabled:               true,
			Vendor:                "Ericsson",
			VendorID:              193,
			Dictionary:            "dictionary.ericsson",
			Domain:                "mobile-bng-policy",
			Format:                "radius-vsa",
			GroupedRootAttributes: []string{"Ericsson-Service-Name", "Ericsson-QoS-Profile"},
			IdentityAttributes:    []string{"Ericsson-Subscriber-Name", "Ericsson-IMSI"},
			ChargingAttributes:    []string{"Ericsson-Charging-Profile", "Ericsson-Accounting-Policy"},
			QoSAttributes:         []string{"Ericsson-QoS-Profile", "Ericsson-Rate-Limit"},
			PolicyAttributes:      []string{"Ericsson-ACL-Name", "Ericsson-Context-Name"},
			SafeRawEvidence:       true,
			HashRawValues:         true,
		},
		{
			Name:                  "wimax-service-flow",
			Enabled:               true,
			Vendor:                "WiMAX",
			VendorID:              24757,
			Dictionary:            "dictionary.wimax",
			Domain:                "wimax-service-flow",
			Format:                "grouped-tlv",
			GroupedRootAttributes: []string{"WiMAX-QoS-Descriptor", "WiMAX-Packet-Flow-Descriptor"},
			IdentityAttributes:    []string{"WiMAX-MN-NAI", "WiMAX-Calling-Station-Id"},
			ChargingAttributes:    []string{"WiMAX-Session-Id", "WiMAX-Accounting-Capabilities"},
			QoSAttributes:         []string{"WiMAX-QoS-Descriptor", "WiMAX-Service-Flow-ID"},
			PolicyAttributes:      []string{"WiMAX-Termination-Action", "WiMAX-Packet-Flow-Descriptor"},
			SafeRawEvidence:       true,
			HashRawValues:         true,
		},
	}
}
