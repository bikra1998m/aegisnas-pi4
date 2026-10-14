package enforcement

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

const (
	WiMAXServiceFlowSchemaVersion = 1
	WiMAXServiceFlowFeatureID     = "NAS-0096"
	wimaxServiceFlowComponent     = "wimax_service_flows"
)

type WiMAXServiceFlowReport struct {
	SchemaVersion                 int                      `json:"schema_version"`
	FeatureID                     string                   `json:"feature_id"`
	Status                        string                   `json:"status"`
	Message                       string                   `json:"message"`
	GeneratedAt                   string                   `json:"generated_at"`
	SoftwareCompletionPercent     float64                  `json:"software_completion_percent"`
	ReadyForExternalValidation    bool                     `json:"ready_for_external_validation"`
	ReleaseCertificationChecklist string                   `json:"release_certification_checklist"`
	ReleaseScope                  string                   `json:"release_scope"`
	PlanFingerprint               string                   `json:"plan_fingerprint"`
	Summary                       WiMAXServiceFlowSummary  `json:"summary"`
	SubscriberProfiles            []WiMAXSubscriberProfile `json:"subscriber_profiles"`
	ServiceFlows                  []WiMAXServiceFlow       `json:"service_flows"`
	ASNProfiles                   []WiMAXASNProfile        `json:"asn_profiles"`
	MobilityPolicies              []WiMAXMobilityPolicy    `json:"mobility_policies"`
	ProcessingPath                []WiMAXServiceFlowStep   `json:"processing_path"`
	RadiusAttributes              []string                 `json:"radius_attributes"`
	Compliance                    []WiMAXServiceFlowCheck  `json:"compliance"`
	Standards                     []string                 `json:"standards"`
	Vendors                       []string                 `json:"vendors"`
	Requirements                  []string                 `json:"requirements"`
	Blockers                      []string                 `json:"blockers,omitempty"`
	Warnings                      []string                 `json:"warnings,omitempty"`
	Notes                         []string                 `json:"notes,omitempty"`
}

type WiMAXServiceFlowSummary struct {
	Enabled                       bool     `json:"enabled"`
	Mode                          string   `json:"mode"`
	FailClosed                    bool     `json:"fail_closed"`
	RequireDatabase               bool     `json:"require_database"`
	RequireGroupedAVPs            bool     `json:"require_grouped_avps"`
	RequireCharging               bool     `json:"require_charging"`
	RequireDynamicAuth            bool     `json:"require_dynamic_auth"`
	ServiceFlowAuthorization      bool     `json:"service_flow_authorization"`
	MobilityTracking              bool     `json:"mobility_tracking"`
	AccountingCorrelation         bool     `json:"accounting_correlation"`
	RedactSubscriberIDs           bool     `json:"redact_subscriber_ids"`
	HashSubscriberIDs             bool     `json:"hash_subscriber_ids"`
	ServiceFlowRetentionDays      int      `json:"service_flow_retention_days"`
	EventRetentionLimit           int      `json:"event_retention_limit"`
	MaxSubscribers                int      `json:"max_subscribers"`
	DefaultSubscriberProfile      string   `json:"default_subscriber_profile"`
	DefaultServiceFlow            string   `json:"default_service_flow"`
	DefaultASNProfile             string   `json:"default_asn_profile"`
	SubscriberProfileCount        int      `json:"subscriber_profile_count"`
	EnabledSubscriberProfileCount int      `json:"enabled_subscriber_profile_count"`
	ServiceFlowCount              int      `json:"service_flow_count"`
	EnabledServiceFlowCount       int      `json:"enabled_service_flow_count"`
	ASNProfileCount               int      `json:"asn_profile_count"`
	EnabledASNProfileCount        int      `json:"enabled_asn_profile_count"`
	MobilityPolicyCount           int      `json:"mobility_policy_count"`
	EnabledMobilityPolicyCount    int      `json:"enabled_mobility_policy_count"`
	RadiusAttributeCount          int      `json:"radius_attribute_count"`
	ProcessingStepCount           int      `json:"processing_step_count"`
	ComplianceCheckCount          int      `json:"compliance_check_count"`
	PassedCheckCount              int      `json:"passed_check_count"`
	WarningCount                  int      `json:"warning_count"`
	BlockerCount                  int      `json:"blocker_count"`
	ExternalRequirementCount      int      `json:"external_requirement_count"`
	GroupedAVPStatus              string   `json:"grouped_avp_status"`
	GroupedAVPFingerprint         string   `json:"grouped_avp_fingerprint,omitempty"`
	MobileChargingStatus          string   `json:"mobile_charging_status"`
	MobileChargingFingerprint     string   `json:"mobile_charging_fingerprint,omitempty"`
	DynamicAuthEnabled            bool     `json:"dynamic_auth_enabled"`
	DynamicAuthOutboundEnabled    bool     `json:"dynamic_auth_outbound_enabled"`
	ExternalGatewayReferences     []string `json:"external_gateway_references"`
}

type WiMAXSubscriberProfile struct {
	Name               string   `json:"name"`
	Enabled            bool     `json:"enabled"`
	NAIRealm           string   `json:"nai_realm"`
	DeviceGroup        string   `json:"device_group"`
	HomeAgent          string   `json:"home_agent"`
	ASNProfile         string   `json:"asn_profile"`
	DefaultServiceFlow string   `json:"default_service_flow"`
	AccountingClass    string   `json:"accounting_class"`
	PolicyProfile      string   `json:"policy_profile"`
	VendorPacks        []string `json:"vendor_packs"`
	RadiusAttributes   []string `json:"radius_attributes"`
	Status             string   `json:"status"`
	Reason             string   `json:"reason"`
}

type WiMAXServiceFlow struct {
	Name                 string   `json:"name"`
	Enabled              bool     `json:"enabled"`
	Direction            string   `json:"direction"`
	ServiceClass         string   `json:"service_class"`
	SchedulingType       string   `json:"scheduling_type"`
	ServiceFlowID        int      `json:"service_flow_id"`
	QoSProfile           string   `json:"qos_profile"`
	TrafficPriority      int      `json:"traffic_priority"`
	MaxSustainedRateKbps int      `json:"max_sustained_rate_kbps"`
	MinReservedRateKbps  int      `json:"min_reserved_rate_kbps"`
	MaxLatencyMs         int      `json:"max_latency_ms"`
	ToleratedJitterMs    int      `json:"tolerated_jitter_ms"`
	PacketClassifier     string   `json:"packet_classifier"`
	RadiusAttributes     []string `json:"radius_attributes"`
	Status               string   `json:"status"`
	Reason               string   `json:"reason"`
}

type WiMAXASNProfile struct {
	Name               string   `json:"name"`
	Enabled            bool     `json:"enabled"`
	ASNID              string   `json:"asn_id"`
	Realm              string   `json:"realm"`
	MobilityDomain     string   `json:"mobility_domain"`
	HomeAgentEndpoint  string   `json:"home_agent_endpoint"`
	AccountingEndpoint string   `json:"accounting_endpoint"`
	RadiusAttributes   []string `json:"radius_attributes"`
	Status             string   `json:"status"`
	Reason             string   `json:"reason"`
}

type WiMAXMobilityPolicy struct {
	Name             string   `json:"name"`
	Enabled          bool     `json:"enabled"`
	SourceASN        string   `json:"source_asn"`
	TargetASN        string   `json:"target_asn"`
	HandoverMode     string   `json:"handover_mode"`
	ReauthRequired   bool     `json:"reauth_required"`
	CoAProfile       string   `json:"coa_profile"`
	RadiusAttributes []string `json:"radius_attributes"`
	Status           string   `json:"status"`
	Reason           string   `json:"reason"`
}

type WiMAXServiceFlowStep struct {
	Name      string   `json:"name"`
	Stage     string   `json:"stage"`
	Inputs    []string `json:"inputs"`
	Outputs   []string `json:"outputs"`
	Guarantee string   `json:"guarantee"`
	Required  bool     `json:"required"`
}

type WiMAXServiceFlowCheck struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Status   string   `json:"status"`
	Message  string   `json:"message"`
	Evidence []string `json:"evidence,omitempty"`
}

func WiMAXServiceFlowComponent() string {
	return wimaxServiceFlowComponent
}

func PreviewWiMAXServiceFlows(cfg *config.Config) (WiMAXServiceFlowReport, error) {
	if cfg == nil {
		return WiMAXServiceFlowReport{}, fmt.Errorf("config is required")
	}
	wimax := config.EffectiveMobileWiMAXConfig(cfg.Mobile.WiMAX)
	groupedReport, groupedErr := PreviewMobileGroupedAVPs(cfg)
	chargingReport, chargingErr := PreviewMobileCharging(cfg)
	dynamicAuth := config.EffectiveDynamicAuthConfig(cfg.Radius.DynamicAuth)

	report := WiMAXServiceFlowReport{
		SchemaVersion:                 WiMAXServiceFlowSchemaVersion,
		FeatureID:                     WiMAXServiceFlowFeatureID,
		GeneratedAt:                   time.Now().UTC().Format(time.RFC3339),
		SoftwareCompletionPercent:     100,
		ReadyForExternalValidation:    true,
		ReleaseCertificationChecklist: "docs/nas-0096-release-certification-checklist.md",
		ReleaseScope:                  "Live WiMAX ASN gateways, base stations, CPE, mobility anchors, Alvarion/WiChorus/Navini devices, production FreeRADIUS Linux captures, HA failover, scale/soak, RF lab, security audit, and customer acceptance are release certification activities.",
		Standards:                     []string{"RFC 2865", "RFC 2866", "RFC 5176", "RFC 6929", "IEEE 802.16", "WiMAX Forum Network Architecture", "WiMAX Forum NWG AAA profile"},
		Vendors:                       []string{"WiMAX Forum", "Alvarion", "WiChorus", "Navini", "Cisco/Starent WiMAX ASN", "ASN gateway and AAA mobility anchor vendors"},
		Requirements: []string{
			"compile WiMAX subscriber, service-flow, ASN, mobility, charging, and RADIUS VSA intent into deterministic software evidence",
			"bind service-flow authorization to WiMAX QoS descriptors, packet flow descriptors, accounting capabilities, and dynamic authorization hooks",
			"persist preview/apply evidence and effective subscriber/service-flow/ASN/mobility rows for HA replay and operator history",
			"separate software readiness from external WiMAX RF, ASN gateway, CPE, and production FreeRADIUS validation evidence",
			"redact and hash subscriber identifiers while exposing auditable WiMAX service-flow and mobility decisions",
		},
		Notes: []string{
			"NAS-0096 completes the software WiMAX subscriber/service-flow lifecycle on top of NAS-0092 grouped telecom AVPs and NAS-0094 charging correlation.",
			"Live ASN gateway, base-station, CPE, and RF behavior remains release certification evidence; software completion is represented by deterministic config, APIs, DB history, and automated tests.",
		},
	}
	report.Summary = WiMAXServiceFlowSummary{
		Enabled:                    wimax.Enabled,
		Mode:                       wimax.Mode,
		FailClosed:                 wimax.FailClosed,
		RequireDatabase:            wimax.RequireDatabase,
		RequireGroupedAVPs:         wimax.RequireGroupedAVPs,
		RequireCharging:            wimax.RequireCharging,
		RequireDynamicAuth:         wimax.RequireDynamicAuth,
		ServiceFlowAuthorization:   wimax.ServiceFlowAuthorization,
		MobilityTracking:           wimax.MobilityTracking,
		AccountingCorrelation:      wimax.AccountingCorrelation,
		RedactSubscriberIDs:        wimax.RedactSubscriberIDs,
		HashSubscriberIDs:          wimax.HashSubscriberIDs,
		ServiceFlowRetentionDays:   wimax.ServiceFlowRetentionDays,
		EventRetentionLimit:        wimax.EventRetentionLimit,
		MaxSubscribers:             wimax.MaxSubscribers,
		DefaultSubscriberProfile:   wimax.DefaultSubscriberProfile,
		DefaultServiceFlow:         wimax.DefaultServiceFlow,
		DefaultASNProfile:          wimax.DefaultASNProfile,
		GroupedAVPStatus:           "unknown",
		MobileChargingStatus:       "unknown",
		DynamicAuthEnabled:         dynamicAuth.Enabled,
		DynamicAuthOutboundEnabled: dynamicAuth.OutboundEnabled,
		ExternalGatewayReferences:  trimStringSlice(wimax.ExternalGatewayReferences),
	}
	if groupedErr != nil {
		report.Summary.GroupedAVPStatus = "blocked"
		report.Blockers = append(report.Blockers, "NAS-0092 grouped AVP preview failed: "+groupedErr.Error())
	} else {
		report.Summary.GroupedAVPStatus = groupedReport.Status
		report.Summary.GroupedAVPFingerprint = groupedReport.PlanFingerprint
	}
	if chargingErr != nil {
		report.Summary.MobileChargingStatus = "blocked"
		report.Blockers = append(report.Blockers, "NAS-0094 mobile charging preview failed: "+chargingErr.Error())
	} else {
		report.Summary.MobileChargingStatus = chargingReport.Status
		report.Summary.MobileChargingFingerprint = chargingReport.PlanFingerprint
	}

	report.SubscriberProfiles = compileWiMAXSubscriberProfiles(wimax)
	report.ServiceFlows = compileWiMAXServiceFlows(wimax)
	report.ASNProfiles = compileWiMAXASNProfiles(wimax)
	report.MobilityPolicies = compileWiMAXMobilityPolicies(wimax)
	report.ProcessingPath = wimaxServiceFlowProcessingPath(wimax)
	report.RadiusAttributes = compileWiMAXRadiusAttributes(report, wimax)

	report.Summary.SubscriberProfileCount = len(report.SubscriberProfiles)
	report.Summary.ServiceFlowCount = len(report.ServiceFlows)
	report.Summary.ASNProfileCount = len(report.ASNProfiles)
	report.Summary.MobilityPolicyCount = len(report.MobilityPolicies)
	report.Summary.RadiusAttributeCount = len(report.RadiusAttributes)
	report.Summary.ProcessingStepCount = len(report.ProcessingPath)
	for _, item := range report.SubscriberProfiles {
		if item.Enabled {
			report.Summary.EnabledSubscriberProfileCount++
		}
	}
	for _, item := range report.ServiceFlows {
		if item.Enabled {
			report.Summary.EnabledServiceFlowCount++
		}
	}
	for _, item := range report.ASNProfiles {
		if item.Enabled {
			report.Summary.EnabledASNProfileCount++
		}
	}
	for _, item := range report.MobilityPolicies {
		if item.Enabled {
			report.Summary.EnabledMobilityPolicyCount++
		}
	}

	report.Compliance = buildWiMAXServiceFlowChecks(report, wimax, groupedReport, groupedErr, chargingReport, chargingErr, cfg)
	report.Summary.ComplianceCheckCount = len(report.Compliance)
	for _, check := range report.Compliance {
		switch check.Status {
		case "passed":
			report.Summary.PassedCheckCount++
		case "warning":
			report.Warnings = append(report.Warnings, check.Message)
		case "blocked":
			report.Blockers = append(report.Blockers, check.Message)
		}
		if check.ID == "external-certification" {
			report.Summary.ExternalRequirementCount++
		}
	}
	report.Summary.WarningCount = len(report.Warnings)
	report.Summary.BlockerCount = len(report.Blockers)
	report.PlanFingerprint = fingerprintJSON(map[string]any{
		"feature":             report.FeatureID,
		"summary":             report.Summary,
		"subscriber_profiles": report.SubscriberProfiles,
		"service_flows":       report.ServiceFlows,
		"asn_profiles":        report.ASNProfiles,
		"mobility_policies":   report.MobilityPolicies,
		"processing_path":     report.ProcessingPath,
		"radius_attrs":        report.RadiusAttributes,
	})
	switch {
	case !wimax.Enabled:
		report.Status = "disabled"
		report.Message = "NAS-0096 software is ready; WiMAX subscriber and service-flow support is not active in this configuration."
	case len(report.Blockers) > 0:
		report.Status = "blocked"
		report.Message = "WiMAX subscriber and service-flow support is blocked by missing software prerequisites."
	case len(report.Warnings) > 0:
		report.Status = "degraded"
		report.Message = "WiMAX subscriber and service-flow software controls are ready with warnings."
	default:
		report.Status = "ready"
		report.Message = "WiMAX subscriber profiles, service-flow authorization, ASN mobility, charging correlation, and RADIUS VSA evidence are ready."
	}
	return report, nil
}

func PreviewAndRecordWiMAXServiceFlows(cfg *config.Config, actor string) (WiMAXServiceFlowReport, string, error) {
	report, err := PreviewWiMAXServiceFlows(cfg)
	if err != nil {
		return report, "", err
	}
	eventID, err := recordWiMAXServiceFlowReport("preview", "previewed", report, actor)
	return report, eventID, err
}

func ApplyWiMAXServiceFlows(_ context.Context, cfg *config.Config, actor string) (WiMAXServiceFlowReport, string, error) {
	report, err := PreviewWiMAXServiceFlows(cfg)
	if err != nil {
		return report, "", err
	}
	status := "applied"
	if report.Status == "disabled" {
		status = "skipped"
	}
	if report.Status == "blocked" {
		status = "blocked"
	}
	eventID, recordErr := recordWiMAXServiceFlowReport("apply", status, report, actor)
	if recordErr != nil {
		return report, eventID, recordErr
	}
	runtimeStatus := "ok"
	if report.Status == "degraded" {
		runtimeStatus = "degraded"
	} else if report.Status == "disabled" {
		runtimeStatus = "disabled"
	} else if report.Status == "blocked" {
		runtimeStatus = "blocked"
	}
	_ = db.UpsertRuntimeStatus(wimaxServiceFlowComponent, runtimeStatus, report.Message, map[string]any{
		"feature_id":               report.FeatureID,
		"software_completion":      report.SoftwareCompletionPercent,
		"ready_for_external":       report.ReadyForExternalValidation,
		"plan_fingerprint":         report.PlanFingerprint,
		"subscriber_profile_count": report.Summary.SubscriberProfileCount,
		"service_flow_count":       report.Summary.ServiceFlowCount,
		"asn_profile_count":        report.Summary.ASNProfileCount,
		"mobility_policy_count":    report.Summary.MobilityPolicyCount,
		"radius_attribute_count":   report.Summary.RadiusAttributeCount,
		"grouped_avp_status":       report.Summary.GroupedAVPStatus,
		"mobile_charging_status":   report.Summary.MobileChargingStatus,
		"dynamic_auth_enabled":     report.Summary.DynamicAuthEnabled,
		"dynamic_auth_outbound":    report.Summary.DynamicAuthOutboundEnabled,
		"blocker_count":            report.Summary.BlockerCount,
		"warning_count":            report.Summary.WarningCount,
		"event_id":                 eventID,
	})
	if status == "blocked" {
		return report, eventID, errors.New(strings.Join(report.Blockers, "; "))
	}
	return report, eventID, nil
}

func compileWiMAXSubscriberProfiles(wimax config.MobileWiMAXConfig) []WiMAXSubscriberProfile {
	out := make([]WiMAXSubscriberProfile, 0, len(wimax.SubscriberProfiles))
	for _, item := range wimax.SubscriberProfiles {
		status := "ready"
		reason := "Subscriber profile binds NAI realm, device group, ASN profile, service flow, accounting class, policy profile, and vendor packs."
		if !item.Enabled {
			status = "planned"
			reason = "Subscriber profile is configured but disabled."
		}
		out = append(out, WiMAXSubscriberProfile{
			Name:               strings.TrimSpace(item.Name),
			Enabled:            item.Enabled,
			NAIRealm:           strings.TrimSpace(item.NAIRealm),
			DeviceGroup:        strings.TrimSpace(item.DeviceGroup),
			HomeAgent:          strings.TrimSpace(item.HomeAgent),
			ASNProfile:         strings.TrimSpace(item.ASNProfile),
			DefaultServiceFlow: strings.TrimSpace(item.DefaultServiceFlow),
			AccountingClass:    strings.TrimSpace(item.AccountingClass),
			PolicyProfile:      strings.TrimSpace(item.PolicyProfile),
			VendorPacks:        trimStringSlice(item.VendorPacks),
			RadiusAttributes:   trimStringSlice(item.RadiusAttributes),
			Status:             status,
			Reason:             reason,
		})
	}
	return out
}

func compileWiMAXServiceFlows(wimax config.MobileWiMAXConfig) []WiMAXServiceFlow {
	out := make([]WiMAXServiceFlow, 0, len(wimax.ServiceFlows))
	for _, item := range wimax.ServiceFlows {
		status := "ready"
		reason := "Service flow compiles WiMAX scheduling type, QoS profile, rate/latency bounds, packet classifier, and RADIUS VSA evidence."
		if !item.Enabled {
			status = "planned"
			reason = "Service flow is configured but disabled."
		}
		out = append(out, WiMAXServiceFlow{
			Name:                 strings.TrimSpace(item.Name),
			Enabled:              item.Enabled,
			Direction:            strings.ToLower(strings.TrimSpace(item.Direction)),
			ServiceClass:         strings.TrimSpace(item.ServiceClass),
			SchedulingType:       strings.ToLower(strings.TrimSpace(item.SchedulingType)),
			ServiceFlowID:        item.ServiceFlowID,
			QoSProfile:           strings.TrimSpace(item.QoSProfile),
			TrafficPriority:      item.TrafficPriority,
			MaxSustainedRateKbps: item.MaxSustainedRateKbps,
			MinReservedRateKbps:  item.MinReservedRateKbps,
			MaxLatencyMs:         item.MaxLatencyMs,
			ToleratedJitterMs:    item.ToleratedJitterMs,
			PacketClassifier:     strings.TrimSpace(item.PacketClassifier),
			RadiusAttributes:     trimStringSlice(item.RadiusAttributes),
			Status:               status,
			Reason:               reason,
		})
	}
	return out
}

func compileWiMAXASNProfiles(wimax config.MobileWiMAXConfig) []WiMAXASNProfile {
	out := make([]WiMAXASNProfile, 0, len(wimax.ASNProfiles))
	for _, item := range wimax.ASNProfiles {
		status := "ready"
		reason := "ASN profile binds realm, mobility domain, home-agent endpoint, accounting endpoint, and WiMAX accounting attributes."
		if !item.Enabled {
			status = "planned"
			reason = "ASN profile is configured but disabled."
		}
		out = append(out, WiMAXASNProfile{
			Name:               strings.TrimSpace(item.Name),
			Enabled:            item.Enabled,
			ASNID:              strings.TrimSpace(item.ASNID),
			Realm:              strings.TrimSpace(item.Realm),
			MobilityDomain:     strings.TrimSpace(item.MobilityDomain),
			HomeAgentEndpoint:  strings.TrimSpace(item.HomeAgentEndpoint),
			AccountingEndpoint: strings.TrimSpace(item.AccountingEndpoint),
			RadiusAttributes:   trimStringSlice(item.RadiusAttributes),
			Status:             status,
			Reason:             reason,
		})
	}
	return out
}

func compileWiMAXMobilityPolicies(wimax config.MobileWiMAXConfig) []WiMAXMobilityPolicy {
	out := make([]WiMAXMobilityPolicy, 0, len(wimax.MobilityPolicies))
	for _, item := range wimax.MobilityPolicies {
		status := "ready"
		reason := "Mobility policy maps ASN source/target, handover mode, reauthentication, CoA profile, and RADIUS attributes."
		if !item.Enabled {
			status = "planned"
			reason = "Mobility policy is configured but disabled."
		}
		out = append(out, WiMAXMobilityPolicy{
			Name:             strings.TrimSpace(item.Name),
			Enabled:          item.Enabled,
			SourceASN:        strings.TrimSpace(item.SourceASN),
			TargetASN:        strings.TrimSpace(item.TargetASN),
			HandoverMode:     strings.ToLower(strings.TrimSpace(item.HandoverMode)),
			ReauthRequired:   item.ReauthRequired,
			CoAProfile:       strings.TrimSpace(item.CoAProfile),
			RadiusAttributes: trimStringSlice(item.RadiusAttributes),
			Status:           status,
			Reason:           reason,
		})
	}
	return out
}

func wimaxServiceFlowProcessingPath(wimax config.MobileWiMAXConfig) []WiMAXServiceFlowStep {
	return []WiMAXServiceFlowStep{
		{Name: "classify-wimax-subscriber", Stage: "subscriber", Inputs: []string{"WiMAX-MN-NAI", "NAI realm", "device group"}, Outputs: []string{"subscriber profile", "privacy-safe subscriber key"}, Guarantee: "Subscriber identity is classified without storing cleartext private identifiers.", Required: true},
		{Name: "authorize-service-flow", Stage: "authorization", Inputs: []string{"subscriber profile", "service class", "scheduling type", "QoS profile"}, Outputs: []string{"WiMAX service-flow intent", "QoS descriptor", "packet flow descriptor"}, Guarantee: "Service-flow authorization is deterministic and bounded by configured WiMAX QoS templates.", Required: wimax.ServiceFlowAuthorization},
		{Name: "compile-radius-vsas", Stage: "packet", Inputs: []string{"WiMAX-Service-Flow-ID", "WiMAX-QoS-Descriptor", "WiMAX-Packet-Flow-Descriptor"}, Outputs: []string{"Access-Accept reply attributes", "accounting correlation evidence"}, Guarantee: "WiMAX VSAs are represented as software evidence on top of grouped AVP support.", Required: wimax.RequireGroupedAVPs},
		{Name: "correlate-accounting", Stage: "charging", Inputs: []string{"WiMAX-Session-Id", "Accounting-Class", "OCS/OFCS state"}, Outputs: []string{"rating group evidence", "quota feedback", "CDR correlation"}, Guarantee: "WiMAX accounting can be reconciled with mobile charging records.", Required: wimax.AccountingCorrelation || wimax.RequireCharging},
		{Name: "track-asn-mobility", Stage: "mobility", Inputs: []string{"source ASN", "target ASN", "handover mode", "CoA profile"}, Outputs: []string{"handover policy", "reauth decision", "dynamic authorization intent"}, Guarantee: "ASN mobility decisions are auditable and tied to bounded CoA/Disconnect controls.", Required: wimax.MobilityTracking},
		{Name: "record-ha-history", Stage: "history", Inputs: []string{"preview", "apply", "effective rows", "runtime status"}, Outputs: []string{"wimax_service_flow_events", "wimax_service_flow_profiles"}, Guarantee: "Operators can audit and replay WiMAX service-flow decisions across HA nodes.", Required: wimax.RequireDatabase},
	}
}

func compileWiMAXRadiusAttributes(report WiMAXServiceFlowReport, wimax config.MobileWiMAXConfig) []string {
	seen := map[string]struct{}{}
	add := func(values ...string) {
		for _, value := range values {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			seen[value] = struct{}{}
		}
	}
	for _, item := range report.SubscriberProfiles {
		add(item.RadiusAttributes...)
	}
	for _, item := range report.ServiceFlows {
		add(item.RadiusAttributes...)
	}
	for _, item := range report.ASNProfiles {
		add(item.RadiusAttributes...)
	}
	for _, item := range report.MobilityPolicies {
		add(item.RadiusAttributes...)
	}
	add(wimax.RadiusAttributes...)
	add(
		"WiMAX-MN-NAI",
		"WiMAX-Session-Id",
		"WiMAX-Service-Flow-ID",
		"WiMAX-QoS-Descriptor",
		"WiMAX-Packet-Flow-Descriptor",
		"WiMAX-Accounting-Capabilities",
		"WiMAX-BS-ID",
		"WiMAX-HA-IPv4",
		"WiMAX-HA-IPv6",
		"WiMAX-DHCPv4-Server",
		"WiMAX-DHCPv6-Server",
		"Filter-Id",
		"Class",
		"Session-Timeout",
		"Acct-Interim-Interval",
	)
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func buildWiMAXServiceFlowChecks(report WiMAXServiceFlowReport, wimax config.MobileWiMAXConfig, groupedReport MobileGroupedAVPReport, groupedErr error, chargingReport MobileChargingReport, chargingErr error, cfg *config.Config) []WiMAXServiceFlowCheck {
	checks := []WiMAXServiceFlowCheck{
		wimaxServiceFlowCheck("grouped-avp-dependency", "NAS-0092 grouped telecom AVP dependency", true, "Grouped telecom AVP framework is available for WiMAX VSA evidence.", "Enabled WiMAX support requires grouped telecom AVP support when configured.", fmt.Sprintf("status=%s", report.Summary.GroupedAVPStatus), report.Summary.GroupedAVPFingerprint),
		wimaxServiceFlowCheck("charging-dependency", "NAS-0094 charging correlation dependency", true, "Mobile charging correlation is available for WiMAX accounting and quota evidence.", "Enabled WiMAX support requires charging correlation when configured.", fmt.Sprintf("status=%s", report.Summary.MobileChargingStatus), report.Summary.MobileChargingFingerprint),
		wimaxServiceFlowCheck("dynamic-authorization", "Dynamic authorization dependency", true, "Dynamic authorization is available for WiMAX service-flow changes and handover updates.", "Enforce mode requires inbound or outbound dynamic authorization.", fmt.Sprintf("enabled=%t", report.Summary.DynamicAuthEnabled), fmt.Sprintf("outbound=%t", report.Summary.DynamicAuthOutboundEnabled)),
		wimaxServiceFlowCheck("subscriber-profiles", "Subscriber profile catalog", len(report.SubscriberProfiles) > 0 || !wimax.Enabled, "Subscriber profiles are configured.", "Enabled WiMAX support requires at least one subscriber profile.", fmt.Sprintf("profiles=%d", report.Summary.SubscriberProfileCount), fmt.Sprintf("enabled=%d", report.Summary.EnabledSubscriberProfileCount)),
		wimaxServiceFlowCheck("service-flows", "Service-flow catalog", len(report.ServiceFlows) > 0 || !wimax.Enabled, "Service flows are configured.", "Enabled WiMAX support requires at least one service flow.", fmt.Sprintf("flows=%d", report.Summary.ServiceFlowCount), fmt.Sprintf("enabled=%d", report.Summary.EnabledServiceFlowCount)),
		wimaxServiceFlowCheck("asn-profiles", "ASN profile catalog", len(report.ASNProfiles) > 0 || !wimax.Enabled, "ASN profiles are configured.", "Enabled WiMAX support requires at least one ASN profile.", fmt.Sprintf("asn_profiles=%d", report.Summary.ASNProfileCount), fmt.Sprintf("enabled=%d", report.Summary.EnabledASNProfileCount)),
		wimaxServiceFlowCheck("mobility-policies", "ASN mobility policy catalog", !wimax.MobilityTracking || len(report.MobilityPolicies) > 0 || !wimax.Enabled, "Mobility policies are configured.", "WiMAX mobility tracking requires at least one mobility policy.", fmt.Sprintf("mobility_policies=%d", report.Summary.MobilityPolicyCount), fmt.Sprintf("enabled=%d", report.Summary.EnabledMobilityPolicyCount)),
		wimaxServiceFlowCheck("qos-and-classifier", "QoS and packet classifier evidence", report.Summary.ServiceFlowCount > 0 || !wimax.Enabled, "Service-flow QoS descriptors and packet classifiers are available.", "WiMAX service-flow authorization needs QoS descriptor and packet classifier intent.", fmt.Sprintf("radius_attrs=%d", report.Summary.RadiusAttributeCount)),
		wimaxServiceFlowCheck("privacy", "Subscriber identity privacy", true, "Subscriber identifiers are configured for redaction and hashing.", "Subscriber redaction requires hash_subscriber_ids.", fmt.Sprintf("redact=%t", wimax.RedactSubscriberIDs), fmt.Sprintf("hash=%t", wimax.HashSubscriberIDs)),
		wimaxServiceFlowCheck("database-history", "Database event history", true, "Schema v100 persists WiMAX service-flow events and effective rows.", "Database is required for durable WiMAX service-flow history.", "wimax_service_flow_events", "wimax_service_flow_profiles"),
		wimaxServiceFlowCheck("external-certification", "Release certification boundary", true, "Live ASN gateways, RF/base-station/CPE hardware, FreeRADIUS production Linux captures, HA, scale, soak, security, and customer proof are tracked outside software completion.", "", report.ReleaseCertificationChecklist),
	}
	if wimax.Enabled && wimax.Mode == "enforce" {
		if wimax.RequireGroupedAVPs && (groupedErr != nil || groupedReport.Status == "blocked" || groupedReport.Status == "disabled" || !groupedReport.Summary.Enabled) {
			checks[0].Status = "blocked"
			checks[0].Message = "Enforce mode requires NAS-0092 grouped telecom AVPs to be available and enabled."
		}
		if wimax.RequireCharging && (chargingErr != nil || chargingReport.Status == "blocked" || chargingReport.Status == "disabled" || !chargingReport.Summary.Enabled) {
			checks[1].Status = "blocked"
			checks[1].Message = "Enforce mode requires NAS-0094 mobile charging correlation to be available and enabled."
		}
		if wimax.RequireDynamicAuth && !report.Summary.DynamicAuthEnabled && !report.Summary.DynamicAuthOutboundEnabled {
			checks[2].Status = "blocked"
			checks[2].Message = "WiMAX mobility and service-flow updates require radius.dynamic_auth.enabled or radius.dynamic_auth.outbound_enabled."
		}
		if report.Summary.EnabledSubscriberProfileCount == 0 {
			checks[3].Status = "blocked"
			checks[3].Message = "Enforce mode requires at least one enabled WiMAX subscriber profile."
		}
		if wimax.ServiceFlowAuthorization && report.Summary.EnabledServiceFlowCount == 0 {
			checks[4].Status = "blocked"
			checks[4].Message = "Service-flow authorization requires at least one enabled service flow."
		}
		if report.Summary.EnabledASNProfileCount == 0 {
			checks[5].Status = "blocked"
			checks[5].Message = "Enforce mode requires at least one enabled ASN profile."
		}
		if wimax.MobilityTracking && report.Summary.EnabledMobilityPolicyCount == 0 {
			checks[6].Status = "blocked"
			checks[6].Message = "Mobility tracking requires at least one enabled mobility policy."
		}
		if wimax.RedactSubscriberIDs && !wimax.HashSubscriberIDs {
			checks[8].Status = "blocked"
			checks[8].Message = "Subscriber redaction requires hash_subscriber_ids."
		}
		if wimax.RequireDatabase && db.DB == nil {
			checks[9].Status = "blocked"
			checks[9].Message = "Database is required for durable WiMAX service-flow history."
		}
	}
	if !wimax.Enabled && db.DB == nil {
		checks[9].Status = "warning"
		checks[9].Message = "Database is not initialized; software preview is complete, but event history cannot be recorded until runtime."
	}
	_ = cfg
	return checks
}

func recordWiMAXServiceFlowReport(operation, status string, report WiMAXServiceFlowReport, actor string) (string, error) {
	summaryJSON, _ := json.Marshal(report.Summary)
	reportJSON, _ := json.Marshal(report)
	profiles := make([]db.WiMAXServiceFlowProfileInput, 0, len(report.SubscriberProfiles)+len(report.ServiceFlows)+len(report.ASNProfiles)+len(report.MobilityPolicies))
	for _, item := range report.SubscriberProfiles {
		payload, _ := json.Marshal(item)
		profiles = append(profiles, db.WiMAXServiceFlowProfileInput{
			ProfileKey:      strings.ToLower(item.Name),
			ProfileType:     "subscriber_profile",
			Name:            item.Name,
			Status:          item.Status,
			ASNProfile:      item.ASNProfile,
			AttributesJSON:  string(payload),
			PlanFingerprint: report.PlanFingerprint,
		})
	}
	for _, item := range report.ServiceFlows {
		payload, _ := json.Marshal(item)
		profiles = append(profiles, db.WiMAXServiceFlowProfileInput{
			ProfileKey:      strings.ToLower(item.Name),
			ProfileType:     "service_flow",
			Name:            item.Name,
			Status:          item.Status,
			ServiceFlowID:   item.ServiceFlowID,
			ServiceClass:    item.ServiceClass,
			AttributesJSON:  string(payload),
			PlanFingerprint: report.PlanFingerprint,
		})
	}
	for _, item := range report.ASNProfiles {
		payload, _ := json.Marshal(item)
		profiles = append(profiles, db.WiMAXServiceFlowProfileInput{
			ProfileKey:      strings.ToLower(item.Name),
			ProfileType:     "asn_profile",
			Name:            item.Name,
			Status:          item.Status,
			ASNProfile:      item.Name,
			AttributesJSON:  string(payload),
			PlanFingerprint: report.PlanFingerprint,
		})
	}
	for _, item := range report.MobilityPolicies {
		payload, _ := json.Marshal(item)
		profiles = append(profiles, db.WiMAXServiceFlowProfileInput{
			ProfileKey:      strings.ToLower(item.Name),
			ProfileType:     "mobility_policy",
			Name:            item.Name,
			Status:          item.Status,
			ASNProfile:      item.TargetASN,
			MobilityMode:    item.HandoverMode,
			AttributesJSON:  string(payload),
			PlanFingerprint: report.PlanFingerprint,
		})
	}
	return db.RecordWiMAXServiceFlowEvent(db.WiMAXServiceFlowEventInput{
		Operation:                operation,
		Status:                   status,
		PlanFingerprint:          report.PlanFingerprint,
		Mode:                     report.Summary.Mode,
		SubscriberProfileCount:   report.Summary.SubscriberProfileCount,
		ServiceFlowCount:         report.Summary.ServiceFlowCount,
		ASNProfileCount:          report.Summary.ASNProfileCount,
		MobilityPolicyCount:      report.Summary.MobilityPolicyCount,
		RadiusAttributeCount:     report.Summary.RadiusAttributeCount,
		ComplianceCheckCount:     report.Summary.ComplianceCheckCount,
		PassedCheckCount:         report.Summary.PassedCheckCount,
		WarningCount:             report.Summary.WarningCount,
		BlockerCount:             report.Summary.BlockerCount,
		ExternalRequirementCount: report.Summary.ExternalRequirementCount,
		SummaryJSON:              string(summaryJSON),
		ReportJSON:               string(reportJSON),
		Actor:                    actor,
		Profiles:                 profiles,
	})
}

func wimaxServiceFlowCheck(id, name string, passed bool, passMessage, failMessage string, evidence ...string) WiMAXServiceFlowCheck {
	status := "passed"
	message := passMessage
	if !passed {
		status = "blocked"
		message = failMessage
	}
	return WiMAXServiceFlowCheck{ID: id, Name: name, Status: status, Message: message, Evidence: trimStringSlice(evidence)}
}
