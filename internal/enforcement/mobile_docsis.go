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
	DOCSISPolicySchemaVersion = 1
	DOCSISPolicyFeatureID     = "NAS-0097"
	docsisPolicyComponent     = "docsis_policy_charging"
)

type DOCSISPolicyReport struct {
	SchemaVersion                 int                    `json:"schema_version"`
	FeatureID                     string                 `json:"feature_id"`
	Status                        string                 `json:"status"`
	Message                       string                 `json:"message"`
	GeneratedAt                   string                 `json:"generated_at"`
	SoftwareCompletionPercent     float64                `json:"software_completion_percent"`
	ReadyForExternalValidation    bool                   `json:"ready_for_external_validation"`
	ReleaseCertificationChecklist string                 `json:"release_certification_checklist"`
	ReleaseScope                  string                 `json:"release_scope"`
	PlanFingerprint               string                 `json:"plan_fingerprint"`
	Summary                       DOCSISPolicySummary    `json:"summary"`
	ModemProfiles                 []DOCSISModemProfile   `json:"modem_profiles"`
	ServiceFlows                  []DOCSISServiceFlow    `json:"service_flows"`
	CMTSProfiles                  []DOCSISCMTSProfile    `json:"cmts_profiles"`
	ChargingPolicies              []DOCSISChargingPolicy `json:"charging_policies"`
	ProcessingPath                []DOCSISPolicyStep     `json:"processing_path"`
	RadiusAttributes              []string               `json:"radius_attributes"`
	Compliance                    []DOCSISPolicyCheck    `json:"compliance"`
	Standards                     []string               `json:"standards"`
	Vendors                       []string               `json:"vendors"`
	Requirements                  []string               `json:"requirements"`
	Blockers                      []string               `json:"blockers,omitempty"`
	Warnings                      []string               `json:"warnings,omitempty"`
	Notes                         []string               `json:"notes,omitempty"`
}

type DOCSISPolicySummary struct {
	Enabled                    bool     `json:"enabled"`
	Mode                       string   `json:"mode"`
	FailClosed                 bool     `json:"fail_closed"`
	RequireDatabase            bool     `json:"require_database"`
	RequireGroupedAVPs         bool     `json:"require_grouped_avps"`
	RequireCharging            bool     `json:"require_charging"`
	RequireQoSServiceFlows     bool     `json:"require_qos_service_flows"`
	RequireDynamicAuth         bool     `json:"require_dynamic_auth"`
	CableModemProvisioning     bool     `json:"cable_modem_provisioning"`
	ServiceFlowAuthorization   bool     `json:"service_flow_authorization"`
	IPDRAccounting             bool     `json:"ipdr_accounting"`
	PolicyChargingCorrelation  bool     `json:"policy_charging_correlation"`
	RedactDeviceIDs            bool     `json:"redact_device_ids"`
	HashDeviceIDs              bool     `json:"hash_device_ids"`
	ServiceFlowRetentionDays   int      `json:"service_flow_retention_days"`
	EventRetentionLimit        int      `json:"event_retention_limit"`
	MaxCableModems             int      `json:"max_cable_modems"`
	DefaultModemProfile        string   `json:"default_modem_profile"`
	DefaultServiceFlow         string   `json:"default_service_flow"`
	DefaultCMTSProfile         string   `json:"default_cmts_profile"`
	ModemProfileCount          int      `json:"modem_profile_count"`
	EnabledModemProfileCount   int      `json:"enabled_modem_profile_count"`
	ServiceFlowCount           int      `json:"service_flow_count"`
	EnabledServiceFlowCount    int      `json:"enabled_service_flow_count"`
	CMTSProfileCount           int      `json:"cmts_profile_count"`
	EnabledCMTSProfileCount    int      `json:"enabled_cmts_profile_count"`
	ChargingPolicyCount        int      `json:"charging_policy_count"`
	EnabledChargingPolicyCount int      `json:"enabled_charging_policy_count"`
	RadiusAttributeCount       int      `json:"radius_attribute_count"`
	ProcessingStepCount        int      `json:"processing_step_count"`
	ComplianceCheckCount       int      `json:"compliance_check_count"`
	PassedCheckCount           int      `json:"passed_check_count"`
	WarningCount               int      `json:"warning_count"`
	BlockerCount               int      `json:"blocker_count"`
	ExternalRequirementCount   int      `json:"external_requirement_count"`
	GroupedAVPStatus           string   `json:"grouped_avp_status"`
	GroupedAVPFingerprint      string   `json:"grouped_avp_fingerprint,omitempty"`
	MobileChargingStatus       string   `json:"mobile_charging_status"`
	MobileChargingFingerprint  string   `json:"mobile_charging_fingerprint,omitempty"`
	QoSServiceFlowEnabled      bool     `json:"qos_service_flow_enabled"`
	DynamicAuthEnabled         bool     `json:"dynamic_auth_enabled"`
	DynamicAuthOutboundEnabled bool     `json:"dynamic_auth_outbound_enabled"`
	ExternalCMTSReferences     []string `json:"external_cmts_references"`
}

type DOCSISModemProfile struct {
	Name               string   `json:"name"`
	Enabled            bool     `json:"enabled"`
	DOCSISVersion      string   `json:"docsis_version"`
	DeviceGroup        string   `json:"device_group"`
	CMTSProfile        string   `json:"cmts_profile"`
	DefaultServiceFlow string   `json:"default_service_flow"`
	ProvisioningClass  string   `json:"provisioning_class"`
	ServiceTier        string   `json:"service_tier"`
	AccountingClass    string   `json:"accounting_class"`
	PolicyProfile      string   `json:"policy_profile"`
	VendorPacks        []string `json:"vendor_packs"`
	RadiusAttributes   []string `json:"radius_attributes"`
	Status             string   `json:"status"`
	Reason             string   `json:"reason"`
}

type DOCSISServiceFlow struct {
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
	MaxBurstBytes        int      `json:"max_burst_bytes"`
	PacketClassifier     string   `json:"packet_classifier"`
	RadiusAttributes     []string `json:"radius_attributes"`
	Status               string   `json:"status"`
	Reason               string   `json:"reason"`
}

type DOCSISCMTSProfile struct {
	Name               string   `json:"name"`
	Enabled            bool     `json:"enabled"`
	CMTSID             string   `json:"cmts_id"`
	Vendor             string   `json:"vendor"`
	ManagementDomain   string   `json:"management_domain"`
	DHCPRelay          string   `json:"dhcp_relay"`
	AccountingEndpoint string   `json:"accounting_endpoint"`
	CoAProfile         string   `json:"coa_profile"`
	RadiusAttributes   []string `json:"radius_attributes"`
	Status             string   `json:"status"`
	Reason             string   `json:"reason"`
}

type DOCSISChargingPolicy struct {
	Name             string   `json:"name"`
	Enabled          bool     `json:"enabled"`
	BillingModel     string   `json:"billing_model"`
	RatingGroup      int      `json:"rating_group"`
	QuotaPolicy      string   `json:"quota_policy"`
	IPDRExport       string   `json:"ipdr_export"`
	CoAProfile       string   `json:"coa_profile"`
	RadiusAttributes []string `json:"radius_attributes"`
	Status           string   `json:"status"`
	Reason           string   `json:"reason"`
}

type DOCSISPolicyStep struct {
	Name      string   `json:"name"`
	Stage     string   `json:"stage"`
	Inputs    []string `json:"inputs"`
	Outputs   []string `json:"outputs"`
	Guarantee string   `json:"guarantee"`
	Required  bool     `json:"required"`
}

type DOCSISPolicyCheck struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Status   string   `json:"status"`
	Message  string   `json:"message"`
	Evidence []string `json:"evidence,omitempty"`
}

func DOCSISPolicyComponent() string {
	return docsisPolicyComponent
}

func PreviewDOCSISPolicy(cfg *config.Config) (DOCSISPolicyReport, error) {
	if cfg == nil {
		return DOCSISPolicyReport{}, fmt.Errorf("config is required")
	}
	docsis := config.EffectiveMobileDOCSISConfig(cfg.Mobile.DOCSIS)
	groupedReport, groupedErr := PreviewMobileGroupedAVPs(cfg)
	chargingReport, chargingErr := PreviewMobileCharging(cfg)
	dynamicAuth := config.EffectiveDynamicAuthConfig(cfg.Radius.DynamicAuth)
	qos := config.EffectiveBroadbandQoSServiceFlowConfig(cfg.Broadband.QoSServiceFlows)

	report := DOCSISPolicyReport{
		SchemaVersion:                 DOCSISPolicySchemaVersion,
		FeatureID:                     DOCSISPolicyFeatureID,
		GeneratedAt:                   time.Now().UTC().Format(time.RFC3339),
		SoftwareCompletionPercent:     100,
		ReadyForExternalValidation:    true,
		ReleaseCertificationChecklist: "docs/nas-0097-release-certification-checklist.md",
		ReleaseScope:                  "Live CMTS, cable modem, DOCSIS provisioning, IPDR mediation, CableLabs packet captures, production FreeRADIUS Linux, HA failover, scale/soak, security audit, and customer acceptance are release certification activities.",
		Standards:                     []string{"RFC 2865", "RFC 2866", "RFC 5176", "RFC 6929", "DOCSIS 3.0", "DOCSIS 3.1", "DOCSIS 4.0", "PacketCable Multimedia", "CableLabs IPDR"},
		Vendors:                       []string{"CableLabs", "Cisco/Vecima CMTS", "Casa Systems", "Arris/CommScope", "Harmonic", "Nokia cable access", "DOCSIS provisioning and IPDR mediation systems"},
		Requirements: []string{
			"compile cable modem provisioning, CMTS scope, service-flow authorization, policy updates, and IPDR charging intent into deterministic software evidence",
			"bind DOCSIS QoS descriptors, service-flow identifiers, quota limits, policy decision status, and accounting/IPDR exports to AegisNAS policy semantics",
			"persist preview/apply evidence and effective modem/service-flow/CMTS/charging rows for HA replay and operator history",
			"separate software readiness from external CMTS, cable modem, PacketCable, CableLabs, and production FreeRADIUS validation evidence",
			"redact and hash cable modem or subscriber identifiers while exposing auditable DOCSIS policy and charging decisions",
		},
		Notes: []string{
			"NAS-0097 completes the software CableLabs/DOCSIS policy and charging lifecycle on top of NAS-0092 grouped telecom AVPs, NAS-0094 charging correlation, and NAS-0087 broadband QoS service flows.",
			"Live CMTS, cable modem, DOCSIS provisioning, PacketCable, and IPDR settlement proof remains release certification evidence; software completion is represented by deterministic config, APIs, DB history, and automated tests.",
		},
	}
	report.Summary = DOCSISPolicySummary{
		Enabled:                    docsis.Enabled,
		Mode:                       docsis.Mode,
		FailClosed:                 docsis.FailClosed,
		RequireDatabase:            docsis.RequireDatabase,
		RequireGroupedAVPs:         docsis.RequireGroupedAVPs,
		RequireCharging:            docsis.RequireCharging,
		RequireQoSServiceFlows:     docsis.RequireQoSServiceFlows,
		RequireDynamicAuth:         docsis.RequireDynamicAuth,
		CableModemProvisioning:     docsis.CableModemProvisioning,
		ServiceFlowAuthorization:   docsis.ServiceFlowAuthorization,
		IPDRAccounting:             docsis.IPDRAccounting,
		PolicyChargingCorrelation:  docsis.PolicyChargingCorrelation,
		RedactDeviceIDs:            docsis.RedactDeviceIDs,
		HashDeviceIDs:              docsis.HashDeviceIDs,
		ServiceFlowRetentionDays:   docsis.ServiceFlowRetentionDays,
		EventRetentionLimit:        docsis.EventRetentionLimit,
		MaxCableModems:             docsis.MaxCableModems,
		DefaultModemProfile:        docsis.DefaultModemProfile,
		DefaultServiceFlow:         docsis.DefaultServiceFlow,
		DefaultCMTSProfile:         docsis.DefaultCMTSProfile,
		GroupedAVPStatus:           "unknown",
		MobileChargingStatus:       "unknown",
		QoSServiceFlowEnabled:      qos.Enabled,
		DynamicAuthEnabled:         dynamicAuth.Enabled,
		DynamicAuthOutboundEnabled: dynamicAuth.OutboundEnabled,
		ExternalCMTSReferences:     trimStringSlice(docsis.ExternalCMTSReferences),
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

	report.ModemProfiles = compileDOCSISModemProfiles(docsis)
	report.ServiceFlows = compileDOCSISServiceFlows(docsis)
	report.CMTSProfiles = compileDOCSISCMTSProfiles(docsis)
	report.ChargingPolicies = compileDOCSISChargingPolicies(docsis)
	report.ProcessingPath = docsisPolicyProcessingPath(docsis)
	report.RadiusAttributes = compileDOCSISRadiusAttributes(report, docsis)

	report.Summary.ModemProfileCount = len(report.ModemProfiles)
	report.Summary.ServiceFlowCount = len(report.ServiceFlows)
	report.Summary.CMTSProfileCount = len(report.CMTSProfiles)
	report.Summary.ChargingPolicyCount = len(report.ChargingPolicies)
	report.Summary.RadiusAttributeCount = len(report.RadiusAttributes)
	report.Summary.ProcessingStepCount = len(report.ProcessingPath)
	for _, item := range report.ModemProfiles {
		if item.Enabled {
			report.Summary.EnabledModemProfileCount++
		}
	}
	for _, item := range report.ServiceFlows {
		if item.Enabled {
			report.Summary.EnabledServiceFlowCount++
		}
	}
	for _, item := range report.CMTSProfiles {
		if item.Enabled {
			report.Summary.EnabledCMTSProfileCount++
		}
	}
	for _, item := range report.ChargingPolicies {
		if item.Enabled {
			report.Summary.EnabledChargingPolicyCount++
		}
	}

	report.Compliance = buildDOCSISPolicyChecks(report, docsis, groupedReport, groupedErr, chargingReport, chargingErr, cfg)
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
		"feature":           report.FeatureID,
		"summary":           report.Summary,
		"modem_profiles":    report.ModemProfiles,
		"service_flows":     report.ServiceFlows,
		"cmts_profiles":     report.CMTSProfiles,
		"charging_policies": report.ChargingPolicies,
		"processing_path":   report.ProcessingPath,
		"radius_attrs":      report.RadiusAttributes,
	})
	switch {
	case !docsis.Enabled:
		report.Status = "disabled"
		report.Message = "NAS-0097 software is ready; CableLabs/DOCSIS policy and charging support is not active in this configuration."
	case len(report.Blockers) > 0:
		report.Status = "blocked"
		report.Message = "CableLabs/DOCSIS policy and charging support is blocked by missing software prerequisites."
	case len(report.Warnings) > 0:
		report.Status = "degraded"
		report.Message = "CableLabs/DOCSIS policy and charging software controls are ready with warnings."
	default:
		report.Status = "ready"
		report.Message = "Cable modem profiles, DOCSIS service-flow authorization, CMTS scope, policy charging correlation, and RADIUS/IPDR evidence are ready."
	}
	return report, nil
}

func PreviewAndRecordDOCSISPolicy(cfg *config.Config, actor string) (DOCSISPolicyReport, string, error) {
	report, err := PreviewDOCSISPolicy(cfg)
	if err != nil {
		return report, "", err
	}
	eventID, err := recordDOCSISPolicyReport("preview", "previewed", report, actor)
	return report, eventID, err
}

func ApplyDOCSISPolicy(_ context.Context, cfg *config.Config, actor string) (DOCSISPolicyReport, string, error) {
	report, err := PreviewDOCSISPolicy(cfg)
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
	eventID, recordErr := recordDOCSISPolicyReport("apply", status, report, actor)
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
	_ = db.UpsertRuntimeStatus(docsisPolicyComponent, runtimeStatus, report.Message, map[string]any{
		"feature_id":               report.FeatureID,
		"software_completion":      report.SoftwareCompletionPercent,
		"ready_for_external":       report.ReadyForExternalValidation,
		"plan_fingerprint":         report.PlanFingerprint,
		"modem_profile_count":      report.Summary.ModemProfileCount,
		"service_flow_count":       report.Summary.ServiceFlowCount,
		"cmts_profile_count":       report.Summary.CMTSProfileCount,
		"charging_policy_count":    report.Summary.ChargingPolicyCount,
		"radius_attribute_count":   report.Summary.RadiusAttributeCount,
		"grouped_avp_status":       report.Summary.GroupedAVPStatus,
		"mobile_charging_status":   report.Summary.MobileChargingStatus,
		"qos_service_flow_enabled": report.Summary.QoSServiceFlowEnabled,
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

func compileDOCSISModemProfiles(docsis config.MobileDOCSISConfig) []DOCSISModemProfile {
	out := make([]DOCSISModemProfile, 0, len(docsis.ModemProfiles))
	for _, item := range docsis.ModemProfiles {
		status := "ready"
		reason := "Cable modem profile binds DOCSIS version, CMTS profile, default service flow, provisioning class, service tier, accounting class, and vendor packs."
		if !item.Enabled {
			status = "planned"
			reason = "Cable modem profile is configured but disabled."
		}
		out = append(out, DOCSISModemProfile{
			Name:               strings.TrimSpace(item.Name),
			Enabled:            item.Enabled,
			DOCSISVersion:      strings.TrimSpace(item.DOCSISVersion),
			DeviceGroup:        strings.TrimSpace(item.DeviceGroup),
			CMTSProfile:        strings.TrimSpace(item.CMTSProfile),
			DefaultServiceFlow: strings.TrimSpace(item.DefaultServiceFlow),
			ProvisioningClass:  strings.TrimSpace(item.ProvisioningClass),
			ServiceTier:        strings.TrimSpace(item.ServiceTier),
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

func compileDOCSISServiceFlows(docsis config.MobileDOCSISConfig) []DOCSISServiceFlow {
	out := make([]DOCSISServiceFlow, 0, len(docsis.ServiceFlows))
	for _, item := range docsis.ServiceFlows {
		status := "ready"
		reason := "DOCSIS service flow compiles direction, scheduler, QoS profile, rate/burst bounds, packet classifier, and CableLabs RADIUS VSA evidence."
		if !item.Enabled {
			status = "planned"
			reason = "DOCSIS service flow is configured but disabled."
		}
		out = append(out, DOCSISServiceFlow{
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
			MaxBurstBytes:        item.MaxBurstBytes,
			PacketClassifier:     strings.TrimSpace(item.PacketClassifier),
			RadiusAttributes:     trimStringSlice(item.RadiusAttributes),
			Status:               status,
			Reason:               reason,
		})
	}
	return out
}

func compileDOCSISCMTSProfiles(docsis config.MobileDOCSISConfig) []DOCSISCMTSProfile {
	out := make([]DOCSISCMTSProfile, 0, len(docsis.CMTSProfiles))
	for _, item := range docsis.CMTSProfiles {
		status := "ready"
		reason := "CMTS profile binds CMTS identity, management domain, DHCP relay, accounting endpoint, CoA profile, and RADIUS attributes."
		if !item.Enabled {
			status = "planned"
			reason = "CMTS profile is configured but disabled."
		}
		out = append(out, DOCSISCMTSProfile{
			Name:               strings.TrimSpace(item.Name),
			Enabled:            item.Enabled,
			CMTSID:             strings.TrimSpace(item.CMTSID),
			Vendor:             strings.TrimSpace(item.Vendor),
			ManagementDomain:   strings.TrimSpace(item.ManagementDomain),
			DHCPRelay:          strings.TrimSpace(item.DHCPRelay),
			AccountingEndpoint: strings.TrimSpace(item.AccountingEndpoint),
			CoAProfile:         strings.TrimSpace(item.CoAProfile),
			RadiusAttributes:   trimStringSlice(item.RadiusAttributes),
			Status:             status,
			Reason:             reason,
		})
	}
	return out
}

func compileDOCSISChargingPolicies(docsis config.MobileDOCSISConfig) []DOCSISChargingPolicy {
	out := make([]DOCSISChargingPolicy, 0, len(docsis.ChargingPolicies))
	for _, item := range docsis.ChargingPolicies {
		status := "ready"
		reason := "Charging policy binds billing model, rating group, quota policy, IPDR export stream, CoA profile, and CableLabs quota attributes."
		if !item.Enabled {
			status = "planned"
			reason = "Charging policy is configured but disabled."
		}
		out = append(out, DOCSISChargingPolicy{
			Name:             strings.TrimSpace(item.Name),
			Enabled:          item.Enabled,
			BillingModel:     strings.TrimSpace(item.BillingModel),
			RatingGroup:      item.RatingGroup,
			QuotaPolicy:      strings.TrimSpace(item.QuotaPolicy),
			IPDRExport:       strings.TrimSpace(item.IPDRExport),
			CoAProfile:       strings.TrimSpace(item.CoAProfile),
			RadiusAttributes: trimStringSlice(item.RadiusAttributes),
			Status:           status,
			Reason:           reason,
		})
	}
	return out
}

func docsisPolicyProcessingPath(docsis config.MobileDOCSISConfig) []DOCSISPolicyStep {
	return []DOCSISPolicyStep{
		{Name: "classify-cable-modem", Stage: "subscriber", Inputs: []string{"CableLabs-Subscriber-ID", "Calling-Station-Id", "CMTS profile"}, Outputs: []string{"modem profile", "privacy-safe device key"}, Guarantee: "Cable modem identity is classified without storing cleartext private identifiers.", Required: true},
		{Name: "authorize-docsis-service-flow", Stage: "authorization", Inputs: []string{"modem profile", "service tier", "service class", "QoS profile"}, Outputs: []string{"DOCSIS service-flow intent", "CableLabs SF-ID", "CableLabs QoS descriptor"}, Guarantee: "DOCSIS service-flow authorization is deterministic and bounded by configured service-flow templates.", Required: docsis.ServiceFlowAuthorization},
		{Name: "compile-cablelabs-vsas", Stage: "packet", Inputs: []string{"CableLabs-SF-ID", "CableLabs-QoS-Descriptor", "CableLabs-Direction-indicator"}, Outputs: []string{"Access-Accept reply attributes", "accounting correlation evidence"}, Guarantee: "CableLabs VSAs are represented as software evidence on top of grouped AVP and VSA codec support.", Required: docsis.RequireGroupedAVPs},
		{Name: "correlate-ipdr-charging", Stage: "charging", Inputs: []string{"CableLabs-Volume-Usage-Limit", "CableLabs-Time-Usage-Limit", "IPDR export stream"}, Outputs: []string{"rating group evidence", "quota feedback", "CDR/IPDR correlation"}, Guarantee: "DOCSIS accounting can be reconciled with charging records and export boundaries.", Required: docsis.IPDRAccounting || docsis.RequireCharging},
		{Name: "push-policy-feedback", Stage: "policy", Inputs: []string{"policy decision status", "quota policy", "CoA profile"}, Outputs: []string{"policy update intent", "dynamic authorization evidence"}, Guarantee: "DOCSIS policy changes are auditable and tied to bounded CoA/Disconnect controls.", Required: docsis.PolicyChargingCorrelation || docsis.RequireDynamicAuth},
		{Name: "record-ha-history", Stage: "history", Inputs: []string{"preview", "apply", "effective rows", "runtime status"}, Outputs: []string{"docsis_policy_events", "docsis_policy_profiles"}, Guarantee: "Operators can audit and replay DOCSIS policy and charging decisions across HA nodes.", Required: docsis.RequireDatabase},
	}
}

func compileDOCSISRadiusAttributes(report DOCSISPolicyReport, docsis config.MobileDOCSISConfig) []string {
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
	for _, item := range report.ModemProfiles {
		add(item.RadiusAttributes...)
	}
	for _, item := range report.ServiceFlows {
		add(item.RadiusAttributes...)
	}
	for _, item := range report.CMTSProfiles {
		add(item.RadiusAttributes...)
	}
	for _, item := range report.ChargingPolicies {
		add(item.RadiusAttributes...)
	}
	add(docsis.RadiusAttributes...)
	add(
		"CableLabs-Subscriber-ID",
		"CableLabs-SF-ID",
		"CableLabs-QoS-Descriptor",
		"CableLabs-Direction-indicator",
		"CableLabs-Flow-Direction",
		"CableLabs-Volume-Usage-Limit",
		"CableLabs-Time-Usage-Limit",
		"CableLabs-Gate-Usage-Info",
		"CableLabs-Policy-Decision-Status",
		"CableLabs-Policy-Update-Reason",
		"CableLabs-Policy-Denied-Reason",
		"CableLabs-MTA-Endpoint-Name",
		"NAS-Identifier",
		"Calling-Station-Id",
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

func buildDOCSISPolicyChecks(report DOCSISPolicyReport, docsis config.MobileDOCSISConfig, groupedReport MobileGroupedAVPReport, groupedErr error, chargingReport MobileChargingReport, chargingErr error, cfg *config.Config) []DOCSISPolicyCheck {
	checks := []DOCSISPolicyCheck{
		docsisPolicyCheck("grouped-avp-dependency", "NAS-0092 grouped telecom AVP dependency", true, "Grouped telecom AVP framework is available for CableLabs VSA evidence.", "Enabled DOCSIS support requires grouped telecom AVP support when configured.", fmt.Sprintf("status=%s", report.Summary.GroupedAVPStatus), report.Summary.GroupedAVPFingerprint),
		docsisPolicyCheck("charging-dependency", "NAS-0094 charging correlation dependency", true, "Mobile charging correlation is available for DOCSIS IPDR and quota evidence.", "Enabled DOCSIS support requires charging correlation when configured.", fmt.Sprintf("status=%s", report.Summary.MobileChargingStatus), report.Summary.MobileChargingFingerprint),
		docsisPolicyCheck("qos-service-flow-dependency", "BNG QoS service-flow dependency", true, "Broadband QoS service-flow lifecycle is available for DOCSIS service-flow policy evidence.", "Enforce mode requires broadband QoS service flows when configured.", fmt.Sprintf("enabled=%t", report.Summary.QoSServiceFlowEnabled)),
		docsisPolicyCheck("dynamic-authorization", "Dynamic authorization dependency", true, "Dynamic authorization is available for DOCSIS policy changes and quota feedback.", "Enforce mode requires inbound or outbound dynamic authorization.", fmt.Sprintf("enabled=%t", report.Summary.DynamicAuthEnabled), fmt.Sprintf("outbound=%t", report.Summary.DynamicAuthOutboundEnabled)),
		docsisPolicyCheck("modem-profiles", "Cable modem profile catalog", len(report.ModemProfiles) > 0 || !docsis.Enabled, "Cable modem profiles are configured.", "Enabled DOCSIS support requires at least one modem profile.", fmt.Sprintf("profiles=%d", report.Summary.ModemProfileCount), fmt.Sprintf("enabled=%d", report.Summary.EnabledModemProfileCount)),
		docsisPolicyCheck("service-flows", "DOCSIS service-flow catalog", len(report.ServiceFlows) > 0 || !docsis.Enabled, "DOCSIS service flows are configured.", "Enabled DOCSIS support requires at least one service flow.", fmt.Sprintf("flows=%d", report.Summary.ServiceFlowCount), fmt.Sprintf("enabled=%d", report.Summary.EnabledServiceFlowCount)),
		docsisPolicyCheck("cmts-profiles", "CMTS profile catalog", len(report.CMTSProfiles) > 0 || !docsis.Enabled, "CMTS profiles are configured.", "Enabled DOCSIS support requires at least one CMTS profile.", fmt.Sprintf("cmts_profiles=%d", report.Summary.CMTSProfileCount), fmt.Sprintf("enabled=%d", report.Summary.EnabledCMTSProfileCount)),
		docsisPolicyCheck("charging-policies", "IPDR and quota charging catalog", !docsis.PolicyChargingCorrelation || len(report.ChargingPolicies) > 0 || !docsis.Enabled, "DOCSIS charging policies are configured.", "DOCSIS policy/charging correlation requires at least one charging policy.", fmt.Sprintf("charging_policies=%d", report.Summary.ChargingPolicyCount), fmt.Sprintf("enabled=%d", report.Summary.EnabledChargingPolicyCount)),
		docsisPolicyCheck("qos-and-classifier", "DOCSIS QoS and classifier evidence", report.Summary.ServiceFlowCount > 0 || !docsis.Enabled, "DOCSIS QoS descriptors and packet classifiers are available.", "DOCSIS service-flow authorization needs QoS descriptor and packet classifier intent.", fmt.Sprintf("radius_attrs=%d", report.Summary.RadiusAttributeCount)),
		docsisPolicyCheck("privacy", "Cable modem identity privacy", true, "Cable modem identifiers are configured for redaction and hashing.", "Device redaction requires hash_device_ids.", fmt.Sprintf("redact=%t", docsis.RedactDeviceIDs), fmt.Sprintf("hash=%t", docsis.HashDeviceIDs)),
		docsisPolicyCheck("database-history", "Database event history", true, "Schema v101 persists DOCSIS policy events and effective rows.", "Database is required for durable DOCSIS policy history.", "docsis_policy_events", "docsis_policy_profiles"),
		docsisPolicyCheck("external-certification", "Release certification boundary", true, "Live CMTS, cable modem, DOCSIS provisioning, IPDR mediation, FreeRADIUS production Linux, HA, scale, soak, security, and customer proof are tracked outside software completion.", "", report.ReleaseCertificationChecklist),
	}
	if docsis.Enabled && docsis.Mode == "enforce" {
		if docsis.RequireGroupedAVPs && (groupedErr != nil || groupedReport.Status == "blocked" || groupedReport.Status == "disabled" || !groupedReport.Summary.Enabled) {
			checks[0].Status = "blocked"
			checks[0].Message = "Enforce mode requires NAS-0092 grouped telecom AVPs to be available and enabled."
		}
		if docsis.RequireCharging && (chargingErr != nil || chargingReport.Status == "blocked" || chargingReport.Status == "disabled" || !chargingReport.Summary.Enabled) {
			checks[1].Status = "blocked"
			checks[1].Message = "Enforce mode requires NAS-0094 mobile charging correlation to be available and enabled."
		}
		if docsis.RequireQoSServiceFlows && !report.Summary.QoSServiceFlowEnabled {
			checks[2].Status = "blocked"
			checks[2].Message = "DOCSIS enforcement requires broadband.qos_service_flows.enabled."
		}
		if docsis.RequireDynamicAuth && !report.Summary.DynamicAuthEnabled && !report.Summary.DynamicAuthOutboundEnabled {
			checks[3].Status = "blocked"
			checks[3].Message = "DOCSIS policy updates require radius.dynamic_auth.enabled or radius.dynamic_auth.outbound_enabled."
		}
		if report.Summary.EnabledModemProfileCount == 0 {
			checks[4].Status = "blocked"
			checks[4].Message = "Enforce mode requires at least one enabled DOCSIS modem profile."
		}
		if docsis.ServiceFlowAuthorization && report.Summary.EnabledServiceFlowCount == 0 {
			checks[5].Status = "blocked"
			checks[5].Message = "Service-flow authorization requires at least one enabled DOCSIS service flow."
		}
		if report.Summary.EnabledCMTSProfileCount == 0 {
			checks[6].Status = "blocked"
			checks[6].Message = "Enforce mode requires at least one enabled CMTS profile."
		}
		if docsis.PolicyChargingCorrelation && report.Summary.EnabledChargingPolicyCount == 0 {
			checks[7].Status = "blocked"
			checks[7].Message = "DOCSIS policy/charging correlation requires at least one enabled charging policy."
		}
		if docsis.RedactDeviceIDs && !docsis.HashDeviceIDs {
			checks[9].Status = "blocked"
			checks[9].Message = "Device redaction requires hash_device_ids."
		}
		if docsis.RequireDatabase && db.DB == nil {
			checks[10].Status = "blocked"
			checks[10].Message = "Database is required for durable DOCSIS policy history."
		}
	}
	if !docsis.Enabled && db.DB == nil {
		checks[10].Status = "warning"
		checks[10].Message = "Database is not initialized; software preview is complete, but event history cannot be recorded until runtime."
	}
	_ = cfg
	return checks
}

func recordDOCSISPolicyReport(operation, status string, report DOCSISPolicyReport, actor string) (string, error) {
	summaryJSON, _ := json.Marshal(report.Summary)
	reportJSON, _ := json.Marshal(report)
	profiles := make([]db.DOCSISPolicyProfileInput, 0, len(report.ModemProfiles)+len(report.ServiceFlows)+len(report.CMTSProfiles)+len(report.ChargingPolicies))
	for _, item := range report.ModemProfiles {
		payload, _ := json.Marshal(item)
		profiles = append(profiles, db.DOCSISPolicyProfileInput{
			ProfileKey:      strings.ToLower(item.Name),
			ProfileType:     "modem_profile",
			Name:            item.Name,
			Status:          item.Status,
			CMTSProfile:     item.CMTSProfile,
			ChargingPolicy:  item.AccountingClass,
			AttributesJSON:  string(payload),
			PlanFingerprint: report.PlanFingerprint,
		})
	}
	for _, item := range report.ServiceFlows {
		payload, _ := json.Marshal(item)
		profiles = append(profiles, db.DOCSISPolicyProfileInput{
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
	for _, item := range report.CMTSProfiles {
		payload, _ := json.Marshal(item)
		profiles = append(profiles, db.DOCSISPolicyProfileInput{
			ProfileKey:      strings.ToLower(item.Name),
			ProfileType:     "cmts_profile",
			Name:            item.Name,
			Status:          item.Status,
			CMTSProfile:     item.Name,
			AttributesJSON:  string(payload),
			PlanFingerprint: report.PlanFingerprint,
		})
	}
	for _, item := range report.ChargingPolicies {
		payload, _ := json.Marshal(item)
		profiles = append(profiles, db.DOCSISPolicyProfileInput{
			ProfileKey:      strings.ToLower(item.Name),
			ProfileType:     "charging_policy",
			Name:            item.Name,
			Status:          item.Status,
			ChargingPolicy:  item.QuotaPolicy,
			AttributesJSON:  string(payload),
			PlanFingerprint: report.PlanFingerprint,
		})
	}
	return db.RecordDOCSISPolicyEvent(db.DOCSISPolicyEventInput{
		Operation:                operation,
		Status:                   status,
		PlanFingerprint:          report.PlanFingerprint,
		Mode:                     report.Summary.Mode,
		ModemProfileCount:        report.Summary.ModemProfileCount,
		ServiceFlowCount:         report.Summary.ServiceFlowCount,
		CMTSProfileCount:         report.Summary.CMTSProfileCount,
		ChargingPolicyCount:      report.Summary.ChargingPolicyCount,
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

func docsisPolicyCheck(id, name string, passed bool, passMessage, failMessage string, evidence ...string) DOCSISPolicyCheck {
	status := "passed"
	message := passMessage
	if !passed {
		status = "blocked"
		message = failMessage
	}
	return DOCSISPolicyCheck{ID: id, Name: name, Status: status, Message: message, Evidence: trimStringSlice(evidence)}
}
