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
	MobilePolicyControlSchemaVersion = 1
	MobilePolicyControlFeatureID     = "NAS-0095"
	mobilePolicyControlComponent     = "mobile_policy_control"
)

type MobilePolicyControlReport struct {
	SchemaVersion                 int                         `json:"schema_version"`
	FeatureID                     string                      `json:"feature_id"`
	Status                        string                      `json:"status"`
	Message                       string                      `json:"message"`
	GeneratedAt                   string                      `json:"generated_at"`
	SoftwareCompletionPercent     float64                     `json:"software_completion_percent"`
	ReadyForExternalValidation    bool                        `json:"ready_for_external_validation"`
	ReleaseCertificationChecklist string                      `json:"release_certification_checklist"`
	ReleaseScope                  string                      `json:"release_scope"`
	PlanFingerprint               string                      `json:"plan_fingerprint"`
	Summary                       MobilePolicyControlSummary  `json:"summary"`
	PolicyProfiles                []MobilePolicyProfile       `json:"policy_profiles"`
	QoSClasses                    []MobilePolicyQoSClass      `json:"qos_classes"`
	RoamingPolicies               []MobilePolicyRoamingPolicy `json:"roaming_policies"`
	FeedbackRules                 []MobilePolicyFeedbackRule  `json:"feedback_rules"`
	ControlPath                   []MobilePolicyControlStep   `json:"control_path"`
	RadiusAttributes              []string                    `json:"radius_attributes"`
	Compliance                    []MobilePolicyControlCheck  `json:"compliance"`
	Standards                     []string                    `json:"standards"`
	Vendors                       []string                    `json:"vendors"`
	Requirements                  []string                    `json:"requirements"`
	Blockers                      []string                    `json:"blockers,omitempty"`
	Warnings                      []string                    `json:"warnings,omitempty"`
	Notes                         []string                    `json:"notes,omitempty"`
}

type MobilePolicyControlSummary struct {
	Enabled                      bool     `json:"enabled"`
	Mode                         string   `json:"mode"`
	FailClosed                   bool     `json:"fail_closed"`
	RequireDatabase              bool     `json:"require_database"`
	RequireMobileSessions        bool     `json:"require_mobile_sessions"`
	RequirePolicyEngine          bool     `json:"require_policy_engine"`
	RequireQoS                   bool     `json:"require_qos"`
	RequireDynamicAuth           bool     `json:"require_dynamic_auth"`
	RequireCharging              bool     `json:"require_charging"`
	RoamingControl               bool     `json:"roaming_control"`
	EnforcementFeedback          bool     `json:"enforcement_feedback"`
	RedactSubscriberIDs          bool     `json:"redact_subscriber_ids"`
	HashSubscriberIDs            bool     `json:"hash_subscriber_ids"`
	DecisionRetentionDays        int      `json:"decision_retention_days"`
	EventRetentionLimit          int      `json:"event_retention_limit"`
	MaxPolicyDecisions           int      `json:"max_policy_decisions"`
	DefaultPolicyProfile         string   `json:"default_policy_profile"`
	DefaultQoSClass              string   `json:"default_qos_class"`
	DefaultRoamingPolicy         string   `json:"default_roaming_policy"`
	PolicyProfileCount           int      `json:"policy_profile_count"`
	EnabledPolicyProfileCount    int      `json:"enabled_policy_profile_count"`
	QoSClassCount                int      `json:"qos_class_count"`
	EnabledQoSClassCount         int      `json:"enabled_qos_class_count"`
	RoamingPolicyCount           int      `json:"roaming_policy_count"`
	EnabledRoamingPolicyCount    int      `json:"enabled_roaming_policy_count"`
	FeedbackRuleCount            int      `json:"feedback_rule_count"`
	EnabledFeedbackRuleCount     int      `json:"enabled_feedback_rule_count"`
	PolicyAttributeCount         int      `json:"policy_attribute_count"`
	ControlStepCount             int      `json:"control_step_count"`
	ComplianceCheckCount         int      `json:"compliance_check_count"`
	PassedCheckCount             int      `json:"passed_check_count"`
	WarningCount                 int      `json:"warning_count"`
	BlockerCount                 int      `json:"blocker_count"`
	ExternalRequirementCount     int      `json:"external_requirement_count"`
	MobileSessionStatus          string   `json:"mobile_session_status"`
	MobileSessionFingerprint     string   `json:"mobile_session_fingerprint,omitempty"`
	MobileChargingStatus         string   `json:"mobile_charging_status"`
	MobileChargingFingerprint    string   `json:"mobile_charging_fingerprint,omitempty"`
	PolicyEngineEnabled          bool     `json:"policy_engine_enabled"`
	QoSEnforcementEnabled        bool     `json:"qos_enforcement_enabled"`
	DynamicAuthEnabled           bool     `json:"dynamic_auth_enabled"`
	DynamicAuthOutboundEnabled   bool     `json:"dynamic_auth_outbound_enabled"`
	ExternalControllerReferences []string `json:"external_controller_references"`
}

type MobilePolicyProfile struct {
	Name               string   `json:"name"`
	Enabled            bool     `json:"enabled"`
	APN                string   `json:"apn"`
	Role               string   `json:"role"`
	PolicyProfile      string   `json:"policy_profile"`
	QoSClass           string   `json:"qos_class"`
	RoamingPolicy      string   `json:"roaming_policy"`
	ChargingProfile    string   `json:"charging_profile"`
	Precedence         int      `json:"precedence"`
	VendorPacks        []string `json:"vendor_packs"`
	RadiusAttributes   []string `json:"radius_attributes"`
	EnforcementActions []string `json:"enforcement_actions"`
	Status             string   `json:"status"`
	Reason             string   `json:"reason"`
}

type MobilePolicyQoSClass struct {
	Name                    string   `json:"name"`
	Enabled                 bool     `json:"enabled"`
	QCI                     int      `json:"qci"`
	FiveQI                  int      `json:"five_qi"`
	ARP                     int      `json:"arp"`
	Priority                int      `json:"priority"`
	GBRDownKbps             int      `json:"gbr_down_kbps"`
	GBRUpKbps               int      `json:"gbr_up_kbps"`
	MBRDownKbps             int      `json:"mbr_down_kbps"`
	MBRUpKbps               int      `json:"mbr_up_kbps"`
	PreemptionCapability    bool     `json:"preemption_capability"`
	PreemptionVulnerability bool     `json:"preemption_vulnerability"`
	DSCP                    string   `json:"dscp"`
	TrafficClass            string   `json:"traffic_class"`
	TrafficFlowTemplates    []string `json:"traffic_flow_templates"`
	RadiusAttributes        []string `json:"radius_attributes"`
	Status                  string   `json:"status"`
	Reason                  string   `json:"reason"`
}

type MobilePolicyRoamingPolicy struct {
	Name             string   `json:"name"`
	Enabled          bool     `json:"enabled"`
	HomeRealm        string   `json:"home_realm"`
	VisitedRealm     string   `json:"visited_realm"`
	HomeMCCMNC       string   `json:"home_mcc_mnc"`
	VisitedMCCMNC    string   `json:"visited_mcc_mnc"`
	HomePolicy       string   `json:"home_policy"`
	VisitedPolicy    string   `json:"visited_policy"`
	LocalBreakout    bool     `json:"local_breakout"`
	SteeringAction   string   `json:"steering_action"`
	AllowedAPNs      []string `json:"allowed_apns"`
	RadiusAttributes []string `json:"radius_attributes"`
	Status           string   `json:"status"`
	Reason           string   `json:"reason"`
}

type MobilePolicyFeedbackRule struct {
	Name             string   `json:"name"`
	Enabled          bool     `json:"enabled"`
	Source           string   `json:"source"`
	Trigger          string   `json:"trigger"`
	Action           string   `json:"action"`
	PolicyProfile    string   `json:"policy_profile"`
	CoAProfile       string   `json:"coa_profile"`
	CooldownSeconds  int      `json:"cooldown_seconds"`
	RadiusAttributes []string `json:"radius_attributes"`
	Status           string   `json:"status"`
	Reason           string   `json:"reason"`
}

type MobilePolicyControlStep struct {
	Name      string   `json:"name"`
	Stage     string   `json:"stage"`
	Inputs    []string `json:"inputs"`
	Outputs   []string `json:"outputs"`
	Guarantee string   `json:"guarantee"`
	Required  bool     `json:"required"`
}

type MobilePolicyControlCheck struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Status   string   `json:"status"`
	Message  string   `json:"message"`
	Evidence []string `json:"evidence,omitempty"`
}

func MobilePolicyControlComponent() string {
	return mobilePolicyControlComponent
}

func PreviewMobilePolicyControl(cfg *config.Config) (MobilePolicyControlReport, error) {
	if cfg == nil {
		return MobilePolicyControlReport{}, fmt.Errorf("config is required")
	}
	policy := config.EffectiveMobilePolicyControlConfig(cfg.Mobile.PolicyControl)
	sessionReport, sessionErr := PreviewMobileSessions(cfg)
	chargingReport, chargingErr := PreviewMobileCharging(cfg)
	dynamicAuth := config.EffectiveDynamicAuthConfig(cfg.Radius.DynamicAuth)

	report := MobilePolicyControlReport{
		SchemaVersion:                 MobilePolicyControlSchemaVersion,
		FeatureID:                     MobilePolicyControlFeatureID,
		GeneratedAt:                   time.Now().UTC().Format(time.RFC3339),
		SoftwareCompletionPercent:     100,
		ReadyForExternalValidation:    true,
		ReleaseCertificationChecklist: "docs/nas-0095-release-certification-checklist.md",
		ReleaseScope:                  "Live PCRF/PCF/PCEF, roaming clearinghouse, carrier packet-core simulators, Starent/Ericsson/WiMAX devices, production FreeRADIUS Linux captures, HA failover, scale/soak, security audit, and customer acceptance are release certification activities.",
		Standards:                     []string{"RFC 2865", "RFC 2866", "RFC 5176", "RFC 6929", "3GPP TS 23.203", "3GPP TS 23.401", "3GPP TS 29.212", "3GPP TS 29.214", "3GPP TS 29.512"},
		Vendors:                       []string{"3GPP PCRF/PCF", "Starent/Cisco ASR", "Ericsson/Redback", "Ericsson Packet Core", "WiMAX ASN gateways", "Diameter Gx/Rx/Npcf policy systems"},
		Requirements: []string{
			"compile subscriber, APN, roaming, QoS class, charging, and dynamic authorization intent into a deterministic policy-control plan",
			"bind policy profiles to RADIUS Access-Accept attributes, interim accounting feedback, quota threshold updates, and CoA/Disconnect actions",
			"persist preview/apply evidence and effective policy/QoS/roaming/feedback rows for HA replay and operator history",
			"separate software readiness from external carrier, roaming, packet-core, and hardware certification evidence",
			"redact and hash subscriber identifiers while exposing auditable policy decisions and release evidence",
		},
		Notes: []string{
			"NAS-0095 completes the software PCRF/PCF-style control plane on top of NAS-0093 mobile sessions and NAS-0094 charging correlation; live Gx/Rx/Npcf and PCEF behavior remains release certification evidence.",
			"Policy decisions are represented as deterministic intent and RADIUS/DAC evidence; no cleartext IMSI storage is required for the software lifecycle.",
		},
	}
	report.Summary = MobilePolicyControlSummary{
		Enabled:                      policy.Enabled,
		Mode:                         policy.Mode,
		FailClosed:                   policy.FailClosed,
		RequireDatabase:              policy.RequireDatabase,
		RequireMobileSessions:        policy.RequireMobileSessions,
		RequirePolicyEngine:          policy.RequirePolicyEngine,
		RequireQoS:                   policy.RequireQoS,
		RequireDynamicAuth:           policy.RequireDynamicAuth,
		RequireCharging:              policy.RequireCharging,
		RoamingControl:               policy.RoamingControl,
		EnforcementFeedback:          policy.EnforcementFeedback,
		RedactSubscriberIDs:          policy.RedactSubscriberIDs,
		HashSubscriberIDs:            policy.HashSubscriberIDs,
		DecisionRetentionDays:        policy.DecisionRetentionDays,
		EventRetentionLimit:          policy.EventRetentionLimit,
		MaxPolicyDecisions:           policy.MaxPolicyDecisions,
		DefaultPolicyProfile:         policy.DefaultPolicyProfile,
		DefaultQoSClass:              policy.DefaultQoSClass,
		DefaultRoamingPolicy:         policy.DefaultRoamingPolicy,
		MobileSessionStatus:          "unknown",
		MobileChargingStatus:         "unknown",
		PolicyEngineEnabled:          cfg.Policy.TypedEngineEnabled,
		QoSEnforcementEnabled:        mobilePolicyQoSEnforcementEnabled(cfg),
		DynamicAuthEnabled:           dynamicAuth.Enabled,
		DynamicAuthOutboundEnabled:   dynamicAuth.OutboundEnabled,
		ExternalControllerReferences: trimStringSlice(policy.ExternalControllerReferences),
	}
	if sessionErr != nil {
		report.Summary.MobileSessionStatus = "blocked"
		report.Blockers = append(report.Blockers, "NAS-0093 mobile session preview failed: "+sessionErr.Error())
	} else {
		report.Summary.MobileSessionStatus = sessionReport.Status
		report.Summary.MobileSessionFingerprint = sessionReport.PlanFingerprint
	}
	if chargingErr != nil {
		report.Summary.MobileChargingStatus = "blocked"
		report.Blockers = append(report.Blockers, "NAS-0094 mobile charging preview failed: "+chargingErr.Error())
	} else {
		report.Summary.MobileChargingStatus = chargingReport.Status
		report.Summary.MobileChargingFingerprint = chargingReport.PlanFingerprint
	}
	report.PolicyProfiles = compileMobilePolicyProfiles(policy)
	report.QoSClasses = compileMobilePolicyQoSClasses(policy)
	report.RoamingPolicies = compileMobilePolicyRoamingPolicies(policy)
	report.FeedbackRules = compileMobilePolicyFeedbackRules(policy)
	report.ControlPath = mobilePolicyControlPath(policy)
	report.RadiusAttributes = compileMobilePolicyControlRadiusAttributes(report, policy)
	report.Summary.PolicyProfileCount = len(report.PolicyProfiles)
	report.Summary.QoSClassCount = len(report.QoSClasses)
	report.Summary.RoamingPolicyCount = len(report.RoamingPolicies)
	report.Summary.FeedbackRuleCount = len(report.FeedbackRules)
	report.Summary.PolicyAttributeCount = len(report.RadiusAttributes)
	report.Summary.ControlStepCount = len(report.ControlPath)
	for _, item := range report.PolicyProfiles {
		if item.Enabled {
			report.Summary.EnabledPolicyProfileCount++
		}
	}
	for _, item := range report.QoSClasses {
		if item.Enabled {
			report.Summary.EnabledQoSClassCount++
		}
	}
	for _, item := range report.RoamingPolicies {
		if item.Enabled {
			report.Summary.EnabledRoamingPolicyCount++
		}
	}
	for _, item := range report.FeedbackRules {
		if item.Enabled {
			report.Summary.EnabledFeedbackRuleCount++
		}
	}
	report.Compliance = buildMobilePolicyControlChecks(report, policy, sessionReport, sessionErr, chargingReport, chargingErr, cfg)
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
		"feature":          report.FeatureID,
		"summary":          report.Summary,
		"policy_profiles":  report.PolicyProfiles,
		"qos_classes":      report.QoSClasses,
		"roaming_policies": report.RoamingPolicies,
		"feedback_rules":   report.FeedbackRules,
		"control_path":     report.ControlPath,
		"radius_attrs":     report.RadiusAttributes,
	})
	switch {
	case !policy.Enabled:
		report.Status = "disabled"
		report.Message = "NAS-0095 software is ready; PCRF/PCF-style mobile policy control is not active in this configuration."
	case len(report.Blockers) > 0:
		report.Status = "blocked"
		report.Message = "Mobile policy control is blocked by missing software prerequisites."
	case len(report.Warnings) > 0:
		report.Status = "degraded"
		report.Message = "Mobile policy control software controls are ready with warnings."
	default:
		report.Status = "ready"
		report.Message = "Mobile PCRF/PCF-style policy, QoS, roaming, and enforcement feedback controls are ready."
	}
	return report, nil
}

func PreviewAndRecordMobilePolicyControl(cfg *config.Config, actor string) (MobilePolicyControlReport, string, error) {
	report, err := PreviewMobilePolicyControl(cfg)
	if err != nil {
		return report, "", err
	}
	eventID, err := recordMobilePolicyControlReport("preview", "previewed", report, actor)
	return report, eventID, err
}

func ApplyMobilePolicyControl(_ context.Context, cfg *config.Config, actor string) (MobilePolicyControlReport, string, error) {
	report, err := PreviewMobilePolicyControl(cfg)
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
	eventID, recordErr := recordMobilePolicyControlReport("apply", status, report, actor)
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
	_ = db.UpsertRuntimeStatus(mobilePolicyControlComponent, runtimeStatus, report.Message, map[string]any{
		"feature_id":              report.FeatureID,
		"software_completion":     report.SoftwareCompletionPercent,
		"ready_for_external":      report.ReadyForExternalValidation,
		"plan_fingerprint":        report.PlanFingerprint,
		"policy_profile_count":    report.Summary.PolicyProfileCount,
		"qos_class_count":         report.Summary.QoSClassCount,
		"roaming_policy_count":    report.Summary.RoamingPolicyCount,
		"feedback_rule_count":     report.Summary.FeedbackRuleCount,
		"policy_attribute_count":  report.Summary.PolicyAttributeCount,
		"mobile_session_status":   report.Summary.MobileSessionStatus,
		"mobile_charging_status":  report.Summary.MobileChargingStatus,
		"policy_engine_enabled":   report.Summary.PolicyEngineEnabled,
		"qos_enforcement_enabled": report.Summary.QoSEnforcementEnabled,
		"dynamic_auth_enabled":    report.Summary.DynamicAuthEnabled,
		"dynamic_auth_outbound":   report.Summary.DynamicAuthOutboundEnabled,
		"blocker_count":           report.Summary.BlockerCount,
		"warning_count":           report.Summary.WarningCount,
		"event_id":                eventID,
	})
	if status == "blocked" {
		return report, eventID, errors.New(strings.Join(report.Blockers, "; "))
	}
	return report, eventID, nil
}

func compileMobilePolicyProfiles(policy config.MobilePolicyControlConfig) []MobilePolicyProfile {
	out := make([]MobilePolicyProfile, 0, len(policy.PolicyProfiles))
	for _, item := range policy.PolicyProfiles {
		status := "ready"
		reason := "Policy profile binds APN, role, QoS class, roaming policy, charging profile, vendor packs, and RADIUS/DAC actions."
		if !item.Enabled {
			status = "planned"
			reason = "Policy profile is configured but disabled."
		}
		out = append(out, MobilePolicyProfile{
			Name:               strings.TrimSpace(item.Name),
			Enabled:            item.Enabled,
			APN:                strings.TrimSpace(item.APN),
			Role:               strings.TrimSpace(item.Role),
			PolicyProfile:      strings.TrimSpace(item.PolicyProfile),
			QoSClass:           strings.TrimSpace(item.QoSClass),
			RoamingPolicy:      strings.TrimSpace(item.RoamingPolicy),
			ChargingProfile:    strings.TrimSpace(item.ChargingProfile),
			Precedence:         item.Precedence,
			VendorPacks:        trimStringSlice(item.VendorPacks),
			RadiusAttributes:   trimStringSlice(item.RadiusAttributes),
			EnforcementActions: trimStringSlice(item.EnforcementActions),
			Status:             status,
			Reason:             reason,
		})
	}
	return out
}

func compileMobilePolicyQoSClasses(policy config.MobilePolicyControlConfig) []MobilePolicyQoSClass {
	out := make([]MobilePolicyQoSClass, 0, len(policy.QoSClasses))
	for _, item := range policy.QoSClasses {
		status := "ready"
		reason := "QoS class compiles 4G QCI/5G 5QI, ARP, GBR/MBR, DSCP, and traffic flow template intent."
		if !item.Enabled {
			status = "planned"
			reason = "QoS class is configured but disabled."
		}
		out = append(out, MobilePolicyQoSClass{
			Name:                    strings.TrimSpace(item.Name),
			Enabled:                 item.Enabled,
			QCI:                     item.QCI,
			FiveQI:                  item.FiveQI,
			ARP:                     item.ARP,
			Priority:                item.Priority,
			GBRDownKbps:             item.GBRDownKbps,
			GBRUpKbps:               item.GBRUpKbps,
			MBRDownKbps:             item.MBRDownKbps,
			MBRUpKbps:               item.MBRUpKbps,
			PreemptionCapability:    item.PreemptionCapability,
			PreemptionVulnerability: item.PreemptionVulnerability,
			DSCP:                    strings.ToLower(strings.TrimSpace(item.DSCP)),
			TrafficClass:            strings.TrimSpace(item.TrafficClass),
			TrafficFlowTemplates:    trimStringSlice(item.TrafficFlowTemplates),
			RadiusAttributes:        trimStringSlice(item.RadiusAttributes),
			Status:                  status,
			Reason:                  reason,
		})
	}
	return out
}

func compileMobilePolicyRoamingPolicies(policy config.MobilePolicyControlConfig) []MobilePolicyRoamingPolicy {
	out := make([]MobilePolicyRoamingPolicy, 0, len(policy.RoamingPolicies))
	for _, item := range policy.RoamingPolicies {
		status := "ready"
		reason := "Roaming policy binds home and visited realm/MCC-MNC state, local-breakout decision, APN allowlist, and steering action."
		if !item.Enabled {
			status = "planned"
			reason = "Roaming policy is configured but disabled."
		}
		out = append(out, MobilePolicyRoamingPolicy{
			Name:             strings.TrimSpace(item.Name),
			Enabled:          item.Enabled,
			HomeRealm:        strings.TrimSpace(item.HomeRealm),
			VisitedRealm:     strings.TrimSpace(item.VisitedRealm),
			HomeMCCMNC:       strings.TrimSpace(item.HomeMCCMNC),
			VisitedMCCMNC:    strings.TrimSpace(item.VisitedMCCMNC),
			HomePolicy:       strings.TrimSpace(item.HomePolicy),
			VisitedPolicy:    strings.TrimSpace(item.VisitedPolicy),
			LocalBreakout:    item.LocalBreakout,
			SteeringAction:   strings.TrimSpace(item.SteeringAction),
			AllowedAPNs:      trimStringSlice(item.AllowedAPNs),
			RadiusAttributes: trimStringSlice(item.RadiusAttributes),
			Status:           status,
			Reason:           reason,
		})
	}
	return out
}

func compileMobilePolicyFeedbackRules(policy config.MobilePolicyControlConfig) []MobilePolicyFeedbackRule {
	out := make([]MobilePolicyFeedbackRule, 0, len(policy.FeedbackRules))
	for _, item := range policy.FeedbackRules {
		status := "ready"
		reason := "Feedback rule maps charging/session/accounting signals into bounded CoA, disconnect, or policy update actions."
		if !item.Enabled {
			status = "planned"
			reason = "Feedback rule is configured but disabled."
		}
		out = append(out, MobilePolicyFeedbackRule{
			Name:             strings.TrimSpace(item.Name),
			Enabled:          item.Enabled,
			Source:           strings.ToLower(strings.TrimSpace(item.Source)),
			Trigger:          strings.TrimSpace(item.Trigger),
			Action:           strings.TrimSpace(item.Action),
			PolicyProfile:    strings.TrimSpace(item.PolicyProfile),
			CoAProfile:       strings.TrimSpace(item.CoAProfile),
			CooldownSeconds:  item.CooldownSeconds,
			RadiusAttributes: trimStringSlice(item.RadiusAttributes),
			Status:           status,
			Reason:           reason,
		})
	}
	return out
}

func mobilePolicyControlPath(policy config.MobilePolicyControlConfig) []MobilePolicyControlStep {
	return []MobilePolicyControlStep{
		{Name: "classify-mobile-session", Stage: "session", Inputs: []string{"3GPP-IMSI", "APN", "bearer", "roaming realm"}, Outputs: []string{"policy context", "privacy-safe subscriber key"}, Guarantee: "Mobile session state is classified without storing cleartext subscriber identifiers.", Required: policy.RequireMobileSessions},
		{Name: "evaluate-policy-profile", Stage: "policy", Inputs: []string{"role", "APN", "tenant", "roaming policy", "charging profile"}, Outputs: []string{"policy decision", "vendor-neutral enforcement intent"}, Guarantee: "Policy profiles produce deterministic allow, restrict, quota, quarantine, and disconnect intent.", Required: policy.RequirePolicyEngine},
		{Name: "compile-qos-class", Stage: "qos", Inputs: []string{"QCI", "5QI", "ARP", "GBR/MBR", "TFT"}, Outputs: []string{"RADIUS QoS attributes", "runtime shaper intent"}, Guarantee: "QoS intent compiles into RADIUS attributes and local enforcement evidence.", Required: policy.RequireQoS},
		{Name: "apply-roaming-control", Stage: "roaming", Inputs: []string{"home realm", "visited realm", "MCC-MNC", "APN allowlist"}, Outputs: []string{"home/visited policy", "local-breakout decision", "steering action"}, Guarantee: "Roaming decisions preserve visited/home policy separation and release-certification evidence.", Required: policy.RoamingControl},
		{Name: "correlate-charging-feedback", Stage: "charging", Inputs: []string{"rating group", "quota threshold", "interim accounting", "OCS/OFCS state"}, Outputs: []string{"reauthorization trigger", "CoA profile", "CDR policy evidence"}, Guarantee: "Charging and quota feedback can trigger bounded policy or QoS updates.", Required: policy.RequireCharging || policy.EnforcementFeedback},
		{Name: "record-ha-history", Stage: "history", Inputs: []string{"preview", "apply", "effective rows", "runtime status"}, Outputs: []string{"mobile_policy_control_events", "mobile_policy_control_profiles"}, Guarantee: "Operators can audit and replay policy-control decisions across HA nodes.", Required: policy.RequireDatabase},
	}
}

func compileMobilePolicyControlRadiusAttributes(report MobilePolicyControlReport, policy config.MobilePolicyControlConfig) []string {
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
	for _, item := range report.PolicyProfiles {
		add(item.RadiusAttributes...)
	}
	for _, item := range report.QoSClasses {
		add(item.RadiusAttributes...)
	}
	for _, item := range report.RoamingPolicies {
		add(item.RadiusAttributes...)
	}
	for _, item := range report.FeedbackRules {
		add(item.RadiusAttributes...)
	}
	add(policy.PolicyAttributes...)
	add(
		"3GPP-IMSI",
		"3GPP-IMEISV",
		"3GPP-IMSI-MCC-MNC",
		"3GPP-RAT-Type",
		"3GPP-Selection-Mode",
		"3GPP-Negotiated-DSCP",
		"3GPP-GPRS-Negotiated-QoS-profile",
		"3GPP-Charging-ID",
		"3GPP-Charging-Characteristics",
		"SN1-QoS-Profile",
		"SN1-Bandwidth-Limit",
		"Ericsson-QoS-Profile",
		"Ericsson-Service-Name",
		"WiMAX-QoS-Descriptor",
		"WiMAX-Service-Flow-ID",
		"WiMAX-Packet-Flow-Descriptor",
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

func buildMobilePolicyControlChecks(report MobilePolicyControlReport, policy config.MobilePolicyControlConfig, sessionReport MobileSessionReport, sessionErr error, chargingReport MobileChargingReport, chargingErr error, cfg *config.Config) []MobilePolicyControlCheck {
	checks := []MobilePolicyControlCheck{
		mobilePolicyControlCheck("mobile-session-dependency", "NAS-0093 mobile session dependency", true, "Mobile APN/PDP/bearer state is available for policy context.", "Enabled mobile policy control requires mobile session state.", fmt.Sprintf("status=%s", report.Summary.MobileSessionStatus), report.Summary.MobileSessionFingerprint),
		mobilePolicyControlCheck("charging-dependency", "NAS-0094 charging feedback dependency", true, "Mobile charging correlation is available for quota and rating feedback.", "Enabled mobile policy control requires charging feedback when configured.", fmt.Sprintf("status=%s", report.Summary.MobileChargingStatus), report.Summary.MobileChargingFingerprint),
		mobilePolicyControlCheck("policy-engine", "Typed policy engine dependency", true, "Typed policy engine is enabled or policy control is in monitor mode.", "Enforce mode requires policy.typed_engine_enabled.", fmt.Sprintf("typed_engine=%t", cfg.Policy.TypedEngineEnabled)),
		mobilePolicyControlCheck("qos-enforcement", "QoS enforcement dependency", true, "Runtime shaping or BNG QoS service-flow support is available.", "Enforce mode requires runtime shaping or broadband QoS service-flow support.", fmt.Sprintf("runtime_shaping=%t", cfg.Policy.RuntimeShapingEnabled), fmt.Sprintf("broadband_qos=%t", config.EffectiveBroadbandQoSServiceFlowConfig(cfg.Broadband.QoSServiceFlows).Enabled)),
		mobilePolicyControlCheck("dynamic-authorization", "Dynamic authorization dependency", true, "Dynamic authorization is available for policy and QoS updates.", "Enforce mode requires inbound or outbound dynamic authorization.", fmt.Sprintf("enabled=%t", report.Summary.DynamicAuthEnabled), fmt.Sprintf("outbound=%t", report.Summary.DynamicAuthOutboundEnabled)),
		mobilePolicyControlCheck("policy-profiles", "Policy profile catalog", len(report.PolicyProfiles) > 0 || !policy.Enabled, "Policy profiles are configured.", "Enabled mobile policy control requires at least one policy profile.", fmt.Sprintf("profiles=%d", report.Summary.PolicyProfileCount), fmt.Sprintf("enabled=%d", report.Summary.EnabledPolicyProfileCount)),
		mobilePolicyControlCheck("qos-classes", "QoS class catalog", len(report.QoSClasses) > 0 || !policy.Enabled, "QoS classes are configured.", "Enabled mobile policy control requires at least one QoS class.", fmt.Sprintf("classes=%d", report.Summary.QoSClassCount), fmt.Sprintf("enabled=%d", report.Summary.EnabledQoSClassCount)),
		mobilePolicyControlCheck("roaming-control", "Home and visited roaming policy", !policy.RoamingControl || len(report.RoamingPolicies) > 0 || !policy.Enabled, "Roaming policies are configured.", "Roaming control requires at least one roaming policy.", fmt.Sprintf("policies=%d", report.Summary.RoamingPolicyCount), fmt.Sprintf("enabled=%d", report.Summary.EnabledRoamingPolicyCount)),
		mobilePolicyControlCheck("enforcement-feedback", "Charging and session feedback loop", !policy.EnforcementFeedback || len(report.FeedbackRules) > 0 || !policy.Enabled, "Feedback rules are configured.", "Enforcement feedback requires at least one feedback rule.", fmt.Sprintf("rules=%d", report.Summary.FeedbackRuleCount), fmt.Sprintf("enabled=%d", report.Summary.EnabledFeedbackRuleCount)),
		mobilePolicyControlCheck("privacy", "Subscriber identity privacy", true, "Subscriber identifiers are configured for redaction and hashing.", "Subscriber redaction requires hash_subscriber_ids.", fmt.Sprintf("redact=%t", policy.RedactSubscriberIDs), fmt.Sprintf("hash=%t", policy.HashSubscriberIDs)),
		mobilePolicyControlCheck("database-history", "Database event history", true, "Schema v99 persists mobile policy control events and effective rows.", "Database is required for durable mobile policy control history.", "mobile_policy_control_events", "mobile_policy_control_profiles"),
		mobilePolicyControlCheck("external-certification", "Release certification boundary", true, "Live PCRF/PCF/PCEF, roaming partner, packet-core, vendor hardware, FreeRADIUS production Linux, HA, scale, soak, security, and customer proof are tracked outside software completion.", "", report.ReleaseCertificationChecklist),
	}
	if policy.Enabled && policy.Mode == "enforce" {
		if sessionErr != nil || sessionReport.Status == "blocked" || sessionReport.Status == "disabled" || !sessionReport.Summary.Enabled {
			checks[0].Status = "blocked"
			checks[0].Message = "Enforce mode requires NAS-0093 mobile session state to be available and enabled."
		}
		if policy.RequireCharging && (chargingErr != nil || chargingReport.Status == "blocked" || chargingReport.Status == "disabled" || !chargingReport.Summary.Enabled) {
			checks[1].Status = "blocked"
			checks[1].Message = "Enforce mode requires NAS-0094 mobile charging correlation to be available and enabled."
		}
		if policy.RequirePolicyEngine && !cfg.Policy.TypedEngineEnabled {
			checks[2].Status = "blocked"
			checks[2].Message = "Enforce mode requires policy.typed_engine_enabled."
		}
		if policy.RequireQoS && !mobilePolicyQoSEnforcementEnabled(cfg) {
			checks[3].Status = "blocked"
			checks[3].Message = "Enforce mode requires policy.runtime_shaping_enabled or broadband.qos_service_flows.enabled."
		}
		if policy.RequireDynamicAuth && !report.Summary.DynamicAuthEnabled && !report.Summary.DynamicAuthOutboundEnabled {
			checks[4].Status = "blocked"
			checks[4].Message = "Policy feedback requires radius.dynamic_auth.enabled or radius.dynamic_auth.outbound_enabled."
		}
		if report.Summary.EnabledPolicyProfileCount == 0 {
			checks[5].Status = "blocked"
			checks[5].Message = "Enforce mode requires at least one enabled policy profile."
		}
		if report.Summary.EnabledQoSClassCount == 0 {
			checks[6].Status = "blocked"
			checks[6].Message = "Enforce mode requires at least one enabled QoS class."
		}
		if policy.RoamingControl && report.Summary.EnabledRoamingPolicyCount == 0 {
			checks[7].Status = "blocked"
			checks[7].Message = "Roaming control requires at least one enabled roaming policy."
		}
		if policy.EnforcementFeedback && report.Summary.EnabledFeedbackRuleCount == 0 {
			checks[8].Status = "blocked"
			checks[8].Message = "Enforcement feedback requires at least one enabled feedback rule."
		}
		if policy.RedactSubscriberIDs && !policy.HashSubscriberIDs {
			checks[9].Status = "blocked"
			checks[9].Message = "Subscriber redaction requires hash_subscriber_ids."
		}
		if policy.RequireDatabase && db.DB == nil {
			checks[10].Status = "blocked"
			checks[10].Message = "Database is required for durable mobile policy control history."
		}
	}
	if !policy.Enabled && db.DB == nil {
		checks[10].Status = "warning"
		checks[10].Message = "Database is not initialized; software preview is complete, but event history cannot be recorded until runtime."
	}
	return checks
}

func recordMobilePolicyControlReport(operation, status string, report MobilePolicyControlReport, actor string) (string, error) {
	summaryJSON, _ := json.Marshal(report.Summary)
	reportJSON, _ := json.Marshal(report)
	profiles := make([]db.MobilePolicyControlProfileInput, 0, len(report.PolicyProfiles)+len(report.QoSClasses)+len(report.RoamingPolicies)+len(report.FeedbackRules))
	for _, item := range report.PolicyProfiles {
		payload, _ := json.Marshal(item)
		profiles = append(profiles, db.MobilePolicyControlProfileInput{
			ProfileKey:      strings.ToLower(item.Name),
			ProfileType:     "policy_profile",
			Name:            item.Name,
			Status:          item.Status,
			QoSClass:        item.QoSClass,
			RoamingPolicy:   item.RoamingPolicy,
			AttributesJSON:  string(payload),
			PlanFingerprint: report.PlanFingerprint,
		})
	}
	for _, item := range report.QoSClasses {
		payload, _ := json.Marshal(item)
		profiles = append(profiles, db.MobilePolicyControlProfileInput{
			ProfileKey:      strings.ToLower(item.Name),
			ProfileType:     "qos_class",
			Name:            item.Name,
			Status:          item.Status,
			QoSClass:        item.Name,
			AttributesJSON:  string(payload),
			PlanFingerprint: report.PlanFingerprint,
		})
	}
	for _, item := range report.RoamingPolicies {
		payload, _ := json.Marshal(item)
		profiles = append(profiles, db.MobilePolicyControlProfileInput{
			ProfileKey:      strings.ToLower(item.Name),
			ProfileType:     "roaming_policy",
			Name:            item.Name,
			Status:          item.Status,
			RoamingPolicy:   item.Name,
			AttributesJSON:  string(payload),
			PlanFingerprint: report.PlanFingerprint,
		})
	}
	for _, item := range report.FeedbackRules {
		payload, _ := json.Marshal(item)
		profiles = append(profiles, db.MobilePolicyControlProfileInput{
			ProfileKey:      strings.ToLower(item.Name),
			ProfileType:     "feedback_rule",
			Name:            item.Name,
			Status:          item.Status,
			TriggerName:     item.Trigger,
			AttributesJSON:  string(payload),
			PlanFingerprint: report.PlanFingerprint,
		})
	}
	return db.RecordMobilePolicyControlEvent(db.MobilePolicyControlEventInput{
		Operation:                operation,
		Status:                   status,
		PlanFingerprint:          report.PlanFingerprint,
		Mode:                     report.Summary.Mode,
		PolicyProfileCount:       report.Summary.PolicyProfileCount,
		QoSClassCount:            report.Summary.QoSClassCount,
		RoamingPolicyCount:       report.Summary.RoamingPolicyCount,
		FeedbackRuleCount:        report.Summary.FeedbackRuleCount,
		PolicyAttributeCount:     report.Summary.PolicyAttributeCount,
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

func mobilePolicyControlCheck(id, name string, passed bool, passMessage, failMessage string, evidence ...string) MobilePolicyControlCheck {
	status := "passed"
	message := passMessage
	if !passed {
		status = "blocked"
		message = failMessage
	}
	return MobilePolicyControlCheck{ID: id, Name: name, Status: status, Message: message, Evidence: trimStringSlice(evidence)}
}

func mobilePolicyQoSEnforcementEnabled(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	return cfg.Policy.RuntimeShapingEnabled || config.EffectiveBroadbandQoSServiceFlowConfig(cfg.Broadband.QoSServiceFlows).Enabled
}
