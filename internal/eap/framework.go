package eap

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
)

const FrameworkSchemaVersion = 1

type MethodCapability struct {
	Method                string   `json:"method"`
	DisplayName           string   `json:"display_name"`
	Kind                  string   `json:"kind"`
	RFCs                  []string `json:"rfcs"`
	FreeRADIUSModule      string   `json:"freeradius_module"`
	SoftwareStatus        string   `json:"software_status"`
	GeneratedByFramework  bool     `json:"generated_by_framework"`
	PasswordBased         bool     `json:"password_based"`
	CertificateBased      bool     `json:"certificate_based"`
	TunnelBased           bool     `json:"tunnel_based"`
	InnerMethodCapable    bool     `json:"inner_method_capable"`
	MethodChainingCapable bool     `json:"method_chaining_capable"`
	RequiresFutureFeature string   `json:"requires_future_feature,omitempty"`
	Summary               string   `json:"summary"`
}

type IdentitySourceReport struct {
	Name                    string   `json:"name"`
	Source                  string   `json:"source"`
	Enabled                 bool     `json:"enabled"`
	Methods                 []string `json:"methods"`
	AllowPasswordVerifier   bool     `json:"allow_password_verifier"`
	AllowCertificateSubject bool     `json:"allow_certificate_subject"`
	Priority                int      `json:"priority"`
	Status                  string   `json:"status"`
	Message                 string   `json:"message"`
}

type MethodPolicyReport struct {
	Method                string   `json:"method"`
	Enabled               bool     `json:"enabled"`
	Configured            bool     `json:"configured"`
	SoftwareStatus        string   `json:"software_status"`
	EffectiveStatus       string   `json:"effective_status"`
	GeneratedInFreeRADIUS bool     `json:"generated_in_freeradius"`
	InnerMethods          []string `json:"inner_methods,omitempty"`
	IdentitySource        string   `json:"identity_source,omitempty"`
	RequireCertificate    bool     `json:"require_certificate"`
	RequireRevocation     bool     `json:"require_revocation"`
	AllowPasswordVerifier bool     `json:"allow_password_verifier"`
	MinTLSVersion         string   `json:"min_tls_version,omitempty"`
	MaxTLSVersion         string   `json:"max_tls_version,omitempty"`
	VendorProfiles        []string `json:"vendor_profiles,omitempty"`
	Warnings              []string `json:"warnings,omitempty"`
	Dependencies          []string `json:"dependencies,omitempty"`
}

type VendorProfileReport struct {
	Name            string   `json:"name"`
	NASTypes        []string `json:"nas_types"`
	AllowedMethods  []string `json:"allowed_methods"`
	RequiredMethods []string `json:"required_methods"`
	Notes           string   `json:"notes,omitempty"`
	Status          string   `json:"status"`
	Message         string   `json:"message"`
}

type PolicyReport struct {
	Enabled                      bool     `json:"enabled"`
	Mode                         string   `json:"mode"`
	FailClosed                   bool     `json:"fail_closed"`
	DefaultType                  string   `json:"default_type"`
	PEAPInner                    string   `json:"peap_inner"`
	TTLSInner                    string   `json:"ttls_inner"`
	TLSMinVersion                string   `json:"tls_min_version"`
	TLSMaxVersion                string   `json:"tls_max_version"`
	AllowedMethods               []string `json:"allowed_methods"`
	AllowedInnerMethods          []string `json:"allowed_inner_methods"`
	DefaultOuterIdentitySource   string   `json:"default_outer_identity_source"`
	DefaultInnerIdentitySource   string   `json:"default_inner_identity_source"`
	UnsupportedMethodAction      string   `json:"unsupported_method_action"`
	RequireMessageAuthenticator  bool     `json:"require_message_authenticator"`
	RequireIdentityBinding       bool     `json:"require_identity_binding"`
	TelemetryEnabled             bool     `json:"telemetry_enabled"`
	EventRetentionLimit          int      `json:"event_retention_limit"`
	MaxConcurrentSessions        int      `json:"max_concurrent_sessions"`
	EffectiveMaxSessions         int      `json:"effective_max_sessions"`
	MethodTimeoutSeconds         int      `json:"method_timeout_seconds"`
	FragmentSize                 int      `json:"fragment_size"`
	NakUnknownTypes              bool     `json:"nak_unknown_types"`
	GeneratedFreeRADIUSPolicy    bool     `json:"generated_freeradius_policy"`
	ConfiguresUnsupportedMethods bool     `json:"configures_unsupported_methods"`
}

type Summary struct {
	MethodCount              int    `json:"method_count"`
	EnabledMethodCount       int    `json:"enabled_method_count"`
	GeneratedMethodCount     int    `json:"generated_method_count"`
	PlannedMethodCount       int    `json:"planned_method_count"`
	BlockedMethodCount       int    `json:"blocked_method_count"`
	IdentitySourceCount      int    `json:"identity_source_count"`
	VendorProfileCount       int    `json:"vendor_profile_count"`
	WarningCount             int    `json:"warning_count"`
	DependencyCount          int    `json:"dependency_count"`
	RecentEventCount         int    `json:"recent_event_count"`
	RecentRejectedCount      int    `json:"recent_rejected_count"`
	RecentUnsupportedCount   int    `json:"recent_unsupported_count"`
	RecentMonitorAllowCount  int    `json:"recent_monitor_allowed_count"`
	MessageAuthenticatorMode string `json:"message_authenticator_mode"`
}

type RuntimeSummary struct {
	TotalEvents        int            `json:"total_events"`
	Accepted           int            `json:"accepted"`
	Rejected           int            `json:"rejected"`
	MonitorAllowed     int            `json:"monitor_allowed"`
	Unsupported        int            `json:"unsupported"`
	ByMethod           map[string]int `json:"by_method,omitempty"`
	ByDecision         map[string]int `json:"by_decision,omitempty"`
	LastEventAt        string         `json:"last_event_at,omitempty"`
	LastRejectedReason string         `json:"last_rejected_reason,omitempty"`
}

type Report struct {
	SchemaVersion    int                    `json:"schema_version"`
	GeneratedAt      string                 `json:"generated_at"`
	Status           string                 `json:"status"`
	Message          string                 `json:"message"`
	Policy           PolicyReport           `json:"policy"`
	Summary          Summary                `json:"summary"`
	Capabilities     []MethodCapability     `json:"capabilities"`
	Methods          []MethodPolicyReport   `json:"methods"`
	IdentitySources  []IdentitySourceReport `json:"identity_sources"`
	VendorProfiles   []VendorProfileReport  `json:"vendor_profiles"`
	Warnings         []string               `json:"warnings,omitempty"`
	BlockingIssues   []string               `json:"blocking_issues,omitempty"`
	Runtime          RuntimeSummary         `json:"runtime"`
	ReleaseChecklist string                 `json:"release_checklist"`
	ExternalEvidence []string               `json:"external_evidence"`
}

type EvaluationRequest struct {
	Method                      string
	InnerMethod                 string
	NASType                     string
	IdentitySource              string
	EAPMessagePresent           bool
	MessageAuthenticatorPresent bool
	CertificatePresented        bool
	TLSVersion                  string
	OuterIdentity               string
	UserIdentity                string
	MachineIdentity             string
	CryptoBindingValid          bool
	ChannelBindingPresent       bool
	ChannelBindingValid         bool
	IdentityTypePresented       bool
	PACPresented                bool
	PACProvisioningRequested    bool
	PACOpaqueKeyAvailable       bool
	AnonymousProvisioning       bool
	EAPPayloadPresent           bool
	BasicPasswordAuth           bool
	IntermediateResultPresent   bool
	IntermediateResultSuccess   bool
	FinalResultPresent          bool
	FinalResultSuccess          bool
	StepCount                   int
	ProvisioningAttemptCount    int
	PasswordProofValid          bool
	ReplayDetected              bool
	PWDGroup                    int
	PWDServerID                 string
}

type EvaluationDecision struct {
	Decision       string   `json:"decision"`
	Method         string   `json:"method"`
	InnerMethod    string   `json:"inner_method,omitempty"`
	Reason         string   `json:"reason"`
	PolicyMode     string   `json:"policy_mode"`
	IdentitySource string   `json:"identity_source,omitempty"`
	Warnings       []string `json:"warnings,omitempty"`
	Dependencies   []string `json:"dependencies,omitempty"`
}

func BuildFrameworkReport(cfg *config.Config, runtime RuntimeSummary) Report {
	policy := BuildPolicyReport(cfg)
	capabilities := MethodCatalog()
	methods := buildMethodReports(cfg, policy, capabilities)
	identitySources := buildIdentitySourceReports(cfg)
	vendorProfiles := buildVendorProfileReports(cfg)
	report := Report{
		SchemaVersion:    FrameworkSchemaVersion,
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		Policy:           policy,
		Capabilities:     capabilities,
		Methods:          methods,
		IdentitySources:  identitySources,
		VendorProfiles:   vendorProfiles,
		Runtime:          runtime,
		ReleaseChecklist: "nas-0022-release-certification-checklist.md",
		ExternalEvidence: []string{
			"FreeRADIUS -XC validation on production Linux",
			"packet captures for Identity, NAK, Success, Failure, and selected tunneled methods",
			"real supplicant/AP/controller tests for enabled method profiles",
			"HA failover while EAP conversations are active",
		},
	}
	for _, method := range methods {
		report.Summary.MethodCount++
		if method.Enabled {
			report.Summary.EnabledMethodCount++
		}
		if method.GeneratedInFreeRADIUS {
			report.Summary.GeneratedMethodCount++
		}
		switch method.EffectiveStatus {
		case "planned":
			report.Summary.PlannedMethodCount++
		case "blocked":
			report.Summary.BlockedMethodCount++
		}
		report.Summary.WarningCount += len(method.Warnings)
		report.Summary.DependencyCount += len(method.Dependencies)
		report.Warnings = append(report.Warnings, method.Warnings...)
		if method.EffectiveStatus == "blocked" {
			report.BlockingIssues = append(report.BlockingIssues, fmt.Sprintf("%s: %s", method.Method, strings.Join(method.Dependencies, ", ")))
		}
	}
	report.Summary.IdentitySourceCount = len(identitySources)
	report.Summary.VendorProfileCount = len(vendorProfiles)
	report.Summary.RecentEventCount = runtime.TotalEvents
	report.Summary.RecentRejectedCount = runtime.Rejected
	report.Summary.RecentUnsupportedCount = runtime.Unsupported
	report.Summary.RecentMonitorAllowCount = runtime.MonitorAllowed
	if policy.RequireMessageAuthenticator {
		report.Summary.MessageAuthenticatorMode = "required"
	} else {
		report.Summary.MessageAuthenticatorMode = "inherited"
	}
	report.Status, report.Message = frameworkStatusAndMessage(report)
	return report
}

func BuildPolicyReport(cfg *config.Config) PolicyReport {
	radiusCfg := config.RadiusConfig{}
	if cfg != nil {
		radiusCfg = cfg.Radius
	}
	eapCfg := radiusCfg.EAP
	framework := eapCfg.Framework
	policy := PolicyReport{
		Enabled:                     true,
		Mode:                        "monitor",
		FailClosed:                  true,
		DefaultType:                 normalizeMethod(defaultString(eapCfg.DefaultType, "peap")),
		PEAPInner:                   normalizeInner(defaultString(eapCfg.PEAPInner, "mschapv2")),
		TTLSInner:                   normalizeInner(defaultString(eapCfg.TTLSInner, "mschapv2")),
		TLSMinVersion:               defaultString(eapCfg.TLSMinVersion, "1.2"),
		TLSMaxVersion:               defaultString(eapCfg.TLSMaxVersion, "1.3"),
		AllowedMethods:              normalizeMethodList(defaultStringSlice(framework.AllowedMethods, []string{"peap", "ttls", "tls"})),
		AllowedInnerMethods:         normalizeInnerList(defaultStringSlice(framework.AllowedInnerMethods, []string{"mschapv2", "pap", "chap", "gtc", "tls"})),
		DefaultOuterIdentitySource:  defaultString(framework.DefaultOuterIdentitySource, "configured-default"),
		DefaultInnerIdentitySource:  defaultString(framework.DefaultInnerIdentitySource, "identity-failover"),
		UnsupportedMethodAction:     defaultString(framework.UnsupportedMethodAction, "reject"),
		RequireMessageAuthenticator: true,
		RequireIdentityBinding:      true,
		TelemetryEnabled:            true,
		EventRetentionLimit:         6000,
		MethodTimeoutSeconds:        60,
		FragmentSize:                1024,
		NakUnknownTypes:             true,
		GeneratedFreeRADIUSPolicy:   true,
	}
	if cfg != nil {
		policy.Enabled = framework.Enabled
		policy.Mode = normalizeMode(framework.Mode)
		policy.FailClosed = framework.FailClosed
		policy.RequireMessageAuthenticator = framework.RequireMessageAuthenticator
		policy.RequireIdentityBinding = framework.RequireIdentityBinding
		policy.TelemetryEnabled = framework.TelemetryEnabled
		policy.NakUnknownTypes = framework.NakUnknownTypes
		if framework.EventRetentionLimit > 0 {
			policy.EventRetentionLimit = framework.EventRetentionLimit
		}
		policy.MaxConcurrentSessions = framework.MaxConcurrentSessions
		if framework.MethodTimeoutSeconds > 0 {
			policy.MethodTimeoutSeconds = framework.MethodTimeoutSeconds
		}
		if framework.FragmentSize > 0 {
			policy.FragmentSize = framework.FragmentSize
		}
	}
	if policy.Mode == "" {
		policy.Mode = "monitor"
	}
	if policy.EffectiveMaxSessions = policy.MaxConcurrentSessions; policy.EffectiveMaxSessions <= 0 {
		policy.EffectiveMaxSessions = radiusCfg.MaxSessions
	}
	if policy.EffectiveMaxSessions <= 0 {
		policy.EffectiveMaxSessions = 1024
	}
	policy.ConfiguresUnsupportedMethods = configuresUnsupportedMethods(policy)
	return policy
}

func Evaluate(cfg *config.Config, request EvaluationRequest) EvaluationDecision {
	report := BuildFrameworkReport(cfg, RuntimeSummary{})
	policy := report.Policy
	method := normalizeMethod(request.Method)
	inner := normalizeInner(request.InnerMethod)
	if method == "" {
		method = "unknown"
	}
	decision := EvaluationDecision{
		Method:      method,
		InnerMethod: inner,
		PolicyMode:  policy.Mode,
	}
	reject := func(reason string, deps ...string) EvaluationDecision {
		decision.Reason = reason
		decision.Dependencies = append(decision.Dependencies, deps...)
		if !policy.Enabled || policy.Mode == "monitor" || !policy.FailClosed {
			decision.Decision = "monitor_allowed"
			decision.Warnings = append(decision.Warnings, reason)
			return decision
		}
		decision.Decision = "rejected"
		return decision
	}
	if !policy.Enabled {
		decision.Decision = "monitor_allowed"
		decision.Reason = "EAP framework is disabled; legacy FreeRADIUS behavior remains active"
		return decision
	}
	if policy.RequireMessageAuthenticator && request.EAPMessagePresent && !request.MessageAuthenticatorPresent {
		return reject("EAP-Message requires Message-Authenticator", "radius.packet_hardening.require_message_authenticator")
	}
	if method == "teap" {
		teapDecision := EvaluateTEAPChain(cfg, TEAPChainEvaluationRequest{
			InnerMethod:                 request.InnerMethod,
			NASType:                     request.NASType,
			OuterIdentity:               request.OuterIdentity,
			UserIdentity:                request.UserIdentity,
			MachineIdentity:             request.MachineIdentity,
			IdentitySource:              request.IdentitySource,
			EAPMessagePresent:           request.EAPMessagePresent,
			MessageAuthenticatorPresent: request.MessageAuthenticatorPresent,
			CertificatePresented:        request.CertificatePresented,
			TLSVersion:                  request.TLSVersion,
			CryptoBindingValid:          request.CryptoBindingValid,
			ChannelBindingPresent:       request.ChannelBindingPresent,
			ChannelBindingValid:         request.ChannelBindingValid,
			IdentityTypePresented:       request.IdentityTypePresented,
			PACPresented:                request.PACPresented,
			PACProvisioningRequested:    request.PACProvisioningRequested,
			EAPPayloadPresent:           request.EAPPayloadPresent,
			BasicPasswordAuth:           request.BasicPasswordAuth,
			IntermediateResultPresent:   request.IntermediateResultPresent,
			IntermediateResultSuccess:   request.IntermediateResultSuccess,
			FinalResultPresent:          request.FinalResultPresent,
			FinalResultSuccess:          request.FinalResultSuccess,
			StepCount:                   request.StepCount,
		})
		return EvaluationDecision{
			Decision:       teapDecision.Decision,
			Method:         teapDecision.Method,
			InnerMethod:    teapDecision.InnerMethod,
			Reason:         teapDecision.Reason,
			PolicyMode:     teapDecision.PolicyMode,
			IdentitySource: teapDecision.IdentitySource,
			Warnings:       teapDecision.Warnings,
			Dependencies:   teapDecision.Dependencies,
		}
	}
	if method == "fast" || method == "pwd" {
		fastPWDDecision := EvaluateFASTPWD(cfg, FASTPWDEvaluationRequest{
			Method:                      method,
			InnerMethod:                 request.InnerMethod,
			NASType:                     request.NASType,
			Identity:                    request.UserIdentity,
			IdentitySource:              request.IdentitySource,
			EAPMessagePresent:           request.EAPMessagePresent,
			MessageAuthenticatorPresent: request.MessageAuthenticatorPresent,
			TLSVersion:                  request.TLSVersion,
			CryptoBindingValid:          request.CryptoBindingValid,
			PACPresented:                request.PACPresented,
			PACProvisioningRequested:    request.PACProvisioningRequested,
			PACOpaqueKeyAvailable:       request.PACOpaqueKeyAvailable,
			AnonymousProvisioning:       request.AnonymousProvisioning,
			EAPPayloadPresent:           request.EAPPayloadPresent,
			ProvisioningAttemptCount:    request.ProvisioningAttemptCount,
			PasswordProofValid:          request.PasswordProofValid,
			ReplayDetected:              request.ReplayDetected,
			PWDGroup:                    request.PWDGroup,
			PWDServerID:                 request.PWDServerID,
		})
		return EvaluationDecision{
			Decision:       fastPWDDecision.Decision,
			Method:         fastPWDDecision.Method,
			InnerMethod:    fastPWDDecision.InnerMethod,
			Reason:         fastPWDDecision.Reason,
			PolicyMode:     fastPWDDecision.PolicyMode,
			IdentitySource: fastPWDDecision.IdentitySource,
			Warnings:       fastPWDDecision.Warnings,
			Dependencies:   fastPWDDecision.Dependencies,
		}
	}
	methodReport, found := methodReportByName(report.Methods, method)
	if !found || !stringInSlice(method, policy.AllowedMethods) {
		switch policy.UnsupportedMethodAction {
		case "nak":
			decision.Decision = "unsupported"
			decision.Reason = "method is not enabled; FreeRADIUS should NAK or reject according to method negotiation"
			return decision
		case "monitor":
			decision.Decision = "monitor_allowed"
			decision.Reason = "method is unsupported but framework is monitoring"
			return decision
		default:
			return reject("method is not enabled in the EAP framework", "radius.eap.framework.allowed_methods")
		}
	}
	if !methodReport.GeneratedInFreeRADIUS {
		return reject("method is cataloged but not generated by this software release", methodReport.Dependencies...)
	}
	if (method == "peap" || method == "ttls") && inner != "" && !stringInSlice(inner, methodReport.InnerMethods) {
		return reject("inner method is not allowed for the selected EAP method", "radius.eap.framework.method_policies")
	}
	if policy.RequireIdentityBinding {
		source := strings.TrimSpace(request.IdentitySource)
		if source == "" {
			source = methodReport.IdentitySource
		}
		decision.IdentitySource = source
		if source == "" {
			return reject("no identity source is bound to the selected EAP method", "radius.eap.framework.identity_sources")
		}
	}
	if methodReport.RequireCertificate && !request.CertificatePresented {
		return reject("selected EAP method requires a client certificate", "certificate lifecycle", "radius.eap.framework.method_policies")
	}
	if methodReport.RequireRevocation && cfg != nil && !cfg.Radius.EAP.CheckCRL && !cfg.Radius.EAP.OCSP.Enabled {
		return reject("selected EAP method requires CRL or OCSP revocation checking", "radius.eap.check_crl", "radius.eap.ocsp.enabled")
	}
	decision.Decision = "accepted"
	decision.Reason = "EAP method is allowed by the framework"
	return decision
}

func MethodCatalog() []MethodCapability {
	catalog := []MethodCapability{
		{Method: "peap", DisplayName: "PEAP", Kind: "tunnel", RFCs: []string{"RFC 3748", "PEAP"}, FreeRADIUSModule: "rlm_eap_peap", SoftwareStatus: "complete", GeneratedByFramework: true, PasswordBased: true, TunnelBased: true, InnerMethodCapable: true, Summary: "Protected EAP tunnel for password-based inner methods such as MSCHAPv2."},
		{Method: "ttls", DisplayName: "EAP-TTLS", Kind: "tunnel", RFCs: []string{"RFC 3748", "RFC 5281"}, FreeRADIUSModule: "rlm_eap_ttls", SoftwareStatus: "complete", GeneratedByFramework: true, PasswordBased: true, TunnelBased: true, InnerMethodCapable: true, Summary: "TLS tunnel for PAP, CHAP, MSCHAPv2, GTC, or certificate-backed inner authentication."},
		{Method: "tls", DisplayName: "EAP-TLS", Kind: "certificate", RFCs: []string{"RFC 3748", "RFC 5216", "RFC 9190"}, FreeRADIUSModule: "rlm_eap_tls", SoftwareStatus: "complete", GeneratedByFramework: true, CertificateBased: true, Summary: "Certificate-based EAP method using server and client certificate validation."},
		{Method: "teap", DisplayName: "TEAP", Kind: "tunnel", RFCs: []string{"RFC 7170"}, FreeRADIUSModule: "rlm_eap_teap", SoftwareStatus: "complete", GeneratedByFramework: true, TunnelBased: true, InnerMethodCapable: true, MethodChainingCapable: true, Summary: "Tunnel Extensible Authentication Protocol with cryptobinding and machine/user method chaining."},
		{Method: "fast", DisplayName: "EAP-FAST", Kind: "tunnel", RFCs: []string{"RFC 4851"}, FreeRADIUSModule: "rlm_eap_fast", SoftwareStatus: "complete", GeneratedByFramework: true, PasswordBased: true, TunnelBased: true, InnerMethodCapable: true, Summary: "Cisco-originated protected access credential tunnel method with PAC governance."},
		{Method: "pwd", DisplayName: "EAP-PWD", Kind: "password", RFCs: []string{"RFC 5931"}, FreeRADIUSModule: "rlm_eap_pwd", SoftwareStatus: "complete", GeneratedByFramework: true, PasswordBased: true, Summary: "Password-authenticated key exchange EAP method with group and replay policy."},
		{Method: "sim", DisplayName: "EAP-SIM", Kind: "mobile", RFCs: []string{"RFC 4186"}, FreeRADIUSModule: "rlm_eap_sim", SoftwareStatus: "planned", RequiresFutureFeature: "NAS-0025", Summary: "GSM SIM triplet based EAP method for carrier offload and roaming."},
		{Method: "aka", DisplayName: "EAP-AKA", Kind: "mobile", RFCs: []string{"RFC 4187"}, FreeRADIUSModule: "rlm_eap_aka", SoftwareStatus: "planned", RequiresFutureFeature: "NAS-0025", Summary: "UMTS AKA quintuplet based EAP method."},
		{Method: "aka-prime", DisplayName: "EAP-AKA'", Kind: "mobile", RFCs: []string{"RFC 5448"}, FreeRADIUSModule: "rlm_eap_aka_prime", SoftwareStatus: "planned", RequiresFutureFeature: "NAS-0025", Summary: "AKA-prime with stronger key derivation for evolved packet systems."},
	}
	return catalog
}

func buildMethodReports(cfg *config.Config, policy PolicyReport, catalog []MethodCapability) []MethodPolicyReport {
	capabilityByName := map[string]MethodCapability{}
	for _, capability := range catalog {
		capabilityByName[capability.Method] = capability
	}
	configured := map[string]config.RadiusEAPMethodPolicy{}
	if cfg != nil {
		for _, item := range cfg.Radius.EAP.Framework.MethodPolicies {
			configured[normalizeMethod(item.Method)] = item
		}
	}
	teapPolicy := BuildTEAPPolicyReport(cfg)
	fastPolicy := BuildFASTPolicyReport(cfg)
	pwdPolicy := BuildPWDPolicyReport(cfg)
	names := append([]string{}, policy.AllowedMethods...)
	for _, capability := range catalog {
		if !stringInSlice(capability.Method, names) {
			names = append(names, capability.Method)
		}
	}
	names = uniqueSorted(names)
	reports := make([]MethodPolicyReport, 0, len(names))
	for _, name := range names {
		capability, known := capabilityByName[name]
		if !known {
			capability = MethodCapability{Method: name, DisplayName: strings.ToUpper(name), SoftwareStatus: "unknown"}
		}
		raw, isConfigured := configured[name]
		report := MethodPolicyReport{
			Method:                name,
			Enabled:               stringInSlice(name, policy.AllowedMethods),
			Configured:            isConfigured,
			SoftwareStatus:        capability.SoftwareStatus,
			GeneratedInFreeRADIUS: capability.GeneratedByFramework && stringInSlice(name, policy.AllowedMethods),
			IdentitySource:        policy.DefaultInnerIdentitySource,
			MinTLSVersion:         policy.TLSMinVersion,
			MaxTLSVersion:         policy.TLSMaxVersion,
		}
		if name == "tls" {
			report.IdentitySource = "certificate-subject"
			report.RequireCertificate = true
		}
		switch name {
		case "peap":
			report.InnerMethods = []string{policy.PEAPInner}
			if isConfigured && len(raw.InnerMethods) > 0 {
				report.InnerMethods = normalizeInnerList(raw.InnerMethods)
			}
			report.AllowPasswordVerifier = true
		case "ttls":
			report.InnerMethods = []string{policy.TTLSInner}
			if isConfigured && len(raw.InnerMethods) > 0 {
				report.InnerMethods = normalizeInnerList(raw.InnerMethods)
			}
			report.AllowPasswordVerifier = true
		case "teap":
			report.InnerMethods = []string{teapPolicy.DefaultInnerMethod}
			if isConfigured && len(raw.InnerMethods) > 0 {
				report.InnerMethods = normalizeInnerList(raw.InnerMethods)
			}
			report.AllowPasswordVerifier = teapPolicy.AllowBasicPasswordAuth
		case "fast":
			report.InnerMethods = []string{fastPolicy.DefaultInnerMethod}
			if isConfigured && len(raw.InnerMethods) > 0 {
				report.InnerMethods = normalizeInnerList(raw.InnerMethods)
			}
			report.AllowPasswordVerifier = true
		case "pwd":
			report.IdentitySource = pwdPolicy.PasswordSource
			report.AllowPasswordVerifier = true
		}
		if isConfigured {
			report.Enabled = raw.Enabled && stringInSlice(name, policy.AllowedMethods)
			if source := strings.TrimSpace(raw.IdentitySource); source != "" {
				report.IdentitySource = source
			}
			report.RequireCertificate = raw.RequireCertificate
			report.RequireRevocation = raw.RequireRevocation
			report.AllowPasswordVerifier = raw.AllowPasswordVerifier
			report.MinTLSVersion = defaultString(raw.MinTLSVersion, report.MinTLSVersion)
			report.MaxTLSVersion = defaultString(raw.MaxTLSVersion, report.MaxTLSVersion)
			report.VendorProfiles = normalizeTokenList(raw.VendorProfiles)
		}
		report.EffectiveStatus = "complete"
		if !report.Enabled {
			report.EffectiveStatus = "disabled"
		}
		if capability.SoftwareStatus == "planned" {
			report.EffectiveStatus = "planned"
			report.GeneratedInFreeRADIUS = false
			report.Dependencies = append(report.Dependencies, capability.RequiresFutureFeature)
		}
		if capability.SoftwareStatus == "unknown" {
			report.EffectiveStatus = "blocked"
			report.GeneratedInFreeRADIUS = false
			report.Dependencies = append(report.Dependencies, "unsupported EAP method catalog entry")
		}
		if name == "teap" {
			report.GeneratedInFreeRADIUS = report.GeneratedInFreeRADIUS && teapPolicy.GeneratedInFreeRADIUS
			report.Warnings = append(report.Warnings, teapPolicy.Warnings...)
			report.Dependencies = append(report.Dependencies, teapPolicy.BlockingIssues...)
			if report.Enabled && !teapPolicy.Enabled {
				report.EffectiveStatus = "blocked"
				report.Dependencies = append(report.Dependencies, "radius.eap.teap.enabled")
			}
			if report.Enabled && len(teapPolicy.BlockingIssues) > 0 {
				report.EffectiveStatus = "blocked"
			}
		}
		if name == "fast" {
			report.GeneratedInFreeRADIUS = report.GeneratedInFreeRADIUS && fastPolicy.GeneratedInFreeRADIUS
			report.Warnings = append(report.Warnings, fastPolicy.Warnings...)
			report.Dependencies = append(report.Dependencies, fastPolicy.BlockingIssues...)
			if report.Enabled && !fastPolicy.Enabled {
				report.EffectiveStatus = "blocked"
				report.Dependencies = append(report.Dependencies, "radius.eap.fast.enabled")
			}
			if report.Enabled && len(fastPolicy.BlockingIssues) > 0 {
				report.EffectiveStatus = "blocked"
			}
		}
		if name == "pwd" {
			report.GeneratedInFreeRADIUS = report.GeneratedInFreeRADIUS && pwdPolicy.GeneratedInFreeRADIUS
			report.Warnings = append(report.Warnings, pwdPolicy.Warnings...)
			report.Dependencies = append(report.Dependencies, pwdPolicy.BlockingIssues...)
			if report.Enabled && !pwdPolicy.Enabled {
				report.EffectiveStatus = "blocked"
				report.Dependencies = append(report.Dependencies, "radius.eap.pwd.enabled")
			}
			if report.Enabled && len(pwdPolicy.BlockingIssues) > 0 {
				report.EffectiveStatus = "blocked"
			}
		}
		if report.Enabled && !report.GeneratedInFreeRADIUS {
			report.EffectiveStatus = "blocked"
			if capability.RequiresFutureFeature != "" && !stringInSlice(capability.RequiresFutureFeature, report.Dependencies) {
				report.Dependencies = append(report.Dependencies, capability.RequiresFutureFeature)
			}
			report.Warnings = append(report.Warnings, "method is allowed by policy but not generated by this software release")
		}
		if report.RequireRevocation && cfg != nil && !cfg.Radius.EAP.CheckCRL && !cfg.Radius.EAP.OCSP.Enabled {
			report.Warnings = append(report.Warnings, "certificate revocation checking is not enabled")
			report.Dependencies = append(report.Dependencies, "radius.eap.check_crl or radius.eap.ocsp.enabled")
			if report.Enabled && policy.Mode == "enforce" && policy.FailClosed {
				report.EffectiveStatus = "blocked"
			}
		}
		reports = append(reports, report)
	}
	return reports
}

func buildIdentitySourceReports(cfg *config.Config) []IdentitySourceReport {
	var sources []config.RadiusEAPIdentitySource
	if cfg != nil {
		sources = cfg.Radius.EAP.Framework.IdentitySources
	}
	if len(sources) == 0 {
		sources = []config.RadiusEAPIdentitySource{
			{Name: "identity-failover", Source: "identity_failover", Enabled: true, Methods: []string{"peap", "ttls"}, AllowPasswordVerifier: true, Priority: 10},
			{Name: "certificate-subject", Source: "certificate", Enabled: true, Methods: []string{"tls"}, AllowCertificateSubject: true, Priority: 20},
		}
	}
	reports := make([]IdentitySourceReport, 0, len(sources))
	for _, source := range sources {
		report := IdentitySourceReport{
			Name:                    strings.TrimSpace(source.Name),
			Source:                  strings.TrimSpace(source.Source),
			Enabled:                 source.Enabled,
			Methods:                 normalizeMethodList(source.Methods),
			AllowPasswordVerifier:   source.AllowPasswordVerifier,
			AllowCertificateSubject: source.AllowCertificateSubject,
			Priority:                source.Priority,
			Status:                  "ready",
			Message:                 "identity source is available for EAP method binding",
		}
		if !source.Enabled {
			report.Status = "disabled"
			report.Message = "identity source is configured but disabled"
		}
		reports = append(reports, report)
	}
	sort.SliceStable(reports, func(i, j int) bool {
		if reports[i].Priority == reports[j].Priority {
			return reports[i].Name < reports[j].Name
		}
		return reports[i].Priority < reports[j].Priority
	})
	return reports
}

func buildVendorProfileReports(cfg *config.Config) []VendorProfileReport {
	var profiles []config.RadiusEAPVendorProfileRule
	if cfg != nil {
		profiles = cfg.Radius.EAP.Framework.VendorCompatibilityProfiles
	}
	reports := make([]VendorProfileReport, 0, len(profiles))
	for _, profile := range profiles {
		report := VendorProfileReport{
			Name:            strings.TrimSpace(profile.Name),
			NASTypes:        normalizeTokenList(profile.NASTypes),
			AllowedMethods:  normalizeMethodList(profile.AllowedMethods),
			RequiredMethods: normalizeMethodList(profile.RequiredMethods),
			Notes:           strings.TrimSpace(profile.Notes),
			Status:          "ready",
			Message:         "vendor profile is available for EAP compatibility checks",
		}
		for _, required := range report.RequiredMethods {
			if !stringInSlice(required, report.AllowedMethods) && len(report.AllowedMethods) > 0 {
				report.Status = "blocked"
				report.Message = "required method is not included in allowed methods"
			}
		}
		reports = append(reports, report)
	}
	sort.SliceStable(reports, func(i, j int) bool { return reports[i].Name < reports[j].Name })
	return reports
}

func frameworkStatusAndMessage(report Report) (string, string) {
	if !report.Policy.Enabled {
		return "disabled", "EAP framework is disabled; legacy FreeRADIUS EAP configuration remains active."
	}
	if len(report.BlockingIssues) > 0 {
		if report.Policy.Mode == "enforce" && report.Policy.FailClosed {
			return "blocked", "EAP framework has blocking method or dependency issues."
		}
		return "degraded", "EAP framework has issues but is not fail-closed."
	}
	if report.Summary.RecentRejectedCount > 0 || report.Summary.RecentUnsupportedCount > 0 {
		return "degraded", "EAP framework is active with recent rejected or unsupported method events."
	}
	return "ready", "EAP framework is active with typed method policy, identity binding, FreeRADIUS generation, and telemetry."
}

func methodReportByName(methods []MethodPolicyReport, name string) (MethodPolicyReport, bool) {
	for _, method := range methods {
		if method.Method == name {
			return method, true
		}
	}
	return MethodPolicyReport{}, false
}

func configuresUnsupportedMethods(policy PolicyReport) bool {
	for _, method := range policy.AllowedMethods {
		switch method {
		case "peap", "ttls", "tls", "teap", "fast", "pwd":
		default:
			return true
		}
	}
	return false
}

func normalizeMode(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "monitor"
	}
	return value
}

func normalizeMethod(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "eap-tls":
		return "tls"
	case "eap-ttls":
		return "ttls"
	case "eap-peap":
		return "peap"
	case "eap-fast":
		return "fast"
	case "eap-pwd":
		return "pwd"
	case "eap-sim":
		return "sim"
	case "eap-aka":
		return "aka"
	case "eap-aka-prime", "eap-aka'":
		return "aka-prime"
	default:
		return value
	}
}

func normalizeInner(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "mschap", "mschap-v2", "ms-chap-v2":
		return "mschapv2"
	case "eap-tls":
		return "tls"
	default:
		return value
	}
}

func normalizeMethodList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		method := normalizeMethod(value)
		if method != "" && !stringInSlice(method, out) {
			out = append(out, method)
		}
	}
	sort.Strings(out)
	return out
}

func normalizeInnerList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		method := normalizeInner(value)
		if method != "" && !stringInSlice(method, out) {
			out = append(out, method)
		}
	}
	sort.Strings(out)
	return out
}

func normalizeTokenList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		token := strings.ToLower(strings.TrimSpace(value))
		if token != "" && !stringInSlice(token, out) {
			out = append(out, token)
		}
	}
	sort.Strings(out)
	return out
}

func uniqueSorted(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !stringInSlice(value, out) {
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

func stringInSlice(value string, values []string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

func defaultStringSlice(values []string, fallback []string) []string {
	if len(values) == 0 {
		return append([]string(nil), fallback...)
	}
	return append([]string(nil), values...)
}
