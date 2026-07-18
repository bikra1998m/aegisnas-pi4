package eap

import (
	"fmt"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
)

const TEAPSchemaVersion = 1

type TEAPTLVCapability struct {
	Name      string `json:"name"`
	Attribute string `json:"attribute"`
	Status    string `json:"status"`
	Semantics string `json:"semantics"`
	Required  bool   `json:"required"`
	Sensitive bool   `json:"sensitive"`
}

type TEAPPolicyReport struct {
	Enabled                     bool     `json:"enabled"`
	AllowedByFramework          bool     `json:"allowed_by_framework"`
	GeneratedInFreeRADIUS       bool     `json:"generated_in_freeradius"`
	FrameworkMode               string   `json:"framework_mode"`
	FrameworkFailClosed         bool     `json:"framework_fail_closed"`
	DefaultInnerMethod          string   `json:"default_inner_method"`
	AllowedInnerMethods         []string `json:"allowed_inner_methods"`
	ChainMode                   string   `json:"chain_mode"`
	RequireCryptoBinding        bool     `json:"require_crypto_binding"`
	RequireChannelBinding       bool     `json:"require_channel_binding"`
	RequireIdentityType         bool     `json:"require_identity_type"`
	RequireMachineIdentity      bool     `json:"require_machine_identity"`
	RequireUserIdentity         bool     `json:"require_user_identity"`
	AllowPAC                    bool     `json:"allow_pac"`
	RequirePAC                  bool     `json:"require_pac"`
	PACProvisioning             string   `json:"pac_provisioning"`
	PACAuthorityIDConfigured    bool     `json:"pac_authority_id_configured"`
	PACLifetimeSeconds          int      `json:"pac_lifetime_seconds"`
	AllowEAPPayload             bool     `json:"allow_eap_payload"`
	AllowBasicPasswordAuth      bool     `json:"allow_basic_password_auth"`
	MaxChainSteps               int      `json:"max_chain_steps"`
	SessionTTLSeconds           int      `json:"session_ttl_seconds"`
	EventRetentionLimit         int      `json:"event_retention_limit"`
	RequireMessageAuthenticator bool     `json:"require_message_authenticator"`
	RequireIdentityBinding      bool     `json:"require_identity_binding"`
	TLSMinVersion               string   `json:"tls_min_version"`
	TLSMaxVersion               string   `json:"tls_max_version"`
	Warnings                    []string `json:"warnings,omitempty"`
	BlockingIssues              []string `json:"blocking_issues,omitempty"`
}

type TEAPRuntimeSummary struct {
	TotalEvents            int            `json:"total_events"`
	Accepted               int            `json:"accepted"`
	Rejected               int            `json:"rejected"`
	MonitorAllowed         int            `json:"monitor_allowed"`
	ByDecision             map[string]int `json:"by_decision,omitempty"`
	ByChainMode            map[string]int `json:"by_chain_mode,omitempty"`
	MissingMachineIdentity int            `json:"missing_machine_identity"`
	MissingUserIdentity    int            `json:"missing_user_identity"`
	InvalidCryptoBinding   int            `json:"invalid_crypto_binding"`
	InvalidChannelBinding  int            `json:"invalid_channel_binding"`
	PACRequiredMissing     int            `json:"pac_required_missing"`
	LastEventAt            string         `json:"last_event_at,omitempty"`
	LastRejectedReason     string         `json:"last_rejected_reason,omitempty"`
}

type TEAPReport struct {
	SchemaVersion    int                 `json:"schema_version"`
	GeneratedAt      string              `json:"generated_at"`
	Status           string              `json:"status"`
	Message          string              `json:"message"`
	Policy           TEAPPolicyReport    `json:"policy"`
	TLVs             []TEAPTLVCapability `json:"tlvs"`
	Runtime          TEAPRuntimeSummary  `json:"runtime"`
	Warnings         []string            `json:"warnings,omitempty"`
	BlockingIssues   []string            `json:"blocking_issues,omitempty"`
	ReleaseChecklist string              `json:"release_checklist"`
	ExternalEvidence []string            `json:"external_evidence"`
}

type TEAPChainEvaluationRequest struct {
	InnerMethod                 string
	NASType                     string
	OuterIdentity               string
	UserIdentity                string
	MachineIdentity             string
	IdentitySource              string
	EAPMessagePresent           bool
	MessageAuthenticatorPresent bool
	CertificatePresented        bool
	TLSVersion                  string
	CryptoBindingValid          bool
	ChannelBindingPresent       bool
	ChannelBindingValid         bool
	IdentityTypePresented       bool
	PACPresented                bool
	PACProvisioningRequested    bool
	EAPPayloadPresent           bool
	BasicPasswordAuth           bool
	IntermediateResultPresent   bool
	IntermediateResultSuccess   bool
	FinalResultPresent          bool
	FinalResultSuccess          bool
	StepCount                   int
}

type TEAPChainDecision struct {
	Decision            string   `json:"decision"`
	Method              string   `json:"method"`
	InnerMethod         string   `json:"inner_method"`
	Reason              string   `json:"reason"`
	PolicyMode          string   `json:"policy_mode"`
	ChainMode           string   `json:"chain_mode"`
	ChainState          string   `json:"chain_state"`
	IdentitySource      string   `json:"identity_source,omitempty"`
	RequiredIdentities  []string `json:"required_identities,omitempty"`
	IdentityCorrelation string   `json:"identity_correlation"`
	Warnings            []string `json:"warnings,omitempty"`
	Dependencies        []string `json:"dependencies,omitempty"`
}

func BuildTEAPReport(cfg *config.Config, runtime TEAPRuntimeSummary) TEAPReport {
	policy := BuildTEAPPolicyReport(cfg)
	report := TEAPReport{
		SchemaVersion:    TEAPSchemaVersion,
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		Policy:           policy,
		TLVs:             TEAPTLVCatalog(),
		Runtime:          runtime,
		Warnings:         append([]string(nil), policy.Warnings...),
		BlockingIssues:   append([]string(nil), policy.BlockingIssues...),
		ReleaseChecklist: "nas-0023-release-certification-checklist.md",
		ExternalEvidence: []string{
			"FreeRADIUS -XC validation with rlm_eap_teap available",
			"packet captures for TEAP Identity-Type, EAP-Payload, Crypto-Binding, Result, and Error TLVs",
			"supplicant/controller tests for machine-only, user-only, and machine-then-user chains",
			"HA failover and replay drills while TEAP chain state is active",
		},
	}
	report.Status, report.Message = teapStatusAndMessage(report)
	return report
}

func BuildTEAPPolicyReport(cfg *config.Config) TEAPPolicyReport {
	framework := BuildPolicyReport(cfg)
	teap := config.RadiusEAPTEAPConfig{}
	if cfg != nil {
		teap = cfg.Radius.EAP.TEAP
	}
	policy := TEAPPolicyReport{
		Enabled:                     true,
		AllowedByFramework:          stringInSlice("teap", framework.AllowedMethods),
		FrameworkMode:               framework.Mode,
		FrameworkFailClosed:         framework.FailClosed,
		DefaultInnerMethod:          normalizeInner(defaultString(teap.DefaultInnerMethod, "mschapv2")),
		AllowedInnerMethods:         framework.AllowedInnerMethods,
		ChainMode:                   defaultString(strings.ToLower(strings.TrimSpace(teap.ChainMode)), "machine_then_user"),
		RequireCryptoBinding:        true,
		RequireChannelBinding:       teap.RequireChannelBinding,
		RequireIdentityType:         true,
		RequireMachineIdentity:      true,
		RequireUserIdentity:         true,
		AllowPAC:                    true,
		RequirePAC:                  teap.RequirePAC,
		PACProvisioning:             defaultString(strings.ToLower(strings.TrimSpace(teap.PACProvisioning)), "authenticated"),
		PACAuthorityIDConfigured:    strings.TrimSpace(teap.PACAuthorityID) != "",
		PACLifetimeSeconds:          2592000,
		AllowEAPPayload:             true,
		AllowBasicPasswordAuth:      teap.AllowBasicPasswordAuth,
		MaxChainSteps:               2,
		SessionTTLSeconds:           900,
		EventRetentionLimit:         6000,
		RequireMessageAuthenticator: framework.RequireMessageAuthenticator,
		RequireIdentityBinding:      framework.RequireIdentityBinding,
		TLSMinVersion:               framework.TLSMinVersion,
		TLSMaxVersion:               framework.TLSMaxVersion,
	}
	if cfg != nil {
		policy.Enabled = teap.Enabled
		policy.RequireCryptoBinding = teap.RequireCryptoBinding
		policy.RequireIdentityType = teap.RequireIdentityType
		policy.RequireMachineIdentity = teap.RequireMachineIdentity
		policy.RequireUserIdentity = teap.RequireUserIdentity
		policy.AllowPAC = teap.AllowPAC
		policy.AllowEAPPayload = teap.AllowEAPPayload
		if teap.PACLifetimeSeconds > 0 {
			policy.PACLifetimeSeconds = teap.PACLifetimeSeconds
		}
		if teap.MaxChainSteps > 0 {
			policy.MaxChainSteps = teap.MaxChainSteps
		}
		if teap.SessionTTLSeconds > 0 {
			policy.SessionTTLSeconds = teap.SessionTTLSeconds
		}
		if teap.EventRetentionLimit > 0 {
			policy.EventRetentionLimit = teap.EventRetentionLimit
		}
	}
	if policy.DefaultInnerMethod == "" {
		policy.DefaultInnerMethod = "mschapv2"
	}
	if len(policy.AllowedInnerMethods) == 0 {
		policy.AllowedInnerMethods = []string{"mschapv2", "pap", "chap", "gtc", "tls"}
	}
	if policy.PACProvisioning == "" {
		policy.PACProvisioning = "authenticated"
	}
	policy.GeneratedInFreeRADIUS = policy.Enabled && policy.AllowedByFramework && framework.Enabled
	if !framework.Enabled {
		policy.BlockingIssues = append(policy.BlockingIssues, "radius.eap.framework.enabled is false")
	}
	if policy.Enabled && !policy.AllowedByFramework {
		policy.Warnings = append(policy.Warnings, "TEAP is configured but not present in radius.eap.framework.allowed_methods")
	}
	if policy.GeneratedInFreeRADIUS && !policy.RequireMessageAuthenticator {
		policy.BlockingIssues = append(policy.BlockingIssues, "TEAP requires Message-Authenticator enforcement")
	}
	if policy.GeneratedInFreeRADIUS && !policy.RequireIdentityBinding {
		policy.BlockingIssues = append(policy.BlockingIssues, "TEAP requires identity binding")
	}
	if policy.GeneratedInFreeRADIUS && !policy.RequireCryptoBinding {
		policy.BlockingIssues = append(policy.BlockingIssues, "TEAP requires cryptobinding in production")
	}
	if policy.RequirePAC && !policy.AllowPAC {
		policy.BlockingIssues = append(policy.BlockingIssues, "require_pac cannot be true when allow_pac is false")
	}
	if policy.ChainMode == "machine_then_user" && policy.MaxChainSteps < 2 {
		policy.BlockingIssues = append(policy.BlockingIssues, "machine_then_user requires at least two chain steps")
	}
	if !stringInSlice(policy.DefaultInnerMethod, policy.AllowedInnerMethods) {
		policy.BlockingIssues = append(policy.BlockingIssues, fmt.Sprintf("default inner method %s is not allowed", policy.DefaultInnerMethod))
	}
	return policy
}

func EvaluateTEAPChain(cfg *config.Config, request TEAPChainEvaluationRequest) TEAPChainDecision {
	framework := BuildPolicyReport(cfg)
	teapReport := BuildTEAPReport(cfg, TEAPRuntimeSummary{})
	policy := teapReport.Policy
	inner := normalizeInner(request.InnerMethod)
	if inner == "" {
		inner = policy.DefaultInnerMethod
	}
	decision := TEAPChainDecision{
		Method:              "teap",
		InnerMethod:         inner,
		PolicyMode:          framework.Mode,
		ChainMode:           policy.ChainMode,
		ChainState:          "evaluating",
		IdentitySource:      defaultString(request.IdentitySource, framework.DefaultInnerIdentitySource),
		RequiredIdentities:  teapRequiredIdentities(policy),
		IdentityCorrelation: teapIdentityCorrelation(request),
	}
	reject := func(reason string, deps ...string) TEAPChainDecision {
		decision.Reason = reason
		decision.Dependencies = append(decision.Dependencies, deps...)
		decision.ChainState = "rejected"
		if !framework.Enabled || framework.Mode == "monitor" || !framework.FailClosed {
			decision.Decision = "monitor_allowed"
			decision.Warnings = append(decision.Warnings, reason)
			return decision
		}
		decision.Decision = "rejected"
		return decision
	}
	if !policy.Enabled {
		return reject("TEAP is disabled", "radius.eap.teap.enabled")
	}
	if !policy.AllowedByFramework {
		return reject("TEAP is not listed in radius.eap.framework.allowed_methods", "radius.eap.framework.allowed_methods")
	}
	if !policy.GeneratedInFreeRADIUS {
		return reject("TEAP is not generated by the current FreeRADIUS policy", "mods-enabled/eap teap")
	}
	if len(policy.BlockingIssues) > 0 {
		return reject("TEAP policy has blocking issues", policy.BlockingIssues...)
	}
	if framework.RequireMessageAuthenticator && request.EAPMessagePresent && !request.MessageAuthenticatorPresent {
		return reject("TEAP EAP-Message requires Message-Authenticator", "radius.packet_hardening.require_message_authenticator")
	}
	if !stringInSlice(inner, policy.AllowedInnerMethods) {
		return reject("TEAP inner method is not allowed", "radius.eap.framework.allowed_inner_methods")
	}
	if request.TLSVersion != "" && !tlsVersionAllowed(request.TLSVersion, policy.TLSMinVersion, policy.TLSMaxVersion) {
		return reject("TEAP TLS version is outside configured bounds", "radius.eap.tls_min_version", "radius.eap.tls_max_version")
	}
	if policy.RequireIdentityType && !request.IdentityTypePresented {
		return reject("TEAP Identity-Type TLV is required", "FreeRADIUS-EAP-TEAP-Identity-Type")
	}
	if policy.RequireCryptoBinding && !request.CryptoBindingValid {
		return reject("TEAP Crypto-Binding TLV is required and must validate", "FreeRADIUS-EAP-TEAP-Crypto-Binding")
	}
	if policy.RequireChannelBinding {
		if !request.ChannelBindingPresent {
			return reject("TEAP Channel-Binding TLV is required", "FreeRADIUS-EAP-TEAP-Channel-Binding")
		}
		if !request.ChannelBindingValid {
			return reject("TEAP Channel-Binding TLV did not validate", "FreeRADIUS-EAP-TEAP-Channel-Binding")
		}
	}
	if request.PACPresented && !policy.AllowPAC {
		return reject("TEAP PAC TLV is not allowed by policy", "radius.eap.teap.allow_pac")
	}
	if policy.RequirePAC && !request.PACPresented {
		return reject("TEAP PAC TLV is required", "FreeRADIUS-EAP-TEAP-PAC")
	}
	if request.PACProvisioningRequested && policy.PACProvisioning == "disabled" {
		return reject("TEAP PAC provisioning is disabled", "radius.eap.teap.pac_provisioning")
	}
	if request.BasicPasswordAuth && !policy.AllowBasicPasswordAuth {
		return reject("TEAP Basic-Password-Auth is disabled", "FreeRADIUS-EAP-TEAP-Basic-Password-Auth-Req")
	}
	if request.EAPPayloadPresent && !policy.AllowEAPPayload {
		return reject("TEAP EAP-Payload TLV is disabled", "FreeRADIUS-EAP-TEAP-EAP-Payload")
	}
	if request.StepCount > policy.MaxChainSteps {
		return reject("TEAP chain step count exceeds policy", "radius.eap.teap.max_chain_steps")
	}
	if request.IntermediateResultPresent && !request.IntermediateResultSuccess {
		return reject("TEAP Intermediate-Result TLV reported failure", "FreeRADIUS-EAP-TEAP-Intermediate-Result")
	}
	if request.FinalResultPresent && !request.FinalResultSuccess {
		return reject("TEAP Result TLV reported failure", "FreeRADIUS-EAP-TEAP-Result")
	}
	if reason, ok := teapIdentityFailure(policy, request); ok {
		return reject(reason, "radius.eap.teap.chain_mode")
	}
	decision.Decision = "accepted"
	decision.Reason = "TEAP chain satisfies policy"
	decision.ChainState = "complete"
	return decision
}

func TEAPTLVCatalog() []TEAPTLVCapability {
	return []TEAPTLVCapability{
		{Name: "Authority-ID", Attribute: "FreeRADIUS-EAP-TEAP-Authority-ID", Status: "governed", Semantics: "server authority binding for TEAP/PAC policy", Sensitive: true},
		{Name: "Identity-Type", Attribute: "FreeRADIUS-EAP-TEAP-Identity-Type", Status: "enforced", Semantics: "distinguishes user and machine identity legs", Required: true},
		{Name: "Result", Attribute: "FreeRADIUS-EAP-TEAP-Result", Status: "enforced", Semantics: "final inner-method result"},
		{Name: "Intermediate-Result", Attribute: "FreeRADIUS-EAP-TEAP-Intermediate-Result", Status: "enforced", Semantics: "intermediate method-chain result"},
		{Name: "Error", Attribute: "FreeRADIUS-EAP-TEAP-Error", Status: "observed", Semantics: "TEAP failure diagnostics"},
		{Name: "Channel-Binding", Attribute: "FreeRADIUS-EAP-TEAP-Channel-Binding", Status: "policy-controlled", Semantics: "supplicant/NAS/server channel context validation"},
		{Name: "Vendor-Specific", Attribute: "FreeRADIUS-EAP-TEAP-Vendor-Specific", Status: "bounded-pass-through", Semantics: "vendor-owned TEAP extension TLV"},
		{Name: "Request-Action", Attribute: "FreeRADIUS-EAP-TEAP-Request-Action", Status: "observed", Semantics: "server action request inside TEAP"},
		{Name: "EAP-Payload", Attribute: "FreeRADIUS-EAP-TEAP-EAP-Payload", Status: "policy-controlled", Semantics: "nested EAP method payload", Required: true, Sensitive: true},
		{Name: "PAC", Attribute: "FreeRADIUS-EAP-TEAP-PAC", Status: "policy-controlled", Semantics: "protected access credential container", Sensitive: true},
		{Name: "Crypto-Binding", Attribute: "FreeRADIUS-EAP-TEAP-Crypto-Binding", Status: "enforced", Semantics: "binds TLS tunnel and inner method chain", Required: true, Sensitive: true},
		{Name: "Basic-Password-Auth", Attribute: "FreeRADIUS-EAP-TEAP-Basic-Password-Auth-Req/Resp", Status: "disabled-by-default", Semantics: "TEAP basic password exchange", Sensitive: true},
		{Name: "PKCS7/PKCS10", Attribute: "FreeRADIUS-EAP-TEAP-PKCS7/PKCS10", Status: "observed", Semantics: "certificate enrollment payloads", Sensitive: true},
		{Name: "Trusted-Server-Root", Attribute: "FreeRADIUS-EAP-TEAP-Trusted-Server-Root", Status: "observed", Semantics: "trusted root distribution payload", Sensitive: true},
	}
}

func teapStatusAndMessage(report TEAPReport) (string, string) {
	if !report.Policy.Enabled {
		return "disabled", "TEAP software is present but disabled by configuration."
	}
	if !report.Policy.AllowedByFramework {
		return "disabled", "TEAP software is present; add teap to allowed_methods to generate FreeRADIUS TEAP."
	}
	if len(report.BlockingIssues) > 0 {
		if report.Policy.FrameworkMode == "enforce" && report.Policy.FrameworkFailClosed {
			return "blocked", "TEAP policy has blocking issues."
		}
		return "degraded", "TEAP policy has issues but is not fail-closed."
	}
	if report.Runtime.Rejected > 0 {
		return "degraded", "TEAP is active with recent rejected chain events."
	}
	return "ready", "TEAP is active with cryptobinding, method chaining policy, FreeRADIUS generation, and bounded telemetry."
}

func teapRequiredIdentities(policy TEAPPolicyReport) []string {
	switch policy.ChainMode {
	case "user_only":
		return []string{"user"}
	case "machine_only":
		return []string{"machine"}
	case "either":
		return []string{"user_or_machine"}
	default:
		return []string{"machine", "user"}
	}
}

func teapIdentityFailure(policy TEAPPolicyReport, request TEAPChainEvaluationRequest) (string, bool) {
	userPresent := strings.TrimSpace(request.UserIdentity) != ""
	machinePresent := strings.TrimSpace(request.MachineIdentity) != ""
	switch policy.ChainMode {
	case "user_only":
		if policy.RequireUserIdentity && !userPresent {
			return "TEAP user identity is required", true
		}
	case "machine_only":
		if policy.RequireMachineIdentity && !machinePresent {
			return "TEAP machine identity is required", true
		}
	case "either":
		if !userPresent && !machinePresent {
			return "TEAP requires a user or machine identity", true
		}
	default:
		if policy.RequireMachineIdentity && !machinePresent {
			return "TEAP machine identity is required", true
		}
		if policy.RequireUserIdentity && !userPresent {
			return "TEAP user identity is required", true
		}
		if request.StepCount > 0 && request.StepCount < 2 {
			return "TEAP machine_then_user requires at least two method-chain steps", true
		}
	}
	return "", false
}

func teapIdentityCorrelation(request TEAPChainEvaluationRequest) string {
	userPresent := strings.TrimSpace(request.UserIdentity) != ""
	machinePresent := strings.TrimSpace(request.MachineIdentity) != ""
	switch {
	case userPresent && machinePresent:
		return "machine_user"
	case userPresent:
		return "user"
	case machinePresent:
		return "machine"
	default:
		return "none"
	}
}

func tlsVersionAllowed(actual, minVersion, maxVersion string) bool {
	actual = strings.TrimSpace(actual)
	minVersion = strings.TrimSpace(minVersion)
	maxVersion = strings.TrimSpace(maxVersion)
	if actual == "" {
		return true
	}
	rank := map[string]int{"1.0": 10, "1.1": 11, "1.2": 12, "1.3": 13}
	value, ok := rank[actual]
	if !ok {
		return false
	}
	if minVersion != "" {
		if min, ok := rank[minVersion]; ok && value < min {
			return false
		}
	}
	if maxVersion != "" {
		if max, ok := rank[maxVersion]; ok && value > max {
			return false
		}
	}
	return true
}
