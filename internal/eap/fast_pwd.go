package eap

import (
	"fmt"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
)

const FASTPWDSchemaVersion = 1

type FASTPolicyReport struct {
	Enabled                     bool     `json:"enabled"`
	AllowedByFramework          bool     `json:"allowed_by_framework"`
	GeneratedInFreeRADIUS       bool     `json:"generated_in_freeradius"`
	FrameworkMode               string   `json:"framework_mode"`
	FrameworkFailClosed         bool     `json:"framework_fail_closed"`
	DefaultInnerMethod          string   `json:"default_inner_method"`
	AllowedInnerMethods         []string `json:"allowed_inner_methods"`
	RequireCryptoBinding        bool     `json:"require_crypto_binding"`
	AllowPAC                    bool     `json:"allow_pac"`
	RequirePAC                  bool     `json:"require_pac"`
	PACProvisioning             string   `json:"pac_provisioning"`
	PACAuthorityIDConfigured    bool     `json:"pac_authority_id_configured"`
	PACOpaqueKeyRefConfigured   bool     `json:"pac_opaque_key_ref_configured"`
	PACLifetimeSeconds          int      `json:"pac_lifetime_seconds"`
	AllowAnonymousProvisioning  bool     `json:"allow_anonymous_provisioning"`
	AllowEAPPayload             bool     `json:"allow_eap_payload"`
	MaxProvisioningAttempts     int      `json:"max_provisioning_attempts"`
	SessionTTLSeconds           int      `json:"session_ttl_seconds"`
	EventRetentionLimit         int      `json:"event_retention_limit"`
	RequireMessageAuthenticator bool     `json:"require_message_authenticator"`
	RequireIdentityBinding      bool     `json:"require_identity_binding"`
	TLSMinVersion               string   `json:"tls_min_version"`
	TLSMaxVersion               string   `json:"tls_max_version"`
	Warnings                    []string `json:"warnings,omitempty"`
	BlockingIssues              []string `json:"blocking_issues,omitempty"`
}

type PWDPolicyReport struct {
	Enabled                     bool     `json:"enabled"`
	AllowedByFramework          bool     `json:"allowed_by_framework"`
	GeneratedInFreeRADIUS       bool     `json:"generated_in_freeradius"`
	FrameworkMode               string   `json:"framework_mode"`
	FrameworkFailClosed         bool     `json:"framework_fail_closed"`
	Group                       int      `json:"group"`
	ServerIDConfigured          bool     `json:"server_id_configured"`
	RequireStrongGroup          bool     `json:"require_strong_group"`
	PasswordSource              string   `json:"password_source"`
	AllowLocalVerifier          bool     `json:"allow_local_verifier"`
	RequireIdentity             bool     `json:"require_identity"`
	RequirePasswordProof        bool     `json:"require_password_proof"`
	ReplayWindowSeconds         int      `json:"replay_window_seconds"`
	FragmentSize                int      `json:"fragment_size"`
	EventRetentionLimit         int      `json:"event_retention_limit"`
	RequireMessageAuthenticator bool     `json:"require_message_authenticator"`
	RequireIdentityBinding      bool     `json:"require_identity_binding"`
	Warnings                    []string `json:"warnings,omitempty"`
	BlockingIssues              []string `json:"blocking_issues,omitempty"`
}

type FASTPWDRuntimeSummary struct {
	TotalEvents           int            `json:"total_events"`
	Accepted              int            `json:"accepted"`
	Rejected              int            `json:"rejected"`
	MonitorAllowed        int            `json:"monitor_allowed"`
	ByMethod              map[string]int `json:"by_method,omitempty"`
	ByDecision            map[string]int `json:"by_decision,omitempty"`
	MissingPAC            int            `json:"missing_pac"`
	InvalidCryptoBinding  int            `json:"invalid_crypto_binding"`
	AnonymousProvisioning int            `json:"anonymous_provisioning"`
	MissingPasswordProof  int            `json:"missing_password_proof"`
	WeakPWDGroup          int            `json:"weak_pwd_group"`
	ReplayRejected        int            `json:"replay_rejected"`
	LastEventAt           string         `json:"last_event_at,omitempty"`
	LastRejectedReason    string         `json:"last_rejected_reason,omitempty"`
}

type FASTPWDAttributeCapability struct {
	Method    string `json:"method"`
	Name      string `json:"name"`
	Attribute string `json:"attribute"`
	Status    string `json:"status"`
	Semantics string `json:"semantics"`
	Required  bool   `json:"required"`
	Sensitive bool   `json:"sensitive"`
}

type FASTPWDReport struct {
	SchemaVersion    int                          `json:"schema_version"`
	GeneratedAt      string                       `json:"generated_at"`
	Status           string                       `json:"status"`
	Message          string                       `json:"message"`
	FAST             FASTPolicyReport             `json:"fast"`
	PWD              PWDPolicyReport              `json:"pwd"`
	Attributes       []FASTPWDAttributeCapability `json:"attributes"`
	Runtime          FASTPWDRuntimeSummary        `json:"runtime"`
	Warnings         []string                     `json:"warnings,omitempty"`
	BlockingIssues   []string                     `json:"blocking_issues,omitempty"`
	ReleaseChecklist string                       `json:"release_checklist"`
	ExternalEvidence []string                     `json:"external_evidence"`
}

type FASTPWDEvaluationRequest struct {
	Method                      string
	InnerMethod                 string
	NASType                     string
	Identity                    string
	IdentitySource              string
	EAPMessagePresent           bool
	MessageAuthenticatorPresent bool
	TLSVersion                  string
	CryptoBindingValid          bool
	PACPresented                bool
	PACProvisioningRequested    bool
	PACOpaqueKeyAvailable       bool
	AnonymousProvisioning       bool
	EAPPayloadPresent           bool
	ProvisioningAttemptCount    int
	PasswordProofValid          bool
	ReplayDetected              bool
	PWDGroup                    int
	PWDServerID                 string
}

type FASTPWDDecision struct {
	Decision       string   `json:"decision"`
	Method         string   `json:"method"`
	InnerMethod    string   `json:"inner_method,omitempty"`
	Reason         string   `json:"reason"`
	PolicyMode     string   `json:"policy_mode"`
	IdentitySource string   `json:"identity_source,omitempty"`
	Warnings       []string `json:"warnings,omitempty"`
	Dependencies   []string `json:"dependencies,omitempty"`
}

func BuildFASTPWDReport(cfg *config.Config, runtime FASTPWDRuntimeSummary) FASTPWDReport {
	fast := BuildFASTPolicyReport(cfg)
	pwd := BuildPWDPolicyReport(cfg)
	report := FASTPWDReport{
		SchemaVersion:    FASTPWDSchemaVersion,
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		FAST:             fast,
		PWD:              pwd,
		Attributes:       FASTPWDAttributeCatalog(),
		Runtime:          runtime,
		Warnings:         append(append([]string{}, fast.Warnings...), pwd.Warnings...),
		BlockingIssues:   append(append([]string{}, fast.BlockingIssues...), pwd.BlockingIssues...),
		ReleaseChecklist: "nas-0024-release-certification-checklist.md",
		ExternalEvidence: []string{
			"FreeRADIUS -XC validation with rlm_eap_fast and rlm_eap_pwd available",
			"packet captures for EAP-FAST PAC, crypto-binding, EAP-Payload, and tunnel result paths",
			"packet captures for EAP-PWD commit/confirm/password-proof exchange and replay rejection",
			"real supplicant/AP/controller tests for enabled FAST and PWD profiles",
			"HA failover and replay drills while FAST/PWD exchanges are active",
		},
	}
	report.Status, report.Message = fastPWDStatusAndMessage(report)
	return report
}

func BuildFASTPolicyReport(cfg *config.Config) FASTPolicyReport {
	framework := BuildPolicyReport(cfg)
	fast := config.RadiusEAPFASTConfig{}
	if cfg != nil {
		fast = cfg.Radius.EAP.FAST
	}
	policy := FASTPolicyReport{
		Enabled:                     true,
		AllowedByFramework:          stringInSlice("fast", framework.AllowedMethods),
		FrameworkMode:               framework.Mode,
		FrameworkFailClosed:         framework.FailClosed,
		DefaultInnerMethod:          normalizeInner(defaultString(fast.DefaultInnerMethod, "mschapv2")),
		AllowedInnerMethods:         framework.AllowedInnerMethods,
		RequireCryptoBinding:        true,
		AllowPAC:                    true,
		RequirePAC:                  fast.RequirePAC,
		PACProvisioning:             defaultString(strings.ToLower(strings.TrimSpace(fast.PACProvisioning)), "authenticated"),
		PACAuthorityIDConfigured:    strings.TrimSpace(fast.PACAuthorityID) != "",
		PACOpaqueKeyRefConfigured:   strings.TrimSpace(fast.PACOpaqueKeyRef) != "",
		PACLifetimeSeconds:          2592000,
		AllowAnonymousProvisioning:  fast.AllowAnonymousProvisioning,
		AllowEAPPayload:             true,
		MaxProvisioningAttempts:     3,
		SessionTTLSeconds:           900,
		EventRetentionLimit:         6000,
		RequireMessageAuthenticator: framework.RequireMessageAuthenticator,
		RequireIdentityBinding:      framework.RequireIdentityBinding,
		TLSMinVersion:               framework.TLSMinVersion,
		TLSMaxVersion:               framework.TLSMaxVersion,
	}
	if cfg != nil {
		policy.Enabled = fast.Enabled
		policy.RequireCryptoBinding = fast.RequireCryptoBinding
		policy.AllowPAC = fast.AllowPAC
		policy.AllowEAPPayload = fast.AllowEAPPayload
		if fast.PACLifetimeSeconds > 0 {
			policy.PACLifetimeSeconds = fast.PACLifetimeSeconds
		}
		if fast.MaxProvisioningAttempts > 0 {
			policy.MaxProvisioningAttempts = fast.MaxProvisioningAttempts
		}
		if fast.SessionTTLSeconds > 0 {
			policy.SessionTTLSeconds = fast.SessionTTLSeconds
		}
		if fast.EventRetentionLimit > 0 {
			policy.EventRetentionLimit = fast.EventRetentionLimit
		}
	}
	if policy.DefaultInnerMethod == "" {
		policy.DefaultInnerMethod = "mschapv2"
	}
	if len(policy.AllowedInnerMethods) == 0 {
		policy.AllowedInnerMethods = []string{"mschapv2", "pap", "chap", "gtc", "tls"}
	}
	policy.GeneratedInFreeRADIUS = policy.Enabled && policy.AllowedByFramework && framework.Enabled
	if !framework.Enabled {
		policy.BlockingIssues = append(policy.BlockingIssues, "radius.eap.framework.enabled is false")
	}
	if policy.Enabled && !policy.AllowedByFramework {
		policy.Warnings = append(policy.Warnings, "EAP-FAST is configured but not present in radius.eap.framework.allowed_methods")
	}
	if policy.GeneratedInFreeRADIUS && !policy.RequireMessageAuthenticator {
		policy.BlockingIssues = append(policy.BlockingIssues, "EAP-FAST requires Message-Authenticator enforcement")
	}
	if policy.GeneratedInFreeRADIUS && !policy.RequireIdentityBinding {
		policy.BlockingIssues = append(policy.BlockingIssues, "EAP-FAST requires identity binding")
	}
	if policy.GeneratedInFreeRADIUS && !policy.RequireCryptoBinding {
		policy.BlockingIssues = append(policy.BlockingIssues, "EAP-FAST requires cryptobinding in production")
	}
	if policy.RequirePAC && !policy.AllowPAC {
		policy.BlockingIssues = append(policy.BlockingIssues, "require_pac cannot be true when allow_pac is false")
	}
	if policy.PACProvisioning == "anonymous" && !policy.AllowAnonymousProvisioning {
		policy.BlockingIssues = append(policy.BlockingIssues, "anonymous PAC provisioning is disabled")
	}
	if !stringInSlice(policy.DefaultInnerMethod, policy.AllowedInnerMethods) {
		policy.BlockingIssues = append(policy.BlockingIssues, fmt.Sprintf("default inner method %s is not allowed", policy.DefaultInnerMethod))
	}
	return policy
}

func BuildPWDPolicyReport(cfg *config.Config) PWDPolicyReport {
	framework := BuildPolicyReport(cfg)
	pwd := config.RadiusEAPPWDConfig{}
	if cfg != nil {
		pwd = cfg.Radius.EAP.PWD
	}
	group := pwd.Group
	if group == 0 {
		group = 19
	}
	fragmentSize := pwd.FragmentSize
	if fragmentSize == 0 {
		fragmentSize = 1020
	}
	policy := PWDPolicyReport{
		Enabled:                     true,
		AllowedByFramework:          stringInSlice("pwd", framework.AllowedMethods),
		FrameworkMode:               framework.Mode,
		FrameworkFailClosed:         framework.FailClosed,
		Group:                       group,
		ServerIDConfigured:          strings.TrimSpace(pwd.ServerID) != "",
		RequireStrongGroup:          true,
		PasswordSource:              defaultString(strings.ToLower(strings.TrimSpace(pwd.PasswordSource)), framework.DefaultInnerIdentitySource),
		AllowLocalVerifier:          true,
		RequireIdentity:             true,
		RequirePasswordProof:        true,
		ReplayWindowSeconds:         30,
		FragmentSize:                fragmentSize,
		EventRetentionLimit:         6000,
		RequireMessageAuthenticator: framework.RequireMessageAuthenticator,
		RequireIdentityBinding:      framework.RequireIdentityBinding,
	}
	if cfg != nil {
		policy.Enabled = pwd.Enabled
		policy.RequireStrongGroup = pwd.RequireStrongGroup
		policy.AllowLocalVerifier = pwd.AllowLocalVerifier
		policy.RequireIdentity = pwd.RequireIdentity
		policy.RequirePasswordProof = pwd.RequirePasswordProof
		if pwd.ReplayWindowSeconds > 0 {
			policy.ReplayWindowSeconds = pwd.ReplayWindowSeconds
		}
		if pwd.EventRetentionLimit > 0 {
			policy.EventRetentionLimit = pwd.EventRetentionLimit
		}
	}
	if policy.PasswordSource == "" {
		policy.PasswordSource = "identity-failover"
	}
	policy.GeneratedInFreeRADIUS = policy.Enabled && policy.AllowedByFramework && framework.Enabled
	if !framework.Enabled {
		policy.BlockingIssues = append(policy.BlockingIssues, "radius.eap.framework.enabled is false")
	}
	if policy.Enabled && !policy.AllowedByFramework {
		policy.Warnings = append(policy.Warnings, "EAP-PWD is configured but not present in radius.eap.framework.allowed_methods")
	}
	if policy.GeneratedInFreeRADIUS && !policy.RequireMessageAuthenticator {
		policy.BlockingIssues = append(policy.BlockingIssues, "EAP-PWD requires Message-Authenticator enforcement")
	}
	if policy.GeneratedInFreeRADIUS && !policy.RequireIdentityBinding {
		policy.BlockingIssues = append(policy.BlockingIssues, "EAP-PWD requires identity binding")
	}
	if policy.GeneratedInFreeRADIUS && policy.RequireStrongGroup && !strongPWDGroup(policy.Group) {
		policy.BlockingIssues = append(policy.BlockingIssues, "EAP-PWD group is not in the strong group allowlist")
	}
	if policy.GeneratedInFreeRADIUS && !policy.AllowLocalVerifier {
		policy.BlockingIssues = append(policy.BlockingIssues, "EAP-PWD needs a local verifier until external verifier adapters are configured")
	}
	if policy.GeneratedInFreeRADIUS && !policy.RequirePasswordProof {
		policy.BlockingIssues = append(policy.BlockingIssues, "EAP-PWD requires password proof in production")
	}
	return policy
}

func EvaluateFASTPWD(cfg *config.Config, request FASTPWDEvaluationRequest) FASTPWDDecision {
	method := normalizeMethod(request.Method)
	if method == "" {
		method = "fast"
	}
	switch method {
	case "fast":
		return evaluateFAST(cfg, request)
	case "pwd":
		return evaluatePWD(cfg, request)
	default:
		return FASTPWDDecision{Decision: "rejected", Method: method, Reason: "method is not handled by the FAST/PWD evaluator", PolicyMode: BuildPolicyReport(cfg).Mode}
	}
}

func evaluateFAST(cfg *config.Config, request FASTPWDEvaluationRequest) FASTPWDDecision {
	framework := BuildPolicyReport(cfg)
	policy := BuildFASTPolicyReport(cfg)
	inner := normalizeInner(request.InnerMethod)
	if inner == "" {
		inner = policy.DefaultInnerMethod
	}
	decision := FASTPWDDecision{
		Method:         "fast",
		InnerMethod:    inner,
		PolicyMode:     framework.Mode,
		IdentitySource: defaultString(request.IdentitySource, framework.DefaultInnerIdentitySource),
	}
	reject := fastPWDRejector(framework, &decision)
	if !policy.Enabled {
		return reject("EAP-FAST is disabled", "radius.eap.fast.enabled")
	}
	if !policy.AllowedByFramework {
		return reject("EAP-FAST is not listed in radius.eap.framework.allowed_methods", "radius.eap.framework.allowed_methods")
	}
	if !policy.GeneratedInFreeRADIUS {
		return reject("EAP-FAST is not generated by the current FreeRADIUS policy", "mods-enabled/eap fast")
	}
	if len(policy.BlockingIssues) > 0 {
		return reject("EAP-FAST policy has blocking issues", policy.BlockingIssues...)
	}
	if framework.RequireMessageAuthenticator && request.EAPMessagePresent && !request.MessageAuthenticatorPresent {
		return reject("EAP-FAST EAP-Message requires Message-Authenticator", "radius.packet_hardening.require_message_authenticator")
	}
	if !stringInSlice(inner, policy.AllowedInnerMethods) {
		return reject("EAP-FAST inner method is not allowed", "radius.eap.framework.allowed_inner_methods")
	}
	if request.TLSVersion != "" && !tlsVersionAllowed(request.TLSVersion, policy.TLSMinVersion, policy.TLSMaxVersion) {
		return reject("EAP-FAST TLS version is outside configured bounds", "radius.eap.tls_min_version", "radius.eap.tls_max_version")
	}
	if policy.RequireCryptoBinding && !request.CryptoBindingValid {
		return reject("EAP-FAST cryptobinding is required and must validate", "EAP-FAST Crypto-Binding")
	}
	if request.PACPresented && !policy.AllowPAC {
		return reject("EAP-FAST PAC is not allowed by policy", "radius.eap.fast.allow_pac")
	}
	if policy.RequirePAC && !request.PACPresented {
		return reject("EAP-FAST PAC is required", "FreeRADIUS-EAP-FAST-PAC")
	}
	if request.PACProvisioningRequested && policy.PACProvisioning == "disabled" {
		return reject("EAP-FAST PAC provisioning is disabled", "radius.eap.fast.pac_provisioning")
	}
	if request.AnonymousProvisioning && !policy.AllowAnonymousProvisioning {
		return reject("EAP-FAST anonymous PAC provisioning is disabled", "radius.eap.fast.allow_anonymous_provisioning")
	}
	if request.ProvisioningAttemptCount > policy.MaxProvisioningAttempts {
		return reject("EAP-FAST PAC provisioning attempts exceed policy", "radius.eap.fast.max_provisioning_attempts")
	}
	if request.EAPPayloadPresent && !policy.AllowEAPPayload {
		return reject("EAP-FAST EAP-Payload is disabled", "EAP-FAST EAP-Payload")
	}
	decision.Decision = "accepted"
	decision.Reason = "EAP-FAST exchange satisfies policy"
	return decision
}

func evaluatePWD(cfg *config.Config, request FASTPWDEvaluationRequest) FASTPWDDecision {
	framework := BuildPolicyReport(cfg)
	policy := BuildPWDPolicyReport(cfg)
	decision := FASTPWDDecision{
		Method:         "pwd",
		PolicyMode:     framework.Mode,
		IdentitySource: defaultString(request.IdentitySource, policy.PasswordSource),
	}
	reject := fastPWDRejector(framework, &decision)
	if !policy.Enabled {
		return reject("EAP-PWD is disabled", "radius.eap.pwd.enabled")
	}
	if !policy.AllowedByFramework {
		return reject("EAP-PWD is not listed in radius.eap.framework.allowed_methods", "radius.eap.framework.allowed_methods")
	}
	if !policy.GeneratedInFreeRADIUS {
		return reject("EAP-PWD is not generated by the current FreeRADIUS policy", "mods-enabled/eap pwd")
	}
	if len(policy.BlockingIssues) > 0 {
		return reject("EAP-PWD policy has blocking issues", policy.BlockingIssues...)
	}
	if framework.RequireMessageAuthenticator && request.EAPMessagePresent && !request.MessageAuthenticatorPresent {
		return reject("EAP-PWD EAP-Message requires Message-Authenticator", "radius.packet_hardening.require_message_authenticator")
	}
	if policy.RequireIdentity && strings.TrimSpace(request.Identity) == "" {
		return reject("EAP-PWD identity is required", "radius.eap.pwd.require_identity")
	}
	group := request.PWDGroup
	if group == 0 {
		group = policy.Group
	}
	if group != policy.Group {
		return reject("EAP-PWD group does not match policy", "radius.eap.pwd.group")
	}
	if policy.RequireStrongGroup && !strongPWDGroup(group) {
		return reject("EAP-PWD group is not in the strong group allowlist", "radius.eap.pwd.require_strong_group")
	}
	if policy.RequirePasswordProof && !request.PasswordProofValid {
		return reject("EAP-PWD password proof is required and must validate", "radius.eap.pwd.require_password_proof")
	}
	if request.ReplayDetected {
		return reject("EAP-PWD replay was detected", "radius.eap.pwd.replay_window_seconds")
	}
	decision.Decision = "accepted"
	decision.Reason = "EAP-PWD exchange satisfies policy"
	return decision
}

func FASTPWDAttributeCatalog() []FASTPWDAttributeCapability {
	return []FASTPWDAttributeCapability{
		{Method: "fast", Name: "PAC", Attribute: "FreeRADIUS-EAP-FAST-PAC", Status: "policy-controlled", Semantics: "protected access credential container", Sensitive: true},
		{Method: "fast", Name: "PAC-Key", Attribute: "FreeRADIUS-EAP-FAST-PAC-Key", Status: "sensitive-governed", Semantics: "PAC key material", Sensitive: true},
		{Method: "fast", Name: "PAC-Opaque", Attribute: "FreeRADIUS-EAP-FAST-PAC-Opaque-TLV", Status: "sensitive-governed", Semantics: "opaque PAC server state", Sensitive: true},
		{Method: "fast", Name: "PAC-Lifetime", Attribute: "FreeRADIUS-EAP-FAST-PAC-Lifetime", Status: "policy-controlled", Semantics: "PAC validity period"},
		{Method: "fast", Name: "PAC-Acknowledge", Attribute: "FreeRADIUS-EAP-FAST-PAC-Acknowledge", Status: "observed", Semantics: "PAC provisioning acknowledgement"},
		{Method: "fast", Name: "Crypto-Binding", Attribute: "EAP-FAST Crypto-Binding", Status: "enforced", Semantics: "binds protected tunnel and inner method", Required: true, Sensitive: true},
		{Method: "fast", Name: "EAP-Payload", Attribute: "EAP-FAST EAP-Payload", Status: "policy-controlled", Semantics: "nested EAP method payload", Required: true, Sensitive: true},
		{Method: "pwd", Name: "Group", Attribute: "rlm_eap_pwd group", Status: "enforced", Semantics: "password-authenticated key exchange group", Required: true},
		{Method: "pwd", Name: "Server-ID", Attribute: "rlm_eap_pwd server_id", Status: "governed", Semantics: "server identity used in EAP-PWD exchange", Required: true, Sensitive: true},
		{Method: "pwd", Name: "Password-Proof", Attribute: "EAP-PWD Confirm", Status: "enforced", Semantics: "password-authenticated proof validation", Required: true, Sensitive: true},
		{Method: "pwd", Name: "Replay-Window", Attribute: "EAP-PWD Replay", Status: "enforced", Semantics: "rejects replayed PWD exchanges"},
	}
}

func fastPWDStatusAndMessage(report FASTPWDReport) (string, string) {
	if !report.FAST.Enabled && !report.PWD.Enabled {
		return "disabled", "EAP-FAST and EAP-PWD software is present but disabled by configuration."
	}
	if len(report.BlockingIssues) > 0 {
		if (report.FAST.FrameworkMode == "enforce" && report.FAST.FrameworkFailClosed) ||
			(report.PWD.FrameworkMode == "enforce" && report.PWD.FrameworkFailClosed) {
			return "blocked", "EAP-FAST/PWD policy has blocking issues."
		}
		return "degraded", "EAP-FAST/PWD policy has issues but is not fail-closed."
	}
	if !report.FAST.AllowedByFramework && !report.PWD.AllowedByFramework {
		return "disabled", "EAP-FAST and EAP-PWD are available; add fast or pwd to allowed_methods to generate them."
	}
	if report.Runtime.Rejected > 0 {
		return "degraded", "EAP-FAST/PWD is active with recent rejected method events."
	}
	return "ready", "EAP-FAST/PWD policy is active with FreeRADIUS generation controls and bounded telemetry."
}

func fastPWDRejector(framework PolicyReport, decision *FASTPWDDecision) func(string, ...string) FASTPWDDecision {
	return func(reason string, deps ...string) FASTPWDDecision {
		decision.Reason = reason
		decision.Dependencies = append(decision.Dependencies, deps...)
		if !framework.Enabled || framework.Mode == "monitor" || !framework.FailClosed {
			decision.Decision = "monitor_allowed"
			decision.Warnings = append(decision.Warnings, reason)
			return *decision
		}
		decision.Decision = "rejected"
		return *decision
	}
}

func strongPWDGroup(group int) bool {
	switch group {
	case 19, 20, 21, 25, 26:
		return true
	default:
		return false
	}
}
