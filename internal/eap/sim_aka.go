package eap

import (
	"fmt"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
)

const SIMAKASchemaVersion = 1

type SIMAKAPolicyReport struct {
	Enabled                     bool     `json:"enabled"`
	AllowedByFramework          bool     `json:"allowed_by_framework"`
	GeneratedInFreeRADIUS       bool     `json:"generated_in_freeradius"`
	FrameworkMode               string   `json:"framework_mode"`
	FrameworkFailClosed         bool     `json:"framework_fail_closed"`
	Methods                     []string `json:"methods"`
	GeneratedMethods            []string `json:"generated_methods"`
	RequireIdentity             bool     `json:"require_identity"`
	RequirePermanentIdentity    bool     `json:"require_permanent_identity"`
	AllowPseudonymIdentity      bool     `json:"allow_pseudonym_identity"`
	RequirePseudonymReauth      bool     `json:"require_pseudonym_reauth"`
	PseudonymTTLSeconds         int      `json:"pseudonym_ttl_seconds"`
	ReauthTTLSeconds            int      `json:"reauth_ttl_seconds"`
	VectorProvider              string   `json:"vector_provider"`
	VectorProviderRefConfigured bool     `json:"vector_provider_ref_configured"`
	RequireFreshVectors         bool     `json:"require_fresh_vectors"`
	MaxVectorAgeSeconds         int      `json:"max_vector_age_seconds"`
	MinTriplets                 int      `json:"min_triplets"`
	MinQuintuplets              int      `json:"min_quintuplets"`
	AllowResynchronization      bool     `json:"allow_resynchronization"`
	ResyncWindowSeconds         int      `json:"resync_window_seconds"`
	RequireNetworkName          bool     `json:"require_network_name"`
	NetworkNameConfigured       bool     `json:"network_name_configured"`
	RequireKDF                  bool     `json:"require_kdf"`
	FailOnProviderUnavailable   bool     `json:"fail_on_provider_unavailable"`
	EventRetentionLimit         int      `json:"event_retention_limit"`
	RequireMessageAuthenticator bool     `json:"require_message_authenticator"`
	RequireIdentityBinding      bool     `json:"require_identity_binding"`
	Warnings                    []string `json:"warnings,omitempty"`
	BlockingIssues              []string `json:"blocking_issues,omitempty"`
}

type SIMAKARuntimeSummary struct {
	TotalEvents          int            `json:"total_events"`
	Accepted             int            `json:"accepted"`
	Rejected             int            `json:"rejected"`
	MonitorAllowed       int            `json:"monitor_allowed"`
	ByMethod             map[string]int `json:"by_method,omitempty"`
	ByDecision           map[string]int `json:"by_decision,omitempty"`
	MissingIdentity      int            `json:"missing_identity"`
	MissingVector        int            `json:"missing_vector"`
	StaleVector          int            `json:"stale_vector"`
	InvalidAuthenticator int            `json:"invalid_authenticator"`
	ResyncEvents         int            `json:"resync_events"`
	ReplayRejected       int            `json:"replay_rejected"`
	LastEventAt          string         `json:"last_event_at,omitempty"`
	LastRejectedReason   string         `json:"last_rejected_reason,omitempty"`
}

type SIMAKAAttributeCapability struct {
	Method    string `json:"method"`
	Name      string `json:"name"`
	Attribute string `json:"attribute"`
	Status    string `json:"status"`
	Semantics string `json:"semantics"`
	Required  bool   `json:"required"`
	Sensitive bool   `json:"sensitive"`
}

type SIMAKAReport struct {
	SchemaVersion    int                         `json:"schema_version"`
	GeneratedAt      string                      `json:"generated_at"`
	Status           string                      `json:"status"`
	Message          string                      `json:"message"`
	Policy           SIMAKAPolicyReport          `json:"policy"`
	Attributes       []SIMAKAAttributeCapability `json:"attributes"`
	Runtime          SIMAKARuntimeSummary        `json:"runtime"`
	Warnings         []string                    `json:"warnings,omitempty"`
	BlockingIssues   []string                    `json:"blocking_issues,omitempty"`
	ReleaseChecklist string                      `json:"release_checklist"`
	ExternalEvidence []string                    `json:"external_evidence"`
}

type SIMAKAEvaluationRequest struct {
	Method                      string
	NASType                     string
	Identity                    string
	PermanentIdentity           string
	PseudonymIdentity           string
	ReauthIdentity              string
	IdentitySource              string
	EAPMessagePresent           bool
	MessageAuthenticatorPresent bool
	VectorProviderAvailable     bool
	VectorAvailable             bool
	VectorFresh                 bool
	VectorAgeSeconds            int
	TripletCount                int
	QuintupletCount             int
	RESValid                    bool
	MACValid                    bool
	AUTNValid                   bool
	AUTSValid                   bool
	ResynchronizationRequested  bool
	ResyncAgeSeconds            int
	NetworkName                 string
	KDFValid                    bool
	ReplayDetected              bool
}

type SIMAKADecision struct {
	Decision       string   `json:"decision"`
	Method         string   `json:"method"`
	Reason         string   `json:"reason"`
	PolicyMode     string   `json:"policy_mode"`
	IdentitySource string   `json:"identity_source,omitempty"`
	Warnings       []string `json:"warnings,omitempty"`
	Dependencies   []string `json:"dependencies,omitempty"`
}

func BuildSIMAKAReport(cfg *config.Config, runtime SIMAKARuntimeSummary) SIMAKAReport {
	policy := BuildSIMAKAPolicyReport(cfg)
	report := SIMAKAReport{
		SchemaVersion:    SIMAKASchemaVersion,
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		Policy:           policy,
		Attributes:       SIMAKAAttributeCatalog(),
		Runtime:          runtime,
		Warnings:         append([]string{}, policy.Warnings...),
		BlockingIssues:   append([]string{}, policy.BlockingIssues...),
		ReleaseChecklist: "nas-0025-release-certification-checklist.md",
		ExternalEvidence: []string{
			"FreeRADIUS -XC validation with rlm_eap_sim, rlm_eap_aka, and rlm_eap_aka_prime available",
			"packet captures for SIM full authentication, AKA challenge, AKA-prime KDF, pseudonym, fast reauth, and resync paths",
			"HSS/HLR/UDM vector-provider failover and outage drills",
			"carrier offload, Passpoint, AP/controller, and roaming lab evidence for enabled mobile profiles",
			"HA failover, replay, stale-vector, and privacy-preserving identity history validation",
		},
	}
	report.Status, report.Message = simAKAStatusAndMessage(report)
	return report
}

func BuildSIMAKAPolicyReport(cfg *config.Config) SIMAKAPolicyReport {
	framework := BuildPolicyReport(cfg)
	simaka := config.RadiusEAPSIMAKAConfig{}
	if cfg != nil {
		simaka = cfg.Radius.EAP.SIMAKA
	}
	methods := normalizeMethodList(defaultStringSlice(simaka.Methods, []string{"sim", "aka", "aka-prime"}))
	methods = filterSIMAKAMethods(methods)
	if len(methods) == 0 {
		methods = []string{"sim", "aka", "aka-prime"}
	}
	pseudonymTTL := simaka.PseudonymTTLSeconds
	if pseudonymTTL == 0 {
		pseudonymTTL = 86400
	}
	reauthTTL := simaka.ReauthTTLSeconds
	if reauthTTL == 0 {
		reauthTTL = 43200
	}
	maxVectorAge := simaka.MaxVectorAgeSeconds
	if maxVectorAge == 0 {
		maxVectorAge = 300
	}
	minTriplets := simaka.MinTriplets
	if minTriplets == 0 {
		minTriplets = 2
	}
	minQuintuplets := simaka.MinQuintuplets
	if minQuintuplets == 0 {
		minQuintuplets = 1
	}
	resyncWindow := simaka.ResyncWindowSeconds
	if resyncWindow == 0 {
		resyncWindow = 300
	}
	policy := SIMAKAPolicyReport{
		Enabled:                     true,
		FrameworkMode:               framework.Mode,
		FrameworkFailClosed:         framework.FailClosed,
		Methods:                     methods,
		RequireIdentity:             true,
		RequirePermanentIdentity:    true,
		AllowPseudonymIdentity:      true,
		RequirePseudonymReauth:      simaka.RequirePseudonymReauth,
		PseudonymTTLSeconds:         pseudonymTTL,
		ReauthTTLSeconds:            reauthTTL,
		VectorProvider:              defaultString(strings.ToLower(strings.TrimSpace(simaka.VectorProvider)), "external-http"),
		VectorProviderRefConfigured: strings.TrimSpace(simaka.VectorProviderRef) != "",
		RequireFreshVectors:         true,
		MaxVectorAgeSeconds:         maxVectorAge,
		MinTriplets:                 minTriplets,
		MinQuintuplets:              minQuintuplets,
		AllowResynchronization:      true,
		ResyncWindowSeconds:         resyncWindow,
		RequireNetworkName:          true,
		NetworkNameConfigured:       strings.TrimSpace(simaka.NetworkName) != "",
		RequireKDF:                  true,
		FailOnProviderUnavailable:   true,
		EventRetentionLimit:         6000,
		RequireMessageAuthenticator: framework.RequireMessageAuthenticator,
		RequireIdentityBinding:      framework.RequireIdentityBinding,
	}
	if cfg != nil {
		policy.Enabled = simaka.Enabled
		policy.RequireIdentity = simaka.RequireIdentity
		policy.RequirePermanentIdentity = simaka.RequirePermanentIdentity
		policy.AllowPseudonymIdentity = simaka.AllowPseudonymIdentity
		policy.RequireFreshVectors = simaka.RequireFreshVectors
		policy.AllowResynchronization = simaka.AllowResynchronization
		policy.RequireNetworkName = simaka.RequireNetworkName
		policy.RequireKDF = simaka.RequireKDF
		policy.FailOnProviderUnavailable = simaka.FailOnProviderUnavailable
		if simaka.EventRetentionLimit > 0 {
			policy.EventRetentionLimit = simaka.EventRetentionLimit
		}
	}
	policy.GeneratedMethods = simAKAGeneratedMethods(policy.Methods, framework.AllowedMethods)
	policy.AllowedByFramework = len(policy.GeneratedMethods) > 0
	policy.GeneratedInFreeRADIUS = policy.Enabled && framework.Enabled && policy.AllowedByFramework
	if !framework.Enabled {
		policy.BlockingIssues = append(policy.BlockingIssues, "radius.eap.framework.enabled is false")
	}
	if policy.Enabled && !policy.AllowedByFramework {
		policy.Warnings = append(policy.Warnings, "SIM/AKA methods are configured but not present in radius.eap.framework.allowed_methods")
	}
	if policy.GeneratedInFreeRADIUS && !policy.RequireMessageAuthenticator {
		policy.BlockingIssues = append(policy.BlockingIssues, "SIM/AKA requires Message-Authenticator enforcement")
	}
	if policy.GeneratedInFreeRADIUS && !policy.RequireIdentityBinding {
		policy.BlockingIssues = append(policy.BlockingIssues, "SIM/AKA requires identity binding")
	}
	if policy.GeneratedInFreeRADIUS && !policy.RequireIdentity {
		policy.BlockingIssues = append(policy.BlockingIssues, "SIM/AKA requires an EAP identity")
	}
	if policy.GeneratedInFreeRADIUS && !policy.RequirePermanentIdentity && !policy.AllowPseudonymIdentity {
		policy.BlockingIssues = append(policy.BlockingIssues, "SIM/AKA requires permanent or pseudonym identity support")
	}
	if policy.GeneratedInFreeRADIUS && policy.FailOnProviderUnavailable && !policy.VectorProviderRefConfigured {
		policy.BlockingIssues = append(policy.BlockingIssues, "SIM/AKA vector provider reference is required")
	}
	if policy.GeneratedInFreeRADIUS && !policy.RequireFreshVectors {
		policy.BlockingIssues = append(policy.BlockingIssues, "SIM/AKA requires fresh vectors in production")
	}
	if policy.GeneratedInFreeRADIUS && policy.MaxVectorAgeSeconds > 3600 {
		policy.BlockingIssues = append(policy.BlockingIssues, "SIM/AKA vector age limit is too loose for production")
	}
	if stringInSlice("sim", policy.GeneratedMethods) && policy.MinTriplets < 2 {
		policy.BlockingIssues = append(policy.BlockingIssues, "EAP-SIM requires at least two GSM triplets")
	}
	if (stringInSlice("aka", policy.GeneratedMethods) || stringInSlice("aka-prime", policy.GeneratedMethods)) && policy.MinQuintuplets < 1 {
		policy.BlockingIssues = append(policy.BlockingIssues, "EAP-AKA methods require at least one AKA quintuplet")
	}
	if stringInSlice("aka-prime", policy.GeneratedMethods) {
		if policy.RequireNetworkName && !policy.NetworkNameConfigured {
			policy.BlockingIssues = append(policy.BlockingIssues, "EAP-AKA-prime requires a configured 3GPP network name")
		}
		if !policy.RequireKDF {
			policy.BlockingIssues = append(policy.BlockingIssues, "EAP-AKA-prime requires KDF validation")
		}
	}
	if policy.GeneratedInFreeRADIUS && !policy.AllowPseudonymIdentity {
		policy.Warnings = append(policy.Warnings, "pseudonym identity privacy is disabled")
	}
	if policy.GeneratedInFreeRADIUS && !policy.AllowResynchronization {
		policy.Warnings = append(policy.Warnings, "AKA resynchronization is disabled")
	}
	return policy
}

func EvaluateSIMAKA(cfg *config.Config, request SIMAKAEvaluationRequest) SIMAKADecision {
	framework := BuildPolicyReport(cfg)
	policy := BuildSIMAKAPolicyReport(cfg)
	method := normalizeMethod(request.Method)
	if method == "" {
		method = "sim"
	}
	decision := SIMAKADecision{
		Method:         method,
		PolicyMode:     framework.Mode,
		IdentitySource: defaultString(request.IdentitySource, "sim-aka-vector-provider"),
	}
	reject := simAKARejector(framework, &decision)
	if !isSIMAKAMethod(method) {
		return reject("method is not handled by the SIM/AKA evaluator", "radius.eap.sim_aka.methods")
	}
	if !policy.Enabled {
		return reject("SIM/AKA methods are disabled", "radius.eap.sim_aka.enabled")
	}
	if !stringInSlice(method, policy.Methods) {
		return reject("SIM/AKA method is not listed in radius.eap.sim_aka.methods", "radius.eap.sim_aka.methods")
	}
	if !stringInSlice(method, policy.GeneratedMethods) {
		return reject("SIM/AKA method is not listed in radius.eap.framework.allowed_methods", "radius.eap.framework.allowed_methods")
	}
	if !policy.GeneratedInFreeRADIUS {
		return reject("SIM/AKA methods are not generated by the current FreeRADIUS policy", "mods-enabled/eap sim/aka")
	}
	if len(policy.BlockingIssues) > 0 {
		return reject("SIM/AKA policy has blocking issues", policy.BlockingIssues...)
	}
	if framework.RequireMessageAuthenticator && request.EAPMessagePresent && !request.MessageAuthenticatorPresent {
		return reject("SIM/AKA EAP-Message requires Message-Authenticator", "radius.packet_hardening.require_message_authenticator")
	}
	if policy.RequireIdentity && !simAKAIdentityPresent(request) {
		return reject("SIM/AKA identity is required", "radius.eap.sim_aka.require_identity")
	}
	permanentPresent := strings.TrimSpace(request.PermanentIdentity) != ""
	pseudonymPresent := strings.TrimSpace(request.PseudonymIdentity) != ""
	reauthPresent := strings.TrimSpace(request.ReauthIdentity) != ""
	if policy.RequirePermanentIdentity && !permanentPresent {
		if !policy.AllowPseudonymIdentity || (!pseudonymPresent && !reauthPresent) {
			return reject("SIM/AKA permanent identity is required unless pseudonym or reauth identity is allowed", "radius.eap.sim_aka.require_permanent_identity")
		}
	}
	if pseudonymPresent && !policy.AllowPseudonymIdentity {
		return reject("SIM/AKA pseudonym identities are disabled", "radius.eap.sim_aka.allow_pseudonym_identity")
	}
	if policy.RequirePseudonymReauth && pseudonymPresent && !reauthPresent {
		return reject("SIM/AKA pseudonym reauthentication identity is required", "radius.eap.sim_aka.require_pseudonym_reauth")
	}
	if policy.FailOnProviderUnavailable && !request.VectorProviderAvailable {
		return reject("SIM/AKA vector provider is unavailable", "radius.eap.sim_aka.vector_provider_ref")
	}
	if !request.VectorAvailable {
		return reject("SIM/AKA authentication vector is missing", "radius.eap.sim_aka.vector_provider")
	}
	if policy.RequireFreshVectors && !request.VectorFresh {
		return reject("SIM/AKA authentication vector is stale", "radius.eap.sim_aka.require_fresh_vectors")
	}
	if request.VectorAgeSeconds > policy.MaxVectorAgeSeconds {
		return reject("SIM/AKA authentication vector age exceeds policy", "radius.eap.sim_aka.max_vector_age_seconds")
	}
	if request.ReplayDetected {
		return reject("SIM/AKA replay was detected", "radius.packet_hardening.replay_cache_enabled")
	}
	if request.ResynchronizationRequested {
		if !policy.AllowResynchronization {
			return reject("SIM/AKA resynchronization is disabled", "radius.eap.sim_aka.allow_resynchronization")
		}
		if !request.AUTSValid {
			return reject("SIM/AKA resynchronization requires valid AUTS", "EAP-AKA AUTS")
		}
		if request.ResyncAgeSeconds > policy.ResyncWindowSeconds {
			return reject("SIM/AKA resynchronization window exceeded", "radius.eap.sim_aka.resync_window_seconds")
		}
	}
	switch method {
	case "sim":
		if request.TripletCount < policy.MinTriplets {
			return reject("EAP-SIM requires additional GSM triplets", "EAP-SIM AT_RAND", "EAP-SIM AT_SRES", "EAP-SIM AT_KC")
		}
		if !request.RESValid {
			return reject("EAP-SIM SRES validation failed", "EAP-SIM AT_SRES")
		}
	case "aka", "aka-prime":
		if request.QuintupletCount < policy.MinQuintuplets {
			return reject("EAP-AKA requires an AKA quintuplet", "EAP-AKA RAND", "EAP-AKA AUTN", "EAP-AKA XRES")
		}
		if !request.MACValid {
			return reject("EAP-AKA MAC validation failed", "EAP-AKA AT_MAC")
		}
		if !request.AUTNValid {
			return reject("EAP-AKA AUTN validation failed", "EAP-AKA AUTN")
		}
		if !request.RESValid {
			return reject("EAP-AKA RES validation failed", "EAP-AKA RES")
		}
		if method == "aka-prime" {
			if policy.RequireNetworkName && strings.TrimSpace(request.NetworkName) == "" {
				return reject("EAP-AKA-prime network name is required", "EAP-AKA-prime AT_KDF_INPUT")
			}
			if policy.RequireKDF && !request.KDFValid {
				return reject("EAP-AKA-prime KDF validation failed", "EAP-AKA-prime AT_KDF")
			}
		}
	}
	decision.Decision = "accepted"
	decision.Reason = "SIM/AKA exchange satisfies policy"
	return decision
}

func SIMAKAAttributeCatalog() []SIMAKAAttributeCapability {
	return []SIMAKAAttributeCapability{
		{Method: "all", Name: "EAP-Message", Attribute: "EAP-Message", Status: "required", Semantics: "carries EAP-SIM/AKA packets in RADIUS", Required: true, Sensitive: true},
		{Method: "all", Name: "Message-Authenticator", Attribute: "Message-Authenticator", Status: "enforced", Semantics: "protects RADIUS packets carrying EAP", Required: true, Sensitive: true},
		{Method: "all", Name: "State", Attribute: "State", Status: "transaction-state", Semantics: "binds multi-round challenge exchanges", Required: true, Sensitive: true},
		{Method: "all", Name: "Permanent Identity", Attribute: "User-Name / EAP Identity", Status: "hashed-observed", Semantics: "IMSI or permanent mobile identity used for vector lookup", Required: true, Sensitive: true},
		{Method: "all", Name: "Pseudonym Identity", Attribute: "EAP-SIM/AKA AT_IDENTITY", Status: "privacy-controlled", Semantics: "privacy-preserving mobile identity alias", Sensitive: true},
		{Method: "all", Name: "Fast Reauth Identity", Attribute: "EAP-SIM/AKA reauth identity", Status: "ttl-controlled", Semantics: "short-lived reauthentication identity", Sensitive: true},
		{Method: "sim", Name: "RAND", Attribute: "EAP-SIM AT_RAND", Status: "vector-provider", Semantics: "GSM challenge randoms", Required: true, Sensitive: true},
		{Method: "sim", Name: "SRES", Attribute: "EAP-SIM AT_SRES", Status: "validated", Semantics: "GSM signed response proof", Required: true, Sensitive: true},
		{Method: "sim", Name: "Kc", Attribute: "EAP-SIM AT_KC", Status: "sensitive-governed", Semantics: "GSM ciphering key material", Required: true, Sensitive: true},
		{Method: "sim", Name: "Version", Attribute: "EAP-SIM AT_SELECTED_VERSION", Status: "validated", Semantics: "SIM protocol version selection", Required: true},
		{Method: "aka", Name: "RAND", Attribute: "EAP-AKA RAND", Status: "vector-provider", Semantics: "AKA challenge random", Required: true, Sensitive: true},
		{Method: "aka", Name: "AUTN", Attribute: "EAP-AKA AUTN", Status: "validated", Semantics: "network authentication token", Required: true, Sensitive: true},
		{Method: "aka", Name: "RES/XRES", Attribute: "EAP-AKA RES/XRES", Status: "validated", Semantics: "subscriber response proof", Required: true, Sensitive: true},
		{Method: "aka", Name: "CK/IK", Attribute: "EAP-AKA CK/IK", Status: "sensitive-governed", Semantics: "cipher and integrity key material", Required: true, Sensitive: true},
		{Method: "aka", Name: "AUTS", Attribute: "EAP-AKA AUTS", Status: "resync-controlled", Semantics: "subscriber resynchronization token", Sensitive: true},
		{Method: "aka-prime", Name: "KDF", Attribute: "EAP-AKA-prime AT_KDF", Status: "enforced", Semantics: "AKA-prime key derivation function identifier", Required: true, Sensitive: true},
		{Method: "aka-prime", Name: "Network Name", Attribute: "EAP-AKA-prime AT_KDF_INPUT", Status: "enforced", Semantics: "3GPP access network binding for AKA-prime", Required: true},
		{Method: "all", Name: "3GPP IMSI", Attribute: "3GPP-IMSI", Status: "dictionary-mapped", Semantics: "carrier subscriber identity in 3GPP RADIUS dictionaries", Sensitive: true},
		{Method: "all", Name: "WiMAX MN-NAI", Attribute: "WiMAX-MN-NAI", Status: "dictionary-mapped", Semantics: "mobile node identity used by WiMAX access networks", Sensitive: true},
	}
}

func simAKAStatusAndMessage(report SIMAKAReport) (string, string) {
	if !report.Policy.Enabled {
		return "disabled", "EAP-SIM/AKA software is present but disabled by configuration."
	}
	if len(report.BlockingIssues) > 0 {
		if report.Policy.FrameworkMode == "enforce" && report.Policy.FrameworkFailClosed {
			return "blocked", "EAP-SIM/AKA policy has blocking issues."
		}
		return "degraded", "EAP-SIM/AKA policy has issues but is not fail-closed."
	}
	if !report.Policy.AllowedByFramework {
		return "disabled", "EAP-SIM/AKA is available; add sim, aka, or aka-prime to allowed_methods to generate it."
	}
	if report.Runtime.Rejected > 0 {
		return "degraded", "EAP-SIM/AKA is active with recent rejected method events."
	}
	return "ready", "EAP-SIM/AKA policy is active with vector-provider controls, identity privacy, resync handling, and bounded telemetry."
}

func simAKARejector(framework PolicyReport, decision *SIMAKADecision) func(string, ...string) SIMAKADecision {
	return func(reason string, deps ...string) SIMAKADecision {
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

func simAKAIdentityPresent(request SIMAKAEvaluationRequest) bool {
	return strings.TrimSpace(request.Identity) != "" ||
		strings.TrimSpace(request.PermanentIdentity) != "" ||
		strings.TrimSpace(request.PseudonymIdentity) != "" ||
		strings.TrimSpace(request.ReauthIdentity) != ""
}

func simAKAGeneratedMethods(methods, allowed []string) []string {
	var out []string
	for _, method := range methods {
		if isSIMAKAMethod(method) && stringInSlice(method, allowed) {
			out = append(out, method)
		}
	}
	return uniqueSorted(out)
}

func filterSIMAKAMethods(methods []string) []string {
	var out []string
	for _, method := range methods {
		if isSIMAKAMethod(method) {
			out = append(out, method)
		}
	}
	return uniqueSorted(out)
}

func isSIMAKAMethod(method string) bool {
	switch normalizeMethod(method) {
	case "sim", "aka", "aka-prime":
		return true
	default:
		return false
	}
}

func SIMAKAFreeRADIUSModuleName(method string) string {
	switch normalizeMethod(method) {
	case "sim":
		return "sim"
	case "aka":
		return "aka"
	case "aka-prime":
		return "aka_prime"
	default:
		return ""
	}
}

func SIMAKAFreeRADIUSModuleNames(methods []string) []string {
	var out []string
	for _, method := range methods {
		module := SIMAKAFreeRADIUSModuleName(method)
		if module != "" && !stringInSlice(module, out) {
			out = append(out, module)
		}
	}
	return out
}

func SIMAKAMethodSummary(methods []string) string {
	if len(methods) == 0 {
		return "none"
	}
	labels := make([]string, 0, len(methods))
	for _, method := range methods {
		switch normalizeMethod(method) {
		case "sim":
			labels = append(labels, "SIM")
		case "aka":
			labels = append(labels, "AKA")
		case "aka-prime":
			labels = append(labels, "AKA-prime")
		}
	}
	if len(labels) == 0 {
		return "none"
	}
	return fmt.Sprintf("%s", strings.Join(labels, ","))
}
