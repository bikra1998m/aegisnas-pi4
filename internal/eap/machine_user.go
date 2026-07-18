package eap

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
)

const MachineUserSchemaVersion = 1

type MachineUserPolicyReport struct {
	Enabled                   bool     `json:"enabled"`
	Mode                      string   `json:"mode"`
	FailClosed                bool     `json:"fail_closed"`
	FrameworkEnabled          bool     `json:"framework_enabled"`
	FrameworkMode             string   `json:"framework_mode"`
	FrameworkFailClosed       bool     `json:"framework_fail_closed"`
	RequireTEAP               bool     `json:"require_teap"`
	TEAPGenerated             bool     `json:"teap_generated"`
	CorrelationMode           string   `json:"correlation_mode"`
	RequireMachineIdentity    bool     `json:"require_machine_identity"`
	RequireUserIdentity       bool     `json:"require_user_identity"`
	RequireMachineBeforeUser  bool     `json:"require_machine_before_user"`
	RequireSameCallingStation bool     `json:"require_same_calling_station"`
	RequireSameNAS            bool     `json:"require_same_nas"`
	RequireFreshMachineAuth   bool     `json:"require_fresh_machine_auth"`
	MachineAuthTTLSeconds     int      `json:"machine_auth_ttl_seconds"`
	UserAuthTTLSeconds        int      `json:"user_auth_ttl_seconds"`
	TransitionWindowSeconds   int      `json:"transition_window_seconds"`
	AllowedMachineMethods     []string `json:"allowed_machine_methods"`
	AllowedUserMethods        []string `json:"allowed_user_methods"`
	IdentityPrecedence        string   `json:"identity_precedence"`
	RoleMergeStrategy         string   `json:"role_merge_strategy"`
	ConflictAction            string   `json:"conflict_action"`
	StaleMachineAction        string   `json:"stale_machine_action"`
	MachineIdentityPrefixes   []string `json:"machine_identity_prefixes,omitempty"`
	UserIdentityPrefixes      []string `json:"user_identity_prefixes,omitempty"`
	MaxActiveCorrelations     int      `json:"max_active_correlations"`
	AuditEnabled              bool     `json:"audit_enabled"`
	EventRetentionLimit       int      `json:"event_retention_limit"`
	Warnings                  []string `json:"warnings,omitempty"`
	BlockingIssues            []string `json:"blocking_issues,omitempty"`
}

type MachineUserRuntimeSummary struct {
	TotalEvents              int            `json:"total_events"`
	Accepted                 int            `json:"accepted"`
	Rejected                 int            `json:"rejected"`
	MonitorAllowed           int            `json:"monitor_allowed"`
	Quarantined              int            `json:"quarantined"`
	ActiveCorrelations       int            `json:"active_correlations"`
	ByDecision               map[string]int `json:"by_decision,omitempty"`
	ByCorrelationMode        map[string]int `json:"by_correlation_mode,omitempty"`
	MissingMachineIdentity   int            `json:"missing_machine_identity"`
	MissingUserIdentity      int            `json:"missing_user_identity"`
	StaleMachineAuth         int            `json:"stale_machine_auth"`
	RoleConflict             int            `json:"role_conflict"`
	CallingStationMismatch   int            `json:"calling_station_mismatch"`
	NASMismatch              int            `json:"nas_mismatch"`
	MachineBeforeUserFailure int            `json:"machine_before_user_failure"`
	LastEventAt              string         `json:"last_event_at,omitempty"`
	LastRejectedReason       string         `json:"last_rejected_reason,omitempty"`
}

type MachineUserCapability struct {
	Name       string   `json:"name"`
	Status     string   `json:"status"`
	Vendors    []string `json:"vendors"`
	RFCs       []string `json:"rfcs"`
	Attributes []string `json:"attributes"`
	Semantics  string   `json:"semantics"`
	Required   bool     `json:"required"`
	Stateful   bool     `json:"stateful"`
	Sensitive  bool     `json:"sensitive"`
}

type MachineUserReport struct {
	SchemaVersion    int                       `json:"schema_version"`
	GeneratedAt      string                    `json:"generated_at"`
	Status           string                    `json:"status"`
	Message          string                    `json:"message"`
	Policy           MachineUserPolicyReport   `json:"policy"`
	Capabilities     []MachineUserCapability   `json:"capabilities"`
	Runtime          MachineUserRuntimeSummary `json:"runtime"`
	Warnings         []string                  `json:"warnings,omitempty"`
	BlockingIssues   []string                  `json:"blocking_issues,omitempty"`
	ReleaseChecklist string                    `json:"release_checklist"`
	ExternalEvidence []string                  `json:"external_evidence"`
}

type MachineUserEvaluationRequest struct {
	NASType                     string
	NASIdentifier               string
	CorrelationID               string
	OuterIdentity               string
	MachineIdentity             string
	UserIdentity                string
	CallingStationID            string
	MachineCallingStationID     string
	UserCallingStationID        string
	MachineNASIdentifier        string
	UserNASIdentifier           string
	IdentitySource              string
	MachineMethod               string
	UserMethod                  string
	MachineAuthenticated        bool
	UserAuthenticated           bool
	MachineAuthAgeSeconds       int
	UserAuthAgeSeconds          int
	MachineRole                 string
	UserRole                    string
	DevicePosture               string
	ExistingMachineSession      bool
	ExistingUserSession         bool
	EAPMessagePresent           bool
	MessageAuthenticatorPresent bool
	TEAPChainComplete           bool
	IdentityTypePresented       bool
	CryptoBindingValid          bool
	ChannelBindingValid         bool
	ReplayDetected              bool
}

type MachineUserDecision struct {
	Decision            string   `json:"decision"`
	Reason              string   `json:"reason"`
	PolicyMode          string   `json:"policy_mode"`
	CorrelationMode     string   `json:"correlation_mode"`
	CorrelationState    string   `json:"correlation_state"`
	CorrelationID       string   `json:"correlation_id,omitempty"`
	IdentitySource      string   `json:"identity_source,omitempty"`
	IdentityCorrelation string   `json:"identity_correlation"`
	IdentityPrecedence  string   `json:"identity_precedence"`
	RoleMergeStrategy   string   `json:"role_merge_strategy"`
	EffectiveRole       string   `json:"effective_role,omitempty"`
	DevicePosture       string   `json:"device_posture,omitempty"`
	RequiredIdentities  []string `json:"required_identities,omitempty"`
	ConflictDetected    bool     `json:"conflict_detected"`
	StaleMachineAuth    bool     `json:"stale_machine_auth"`
	SameCallingStation  bool     `json:"same_calling_station"`
	SameNAS             bool     `json:"same_nas"`
	MachineBeforeUser   bool     `json:"machine_before_user"`
	Warnings            []string `json:"warnings,omitempty"`
	Dependencies        []string `json:"dependencies,omitempty"`
}

func BuildMachineUserReport(cfg *config.Config, runtime MachineUserRuntimeSummary) MachineUserReport {
	policy := BuildMachineUserPolicyReport(cfg)
	report := MachineUserReport{
		SchemaVersion:    MachineUserSchemaVersion,
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		Policy:           policy,
		Capabilities:     MachineUserCapabilityCatalog(),
		Runtime:          runtime,
		Warnings:         append([]string(nil), policy.Warnings...),
		BlockingIssues:   append([]string(nil), policy.BlockingIssues...),
		ReleaseChecklist: "nas-0026-release-certification-checklist.md",
		ExternalEvidence: []string{
			"Windows supplicant machine and user logon packet captures",
			"Microsoft NPS, Cisco ISE, Aruba ClearPass, and HP/Aruba switch or WLAN interop evidence",
			"same-client transition, roaming, stale-machine, and conflict drills",
			"HA failover while correlated EAP sessions are active",
		},
	}
	report.Status, report.Message = machineUserStatusAndMessage(report)
	return report
}

func BuildMachineUserPolicyReport(cfg *config.Config) MachineUserPolicyReport {
	framework := BuildPolicyReport(cfg)
	teap := BuildTEAPPolicyReport(cfg)
	machineUser := config.RadiusEAPMachineUserConfig{}
	if cfg != nil {
		machineUser = cfg.Radius.EAP.MachineUser
	}
	policy := MachineUserPolicyReport{
		Enabled:                   true,
		Mode:                      "monitor",
		FailClosed:                true,
		FrameworkEnabled:          framework.Enabled,
		FrameworkMode:             framework.Mode,
		FrameworkFailClosed:       framework.FailClosed,
		RequireTEAP:               true,
		TEAPGenerated:             teap.GeneratedInFreeRADIUS,
		CorrelationMode:           "machine_then_user",
		RequireMachineIdentity:    true,
		RequireUserIdentity:       true,
		RequireMachineBeforeUser:  true,
		RequireSameCallingStation: true,
		RequireSameNAS:            false,
		RequireFreshMachineAuth:   true,
		MachineAuthTTLSeconds:     28800,
		UserAuthTTLSeconds:        28800,
		TransitionWindowSeconds:   900,
		AllowedMachineMethods:     []string{"teap", "tls"},
		AllowedUserMethods:        []string{"teap", "peap", "ttls"},
		IdentityPrecedence:        "user_over_machine",
		RoleMergeStrategy:         "user_primary",
		ConflictAction:            "reject",
		StaleMachineAction:        "reject",
		MachineIdentityPrefixes:   []string{"host/", "machine/"},
		MaxActiveCorrelations:     100000,
		AuditEnabled:              true,
		EventRetentionLimit:       6000,
	}
	if cfg != nil {
		policy.Enabled = machineUser.Enabled
		policy.Mode = defaultString(strings.ToLower(strings.TrimSpace(machineUser.Mode)), "monitor")
		policy.FailClosed = machineUser.FailClosed
		policy.RequireTEAP = machineUser.RequireTEAP
		policy.CorrelationMode = defaultString(strings.ToLower(strings.TrimSpace(machineUser.CorrelationMode)), "machine_then_user")
		policy.RequireMachineIdentity = machineUser.RequireMachineIdentity
		policy.RequireUserIdentity = machineUser.RequireUserIdentity
		policy.RequireMachineBeforeUser = machineUser.RequireMachineBeforeUser
		policy.RequireSameCallingStation = machineUser.RequireSameCallingStation
		policy.RequireSameNAS = machineUser.RequireSameNAS
		policy.RequireFreshMachineAuth = machineUser.RequireFreshMachineAuth
		if machineUser.MachineAuthTTLSeconds > 0 {
			policy.MachineAuthTTLSeconds = machineUser.MachineAuthTTLSeconds
		}
		if machineUser.UserAuthTTLSeconds > 0 {
			policy.UserAuthTTLSeconds = machineUser.UserAuthTTLSeconds
		}
		if machineUser.TransitionWindowSeconds > 0 {
			policy.TransitionWindowSeconds = machineUser.TransitionWindowSeconds
		}
		policy.AllowedMachineMethods = normalizeMethodList(defaultStringSlice(machineUser.AllowedMachineMethods, policy.AllowedMachineMethods))
		policy.AllowedUserMethods = normalizeMethodList(defaultStringSlice(machineUser.AllowedUserMethods, policy.AllowedUserMethods))
		policy.IdentityPrecedence = defaultString(strings.ToLower(strings.TrimSpace(machineUser.IdentityPrecedence)), "user_over_machine")
		policy.RoleMergeStrategy = defaultString(strings.ToLower(strings.TrimSpace(machineUser.RoleMergeStrategy)), "user_primary")
		policy.ConflictAction = defaultString(strings.ToLower(strings.TrimSpace(machineUser.ConflictAction)), "reject")
		policy.StaleMachineAction = defaultString(strings.ToLower(strings.TrimSpace(machineUser.StaleMachineAction)), "reject")
		policy.MachineIdentityPrefixes = cleanPrefixList(defaultStringSlice(machineUser.MachineIdentityPrefixes, policy.MachineIdentityPrefixes))
		policy.UserIdentityPrefixes = cleanPrefixList(machineUser.UserIdentityPrefixes)
		if machineUser.MaxActiveCorrelations > 0 {
			policy.MaxActiveCorrelations = machineUser.MaxActiveCorrelations
		}
		policy.AuditEnabled = machineUser.AuditEnabled
		if machineUser.EventRetentionLimit > 0 {
			policy.EventRetentionLimit = machineUser.EventRetentionLimit
		}
	}
	if !framework.Enabled {
		policy.BlockingIssues = append(policy.BlockingIssues, "radius.eap.framework.enabled is false")
	}
	if policy.RequireTEAP && !policy.TEAPGenerated {
		policy.BlockingIssues = append(policy.BlockingIssues, "TEAP must be generated for machine/user correlation")
	}
	if policy.Enabled && policy.Mode == "enforce" && policy.FailClosed {
		if (policy.CorrelationMode == "machine_then_user" || policy.CorrelationMode == "same_session") &&
			(!policy.RequireMachineIdentity || !policy.RequireUserIdentity) {
			policy.BlockingIssues = append(policy.BlockingIssues, "machine and user identities must both be required in fail-closed correlation modes")
		}
		if policy.RequireFreshMachineAuth && policy.MachineAuthTTLSeconds <= 0 {
			policy.BlockingIssues = append(policy.BlockingIssues, "fresh machine authentication requires a machine TTL")
		}
		if policy.RequireMachineBeforeUser && policy.CorrelationMode == "user_only" {
			policy.BlockingIssues = append(policy.BlockingIssues, "machine-before-user is incompatible with user_only mode")
		}
		if !policy.RequireSameCallingStation && policy.CorrelationMode != "user_only" && policy.CorrelationMode != "machine_only" {
			policy.BlockingIssues = append(policy.BlockingIssues, "same Calling-Station-Id binding is required for fail-closed correlation")
		}
	}
	if len(policy.AllowedMachineMethods) == 0 {
		policy.Warnings = append(policy.Warnings, "no machine methods are configured")
	}
	if len(policy.AllowedUserMethods) == 0 {
		policy.Warnings = append(policy.Warnings, "no user methods are configured")
	}
	return policy
}

func EvaluateMachineUserCorrelation(cfg *config.Config, request MachineUserEvaluationRequest) MachineUserDecision {
	framework := BuildPolicyReport(cfg)
	policy := BuildMachineUserPolicyReport(cfg)
	machineMethod := normalizeMethod(request.MachineMethod)
	userMethod := normalizeMethod(request.UserMethod)
	decision := MachineUserDecision{
		PolicyMode:          policy.Mode,
		CorrelationMode:     policy.CorrelationMode,
		CorrelationState:    "evaluating",
		CorrelationID:       strings.TrimSpace(request.CorrelationID),
		IdentitySource:      defaultString(request.IdentitySource, framework.DefaultInnerIdentitySource),
		IdentityCorrelation: machineUserIdentityCorrelation(request),
		IdentityPrecedence:  policy.IdentityPrecedence,
		RoleMergeStrategy:   policy.RoleMergeStrategy,
		DevicePosture:       strings.ToLower(strings.TrimSpace(request.DevicePosture)),
		RequiredIdentities:  machineUserRequiredIdentities(policy),
		SameCallingStation:  machineUserSameCallingStation(request),
		SameNAS:             machineUserSameNAS(request),
		MachineBeforeUser:   machineUserMachineBeforeUser(request),
	}
	decision.EffectiveRole, decision.ConflictDetected = machineUserEffectiveRole(policy, request)
	decision.StaleMachineAuth = machineUserStale(policy, request)

	reject := func(reason string, deps ...string) MachineUserDecision {
		decision.Reason = reason
		decision.Dependencies = append(decision.Dependencies, deps...)
		decision.CorrelationState = "rejected"
		if policy.Mode == "monitor" || !policy.FailClosed {
			decision.Decision = "monitor_allowed"
			decision.Warnings = append(decision.Warnings, reason)
			return decision
		}
		decision.Decision = "rejected"
		return decision
	}
	conflict := func(reason string, deps ...string) MachineUserDecision {
		decision.Reason = reason
		decision.Dependencies = append(decision.Dependencies, deps...)
		decision.CorrelationState = "conflict"
		switch policy.ConflictAction {
		case "monitor":
			decision.Decision = "monitor_allowed"
			decision.Warnings = append(decision.Warnings, reason)
		case "quarantine":
			decision.Decision = "quarantined"
			decision.EffectiveRole = "quarantine"
		default:
			if policy.Mode == "monitor" || !policy.FailClosed {
				decision.Decision = "monitor_allowed"
				decision.Warnings = append(decision.Warnings, reason)
			} else {
				decision.Decision = "rejected"
			}
		}
		return decision
	}

	if !policy.Enabled {
		return reject("machine/user correlation is disabled", "radius.eap.machine_user.enabled")
	}
	if len(policy.BlockingIssues) > 0 {
		return reject("machine/user correlation policy has blocking issues", policy.BlockingIssues...)
	}
	if framework.RequireMessageAuthenticator && request.EAPMessagePresent && !request.MessageAuthenticatorPresent {
		return reject("machine/user EAP evidence requires Message-Authenticator", "radius.packet_hardening.require_message_authenticator")
	}
	if request.ReplayDetected {
		return reject("machine/user correlation replay was detected", "radius.packet_hardening.replay_cache_enabled")
	}
	if policy.RequireTEAP {
		if !request.TEAPChainComplete {
			return reject("TEAP chain must be complete before machine/user correlation", "radius.eap.teap", "FreeRADIUS-EAP-TEAP-Result")
		}
		if !request.IdentityTypePresented {
			return reject("TEAP Identity-Type evidence is required for machine/user correlation", "FreeRADIUS-EAP-TEAP-Identity-Type")
		}
		if !request.CryptoBindingValid {
			return reject("TEAP Crypto-Binding must validate before machine/user correlation", "FreeRADIUS-EAP-TEAP-Crypto-Binding")
		}
	}
	if machineMethod != "" && !stringInSlice(machineMethod, policy.AllowedMachineMethods) {
		return reject("machine authentication method is not allowed", "radius.eap.machine_user.allowed_machine_methods")
	}
	if userMethod != "" && !stringInSlice(userMethod, policy.AllowedUserMethods) {
		return reject("user authentication method is not allowed", "radius.eap.machine_user.allowed_user_methods")
	}
	if reason, ok := machineUserIdentityFailure(policy, request); ok {
		return reject(reason, "radius.eap.machine_user.correlation_mode")
	}
	if reason, ok := machineUserPrefixFailure(policy, request); ok {
		return reject(reason, "radius.eap.machine_user.identity_prefixes")
	}
	if policy.RequireSameCallingStation && !decision.SameCallingStation {
		return reject("machine and user evidence must share Calling-Station-Id", "Calling-Station-Id")
	}
	if policy.RequireSameNAS && !decision.SameNAS {
		return reject("machine and user evidence must share NAS-Identifier", "NAS-Identifier")
	}
	if policy.RequireMachineBeforeUser && !decision.MachineBeforeUser {
		return reject("machine authentication must precede user authentication", "radius.eap.machine_user.require_machine_before_user")
	}
	if decision.StaleMachineAuth {
		switch policy.StaleMachineAction {
		case "allow":
			decision.Warnings = append(decision.Warnings, "machine authentication evidence is stale")
		case "monitor":
			decision.Decision = "monitor_allowed"
			decision.Reason = "machine authentication evidence is stale"
			decision.CorrelationState = "stale"
			decision.Warnings = append(decision.Warnings, decision.Reason)
			return decision
		default:
			return reject("machine authentication evidence is stale", "radius.eap.machine_user.machine_auth_ttl_seconds")
		}
	}
	if policy.CorrelationMode == "machine_then_user" && request.MachineAuthAgeSeconds > 0 && request.UserAuthAgeSeconds > 0 {
		if request.MachineAuthAgeSeconds-request.UserAuthAgeSeconds > policy.TransitionWindowSeconds {
			return reject("machine/user transition window has expired", "radius.eap.machine_user.transition_window_seconds")
		}
	}
	if request.UserAuthAgeSeconds > policy.UserAuthTTLSeconds && policy.UserAuthTTLSeconds > 0 {
		return reject("user authentication evidence is stale", "radius.eap.machine_user.user_auth_ttl_seconds")
	}
	if decision.ConflictDetected {
		return conflict("machine and user authorization roles conflict", "radius.eap.machine_user.role_merge_strategy", "radius.eap.machine_user.conflict_action")
	}
	switch decision.DevicePosture {
	case "quarantine", "high-risk", "compromised":
		decision.Decision = "quarantined"
		decision.EffectiveRole = "quarantine"
		decision.Reason = "device posture requires quarantine"
		decision.CorrelationState = "quarantined"
		return decision
	}
	decision.Decision = "accepted"
	decision.Reason = "machine and user authentication are correlated"
	decision.CorrelationState = "complete"
	return decision
}

func MachineUserCapabilityCatalog() []MachineUserCapability {
	return []MachineUserCapability{
		{Name: "TEAP Identity-Type Binding", Status: "enforced", Vendors: []string{"Microsoft", "Cisco", "Aruba", "HP"}, RFCs: []string{"RFC 7170", "RFC 3748"}, Attributes: []string{"FreeRADIUS-EAP-TEAP-Identity-Type", "FreeRADIUS-EAP-TEAP-EAP-Payload"}, Semantics: "distinguishes machine and user inner authentication legs", Required: true, Sensitive: true},
		{Name: "Machine/User Session Correlation", Status: "implemented", Vendors: []string{"Microsoft NPS", "Cisco ISE", "Aruba ClearPass", "HP Aruba"}, RFCs: []string{"RFC 3748", "RFC 2865"}, Attributes: []string{"User-Name", "Calling-Station-Id", "NAS-Identifier", "State"}, Semantics: "binds device and user authentication evidence into one authorization context", Required: true, Stateful: true, Sensitive: true},
		{Name: "Authorization Merge", Status: "implemented", Vendors: []string{"Cisco ISE", "Aruba ClearPass", "Microsoft NPS"}, RFCs: []string{"RFC 2865"}, Attributes: []string{"Filter-Id", "Tunnel-Private-Group-Id", "Class"}, Semantics: "chooses effective role when machine and user policy both apply", Stateful: true},
		{Name: "Transition Window", Status: "implemented", Vendors: []string{"Microsoft", "Cisco", "Aruba"}, RFCs: []string{"RFC 3748"}, Attributes: []string{"State", "Acct-Session-Id"}, Semantics: "limits the gap between machine boot authentication and user logon authentication", Stateful: true},
		{Name: "Conflict Quarantine", Status: "implemented", Vendors: []string{"Cisco ISE", "Aruba ClearPass"}, RFCs: []string{"RFC 2865", "RFC 5176"}, Attributes: []string{"Filter-Id", "Class", "Disconnect-Message"}, Semantics: "rejects or quarantines mismatched machine and user authorization contexts", Stateful: true},
	}
}

func machineUserStatusAndMessage(report MachineUserReport) (string, string) {
	if !report.Policy.Enabled {
		return "disabled", "Machine/user correlation software is present but disabled by configuration."
	}
	if len(report.BlockingIssues) > 0 {
		if report.Policy.Mode == "enforce" && report.Policy.FailClosed {
			return "blocked", "Machine/user correlation policy has blocking issues."
		}
		return "degraded", "Machine/user correlation policy has issues but is not fail-closed."
	}
	if report.Runtime.Rejected > 0 || report.Runtime.Quarantined > 0 {
		return "degraded", "Machine/user correlation is active with recent rejected or quarantined decisions."
	}
	return "ready", "Machine/user correlation is active with identity binding, transition policy, authorization merge, and bounded telemetry."
}

func machineUserIdentityFailure(policy MachineUserPolicyReport, request MachineUserEvaluationRequest) (string, bool) {
	machineIdentity := strings.TrimSpace(request.MachineIdentity)
	userIdentity := strings.TrimSpace(request.UserIdentity)
	switch policy.CorrelationMode {
	case "user_only":
		if policy.RequireUserIdentity && (userIdentity == "" || !request.UserAuthenticated) {
			return "user authentication evidence is required", true
		}
	case "machine_only":
		if policy.RequireMachineIdentity && (machineIdentity == "" || !request.MachineAuthenticated) {
			return "machine authentication evidence is required", true
		}
	case "either":
		if (machineIdentity == "" || !request.MachineAuthenticated) && (userIdentity == "" || !request.UserAuthenticated) {
			return "machine or user authentication evidence is required", true
		}
	default:
		if policy.RequireMachineIdentity && (machineIdentity == "" || !request.MachineAuthenticated) {
			return "machine authentication evidence is required", true
		}
		if policy.RequireUserIdentity && (userIdentity == "" || !request.UserAuthenticated) {
			return "user authentication evidence is required", true
		}
	}
	return "", false
}

func machineUserPrefixFailure(policy MachineUserPolicyReport, request MachineUserEvaluationRequest) (string, bool) {
	machine := strings.ToLower(strings.TrimSpace(request.MachineIdentity))
	user := strings.ToLower(strings.TrimSpace(request.UserIdentity))
	if machine != "" && len(policy.MachineIdentityPrefixes) > 0 && !hasAnyPrefix(machine, policy.MachineIdentityPrefixes) {
		return "machine identity prefix is not trusted", true
	}
	if user != "" && len(policy.UserIdentityPrefixes) > 0 && !hasAnyPrefix(user, policy.UserIdentityPrefixes) {
		return "user identity prefix is not trusted", true
	}
	return "", false
}

func machineUserSameCallingStation(request MachineUserEvaluationRequest) bool {
	machineCalling := strings.TrimSpace(request.MachineCallingStationID)
	userCalling := strings.TrimSpace(request.UserCallingStationID)
	common := strings.TrimSpace(request.CallingStationID)
	if machineCalling == "" {
		machineCalling = common
	}
	if userCalling == "" {
		userCalling = common
	}
	return machineCalling != "" && userCalling != "" && strings.EqualFold(machineCalling, userCalling)
}

func machineUserSameNAS(request MachineUserEvaluationRequest) bool {
	machineNAS := strings.TrimSpace(request.MachineNASIdentifier)
	userNAS := strings.TrimSpace(request.UserNASIdentifier)
	common := strings.TrimSpace(request.NASIdentifier)
	if machineNAS == "" {
		machineNAS = common
	}
	if userNAS == "" {
		userNAS = common
	}
	return machineNAS != "" && userNAS != "" && strings.EqualFold(machineNAS, userNAS)
}

func machineUserMachineBeforeUser(request MachineUserEvaluationRequest) bool {
	if !request.MachineAuthenticated || !request.UserAuthenticated {
		return false
	}
	if request.MachineAuthAgeSeconds <= 0 || request.UserAuthAgeSeconds <= 0 {
		return request.ExistingMachineSession || request.TEAPChainComplete
	}
	return request.MachineAuthAgeSeconds >= request.UserAuthAgeSeconds
}

func machineUserStale(policy MachineUserPolicyReport, request MachineUserEvaluationRequest) bool {
	if !policy.RequireFreshMachineAuth || policy.MachineAuthTTLSeconds <= 0 || !request.MachineAuthenticated {
		return false
	}
	return request.MachineAuthAgeSeconds > policy.MachineAuthTTLSeconds
}

func machineUserEffectiveRole(policy MachineUserPolicyReport, request MachineUserEvaluationRequest) (string, bool) {
	machineRole := strings.TrimSpace(request.MachineRole)
	userRole := strings.TrimSpace(request.UserRole)
	conflict := machineRole != "" && userRole != "" && !strings.EqualFold(machineRole, userRole)
	switch policy.RoleMergeStrategy {
	case "machine_primary":
		if machineRole != "" {
			return machineRole, false
		}
		return userRole, false
	case "intersection":
		if conflict {
			return "restricted", true
		}
		if userRole != "" {
			return userRole, false
		}
		return machineRole, false
	case "deny_conflict":
		if conflict {
			return "", true
		}
		if userRole != "" {
			return userRole, false
		}
		return machineRole, false
	default:
		if userRole != "" {
			return userRole, false
		}
		return machineRole, false
	}
}

func machineUserIdentityCorrelation(request MachineUserEvaluationRequest) string {
	userPresent := strings.TrimSpace(request.UserIdentity) != "" || request.UserAuthenticated
	machinePresent := strings.TrimSpace(request.MachineIdentity) != "" || request.MachineAuthenticated
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

func machineUserRequiredIdentities(policy MachineUserPolicyReport) []string {
	switch policy.CorrelationMode {
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

func cleanPrefixList(values []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func hasAnyPrefix(value string, prefixes []string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	for _, prefix := range prefixes {
		if strings.HasPrefix(value, strings.ToLower(strings.TrimSpace(prefix))) {
			return true
		}
	}
	return false
}

func MachineUserMethodSummary(policy MachineUserPolicyReport) string {
	methods := append([]string{}, policy.AllowedMachineMethods...)
	methods = append(methods, policy.AllowedUserMethods...)
	methods = normalizeMethodList(methods)
	if len(methods) == 0 {
		return "none"
	}
	return strings.Join(methods, ",")
}

func MachineUserVendors() []string {
	return []string{"Aruba ClearPass", "Cisco ISE", "HP Aruba", "Microsoft NPS"}
}

func MachineUserStandards() []string {
	return []string{"RFC 2865", "RFC 3748", "RFC 5176", "RFC 7170"}
}

func MachineUserFeatureSummary() string {
	return fmt.Sprintf("%s with %s", strings.Join(MachineUserVendors(), ", "), strings.Join(MachineUserStandards(), ", "))
}
