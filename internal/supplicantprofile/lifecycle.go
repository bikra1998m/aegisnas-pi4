package supplicantprofile

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
)

const SchemaVersion = 1

type PolicyReport struct {
	Enabled                      bool     `json:"enabled"`
	Mode                         string   `json:"mode"`
	FailClosed                   bool     `json:"fail_closed"`
	SSID                         string   `json:"ssid"`
	Security                     string   `json:"security"`
	DefaultPlatform              string   `json:"default_platform"`
	AllowedPlatforms             []string `json:"allowed_platforms"`
	DefaultEAPMethod             string   `json:"default_eap_method"`
	AllowedEAPMethods            []string `json:"allowed_eap_methods"`
	DefaultInnerMethod           string   `json:"default_inner_method"`
	AllowedInnerMethods          []string `json:"allowed_inner_methods"`
	AnonymousIdentity            string   `json:"anonymous_identity"`
	RequireAnonymousIdentity     bool     `json:"require_anonymous_identity"`
	DomainSuffix                 string   `json:"domain_suffix,omitempty"`
	ServerNames                  []string `json:"server_names"`
	TrustAnchorPins              []string `json:"trust_anchor_pins"`
	RequireTrustAnchorPinning    bool     `json:"require_trust_anchor_pinning"`
	AllowPasswordChange          bool     `json:"allow_password_change"`
	PasswordChangeURL            string   `json:"password_change_url,omitempty"`
	PasswordChangeProviders      []string `json:"password_change_providers"`
	RequireVerifierCompatibility bool     `json:"require_verifier_compatibility"`
	CompatibleVerifiers          []string `json:"compatible_verifiers"`
	MaxPasswordAgeDays           int      `json:"max_password_age_days"`
	ExpiryWarningDays            int      `json:"expiry_warning_days"`
	GracePeriodDays              int      `json:"grace_period_days"`
	MinPasswordLength            int      `json:"min_password_length"`
	RequireMFAForChange          bool     `json:"require_mfa_for_change"`
	RequireTLSForDelivery        bool     `json:"require_tls_for_delivery"`
	RequireSignedProfiles        bool     `json:"require_signed_profiles"`
	ProfileSigningKeyConfigured  bool     `json:"profile_signing_key_configured"`
	ProfileValidityDays          int      `json:"profile_validity_days"`
	DeliveryTokenTTLSeconds      int      `json:"delivery_token_ttl_seconds"`
	AuditEnabled                 bool     `json:"audit_enabled"`
	EventRetentionLimit          int      `json:"event_retention_limit"`
	ProfileRetentionLimit        int      `json:"profile_retention_limit"`
	PortalReady                  bool     `json:"portal_ready"`
	EAPFrameworkReady            bool     `json:"eap_framework_ready"`
	CertificateLifecycleReady    bool     `json:"certificate_lifecycle_ready"`
	Warnings                     []string `json:"warnings,omitempty"`
	BlockingIssues               []string `json:"blocking_issues,omitempty"`
}

type RuntimeSummary struct {
	TotalEvents            int            `json:"total_events"`
	Accepted               int            `json:"accepted"`
	Rejected               int            `json:"rejected"`
	MonitorAllowed         int            `json:"monitor_allowed"`
	PasswordChangeRequired int            `json:"password_change_required"`
	PasswordChanged        int            `json:"password_changed"`
	ProfilesDelivered      int            `json:"profiles_delivered"`
	UnsignedProfileBlocked int            `json:"unsigned_profile_blocked"`
	TrustPinFailures       int            `json:"trust_pin_failures"`
	VerifierFailures       int            `json:"verifier_failures"`
	TLSFailures            int            `json:"tls_failures"`
	ActiveProfiles         int            `json:"active_profiles"`
	ExpiredProfiles        int            `json:"expired_profiles"`
	ByDecision             map[string]int `json:"by_decision,omitempty"`
	ByPlatform             map[string]int `json:"by_platform,omitempty"`
	ByEAPMethod            map[string]int `json:"by_eap_method,omitempty"`
	LastEventAt            string         `json:"last_event_at,omitempty"`
	LastRejectedReason     string         `json:"last_rejected_reason,omitempty"`
	LastProfileDeliveredAt string         `json:"last_profile_delivered_at,omitempty"`
}

type Capability struct {
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

type Report struct {
	SchemaVersion    int            `json:"schema_version"`
	GeneratedAt      string         `json:"generated_at"`
	Status           string         `json:"status"`
	Message          string         `json:"message"`
	Policy           PolicyReport   `json:"policy"`
	Runtime          RuntimeSummary `json:"runtime"`
	Capabilities     []Capability   `json:"capabilities"`
	Warnings         []string       `json:"warnings,omitempty"`
	BlockingIssues   []string       `json:"blocking_issues,omitempty"`
	ReleaseChecklist string         `json:"release_checklist"`
	ExternalEvidence []string       `json:"external_evidence"`
}

type EvaluationRequest struct {
	Protocol                   string            `json:"protocol"`
	Platform                   string            `json:"platform"`
	Username                   string            `json:"username"`
	DeviceID                   string            `json:"device_id"`
	Tenant                     string            `json:"tenant"`
	EAPMethod                  string            `json:"eap_method"`
	InnerMethod                string            `json:"inner_method"`
	IdentitySource             string            `json:"identity_source"`
	PasswordExpired            bool              `json:"password_expired"`
	DaysUntilExpiry            int               `json:"days_until_expiry"`
	PasswordChangeRequested    bool              `json:"password_change_requested"`
	OldPasswordVerified        bool              `json:"old_password_verified"`
	NewPasswordMeetsPolicy     bool              `json:"new_password_meets_policy"`
	MFAComplete                bool              `json:"mfa_complete"`
	TLSProtected               bool              `json:"tls_protected"`
	PasswordVerifierCompatible bool              `json:"password_verifier_compatible"`
	ProfileRequested           bool              `json:"profile_requested"`
	ProfileSigned              bool              `json:"profile_signed"`
	SigningKeyAvailable        bool              `json:"signing_key_available"`
	TrustAnchorPinned          bool              `json:"trust_anchor_pinned"`
	ServerNameMatched          bool              `json:"server_name_matched"`
	DeliveryTokenValid         bool              `json:"delivery_token_valid"`
	DeviceManaged              bool              `json:"device_managed"`
	CertificateLifecycleReady  bool              `json:"certificate_lifecycle_ready"`
	Details                    map[string]string `json:"details,omitempty"`
}

type Decision struct {
	Decision                   string            `json:"decision"`
	Action                     string            `json:"action"`
	Reason                     string            `json:"reason"`
	PolicyMode                 string            `json:"policy_mode"`
	Protocol                   string            `json:"protocol"`
	Platform                   string            `json:"platform"`
	UsernameHash               string            `json:"username_hash,omitempty"`
	DeviceIDHash               string            `json:"device_id_hash,omitempty"`
	Tenant                     string            `json:"tenant,omitempty"`
	EAPMethod                  string            `json:"eap_method"`
	InnerMethod                string            `json:"inner_method,omitempty"`
	IdentitySource             string            `json:"identity_source,omitempty"`
	PasswordExpired            bool              `json:"password_expired"`
	DaysUntilExpiry            int               `json:"days_until_expiry"`
	PasswordChangeRequested    bool              `json:"password_change_requested"`
	PasswordChangeRequired     bool              `json:"password_change_required"`
	PasswordChanged            bool              `json:"password_changed"`
	OldPasswordVerified        bool              `json:"old_password_verified"`
	NewPasswordMeetsPolicy     bool              `json:"new_password_meets_policy"`
	MFAComplete                bool              `json:"mfa_complete"`
	TLSProtected               bool              `json:"tls_protected"`
	PasswordVerifierCompatible bool              `json:"password_verifier_compatible"`
	ProfileRequested           bool              `json:"profile_requested"`
	ProfileSigned              bool              `json:"profile_signed"`
	SigningKeyAvailable        bool              `json:"signing_key_available"`
	TrustAnchorPinned          bool              `json:"trust_anchor_pinned"`
	ServerNameMatched          bool              `json:"server_name_matched"`
	DeliveryTokenValid         bool              `json:"delivery_token_valid"`
	DeviceManaged              bool              `json:"device_managed"`
	CertificateLifecycleReady  bool              `json:"certificate_lifecycle_ready"`
	Warnings                   []string          `json:"warnings,omitempty"`
	Dependencies               []string          `json:"dependencies,omitempty"`
	Details                    map[string]string `json:"details,omitempty"`
}

type ProfileRequest struct {
	Platform            string            `json:"platform"`
	Username            string            `json:"username"`
	DeviceID            string            `json:"device_id"`
	Tenant              string            `json:"tenant"`
	EAPMethod           string            `json:"eap_method"`
	InnerMethod         string            `json:"inner_method"`
	IncludePasswordURL  bool              `json:"include_password_url"`
	CertificateTemplate string            `json:"certificate_template"`
	Delivery            string            `json:"delivery"`
	Details             map[string]string `json:"details,omitempty"`
}

type ProfileManifest struct {
	SchemaVersion       int               `json:"schema_version"`
	GeneratedAt         string            `json:"generated_at"`
	ExpiresAt           string            `json:"expires_at"`
	Platform            string            `json:"platform"`
	SSID                string            `json:"ssid"`
	Security            string            `json:"security"`
	EAPMethod           string            `json:"eap_method"`
	InnerMethod         string            `json:"inner_method,omitempty"`
	AnonymousIdentity   string            `json:"anonymous_identity,omitempty"`
	DomainSuffix        string            `json:"domain_suffix,omitempty"`
	ServerNames         []string          `json:"server_names"`
	TrustAnchorPins     []string          `json:"trust_anchor_pins"`
	CertificateTemplate string            `json:"certificate_template,omitempty"`
	PasswordChangeURL   string            `json:"password_change_url,omitempty"`
	UsernameHash        string            `json:"username_hash,omitempty"`
	DeviceIDHash        string            `json:"device_id_hash,omitempty"`
	Tenant              string            `json:"tenant,omitempty"`
	Delivery            string            `json:"delivery,omitempty"`
	Details             map[string]string `json:"details,omitempty"`
}

type ProfilePackage struct {
	ProfileID             string          `json:"profile_id"`
	Manifest              ProfileManifest `json:"manifest"`
	ContentType           string          `json:"content_type"`
	FileExtension         string          `json:"file_extension"`
	Content               string          `json:"content"`
	ContentSHA256         string          `json:"content_sha256"`
	SignatureAlgorithm    string          `json:"signature_algorithm,omitempty"`
	Signature             string          `json:"signature,omitempty"`
	SigningKeyFingerprint string          `json:"signing_key_fingerprint,omitempty"`
}

func BuildReport(cfg *config.Config, runtime RuntimeSummary) Report {
	policy := BuildPolicyReport(cfg)
	report := Report{
		SchemaVersion:    SchemaVersion,
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		Policy:           policy,
		Runtime:          runtime,
		Capabilities:     CapabilityCatalog(),
		Warnings:         append([]string(nil), policy.Warnings...),
		BlockingIssues:   append([]string(nil), policy.BlockingIssues...),
		ReleaseChecklist: "nas-0028-release-certification-checklist.md",
		ExternalEvidence: []string{
			"Windows, macOS, iOS, Android, Linux, and embedded supplicant profile install smoke tests",
			"password-expiry and password-change drills against Microsoft AD, LDAP, local, and identity-failover verifiers",
			"profile signing-key custody, trust-anchor pin rollover, and revocation recovery evidence",
			"FreeRADIUS, AP/controller, HA, performance, soak, and security validation evidence",
		},
	}
	report.Status, report.Message = statusAndMessage(report)
	return report
}

func BuildPolicyReport(cfg *config.Config) PolicyReport {
	lifecycle := config.SupplicantLifecycleConfig{}
	if cfg != nil {
		lifecycle = cfg.Onboarding.SupplicantLifecycle
	}
	policy := PolicyReport{
		Enabled:                      lifecycle.Enabled,
		Mode:                         defaultString(strings.ToLower(strings.TrimSpace(lifecycle.Mode)), "monitor"),
		FailClosed:                   lifecycle.FailClosed,
		SSID:                         defaultString(strings.TrimSpace(lifecycle.SSID), "AegisNAS-Enterprise"),
		Security:                     defaultString(strings.ToLower(strings.TrimSpace(lifecycle.Security)), "wpa2-enterprise"),
		DefaultPlatform:              defaultString(strings.ToLower(strings.TrimSpace(lifecycle.DefaultPlatform)), "windows"),
		AllowedPlatforms:             normalizedList(lifecycle.AllowedPlatforms, []string{"windows", "macos", "ios", "android", "linux"}, true),
		DefaultEAPMethod:             normalizeEAP(defaultString(lifecycle.DefaultEAPMethod, "tls")),
		AllowedEAPMethods:            normalizedEAPList(lifecycle.AllowedEAPMethods, []string{"tls", "peap", "ttls"}),
		DefaultInnerMethod:           defaultString(strings.ToLower(strings.TrimSpace(lifecycle.DefaultInnerMethod)), "mschapv2"),
		AllowedInnerMethods:          normalizedList(lifecycle.AllowedInnerMethods, []string{"mschapv2", "pap", "gtc", "tls"}, true),
		AnonymousIdentity:            strings.TrimSpace(lifecycle.AnonymousIdentity),
		RequireAnonymousIdentity:     lifecycle.RequireAnonymousIdentity,
		DomainSuffix:                 strings.TrimSpace(lifecycle.DomainSuffix),
		ServerNames:                  normalizedList(lifecycle.ServerNames, nil, true),
		TrustAnchorPins:              normalizedPins(lifecycle.TrustAnchorPins),
		RequireTrustAnchorPinning:    lifecycle.RequireTrustAnchorPinning,
		AllowPasswordChange:          lifecycle.AllowPasswordChange,
		PasswordChangeURL:            strings.TrimSpace(lifecycle.PasswordChangeURL),
		PasswordChangeProviders:      normalizedList(lifecycle.PasswordChangeProviders, []string{"local", "active-directory", "identity-failover"}, true),
		RequireVerifierCompatibility: lifecycle.RequireVerifierCompatibility,
		CompatibleVerifiers:          normalizedList(lifecycle.CompatibleVerifiers, []string{"local", "ldap", "active-directory", "identity-failover", "winbind"}, true),
		MaxPasswordAgeDays:           defaultInt(lifecycle.MaxPasswordAgeDays, 90),
		ExpiryWarningDays:            defaultInt(lifecycle.ExpiryWarningDays, 14),
		GracePeriodDays:              defaultInt(lifecycle.GracePeriodDays, 7),
		MinPasswordLength:            defaultInt(lifecycle.MinPasswordLength, 12),
		RequireMFAForChange:          lifecycle.RequireMFAForChange,
		RequireTLSForDelivery:        lifecycle.RequireTLSForDelivery,
		RequireSignedProfiles:        lifecycle.RequireSignedProfiles,
		ProfileSigningKeyConfigured:  strings.TrimSpace(lifecycle.ProfileSigningKeyRef) != "",
		ProfileValidityDays:          defaultInt(lifecycle.ProfileValidityDays, 365),
		DeliveryTokenTTLSeconds:      defaultInt(lifecycle.DeliveryTokenTTLSeconds, 900),
		AuditEnabled:                 lifecycle.AuditEnabled,
		EventRetentionLimit:          defaultInt(lifecycle.EventRetentionLimit, 6000),
		ProfileRetentionLimit:        defaultInt(lifecycle.ProfileRetentionLimit, 100000),
	}
	if policy.AnonymousIdentity == "" && policy.RequireAnonymousIdentity {
		policy.AnonymousIdentity = "anonymous@aegisnas.local"
	}
	if !contains(policy.AllowedPlatforms, policy.DefaultPlatform) {
		policy.Warnings = append(policy.Warnings, "default platform is not in allowed platform list")
	}
	if !contains(policy.AllowedEAPMethods, policy.DefaultEAPMethod) {
		policy.Warnings = append(policy.Warnings, "default EAP method is not in allowed method list")
	}
	if cfg != nil {
		policy.PortalReady = cfg.Onboarding.PortalEnabled
		policy.EAPFrameworkReady = cfg.Radius.EAP.Framework.Enabled
		policy.CertificateLifecycleReady = cfg.Onboarding.CertificateLifecycle.Enabled
		if policy.Enabled {
			if config.EffectiveDeploymentProfile(cfg.Deployment.Profile) != "enterprise" {
				policy.BlockingIssues = append(policy.BlockingIssues, "enterprise deployment profile is required")
			}
			if !policy.PortalReady {
				policy.BlockingIssues = append(policy.BlockingIssues, "onboarding portal is required")
			}
			if !policy.EAPFrameworkReady {
				policy.BlockingIssues = append(policy.BlockingIssues, "EAP framework is required")
			}
			if contains(policy.AllowedEAPMethods, "tls") && !policy.CertificateLifecycleReady {
				policy.BlockingIssues = append(policy.BlockingIssues, "certificate lifecycle is required for EAP-TLS profiles")
			}
			if policy.RequireTrustAnchorPinning && (len(policy.TrustAnchorPins) == 0 || len(policy.ServerNames) == 0) {
				policy.BlockingIssues = append(policy.BlockingIssues, "trust-anchor pinning requires pins and server names")
			}
			if policy.Mode == "enforce" && policy.FailClosed {
				if policy.RequireSignedProfiles && !policy.ProfileSigningKeyConfigured {
					policy.BlockingIssues = append(policy.BlockingIssues, "signed profiles require profile_signing_key_ref")
				}
				if policy.RequireTLSForDelivery == false {
					policy.BlockingIssues = append(policy.BlockingIssues, "TLS delivery is required in fail-closed enforce mode")
				}
				if policy.RequireVerifierCompatibility && len(policy.CompatibleVerifiers) == 0 {
					policy.BlockingIssues = append(policy.BlockingIssues, "verifier compatibility list is required")
				}
			}
		}
	}
	return policy
}

func Evaluate(cfg *config.Config, request EvaluationRequest) Decision {
	policy := BuildPolicyReport(cfg)
	platform := defaultString(strings.ToLower(strings.TrimSpace(request.Platform)), policy.DefaultPlatform)
	method := normalizeEAP(defaultString(request.EAPMethod, policy.DefaultEAPMethod))
	inner := defaultString(strings.ToLower(strings.TrimSpace(request.InnerMethod)), policy.DefaultInnerMethod)
	identitySource := strings.ToLower(strings.TrimSpace(request.IdentitySource))
	decision := Decision{
		PolicyMode:                 policy.Mode,
		Protocol:                   defaultString(strings.ToLower(strings.TrimSpace(request.Protocol)), "api"),
		Platform:                   platform,
		UsernameHash:               hashString(request.Username),
		DeviceIDHash:               hashString(request.DeviceID),
		Tenant:                     strings.TrimSpace(request.Tenant),
		EAPMethod:                  method,
		InnerMethod:                inner,
		IdentitySource:             identitySource,
		PasswordExpired:            request.PasswordExpired,
		DaysUntilExpiry:            request.DaysUntilExpiry,
		PasswordChangeRequested:    request.PasswordChangeRequested,
		OldPasswordVerified:        request.OldPasswordVerified,
		NewPasswordMeetsPolicy:     request.NewPasswordMeetsPolicy,
		MFAComplete:                request.MFAComplete,
		TLSProtected:               request.TLSProtected,
		PasswordVerifierCompatible: request.PasswordVerifierCompatible,
		ProfileRequested:           request.ProfileRequested,
		ProfileSigned:              request.ProfileSigned,
		SigningKeyAvailable:        request.SigningKeyAvailable,
		TrustAnchorPinned:          request.TrustAnchorPinned,
		ServerNameMatched:          request.ServerNameMatched,
		DeliveryTokenValid:         request.DeliveryTokenValid,
		DeviceManaged:              request.DeviceManaged,
		CertificateLifecycleReady:  request.CertificateLifecycleReady || policy.CertificateLifecycleReady,
		Details:                    copyDetails(request.Details),
	}
	reject := func(reason string, deps ...string) Decision {
		decision.Reason = reason
		decision.Dependencies = append(decision.Dependencies, deps...)
		if policy.Mode == "monitor" || !policy.FailClosed {
			decision.Decision = "monitor_allowed"
			decision.Action = "allow_with_warning"
			decision.Warnings = append(decision.Warnings, reason)
			return decision
		}
		decision.Decision = "rejected"
		decision.Action = "deny"
		return decision
	}
	requireChange := func(reason string, deps ...string) Decision {
		decision.Decision = "password_change_required"
		decision.Action = "password_change_required"
		decision.Reason = reason
		decision.PasswordChangeRequired = true
		decision.Dependencies = append(decision.Dependencies, deps...)
		return decision
	}
	if !policy.Enabled {
		return reject("supplicant lifecycle is disabled", "onboarding.supplicant_lifecycle.enabled")
	}
	if len(policy.BlockingIssues) > 0 {
		return reject("supplicant lifecycle policy has blocking issues", policy.BlockingIssues...)
	}
	if !contains(policy.AllowedPlatforms, platform) {
		return reject("supplicant platform is not allowed", "onboarding.supplicant_lifecycle.allowed_platforms")
	}
	if !contains(policy.AllowedEAPMethods, method) {
		return reject("supplicant EAP method is not allowed", "onboarding.supplicant_lifecycle.allowed_eap_methods")
	}
	if method != "tls" && inner != "" && !contains(policy.AllowedInnerMethods, inner) {
		return reject("supplicant inner method is not allowed", "onboarding.supplicant_lifecycle.allowed_inner_methods")
	}
	if method == "tls" && !decision.CertificateLifecycleReady {
		return reject("EAP-TLS profile delivery requires certificate lifecycle readiness", "onboarding.certificate_lifecycle.enabled")
	}
	if passwordMethod(method, inner) && policy.RequireVerifierCompatibility {
		if identitySource != "" && !contains(policy.CompatibleVerifiers, identitySource) {
			return reject("identity source is not compatible with password-based supplicant method", "onboarding.supplicant_lifecycle.compatible_verifiers")
		}
		if !request.PasswordVerifierCompatible {
			return reject("password verifier compatibility evidence is missing", "onboarding.supplicant_lifecycle.require_verifier_compatibility")
		}
	}
	if request.PasswordExpired || (request.DaysUntilExpiry >= 0 && request.DaysUntilExpiry <= policy.ExpiryWarningDays) {
		if !policy.AllowPasswordChange {
			return reject("password lifecycle requires change but password change is disabled", "onboarding.supplicant_lifecycle.allow_password_change")
		}
		if request.PasswordExpired && !request.PasswordChangeRequested {
			return requireChange("password is expired and must be changed before profile delivery", "onboarding.supplicant_lifecycle.password_change_url")
		}
	}
	if request.PasswordChangeRequested {
		if !policy.AllowPasswordChange {
			return reject("password change workflow is disabled", "onboarding.supplicant_lifecycle.allow_password_change")
		}
		if policy.RequireTLSForDelivery && !request.TLSProtected {
			return reject("password change requires TLS-protected delivery", "onboarding.supplicant_lifecycle.require_tls_for_delivery")
		}
		if !request.OldPasswordVerified {
			return reject("old password was not verified before change", "password.old_password_verified")
		}
		if !request.NewPasswordMeetsPolicy {
			return reject("new password does not satisfy policy", "onboarding.supplicant_lifecycle.min_password_length")
		}
		if policy.RequireMFAForChange && !request.MFAComplete {
			return reject("password change requires completed MFA step-up", "onboarding.supplicant_lifecycle.require_mfa_for_change")
		}
		decision.PasswordChanged = true
	}
	if request.ProfileRequested {
		if policy.RequireTLSForDelivery && !request.TLSProtected {
			return reject("supplicant profile delivery requires TLS", "onboarding.supplicant_lifecycle.require_tls_for_delivery")
		}
		if policy.DeliveryTokenTTLSeconds > 0 && !request.DeliveryTokenValid {
			return reject("supplicant profile delivery token is missing or expired", "onboarding.supplicant_lifecycle.delivery_token_ttl_seconds")
		}
		if policy.RequireTrustAnchorPinning && !request.TrustAnchorPinned {
			return reject("supplicant profile lacks required trust-anchor pinning", "onboarding.supplicant_lifecycle.trust_anchor_pins")
		}
		if policy.RequireTrustAnchorPinning && !request.ServerNameMatched {
			return reject("supplicant profile lacks required server-name matching", "onboarding.supplicant_lifecycle.server_names")
		}
		if policy.RequireSignedProfiles {
			if !request.SigningKeyAvailable {
				return reject("supplicant profile signing key is unavailable", "onboarding.supplicant_lifecycle.profile_signing_key_ref")
			}
			if !request.ProfileSigned {
				return reject("supplicant profile is not signed", "onboarding.supplicant_lifecycle.require_signed_profiles")
			}
		}
	}
	decision.Decision = "accepted"
	switch {
	case request.ProfileRequested:
		decision.Action = "profile_delivery_allowed"
		decision.Reason = "supplicant profile request satisfies platform, EAP, trust-anchor, signing, password, and delivery policy"
	case request.PasswordChangeRequested:
		decision.Action = "password_changed"
		decision.Reason = "password change request satisfies verifier, TLS, MFA, and password policy"
	default:
		decision.Action = "lifecycle_ok"
		decision.Reason = "supplicant lifecycle request satisfies password and profile policy"
	}
	return decision
}

func BuildProfilePackage(cfg *config.Config, req ProfileRequest, signingSecret string) (ProfilePackage, error) {
	policy := BuildPolicyReport(cfg)
	if !policy.Enabled {
		return ProfilePackage{}, errors.New("supplicant lifecycle is disabled")
	}
	if len(policy.BlockingIssues) > 0 && policy.Mode == "enforce" && policy.FailClosed {
		return ProfilePackage{}, errors.New("supplicant lifecycle policy has blocking issues")
	}
	platform := defaultString(strings.ToLower(strings.TrimSpace(req.Platform)), policy.DefaultPlatform)
	method := normalizeEAP(defaultString(req.EAPMethod, policy.DefaultEAPMethod))
	inner := defaultString(strings.ToLower(strings.TrimSpace(req.InnerMethod)), policy.DefaultInnerMethod)
	if !contains(policy.AllowedPlatforms, platform) {
		return ProfilePackage{}, fmt.Errorf("platform %q is not allowed", platform)
	}
	if !contains(policy.AllowedEAPMethods, method) {
		return ProfilePackage{}, fmt.Errorf("EAP method %q is not allowed", method)
	}
	if method != "tls" && inner != "" && !contains(policy.AllowedInnerMethods, inner) {
		return ProfilePackage{}, fmt.Errorf("inner method %q is not allowed", inner)
	}
	expiresAt := time.Now().UTC().AddDate(0, 0, policy.ProfileValidityDays).Format(time.RFC3339)
	manifest := ProfileManifest{
		SchemaVersion:       SchemaVersion,
		GeneratedAt:         time.Now().UTC().Format(time.RFC3339),
		ExpiresAt:           expiresAt,
		Platform:            platform,
		SSID:                policy.SSID,
		Security:            policy.Security,
		EAPMethod:           method,
		InnerMethod:         inner,
		AnonymousIdentity:   policy.AnonymousIdentity,
		DomainSuffix:        policy.DomainSuffix,
		ServerNames:         append([]string(nil), policy.ServerNames...),
		TrustAnchorPins:     append([]string(nil), policy.TrustAnchorPins...),
		CertificateTemplate: defaultString(strings.TrimSpace(req.CertificateTemplate), defaultCertificateTemplate(cfg)),
		UsernameHash:        hashString(req.Username),
		DeviceIDHash:        hashString(req.DeviceID),
		Tenant:              strings.TrimSpace(req.Tenant),
		Delivery:            strings.TrimSpace(req.Delivery),
		Details:             copyDetails(req.Details),
	}
	if req.IncludePasswordURL {
		manifest.PasswordChangeURL = policy.PasswordChangeURL
	}
	content, contentType, extension := renderProfileContent(manifest)
	contentHash := sha256Hex([]byte(content))
	pkg := ProfilePackage{
		ProfileID:     profileID(manifest, contentHash),
		Manifest:      manifest,
		ContentType:   contentType,
		FileExtension: extension,
		Content:       content,
		ContentSHA256: contentHash,
	}
	if policy.RequireSignedProfiles || strings.TrimSpace(signingSecret) != "" {
		if strings.TrimSpace(signingSecret) == "" {
			return ProfilePackage{}, errors.New("profile signing key is required")
		}
		manifestJSON, err := json.Marshal(manifest)
		if err != nil {
			return ProfilePackage{}, err
		}
		signature, fingerprint := signProfile(manifestJSON, []byte(content), signingSecret)
		pkg.SignatureAlgorithm = "HMAC-SHA256"
		pkg.Signature = signature
		pkg.SigningKeyFingerprint = fingerprint
	}
	return pkg, nil
}

func CapabilityCatalog() []Capability {
	return []Capability{
		{Name: "Password Lifecycle", Status: "implemented", Vendors: []string{"Microsoft NPS", "Cisco ISE", "Aruba ClearPass", "Fortinet", "Juniper Mist"}, RFCs: []string{"RFC 2865", "RFC 3748"}, Attributes: []string{"Reply-Message", "State", "MS-CHAP-Error", "EAP-Message"}, Semantics: "detects expiry, forces password-change workflow, validates verifier compatibility, and avoids silent fallback", Required: true, Stateful: true, Sensitive: true},
		{Name: "Supplicant Profile Delivery", Status: "implemented", Vendors: []string{"Microsoft", "Apple", "Android", "Linux NetworkManager"}, RFCs: []string{"RFC 5216", "RFC 9190"}, Attributes: []string{"EAP-Message", "TLS-Client-Cert-*", "Message-Authenticator"}, Semantics: "generates platform-specific 802.1X profile packages with EAP method, anonymous identity, server names, and trust-anchor pins", Required: true, Stateful: true, Sensitive: true},
		{Name: "Trust Anchor Pinning", Status: "implemented", Vendors: []string{"Cisco", "Aruba", "Microsoft", "Apple", "Android"}, RFCs: []string{"RFC 5280", "RFC 5216"}, Attributes: []string{"TLS-Client-Cert-Issuer", "TLS-Client-Cert-Serial"}, Semantics: "requires supplicants to validate the expected RADIUS server identity and pinned CA fingerprints", Required: true, Stateful: false, Sensitive: false},
		{Name: "Signed Profile Package", Status: "implemented", Vendors: []string{"Microsoft Intune", "Jamf", "Workspace ONE", "Apple MDM"}, RFCs: []string{"RFC 2104", "RFC 9190"}, Attributes: []string{"Class", "Reply-Message"}, Semantics: "signs generated profile content with a configured secret reference so clients and MDM workflows can verify package integrity", Required: true, Stateful: false, Sensitive: true},
	}
}

func statusAndMessage(report Report) (string, string) {
	if !report.Policy.Enabled {
		return "disabled", "Supplicant and password lifecycle software is present but disabled by configuration."
	}
	if len(report.BlockingIssues) > 0 {
		if report.Policy.Mode == "enforce" && report.Policy.FailClosed {
			return "blocked", "Supplicant lifecycle policy has blocking issues."
		}
		return "degraded", "Supplicant lifecycle policy has issues but is not fail-closed."
	}
	if report.Runtime.Rejected > 0 || report.Runtime.UnsignedProfileBlocked > 0 || report.Runtime.TrustPinFailures > 0 || report.Runtime.VerifierFailures > 0 || report.Runtime.TLSFailures > 0 {
		return "degraded", "Supplicant lifecycle is active with recent rejected, signing, trust-anchor, verifier, or TLS failures."
	}
	return "ready", "Supplicant lifecycle is active with password-change, verifier compatibility, trust-anchor pinning, and signed profile delivery governance."
}

func renderProfileContent(manifest ProfileManifest) (string, string, string) {
	switch manifest.Platform {
	case "macos", "ios":
		return renderAppleProfile(manifest), "application/x-apple-aspen-config", ".mobileconfig"
	case "android":
		return renderAndroidProfile(manifest), "application/json", ".json"
	case "linux":
		return renderLinuxProfile(manifest), "application/x-networkmanager-connection", ".nmconnection"
	default:
		return renderWindowsProfile(manifest), "application/vnd.ms-wlan-profile+xml", ".xml"
	}
}

func renderWindowsProfile(m ProfileManifest) string {
	auth := "WPA2"
	if m.Security == "wpa3-enterprise" {
		auth = "WPA3ENT192"
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>%s</name>
  <SSIDConfig><SSID><name>%s</name></SSID></SSIDConfig>
  <connectionType>ESS</connectionType>
  <connectionMode>auto</connectionMode>
  <MSM>
    <security>
      <authEncryption><authentication>%s</authentication><encryption>AES</encryption><useOneX>true</useOneX></authEncryption>
      <OneX xmlns="http://www.microsoft.com/networking/OneX/v1">
        <authMode>userOrComputer</authMode>
        <EAPConfig>
          <AegisNASProfile schema="%d" eap="%s" inner="%s" anonymous="%s" servers="%s" trustPins="%s" />
        </EAPConfig>
      </OneX>
    </security>
  </MSM>
</WLANProfile>
`, xmlEscape(m.SSID), xmlEscape(m.SSID), auth, m.SchemaVersion, xmlEscape(m.EAPMethod), xmlEscape(m.InnerMethod), xmlEscape(m.AnonymousIdentity), xmlEscape(strings.Join(m.ServerNames, ",")), xmlEscape(strings.Join(m.TrustAnchorPins, ",")))
}

func renderAppleProfile(m ProfileManifest) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadIdentifier</key><string>com.aegisnas.supplicant.%s</string>
  <key>PayloadDisplayName</key><string>%s</string>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key><string>com.apple.wifi.managed</string>
      <key>SSID_STR</key><string>%s</string>
      <key>EncryptionType</key><string>WPA</string>
      <key>EAPClientConfiguration</key>
      <dict>
        <key>AcceptEAPTypes</key><array><string>%s</string></array>
        <key>OuterIdentity</key><string>%s</string>
        <key>TLSAllowTrustExceptions</key><false/>
        <key>TLSTrustedServerNames</key><array>%s</array>
        <key>AegisNASTrustAnchorPins</key><array>%s</array>
      </dict>
    </dict>
  </array>
</dict>
</plist>
`, xmlEscape(m.Platform), xmlEscape(m.SSID), xmlEscape(m.SSID), xmlEscape(appleEAPType(m.EAPMethod)), xmlEscape(m.AnonymousIdentity), xmlStringArray(m.ServerNames), xmlStringArray(m.TrustAnchorPins))
}

func renderAndroidProfile(m ProfileManifest) string {
	payload := map[string]any{
		"schema_version":      m.SchemaVersion,
		"type":                "aegisnas-android-wifi-profile",
		"ssid":                m.SSID,
		"security":            m.Security,
		"eap_method":          m.EAPMethod,
		"inner_method":        m.InnerMethod,
		"anonymous_identity":  m.AnonymousIdentity,
		"domain_suffix_match": m.DomainSuffix,
		"server_names":        m.ServerNames,
		"trust_anchor_pins":   m.TrustAnchorPins,
		"expires_at":          m.ExpiresAt,
	}
	data, _ := json.MarshalIndent(payload, "", "  ")
	return string(data)
}

func renderLinuxProfile(m ProfileManifest) string {
	return fmt.Sprintf(`[connection]
id=%s
type=wifi
autoconnect=true

[wifi]
ssid=%s
mode=infrastructure

[wifi-security]
key-mgmt=wpa-eap

[802-1x]
eap=%s
identity=
anonymous-identity=%s
phase2-auth=%s
domain-suffix-match=%s
altsubject-matches=%s
ca-cert-pin=%s

[ipv4]
method=auto

[ipv6]
method=auto
`, iniEscape(m.SSID), iniEscape(m.SSID), iniEscape(m.EAPMethod), iniEscape(m.AnonymousIdentity), iniEscape(m.InnerMethod), iniEscape(m.DomainSuffix), iniEscape(strings.Join(m.ServerNames, ";")), iniEscape(strings.Join(m.TrustAnchorPins, ";")))
}

func signProfile(manifestJSON, content []byte, secret string) (string, string) {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(manifestJSON)
	mac.Write([]byte{'\n'})
	mac.Write(content)
	secretHash := sha256.Sum256([]byte(secret))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), hex.EncodeToString(secretHash[:])
}

func profileID(manifest ProfileManifest, contentHash string) string {
	raw := manifest.Platform + "\x00" + manifest.SSID + "\x00" + manifest.UsernameHash + "\x00" + manifest.DeviceIDHash + "\x00" + contentHash
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:16])
}

func defaultCertificateTemplate(cfg *config.Config) string {
	if cfg == nil {
		return "device-eap-tls"
	}
	return defaultString(strings.TrimSpace(cfg.Onboarding.CertificateLifecycle.DefaultTemplate), "device-eap-tls")
}

func passwordMethod(eapMethod, innerMethod string) bool {
	switch normalizeEAP(eapMethod) {
	case "peap", "ttls", "pwd":
		return true
	case "fast", "teap":
		return strings.TrimSpace(innerMethod) != "" && strings.ToLower(strings.TrimSpace(innerMethod)) != "tls"
	default:
		return false
	}
}

func normalizedEAPList(values, fallback []string) []string {
	out := normalizedList(values, fallback, true)
	for i, value := range out {
		out[i] = normalizeEAP(value)
	}
	sort.Strings(out)
	return unique(out)
}

func normalizedPins(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		value = strings.TrimPrefix(value, "sha256:")
		if value != "" {
			out = append(out, "sha256:"+value)
		}
	}
	sort.Strings(out)
	return unique(out)
}

func normalizedList(values, fallback []string, lower bool) []string {
	if len(values) == 0 {
		values = fallback
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if lower {
			value = strings.ToLower(value)
		}
		if value != "" {
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return unique(out)
}

func unique(values []string) []string {
	if len(values) < 2 {
		return values
	}
	out := values[:0]
	var last string
	for i, value := range values {
		if i == 0 || value != last {
			out = append(out, value)
			last = value
		}
	}
	return out
}

func normalizeEAP(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimPrefix(value, "eap-")
	value = strings.ReplaceAll(value, "_", "-")
	switch value {
	case "aka-prime":
		return "aka_prime"
	default:
		return strings.ReplaceAll(value, "-", "_")
	}
}

func contains(values []string, target string) bool {
	target = strings.ToLower(strings.TrimSpace(target))
	for _, value := range values {
		if strings.ToLower(strings.TrimSpace(value)) == target {
			return true
		}
	}
	return false
}

func copyDetails(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		key = strings.TrimSpace(key)
		if key != "" {
			out[key] = strings.TrimSpace(value)
		}
	}
	return out
}

func defaultString(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func defaultInt(value, fallback int) int {
	if value == 0 {
		return fallback
	}
	return value
}

func sha256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func hashString(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return ""
	}
	return sha256Hex([]byte(value))
}

func xmlStringArray(values []string) string {
	if len(values) == 0 {
		return ""
	}
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, "<string>"+xmlEscape(value)+"</string>")
	}
	return strings.Join(parts, "")
}

func xmlEscape(value string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")
	return replacer.Replace(value)
}

func iniEscape(value string) string {
	value = strings.ReplaceAll(value, "\r", "")
	value = strings.ReplaceAll(value, "\n", "")
	return strings.TrimSpace(value)
}

func appleEAPType(method string) string {
	switch normalizeEAP(method) {
	case "tls":
		return "13"
	case "ttls":
		return "21"
	case "pwd":
		return "52"
	case "fast":
		return "43"
	case "teap":
		return "55"
	default:
		return "25"
	}
}
