package adminapi

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/activedirectory"
	"github.com/yourorg/aegisnas-pi4/internal/certlifecycle"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	eappkg "github.com/yourorg/aegisnas-pi4/internal/eap"
	"github.com/yourorg/aegisnas-pi4/internal/identity"
	mabpkg "github.com/yourorg/aegisnas-pi4/internal/mab"
	mfapkg "github.com/yourorg/aegisnas-pi4/internal/mfa"
	"github.com/yourorg/aegisnas-pi4/internal/radius"
	"github.com/yourorg/aegisnas-pi4/internal/secrets"
	"github.com/yourorg/aegisnas-pi4/internal/supplicantprofile"
	webauthnpkg "github.com/yourorg/aegisnas-pi4/internal/webauthn"
)

type productionReadinessReport struct {
	GeneratedAt       string                            `json:"generated_at"`
	Status            string                            `json:"status"`
	Ready             bool                              `json:"ready"`
	Score             int                               `json:"score"`
	Message           string                            `json:"message"`
	DeploymentProfile string                            `json:"deployment_profile"`
	DeploymentForm    string                            `json:"deployment_form"`
	BlockingCount     int                               `json:"blocking_count"`
	WarningCount      int                               `json:"warning_count"`
	DegradedCount     int                               `json:"degraded_count"`
	PassingCount      int                               `json:"passing_count"`
	VendorIdentity    productionVendorIdentityState     `json:"vendor_identity"`
	HardwareScaling   config.HardwareScalingPlan        `json:"hardware_scaling"`
	NASProfileSummary vendorCompatibilityProfileSummary `json:"nas_profile_summary"`
	VendorRuntime     db.VendorObservabilitySummary     `json:"vendor_runtime"`
	Checks            []productionReadinessCheck        `json:"checks"`
}

type productionVendorIdentityState struct {
	Enabled                    bool     `json:"enabled"`
	Name                       string   `json:"name"`
	ConfiguredID               int      `json:"configured_id"`
	ConfiguredIDPlaceholder    bool     `json:"configured_id_placeholder"`
	IDSource                   string   `json:"id_source"`
	DictionaryFilename         string   `json:"dictionary_filename"`
	DictionaryInstallPath      string   `json:"dictionary_install_path"`
	DictionaryInclude          string   `json:"dictionary_include"`
	DictionaryDetected         bool     `json:"dictionary_detected"`
	DictionaryImportPaths      []string `json:"dictionary_import_paths,omitempty"`
	PENRegistryURL             string   `json:"pen_registry_url"`
	PENApplyURL                string   `json:"pen_apply_url"`
	ProductCompatibilityActive bool     `json:"product_compatibility_active"`
	IdentityMode               string   `json:"identity_mode"`
	AssignedOrganization       string   `json:"assigned_organization,omitempty"`
	EvidenceValid              bool     `json:"evidence_valid"`
	AssignmentActive           bool     `json:"assignment_active"`
	AssignmentRecordSHA256     string   `json:"assignment_record_sha256,omitempty"`
	LegacyIDs                  []int    `json:"legacy_ids,omitempty"`
	LegacyAcceptUntil          string   `json:"legacy_accept_until,omitempty"`
}

type productionReadinessCheck struct {
	Key            string   `json:"key"`
	Category       string   `json:"category"`
	Label          string   `json:"label"`
	Status         string   `json:"status"`
	Summary        string   `json:"summary"`
	Recommendation string   `json:"recommendation,omitempty"`
	Dependencies   []string `json:"dependencies,omitempty"`
}

type productionReadinessSummary struct {
	Status        string `json:"status"`
	Ready         bool   `json:"ready"`
	Score         int    `json:"score"`
	Message       string `json:"message"`
	BlockingCount int    `json:"blocking_count"`
	WarningCount  int    `json:"warning_count"`
	DegradedCount int    `json:"degraded_count"`
	PassingCount  int    `json:"passing_count"`
}

func HandleGetProductionReadiness(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	report := buildProductionReadinessReport(cfg)
	writeJSON(w, http.StatusOK, report)
}

func buildProductionReadinessReport(cfg *config.Config) productionReadinessReport {
	report := productionReadinessReport{
		GeneratedAt:       time.Now().UTC().Format(time.RFC3339),
		DeploymentProfile: config.EffectiveDeploymentProfile(cfg.Deployment.Profile),
		DeploymentForm:    config.EffectiveDeploymentForm(cfg.Deployment.Form),
		HardwareScaling:   config.EvaluateHardwareScalingPlan(cfg),
	}
	report.VendorIdentity = buildProductionVendorIdentityState(cfg)
	report.NASProfileSummary = vendorProfileSummaryForProductionReadiness(cfg)
	report.VendorRuntime = vendorRuntimeSummaryForProductionReadiness(&report)

	addProductionConfigCheck(&report, cfg)
	addProductionScalingCheck(&report)
	addProductionVendorIdentityCheck(&report)
	addProductionAttributeRegistryCheck(&report)
	addProductionVSACodecCheck(&report)
	addProductionOpaquePassThroughCheck(&report, cfg)
	addProductionRadiusPacketHardeningCheck(&report, cfg)
	addProductionDynamicNASClientsCheck(&report, cfg)
	addProductionProxyRoutingCheck(&report, cfg)
	addProductionTransportPolicyCheck(&report, cfg)
	addProductionProxyPolicyCheck(&report, cfg)
	addProductionAccountingSpoolCheck(&report, cfg)
	addProductionFallbackPolicyCheck(&report, cfg)
	addProductionIdentityFailoverCheck(&report, cfg)
	addProductionActiveDirectoryCheck(&report, cfg)
	addProductionMFACheck(&report, cfg)
	addProductionAdminWebAuthnCheck(&report, cfg)
	addProductionEAPFrameworkCheck(&report, cfg)
	addProductionTEAPCheck(&report, cfg)
	addProductionMachineUserCheck(&report, cfg)
	addProductionFASTPWDCheck(&report, cfg)
	addProductionSIMAKACheck(&report, cfg)
	addProductionPolicyEngineCheck(&report, cfg)
	addProductionPolicySetGovernanceCheck(&report, cfg)
	addProductionPolicySimulationAnalysisCheck(&report, cfg)
	addProductionCertificateLifecycleCheck(&report, cfg)
	addProductionSupplicantLifecycleCheck(&report, cfg)
	addProductionMABCheck(&report, cfg)
	addProductionSecretProviderCheck(&report, cfg)
	addProductionDatabaseDataPlaneCheck(&report, cfg)
	addProductionDictionaryReleaseProfileCheck(&report, cfg)
	addProductionCompatibilityEvidenceCheck(&report, cfg)
	addProductionDictionaryCheck(&report)
	addProductionVendorPackCheck(&report, cfg)
	addProductionNASProfileCheck(&report)
	addProductionRadSecCheck(&report, cfg)
	addProductionFeatureCapabilityCheck(&report, cfg)
	addProductionControllerCheck(&report, cfg)
	addProductionVendorRuntimeCheck(&report)

	finalizeProductionReadinessReport(&report)
	return report
}

func addProductionRadiusPacketHardeningCheck(report *productionReadinessReport, cfg *config.Config) {
	hardening := radius.BuildPacketHardeningReport(cfg)
	status := "passed"
	switch hardening.Status {
	case "blocked":
		status = "blocked"
	case "degraded", "disabled":
		status = "degraded"
	}
	if hardening.SchemaVersion != radius.PacketHardeningSchemaVersion ||
		!hardening.Policy.Enabled ||
		!hardening.Policy.FailClosed ||
		!hardening.Policy.RequireKnownSource ||
		hardening.Policy.RequireMessageAuthenticator == "never" ||
		hardening.Limits.MaxPacketBytes > 4096 ||
		hardening.Limits.ReplayWindowSeconds <= 0 ||
		hardening.Limits.PerClientRateLimitPerSecond <= 0 {
		if status == "passed" {
			status = "blocked"
		}
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:      "radius_packet_hardening",
		Category: "radius",
		Label:    "RADIUS Packet Hardening",
		Status:   status,
		Summary: fmt.Sprintf("Packet hardening schema %d is %s with Message-Authenticator=%s, known-source=%t, replay window=%ds, rate limit=%d/s, and %d recent hardening event(s).",
			hardening.SchemaVersion, hardening.Status, hardening.Policy.RequireMessageAuthenticator, hardening.Policy.RequireKnownSource,
			hardening.Limits.ReplayWindowSeconds, hardening.Limits.PerClientRateLimitPerSecond, hardening.RuntimeStats.TotalEvents),
		Recommendation: "Keep packet hardening enabled and fail-closed with known RADIUS clients, Message-Authenticator auto or always, replay cache, rate limits, and the NAS-0009 release checklist for external packet-capture evidence.",
		Dependencies:   []string{"radius.packet_hardening", "/api/v1/system/radius-hardening", "radius_packet_hardening_events"},
	})
}

func addProductionDynamicNASClientsCheck(report *productionReadinessReport, cfg *config.Config) {
	dynamicClients := radius.BuildDynamicNASClientReport(cfg)
	status := "passed"
	switch dynamicClients.Status {
	case "disabled":
		status = "degraded"
	case "degraded", "pending":
		status = "degraded"
	case "blocked":
		status = "blocked"
	}
	if dynamicClients.Enabled {
		if strings.TrimSpace(dynamicClients.Policy.EnrollmentTokenRef) == "" {
			status = "blocked"
		}
		if !dynamicClients.Policy.ApprovalRequired {
			status = "blocked"
		}
		if dynamicClients.Policy.DiscoveryEnabled && len(dynamicClients.Policy.DiscoveryAllowedCIDRs) == 0 {
			if status == "passed" {
				status = "degraded"
			}
		}
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:      "dynamic_nas_clients",
		Category: "radius",
		Label:    "Dynamic NAS Clients And Capability Discovery",
		Status:   status,
		Summary: fmt.Sprintf("Dynamic NAS clients are %s with %d pending, %d approved, %d dynamic client(s), and %d capability template(s).",
			dynamicClients.Status, dynamicClients.Summary.PendingCount, dynamicClients.Summary.ApprovedCount,
			dynamicClients.Summary.DynamicClients, dynamicClients.Summary.CapabilityTemplates),
		Recommendation: "Keep approval required, use radius.dynamic_clients.enrollment_token_ref, restrict discovery CIDRs, approve only credential-backed clients, and complete the NAS-0013 release certification checklist before production claims.",
		Dependencies:   []string{"radius.dynamic_clients", "/api/v1/nas/enroll", "/api/v1/system/nas-clients", "nas_client_enrollments", "nas_client_capability_templates", "nas_client_events"},
	})
}

func addProductionProxyRoutingCheck(report *productionReadinessReport, cfg *config.Config) {
	routing := radius.BuildProxyRoutingReport(cfg)
	status := "passed"
	if routing.Status == "blocked" {
		status = "blocked"
	} else if routing.Status == "degraded" {
		status = "degraded"
	}
	if routing.Enabled {
		if routing.Summary.RouteCount == 0 || routing.Summary.ServerCount == 0 {
			status = "blocked"
		}
		if routing.Summary.DefaultRouteCount > 1 {
			status = "blocked"
		}
	}

	summary := "Upstream AAA proxy routing is disabled."
	if routing.Enabled {
		defaultRealm := routing.Summary.DefaultRealm
		if defaultRealm == "" {
			defaultRealm = "none"
		}
		summary = fmt.Sprintf("Proxy routing schema %d is %s with %d route(s), %d upstream server(s), and default realm %s.",
			routing.SchemaVersion, routing.Status, routing.Summary.RouteCount, routing.Summary.ServerCount, defaultRealm)
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:            "radius_proxy_routes",
		Category:       "radius",
		Label:          "RADIUS Proxy Route Table",
		Status:         status,
		Summary:        summary,
		Recommendation: "Use explicit radius.upstream.routes for every production realm, keep server bindings named and secret-backed, review /api/v1/system/proxy-routes before generation, and capture NAS-0010 external interoperability evidence before release sign-off.",
		Dependencies:   []string{"radius.upstream.routes", "/api/v1/system/proxy-routes", "proxy.conf", "sites-enabled/default", "sites-enabled/inner-tunnel"},
	})
}

func addProductionTransportPolicyCheck(report *productionReadinessReport, cfg *config.Config) {
	transportPolicy := radius.BuildTransportPolicyReport(cfg)
	status := "passed"
	if transportPolicy.Status == "blocked" {
		status = "blocked"
	} else if transportPolicy.Status == "degraded" {
		status = "degraded"
	}
	if cfg != nil && cfg.Radius.Upstream.Enabled {
		if !transportPolicy.Enabled || transportPolicy.Policy.Mode != "enforce" || !transportPolicy.Policy.FailClosed {
			status = "blocked"
		}
		if transportPolicy.Summary.ViolationCount > 0 {
			status = "blocked"
		}
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:      "radius_transport_policy",
		Category: "radius",
		Label:    "RADIUS Transport Downgrade Policy",
		Status:   status,
		Summary: fmt.Sprintf("Transport policy schema %d is %s in %s mode with %d route(s), %d mixed route(s), and %d violation(s).",
			transportPolicy.SchemaVersion, transportPolicy.Status, transportPolicy.Policy.Mode,
			transportPolicy.Summary.RouteCount, transportPolicy.Summary.MixedTransportRoutes, transportPolicy.Summary.ViolationCount),
		Recommendation: "Set radius.upstream.transport_policy.mode=enforce, keep fail_closed=true, require RadSec on sensitive routes, and explicitly approve any UDP or mixed-transport exceptions before production proxy operation.",
		Dependencies:   []string{"radius.upstream.transport_policy", "/api/v1/system/transport-policy", "proxy.conf:default_fallback=no"},
	})
}

func addProductionProxyPolicyCheck(report *productionReadinessReport, cfg *config.Config) {
	policy := radius.BuildProxyPolicyReport(cfg)
	status := "passed"
	switch policy.Status {
	case "blocked":
		status = "blocked"
	case "degraded", "disabled":
		if cfg != nil && cfg.Radius.Upstream.Enabled {
			status = "degraded"
		}
	}
	if cfg != nil && cfg.Radius.Upstream.Enabled {
		if !policy.Enabled || policy.Summary.RoutePolicyCount == 0 || !policy.FreeRADIUS.LoopMarkerEnforced {
			status = "blocked"
		}
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:      "radius_proxy_policy",
		Category: "radius",
		Label:    "RADIUS Proxy Loop And Attribute Policy",
		Status:   status,
		Summary: fmt.Sprintf("Proxy policy schema %d is %s with %d route policy item(s), %d vendor allow selector(s), %d deny selector(s), and %d rewrite rule(s).",
			policy.SchemaVersion, policy.Status, policy.Summary.RoutePolicyCount,
			policy.Summary.AllowVendorIDCount+policy.Summary.AllowVendorAttributeCount,
			policy.Summary.DenyVendorIDCount+policy.Summary.DenyVendorAttributeCount,
			policy.Summary.RewriteRuleCount),
		Recommendation: "Keep radius.upstream.proxy_policy enabled, fail-closed, loop-marker enforced, route-scoped, and reviewed through /api/v1/system/proxy-policy before production proxy operation.",
		Dependencies:   []string{"radius.upstream.proxy_policy", "/api/v1/system/proxy-policy", "sites-enabled/default:pre-proxy", "sites-enabled/inner-tunnel:pre-proxy"},
	})
}

func addProductionAccountingSpoolCheck(report *productionReadinessReport, cfg *config.Config) {
	spool := radius.BuildAccountingSpoolReport(cfg)
	status := "passed"
	switch spool.Status {
	case "blocked":
		status = "blocked"
	case "degraded", "disabled":
		if cfg != nil && cfg.Radius.Upstream.Enabled {
			status = "degraded"
		}
	}
	if cfg != nil && cfg.Radius.Upstream.Enabled {
		if !spool.Enabled || spool.Policy.MaxQueueRecords <= 0 || spool.Policy.MaxAttempts <= 0 || spool.Policy.RecordTTLSeconds <= 0 {
			status = "blocked"
		}
		if spool.Summary.QueueUtilization >= 90 || spool.Summary.PoisonCount > 0 {
			if status == "passed" {
				status = "degraded"
			}
		}
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:      "radius_accounting_spool",
		Category: "radius",
		Label:    "Durable RADIUS Accounting Spool",
		Status:   status,
		Summary: fmt.Sprintf("Accounting spool schema %d is %s with %d queued, %d retrying, %d poison, %d expired, and %d%% queue utilization.",
			spool.SchemaVersion, spool.Status, spool.Summary.QueuedCount, spool.Summary.RetryingCount,
			spool.Summary.PoisonCount, spool.Summary.ExpiredCount, spool.Summary.QueueUtilization),
		Recommendation: "Keep radius.upstream.accounting_spool enabled for proxy accounting, monitor /api/v1/system/accounting-spool, and complete the NAS-0012 release certification replay and outage drills.",
		Dependencies:   []string{"radius.upstream.accounting_spool", "/api/v1/system/accounting-spool", "/api/v1/system/accounting-spool/replay", "radius_accounting_spool", "radius_accounting_spool_attempts"},
	})
}

func addProductionFallbackPolicyCheck(report *productionReadinessReport, cfg *config.Config) {
	fallback := radius.BuildFallbackPolicyReport(cfg)
	status := "passed"
	switch fallback.Status {
	case "blocked":
		status = "blocked"
	case "degraded":
		status = "degraded"
	}
	activePortalFallback := cfg != nil && cfg.Radius.Upstream.Enabled && cfg.Portal.RadiusAuth && cfg.Portal.LocalFallback
	if activePortalFallback {
		if !fallback.Enabled || fallback.Policy.Mode != "enforce" || !fallback.Policy.FailClosed {
			status = "blocked"
		}
		if fallback.Policy.RequireIdentityAllowlist && !fallback.Summary.IdentityAllowlistSet {
			status = "blocked"
		}
		if fallback.Policy.AuditEnabled && db.DB == nil {
			status = "blocked"
		}
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:      "radius_fallback_policy",
		Category: "radius",
		Label:    "Upstream Outage Fallback Policy",
		Status:   status,
		Summary: fmt.Sprintf("Fallback policy schema %d is %s in %s mode with local=%t ldap=%t allowlists users=%d realms=%d roles=%d and %d audited decision(s).",
			fallback.SchemaVersion, fallback.Status, fallback.Policy.Mode, fallback.Policy.AllowPortalLocal, fallback.Policy.AllowLDAP,
			fallback.Summary.AllowedUserCount, fallback.Summary.AllowedRealmCount, fallback.Summary.AllowedRoleCount, fallback.AuditSummary.TotalRecords),
		Recommendation: "Set radius.upstream.fallback_policy.mode=enforce, keep fail_closed=true, bound max_outage_seconds, configure identity allowlists, and review /api/v1/system/fallback-policy before production upstream AAA operation.",
		Dependencies:   []string{"radius.upstream.fallback_policy", "portal.radius_auth", "portal.local_fallback", "/api/v1/system/fallback-policy", "radius_fallback_events"},
	})
}

func addProductionIdentityFailoverCheck(report *productionReadinessReport, cfg *config.Config) {
	failover := identity.BuildFailoverReport(cfg)
	status := "passed"
	switch failover.Status {
	case "blocked":
		status = "blocked"
	case "degraded", "disabled":
		status = "degraded"
	}
	activePortalIdentity := cfg != nil && (cfg.Portal.Enabled || cfg.Portal.RadiusAuth || cfg.Portal.LocalFallback || cfg.LDAP.Enabled)
	if activePortalIdentity {
		if !failover.Enabled || failover.Policy.Mode != "enforce" || !failover.Policy.FailClosed {
			status = "blocked"
		}
		if failover.Summary.ExecutableSourceCount == 0 {
			status = "blocked"
		}
		if failover.Policy.AuditEnabled && db.DB == nil {
			status = "blocked"
		}
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:      "identity_source_failover",
		Category: "authentication",
		Label:    "Identity Source HA And Deterministic Failover",
		Status:   status,
		Summary: fmt.Sprintf("Identity failover schema %d is %s in %s mode with %d executable source(s), %d open circuit(s), cache=%t, and %d audited decision(s).",
			failover.SchemaVersion, failover.Status, failover.Policy.Mode, failover.Summary.ExecutableSourceCount,
			failover.Summary.OpenCircuitCount, failover.Policy.CacheCredentials, failover.AuditSummary.TotalRecords),
		Recommendation: "Set identity.failover.mode=enforce, keep fail_closed=true, define source_order, keep audit enabled, and review /api/v1/system/identity-failover before production authentication cutover.",
		Dependencies:   []string{"identity.failover", "identity_sources", "/api/v1/system/identity-failover", "identity_source_events", "identity_source_cache"},
	})
}

func addProductionActiveDirectoryCheck(report *productionReadinessReport, cfg *config.Config) {
	ad := activedirectory.BuildReport(cfg)
	if !ad.Enabled {
		return
	}
	status := "passed"
	switch ad.Status {
	case "blocked":
		status = "blocked"
	case "degraded", "disabled":
		status = "degraded"
	}
	if ad.Policy.Mode != "enforce" || !ad.Policy.FailClosed {
		status = "blocked"
	}
	if !ad.Summary.SourceExecutable {
		status = "blocked"
	}
	if ad.Policy.AuthMethod == "kerberos" && !ad.Policy.KerberosEnabled {
		status = "blocked"
	}
	if ad.Policy.AuthMethod == "winbind_helper" && !ad.Policy.WinbindHelperConfigured {
		status = "blocked"
	}
	if ad.Policy.AuditEnabled && db.DB == nil {
		status = "blocked"
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:      "active_directory_identity",
		Category: "authentication",
		Label:    "Active Directory Kerberos And Winbind",
		Status:   status,
		Summary: fmt.Sprintf("Active Directory schema %d is %s using %s with cache=%t, %d audit event(s), and last health status %s.",
			ad.SchemaVersion, ad.Status, ad.Policy.AuthMethod, ad.Summary.GroupCacheEnabled,
			ad.AuditSummary.TotalRecords, firstNonEmpty(ad.HealthSummary.LastStatus, "none")),
		Recommendation: "Set active_directory.mode=enforce, keep fail_closed=true, use LDAPS or Kerberos/winbind helper, keep audit enabled, and review /api/v1/system/active-directory before production authentication cutover.",
		Dependencies:   []string{"active_directory", "identity.failover.source_order", "/api/v1/system/active-directory", "active_directory_events", "active_directory_group_cache", "active_directory_health_checks"},
	})
}

func addProductionMFACheck(report *productionReadinessReport, cfg *config.Config) {
	mfaReport := mfapkg.BuildReport(cfg)
	status := "passed"
	switch mfaReport.Status {
	case "blocked":
		status = "blocked"
	case "degraded", "disabled":
		status = "degraded"
	}
	activePortalIdentity := cfg != nil && (cfg.Portal.Enabled || cfg.Portal.RadiusAuth || cfg.Portal.LocalFallback || cfg.LDAP.Enabled)
	if activePortalIdentity && cfg != nil && cfg.MFA.Enabled {
		if mfaReport.Policy.Mode != "enforce" || !mfaReport.Policy.FailClosed || !mfaReport.Policy.OTPEnabled {
			status = "blocked"
		}
		if mfaReport.Credentials.EnabledUsers == 0 {
			status = "blocked"
		}
		if mfaReport.Policy.AuditEnabled && db.DB == nil {
			status = "blocked"
		}
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:      "mfa_challenge_otp",
		Category: "authentication",
		Label:    "OTP And RADIUS Challenge MFA",
		Status:   status,
		Summary: fmt.Sprintf("MFA schema %d is %s in %s mode with OTP=%t, challenge=%t, enrolled users=%d, pending challenges=%d, and %d audited decision(s).",
			mfaReport.SchemaVersion, mfaReport.Status, mfaReport.Policy.Mode, mfaReport.Policy.OTPEnabled,
			mfaReport.Policy.ChallengeEnabled, mfaReport.Credentials.EnabledUsers, mfaReport.Credentials.PendingChallenges,
			mfaReport.AuditSummary.TotalRecords),
		Recommendation: "Enable mfa.mode=enforce, keep fail_closed=true, set mfa.otp.sealing_key_ref to a secure env/file secret, enroll required users, and review /api/v1/system/mfa before production cutover.",
		Dependencies:   []string{"mfa", "mfa.otp.sealing_key_ref", "mfa_totp_secrets", "mfa_recovery_codes", "mfa_challenges", "mfa_events", "/api/v1/system/mfa"},
	})
}

func addProductionAdminWebAuthnCheck(report *productionReadinessReport, cfg *config.Config) {
	webAuthnReport := webauthnpkg.BuildReport(cfg)
	if !webAuthnReport.Enabled {
		return
	}
	status := "passed"
	switch webAuthnReport.Status {
	case "blocked":
		status = "blocked"
	case "degraded", "disabled":
		status = "degraded"
	}
	if webAuthnReport.Policy.Mode != "enforce" || !webAuthnReport.Policy.FailClosed {
		status = "blocked"
	}
	if !webAuthnReport.Policy.RPIDConfigured || len(webAuthnReport.Policy.Origins) == 0 {
		status = "blocked"
	}
	if webAuthnReport.Credentials.EnabledCredentials == 0 {
		status = "blocked"
	}
	if webAuthnReport.Policy.BreakGlassAllowed && status != "blocked" {
		status = "degraded"
	}
	if webAuthnReport.Policy.AuditEnabled && db.DB == nil {
		status = "blocked"
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:      "admin_webauthn_passkeys",
		Category: "authentication",
		Label:    "Admin WebAuthn Passkeys",
		Status:   status,
		Summary: fmt.Sprintf("Admin WebAuthn schema %d is %s in %s mode with RP ID configured=%t, %d origin(s), %d enabled credential(s), %d pending challenge(s), and %d audited decision(s).",
			webAuthnReport.SchemaVersion, webAuthnReport.Status, webAuthnReport.Policy.Mode,
			webAuthnReport.Policy.RPIDConfigured, len(webAuthnReport.Policy.Origins),
			webAuthnReport.Credentials.EnabledCredentials, webAuthnReport.Credentials.PendingChallenges,
			webAuthnReport.AuditSummary.TotalRecords),
		Recommendation: "Set admin_webauthn.mode=enforce, keep fail_closed=true, configure rp_id and HTTPS origins, enroll passkeys for privileged admins, and keep break-glass use governed.",
		Dependencies:   []string{"admin_webauthn", "admin_webauthn_credentials", "admin_webauthn_challenges", "admin_webauthn_events", "/api/v1/system/webauthn"},
	})
}

func addProductionEAPFrameworkCheck(report *productionReadinessReport, cfg *config.Config) {
	summary, _ := db.SummarizeEAPMethodEvents(1000)
	eapReport := eappkg.BuildFrameworkReport(cfg, eapRuntimeSummaryFromDB(summary))
	status := "passed"
	switch eapReport.Status {
	case "blocked":
		status = "blocked"
	case "degraded", "disabled":
		status = "degraded"
	}
	if eapReport.Policy.Mode != "enforce" {
		if status == "passed" {
			status = "degraded"
		}
	}
	if !eapReport.Policy.Enabled ||
		!eapReport.Policy.FailClosed ||
		!eapReport.Policy.RequireMessageAuthenticator ||
		!eapReport.Policy.RequireIdentityBinding ||
		!eapReport.Policy.GeneratedFreeRADIUSPolicy ||
		eapReport.Summary.GeneratedMethodCount == 0 ||
		eapReport.Summary.BlockedMethodCount > 0 {
		status = "blocked"
	}
	if eapReport.Runtime.Rejected > 0 || eapReport.Runtime.Unsupported > 0 {
		if status == "passed" {
			status = "degraded"
		}
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:      "eap_method_framework",
		Category: "authentication",
		Label:    "Extensible EAP Method Framework",
		Status:   status,
		Summary: fmt.Sprintf("EAP framework schema %d is %s in %s mode with %d enabled method(s), %d generated method(s), %d blocked method(s), and %d recent event(s).",
			eapReport.SchemaVersion, eapReport.Status, eapReport.Policy.Mode, eapReport.Summary.EnabledMethodCount,
			eapReport.Summary.GeneratedMethodCount, eapReport.Summary.BlockedMethodCount, eapReport.Runtime.TotalEvents),
		Recommendation: "Use radius.eap.framework in enforce/fail-closed mode, keep Message-Authenticator and identity binding required, enable only generated methods for this release, and complete the NAS-0022 release certification checklist for real supplicant/AP evidence.",
		Dependencies:   []string{"radius.eap.framework", "eap_method_events", "mods-enabled/eap", "/api/v1/system/eap-framework"},
	})
}

func addProductionTEAPCheck(report *productionReadinessReport, cfg *config.Config) {
	summary, _ := db.SummarizeTEAPChainEvents(1000)
	teapReport := eappkg.BuildTEAPReport(cfg, teapRuntimeSummaryFromDB(summary))
	status := "passed"
	switch teapReport.Status {
	case "blocked":
		status = "blocked"
	case "disabled", "degraded":
		status = "degraded"
	}
	if teapReport.Policy.GeneratedInFreeRADIUS {
		if !teapReport.Policy.RequireMessageAuthenticator ||
			!teapReport.Policy.RequireIdentityBinding ||
			!teapReport.Policy.RequireCryptoBinding ||
			teapReport.Policy.FrameworkMode != "enforce" ||
			!teapReport.Policy.FrameworkFailClosed {
			status = "blocked"
		}
	}
	if teapReport.Runtime.Rejected > 0 && status == "passed" {
		status = "degraded"
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:      "teap_method_chaining",
		Category: "authentication",
		Label:    "TEAP Method Chaining",
		Status:   status,
		Summary: fmt.Sprintf("TEAP schema %d is %s with chain mode %s, generated=%t, cryptobinding=%t, channel-binding=%t, and %d recent chain event(s).",
			teapReport.SchemaVersion, teapReport.Status, teapReport.Policy.ChainMode, teapReport.Policy.GeneratedInFreeRADIUS,
			teapReport.Policy.RequireCryptoBinding, teapReport.Policy.RequireChannelBinding, teapReport.Runtime.TotalEvents),
		Recommendation: "For TEAP production SSIDs, add teap to radius.eap.framework.allowed_methods, keep framework enforce/fail-closed, require cryptobinding and identity binding, use machine_then_user for chained access, and complete the NAS-0023 release certification checklist for real supplicant evidence.",
		Dependencies:   []string{"radius.eap.teap", "radius.eap.framework.allowed_methods", "eap_teap_chain_events", "rlm_eap_teap", "/api/v1/system/eap-framework/teap"},
	})
}

func addProductionMachineUserCheck(report *productionReadinessReport, cfg *config.Config) {
	summary, _ := db.SummarizeMachineUserCorrelations(1000)
	machineUserReport := eappkg.BuildMachineUserReport(cfg, machineUserRuntimeSummaryFromDB(summary))
	status := "passed"
	switch machineUserReport.Status {
	case "blocked":
		status = "blocked"
	case "disabled", "degraded":
		status = "degraded"
	}
	if machineUserReport.Policy.Enabled {
		if machineUserReport.Policy.Mode != "enforce" {
			if status == "passed" {
				status = "degraded"
			}
		}
		if !machineUserReport.Policy.FailClosed ||
			!machineUserReport.Policy.FrameworkEnabled ||
			(machineUserReport.Policy.RequireTEAP && !machineUserReport.Policy.TEAPGenerated) ||
			len(machineUserReport.Policy.BlockingIssues) > 0 {
			status = "blocked"
		}
	}
	if machineUserReport.Runtime.Rejected > 0 || machineUserReport.Runtime.Quarantined > 0 {
		if status == "passed" {
			status = "degraded"
		}
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:      "eap_machine_user_correlation",
		Category: "authentication",
		Label:    "Machine And User Authentication Correlation",
		Status:   status,
		Summary: fmt.Sprintf("Machine/user schema %d is %s in %s mode with correlation mode %s, TEAP required=%t, active correlations=%d, and %d recent event(s).",
			machineUserReport.SchemaVersion, machineUserReport.Status, machineUserReport.Policy.Mode,
			machineUserReport.Policy.CorrelationMode, machineUserReport.Policy.RequireTEAP,
			machineUserReport.Runtime.ActiveCorrelations, machineUserReport.Runtime.TotalEvents),
		Recommendation: "Use radius.eap.machine_user in enforce/fail-closed mode with TEAP cryptobinding, same Calling-Station-Id binding, fresh machine auth, deterministic role merge, and the NAS-0026 release checklist for real Windows/Cisco/Aruba evidence.",
		Dependencies:   []string{"radius.eap.machine_user", "radius.eap.teap", "eap_machine_user_correlations", "eap_machine_user_session_state", "/api/v1/system/eap-framework/machine-user"},
	})
}

func addProductionFASTPWDCheck(report *productionReadinessReport, cfg *config.Config) {
	summary, _ := db.SummarizeFASTPWDEvents(1000)
	fastPWDReport := eappkg.BuildFASTPWDReport(cfg, fastPWDRuntimeSummaryFromDB(summary))
	status := "passed"
	switch fastPWDReport.Status {
	case "blocked":
		status = "blocked"
	case "disabled", "degraded":
		status = "degraded"
	}
	if fastPWDReport.FAST.GeneratedInFreeRADIUS {
		if !fastPWDReport.FAST.RequireMessageAuthenticator ||
			!fastPWDReport.FAST.RequireIdentityBinding ||
			!fastPWDReport.FAST.RequireCryptoBinding ||
			fastPWDReport.FAST.FrameworkMode != "enforce" ||
			!fastPWDReport.FAST.FrameworkFailClosed {
			status = "blocked"
		}
	}
	if fastPWDReport.PWD.GeneratedInFreeRADIUS {
		if !fastPWDReport.PWD.RequireMessageAuthenticator ||
			!fastPWDReport.PWD.RequireIdentityBinding ||
			!fastPWDReport.PWD.RequireStrongGroup ||
			!fastPWDReport.PWD.RequireIdentity ||
			!fastPWDReport.PWD.RequirePasswordProof ||
			fastPWDReport.PWD.FrameworkMode != "enforce" ||
			!fastPWDReport.PWD.FrameworkFailClosed {
			status = "blocked"
		}
	}
	if fastPWDReport.Runtime.Rejected > 0 && status == "passed" {
		status = "degraded"
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:      "eap_fast_pwd_methods",
		Category: "authentication",
		Label:    "EAP-FAST And EAP-PWD",
		Status:   status,
		Summary: fmt.Sprintf("FAST/PWD schema %d is %s with FAST generated=%t, PAC=%t, cryptobinding=%t, PWD generated=%t, group=%d, and %d recent event(s).",
			fastPWDReport.SchemaVersion, fastPWDReport.Status, fastPWDReport.FAST.GeneratedInFreeRADIUS,
			fastPWDReport.FAST.AllowPAC, fastPWDReport.FAST.RequireCryptoBinding,
			fastPWDReport.PWD.GeneratedInFreeRADIUS, fastPWDReport.PWD.Group, fastPWDReport.Runtime.TotalEvents),
		Recommendation: "For production FAST/PWD profiles, add fast or pwd to radius.eap.framework.allowed_methods only where clients require them, keep framework enforce/fail-closed, require FAST cryptobinding, use strong PWD groups, and complete the NAS-0024 release certification checklist for supplicant evidence.",
		Dependencies:   []string{"radius.eap.fast", "radius.eap.pwd", "radius.eap.framework.allowed_methods", "eap_fast_pwd_events", "rlm_eap_fast", "rlm_eap_pwd", "/api/v1/system/eap-framework/fast-pwd"},
	})
}

func addProductionSIMAKACheck(report *productionReadinessReport, cfg *config.Config) {
	summary, _ := db.SummarizeSIMAKAEvents(1000)
	simAKAReport := eappkg.BuildSIMAKAReport(cfg, simAKARuntimeSummaryFromDB(summary))
	status := "passed"
	switch simAKAReport.Status {
	case "blocked":
		status = "blocked"
	case "disabled", "degraded":
		status = "degraded"
	}
	if simAKAReport.Policy.GeneratedInFreeRADIUS {
		if !simAKAReport.Policy.RequireMessageAuthenticator ||
			!simAKAReport.Policy.RequireIdentityBinding ||
			!simAKAReport.Policy.RequireIdentity ||
			!simAKAReport.Policy.RequireFreshVectors ||
			!simAKAReport.Policy.VectorProviderRefConfigured ||
			simAKAReport.Policy.FrameworkMode != "enforce" ||
			!simAKAReport.Policy.FrameworkFailClosed {
			status = "blocked"
		}
		if containsString(simAKAReport.Policy.GeneratedMethods, "sim") && simAKAReport.Policy.MinTriplets < 2 {
			status = "blocked"
		}
		if (containsString(simAKAReport.Policy.GeneratedMethods, "aka") || containsString(simAKAReport.Policy.GeneratedMethods, "aka-prime")) && simAKAReport.Policy.MinQuintuplets < 1 {
			status = "blocked"
		}
		if containsString(simAKAReport.Policy.GeneratedMethods, "aka-prime") &&
			(!simAKAReport.Policy.RequireNetworkName || !simAKAReport.Policy.NetworkNameConfigured || !simAKAReport.Policy.RequireKDF) {
			status = "blocked"
		}
	}
	if simAKAReport.Runtime.Rejected > 0 && status == "passed" {
		status = "degraded"
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:      "eap_sim_aka_methods",
		Category: "authentication",
		Label:    "EAP-SIM, EAP-AKA, And EAP-AKA-prime",
		Status:   status,
		Summary: fmt.Sprintf("SIM/AKA schema %d is %s with methods=%s, generated=%t, vector provider=%s, fresh vectors=%t, and %d recent event(s).",
			simAKAReport.SchemaVersion, simAKAReport.Status, strings.Join(simAKAReport.Policy.GeneratedMethods, ","),
			simAKAReport.Policy.GeneratedInFreeRADIUS, simAKAReport.Policy.VectorProvider,
			simAKAReport.Policy.RequireFreshVectors, simAKAReport.Runtime.TotalEvents),
		Recommendation: "For production carrier, Passpoint, or roaming profiles, add only required SIM/AKA methods to radius.eap.framework.allowed_methods, configure radius.eap.sim_aka.vector_provider_ref, keep framework enforce/fail-closed, and complete the NAS-0025 release certification checklist for HSS/HLR/UDM and real-device evidence.",
		Dependencies:   []string{"radius.eap.sim_aka", "radius.eap.framework.allowed_methods", "eap_sim_aka_events", "rlm_eap_sim", "rlm_eap_aka", "rlm_eap_aka_prime", "/api/v1/system/eap-framework/sim-aka"},
	})
}

func addProductionPolicyEngineCheck(report *productionReadinessReport, cfg *config.Config) {
	engineReport, err := buildPolicyEngineReport(cfg, 0)
	status := "passed"
	summary := "Typed policy engine is active and ready."
	if err != nil {
		status = "blocked"
		summary = fmt.Sprintf("Typed policy engine report failed: %v", err)
	} else {
		switch engineReport.Status {
		case "blocked", "disabled":
			status = "blocked"
		case "degraded":
			status = "degraded"
		}
		if !cfg.Policy.TypedEngineEnabled || !cfg.Policy.FailClosed {
			status = "blocked"
		}
		if !cfg.Policy.AuditEnabled && status == "passed" {
			status = "degraded"
		}
		if cfg.Policy.EvaluationRetentionLimit < 100 {
			status = "blocked"
		}
		summary = fmt.Sprintf("Typed policy engine schema %d is %s with %d rule(s), %d typed, %d legacy, %d invalid, and %d retained evaluation(s).",
			engineReport.SchemaVersion, engineReport.Status, len(engineReport.Rules), enabledTypedPolicyRules(engineReport.Rules),
			enabledLegacyPolicyRules(engineReport.Rules), enabledInvalidPolicyRules(engineReport.Rules), engineReport.Summary.TotalRecords)
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:            "typed_policy_engine",
		Category:       "policy",
		Label:          "Typed Policy Expression Engine",
		Status:         status,
		Summary:        summary,
		Recommendation: "Keep policy.typed_engine_enabled=true, fail_closed=true, audit_enabled=true, migrate legacy match_conditions to typed all/any/not expressions, and complete the NAS-0029 release certification checklist for real-device evidence.",
		Dependencies:   []string{"policy.typed_engine_enabled", "/api/v1/system/policy-engine", "/api/v1/system/policy-engine/evaluate", "policy_engine_evaluations"},
	})
}

func addProductionPolicySetGovernanceCheck(report *productionReadinessReport, cfg *config.Config) {
	governance, err := buildPolicySetGovernanceReport(cfg, 0)
	status := "passed"
	summary := "Versioned policy set governance is active."
	if err != nil {
		status = "blocked"
		summary = fmt.Sprintf("Policy set governance report failed: %v", err)
	} else {
		switch governance.Status {
		case "blocked":
			status = "blocked"
		case "degraded":
			status = "degraded"
		}
		if !cfg.Policy.VersionApprovalRequired || cfg.Policy.VersionMinApprovals < 1 || !cfg.Policy.VersionMakerChecker {
			status = "blocked"
		}
		if cfg.Policy.VersionRetentionLimit > 0 && cfg.Policy.VersionRetentionLimit < 100 {
			status = "blocked"
		}
		active := 0
		if governance.Active != nil {
			active = governance.Active.Version
		}
		summary = fmt.Sprintf("Policy set governance schema %d is %s with active version %d, %d total version(s), %d pending approval(s), and %d simulation(s).",
			governance.SchemaVersion, governance.Status, active, governance.Summary.TotalVersions,
			governance.Summary.PendingApprovalCount, governance.Summary.SimulationCount)
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:            "policy_set_governance",
		Category:       "policy",
		Label:          "Nested Policy Sets And Versioned Approvals",
		Status:         status,
		Summary:        summary,
		Recommendation: "Keep policy.version_approval_required=true, version_min_approvals>=1, version_maker_checker=true, activate only approved immutable versions, and complete the NAS-0030 release certification checklist before production claims.",
		Dependencies:   []string{"policy_set_versions", "policy_set_approvals", "policy_set_activation_events", "/api/v1/system/policy-sets", "/api/v1/system/policy-sets/versions"},
	})
}

func addProductionPolicySimulationAnalysisCheck(report *productionReadinessReport, cfg *config.Config) {
	summary, err := db.SummarizePolicySimulationAnalyses()
	status := "passed"
	message := "Policy simulation, conflict, and shadow analysis is recording blast-radius evidence."
	if err != nil {
		status = "blocked"
		message = fmt.Sprintf("Policy simulation analysis summary failed: %v", err)
	} else {
		switch {
		case cfg.Policy.SimulationReplayLimit <= 0 || cfg.Policy.SimulationRetentionLimit <= 0:
			status = "blocked"
			message = "Policy simulation analysis requires positive replay and retention limits."
		case summary.TotalAnalyses == 0:
			status = "degraded"
			message = "No policy simulation analysis records exist yet; run analysis before activating candidate policy versions."
		case summary.LastRiskLevel == "critical" || summary.LastRiskLevel == "high":
			status = "degraded"
			message = fmt.Sprintf("Last policy analysis %s has %s risk with %d decision change(s).",
				summary.LastAnalysisID, summary.LastRiskLevel, summary.LastDecisionChangeCount)
		default:
			message = fmt.Sprintf("Last policy analysis %s has %s risk across %d sample(s), %d decision change(s), %d shadowed rule(s), and %d ineffective rule(s).",
				summary.LastAnalysisID, summary.LastRiskLevel, summary.LastSampleCount, summary.LastDecisionChangeCount,
				summary.LastShadowedRuleCount, summary.LastIneffectiveRuleCount)
		}
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:            "policy_simulation_analysis",
		Category:       "policy",
		Label:          "Policy Simulation Conflict And Shadow Analysis",
		Status:         status,
		Summary:        message,
		Recommendation: "Run /api/v1/system/policy-sets/versions/{id}/analyze against retained and manual samples before activation, review high-risk deltas, and complete the NAS-0031 release certification checklist before production claims.",
		Dependencies:   []string{"policy_simulation_analyses", "policy_engine_evaluations.request_replay_json", "/api/v1/system/policy-sets/versions/{id}/analyze", "/api/v1/system/policy-sets/analyses"},
	})
}

func enabledTypedPolicyRules(rules []policyRuleStatus) int {
	count := 0
	for _, rule := range rules {
		if rule.Enabled && rule.Typed && rule.Valid {
			count++
		}
	}
	return count
}

func enabledLegacyPolicyRules(rules []policyRuleStatus) int {
	count := 0
	for _, rule := range rules {
		if rule.Enabled && rule.Legacy {
			count++
		}
	}
	return count
}

func enabledInvalidPolicyRules(rules []policyRuleStatus) int {
	count := 0
	for _, rule := range rules {
		if rule.Enabled && !rule.Valid {
			count++
		}
	}
	return count
}

func addProductionCertificateLifecycleCheck(report *productionReadinessReport, cfg *config.Config) {
	summary, _ := db.SummarizeCertificateLifecycle(1000)
	certReport := certlifecycle.BuildReport(cfg, certificateLifecycleRuntimeSummaryFromDB(summary))
	if !certReport.Policy.Enabled {
		return
	}
	status := "passed"
	switch certReport.Status {
	case "blocked":
		status = "blocked"
	case "disabled", "degraded":
		status = "degraded"
	}
	if certReport.Policy.Mode != "enforce" {
		if status == "passed" {
			status = "degraded"
		}
	}
	if !certReport.Policy.FailClosed ||
		!certReport.Policy.CertificateEnrollmentReady ||
		!certReport.Policy.EAPTLSReady ||
		!certReport.Policy.CAReady ||
		!certReport.Policy.RequireCSR ||
		!certReport.Policy.RequireProofOfPossession ||
		!certReport.Policy.RequireDeviceBinding ||
		!certReport.Policy.RevocationAvailable ||
		certReport.Policy.EscrowPolicy == "allow" ||
		len(certReport.Policy.BlockingIssues) > 0 {
		status = "blocked"
	}
	if certReport.Runtime.Rejected > 0 || certReport.Runtime.RevocationBlocked > 0 || certReport.Runtime.WeakKey > 0 {
		if status == "passed" {
			status = "degraded"
		}
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:      "certificate_lifecycle",
		Category: "authentication",
		Label:    "Enterprise Certificate Lifecycle",
		Status:   status,
		Summary: fmt.Sprintf("Certificate lifecycle schema %d is %s in %s mode with templates=%d, active issuer=%s, EST=%t, SCEP=%t, BYOD=%t, and %d recent event(s).",
			certReport.SchemaVersion, certReport.Status, certReport.Policy.Mode,
			len(certReport.Policy.Templates), certReport.Policy.ActiveIssuer,
			certReport.Policy.ESTEnabled, certReport.Policy.SCEPEnabled,
			certReport.Policy.BYODPortalEnabled, certReport.Runtime.TotalEvents),
		Recommendation: "Use onboarding.certificate_lifecycle in enforce/fail-closed mode with CSR proof-of-possession, device binding, CRL or OCSP readiness, guarded issuer rotation, forbidden or admin-approved escrow, and the NAS-0027 release checklist for external EST/SCEP and AP/controller evidence.",
		Dependencies:   []string{"onboarding.certificate_lifecycle", "onboarding.certificate_enrollment_enabled", "onboarding.eap_tls_enabled", "certificate_lifecycle_events", "certificate_lifecycle_inventory", "/api/v1/system/certificate-lifecycle"},
	})
}

func addProductionSupplicantLifecycleCheck(report *productionReadinessReport, cfg *config.Config) {
	summary, _ := db.SummarizeSupplicantLifecycle(1000)
	supplicantReport := supplicantprofile.BuildReport(cfg, supplicantRuntimeSummaryFromDB(summary))
	if !supplicantReport.Policy.Enabled {
		return
	}
	status := "passed"
	switch supplicantReport.Status {
	case "blocked":
		status = "blocked"
	case "disabled", "degraded":
		status = "degraded"
	}
	if supplicantReport.Policy.Mode != "enforce" {
		if status == "passed" {
			status = "degraded"
		}
	}
	if !supplicantReport.Policy.FailClosed ||
		!supplicantReport.Policy.PortalReady ||
		!supplicantReport.Policy.EAPFrameworkReady ||
		!supplicantReport.Policy.CertificateLifecycleReady ||
		!supplicantReport.Policy.RequireTrustAnchorPinning ||
		len(supplicantReport.Policy.TrustAnchorPins) == 0 ||
		len(supplicantReport.Policy.ServerNames) == 0 ||
		!supplicantReport.Policy.RequireTLSForDelivery ||
		!supplicantReport.Policy.RequireSignedProfiles ||
		!supplicantReport.Policy.ProfileSigningKeyConfigured ||
		!supplicantReport.Policy.RequireVerifierCompatibility ||
		len(supplicantReport.Policy.CompatibleVerifiers) == 0 ||
		len(supplicantReport.Policy.BlockingIssues) > 0 {
		status = "blocked"
	}
	if supplicantReport.Runtime.Rejected > 0 ||
		supplicantReport.Runtime.UnsignedProfileBlocked > 0 ||
		supplicantReport.Runtime.TrustPinFailures > 0 ||
		supplicantReport.Runtime.VerifierFailures > 0 ||
		supplicantReport.Runtime.TLSFailures > 0 {
		if status == "passed" {
			status = "degraded"
		}
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:      "supplicant_lifecycle",
		Category: "authentication",
		Label:    "Password And Supplicant Lifecycle",
		Status:   status,
		Summary: fmt.Sprintf("Supplicant lifecycle schema %d is %s in %s mode with platforms=%d, methods=%d, signed profiles=%t, trust pins=%d, and %d recent event(s).",
			supplicantReport.SchemaVersion, supplicantReport.Status, supplicantReport.Policy.Mode,
			len(supplicantReport.Policy.AllowedPlatforms), len(supplicantReport.Policy.AllowedEAPMethods),
			supplicantReport.Policy.RequireSignedProfiles, len(supplicantReport.Policy.TrustAnchorPins),
			supplicantReport.Runtime.TotalEvents),
		Recommendation: "Use onboarding.supplicant_lifecycle in enforce/fail-closed mode with pinned RADIUS server names, signed profile packages, TLS-only delivery, MFA-gated password changes, verifier compatibility evidence, and the NAS-0028 release checklist for real supplicant and AP/controller validation.",
		Dependencies:   []string{"onboarding.supplicant_lifecycle", "onboarding.certificate_lifecycle", "radius.eap.framework", "supplicant_lifecycle_events", "supplicant_profile_deliveries", "/api/v1/system/supplicant-lifecycle"},
	})
}

func addProductionMABCheck(report *productionReadinessReport, cfg *config.Config) {
	mabReport := mabpkg.BuildReport(cfg)
	if !mabReport.Enabled {
		return
	}
	status := "passed"
	switch mabReport.Status {
	case "blocked":
		status = "blocked"
	case "degraded", "disabled":
		status = "degraded"
	}
	if mabReport.Policy.Mode != "enforce" || !mabReport.Policy.FailClosed {
		status = "blocked"
	}
	if mabReport.EndpointSummary.ApprovedCount == 0 && mabReport.EndpointSummary.QuarantinedCount == 0 {
		status = "blocked"
	}
	if mabReport.Policy.AuditEnabled && db.DB == nil {
		status = "blocked"
	}
	if mabReport.Policy.UnknownEndpointPolicy == "fail_open" && status != "blocked" {
		status = "degraded"
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:      "mac_authentication_bypass",
		Category: "authentication",
		Label:    "MAC Authentication Bypass",
		Status:   status,
		Summary: fmt.Sprintf("MAB schema %d is %s in %s mode with %d approved endpoint(s), %d quarantined endpoint(s), unknown policy %s, and %d audited decision(s).",
			mabReport.SchemaVersion, mabReport.Status, mabReport.Policy.Mode,
			mabReport.EndpointSummary.ApprovedCount, mabReport.EndpointSummary.QuarantinedCount,
			mabReport.Policy.UnknownEndpointPolicy, mabReport.AuditSummary.TotalRecords),
		Recommendation: "Set mab.mode=enforce, keep fail_closed=true, approve or quarantine known endpoints, avoid fail_open for production, and review /api/v1/system/mab before enabling MAB SSIDs or switch ports.",
		Dependencies:   []string{"mab", "mab_endpoints", "mab_events", "/api/v1/system/mab", "/api/v1/system/mab/endpoints"},
	})
}

func addProductionDatabaseDataPlaneCheck(report *productionReadinessReport, cfg *config.Config) {
	statusReport := db.BuildStatusReport(cfg)
	status := "passed"
	if statusReport.Status == "blocked" {
		status = "blocked"
	} else if statusReport.Status == "degraded" {
		status = "degraded"
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:      "database_data_plane",
		Category: "architecture",
		Label:    "Database Data Plane",
		Status:   status,
		Summary: fmt.Sprintf("Database backend %s is %s with schema target %d, DSN reference set=%t, TLS mode=%s, and HA-ready=%t.",
			statusReport.Active.Backend, statusReport.Status, db.LatestSchemaVersion(), statusReport.Active.DSNRefSet, statusReport.Active.SSLMode, statusReport.ReadyForHA),
		Recommendation: "Use database.backend=postgres, database.dsn_ref, TLS sslmode verify-full or verify-ca, and managed PostgreSQL backup/HA validation before enterprise production sign-off.",
		Dependencies:   []string{"database.backend", "database.dsn_ref", "database.sslmode", "/api/v1/system/database", "database_backend_events"},
	})
}

func addProductionAttributeRegistryCheck(report *productionReadinessReport) {
	registry, err := productconfigs.BuiltInAttributeRegistry()
	if err != nil {
		addProductionCheck(report, productionReadinessCheck{
			Key: "attribute_registry", Category: "radius", Label: "Typed Attribute Registry", Status: "blocked",
			Summary:        "The generated RADIUS attribute registry could not be validated.",
			Recommendation: "Regenerate the pinned registry, review the source diff, and rebuild the appliance.",
			Dependencies:   []string{"configs/attribute_registry"},
		})
		return
	}
	if registry.SchemaVersion != productconfigs.AttributeRegistrySchemaVersion || registry.SourceAttributeCount != 7654 || registry.SourceFileCount != 246 {
		addProductionCheck(report, productionReadinessCheck{
			Key: "attribute_registry", Category: "radius", Label: "Typed Attribute Registry", Status: "blocked",
			Summary:        fmt.Sprintf("Registry contract mismatch: schema %d, %d source files, %d source attributes.", registry.SchemaVersion, registry.SourceFileCount, registry.SourceAttributeCount),
			Recommendation: "Review and approve the dictionary release diff before activating the new registry.",
			Dependencies:   []string{"attribute registry source manifest"},
		})
		return
	}
	if err := registry.ValidateCompatibilityPacks(productconfigs.AegisNASVendorCompatibilityPacks()); err != nil {
		addProductionCheck(report, productionReadinessCheck{
			Key: "attribute_registry", Category: "radius", Label: "Typed Attribute Registry", Status: "blocked",
			Summary:        "Compatibility pack metadata conflicts with the generated registry: " + err.Error(),
			Recommendation: "Regenerate and review the typed registry and renderer pack declarations together.",
			Dependencies:   []string{"configs/vendor_packs.go", "configs/attribute_registry"},
		})
		return
	}
	addProductionCheck(report, productionReadinessCheck{
		Key: "attribute_registry", Category: "radius", Label: "Typed Attribute Registry", Status: "passed",
		Summary: fmt.Sprintf("FreeRADIUS %s registry schema %d validates %d source attributes with SHA-256 %s.", registry.SourceRelease, registry.SchemaVersion, registry.SourceAttributeCount, registry.SourceSHA256),
	})
}

func addProductionVSACodecCheck(report *productionReadinessReport) {
	registry, err := productconfigs.BuiltInAttributeRegistry()
	if err != nil {
		addProductionCheck(report, productionReadinessCheck{
			Key: "vsa_codec", Category: "radius", Label: "VSA Codec", Status: "blocked",
			Summary:        "The VSA codec cannot be validated because the generated registry is unavailable.",
			Recommendation: "Regenerate the pinned registry and rebuild the appliance before enabling broad vendor compatibility.",
			Dependencies:   []string{"configs/attribute_registry", "internal/radius/vsa_codec.go"},
		})
		return
	}
	codec := radius.BuildVSACodecReport(registry, productconfigs.AegisNASVendorDictionaryCatalog())
	status := "passed"
	if codec.SchemaVersion != radius.VSACodecSchemaVersion || codec.Status != "ready" ||
		codec.Summary.SourceAttributeCount != registry.SourceAttributeCount ||
		codec.Summary.GroupedAttributeCount == 0 ||
		len(codec.SupportedFormats) < 9 {
		status = "blocked"
	}
	addProductionCheck(report, productionReadinessCheck{
		Key: "vsa_codec", Category: "radius", Label: "VSA Codec", Status: status,
		Summary: fmt.Sprintf("Codec schema %d is %s for %d registry attributes, %d grouped/OID attributes, repeated values, tags, malformed lengths, and %d vendor wire formats.",
			codec.SchemaVersion, codec.Status, codec.Summary.SourceAttributeCount, codec.Summary.GroupedAttributeCount, len(codec.SupportedFormats)),
		Recommendation: "Use /api/v1/system/vsa-codec for software readiness and the NAS-0005 release checklist for hardware/vendor certification evidence.",
		Dependencies:   []string{"internal/radius/vsa_codec.go", "configs/attribute_registry.go"},
	})
}

func addProductionOpaquePassThroughCheck(report *productionReadinessReport, cfg *config.Config) {
	registry, err := productconfigs.BuiltInAttributeRegistry()
	if err != nil {
		addProductionCheck(report, productionReadinessCheck{
			Key: "opaque_passthrough", Category: "radius", Label: "Opaque Attribute Pass-through", Status: "blocked",
			Summary:        "The opaque pass-through policy cannot be validated because the generated registry is unavailable.",
			Recommendation: "Regenerate the pinned registry and rebuild the appliance before enabling proxy pass-through.",
			Dependencies:   []string{"configs/attribute_registry", "internal/radius/opaque_passthrough.go"},
		})
		return
	}
	reportPayload := radius.BuildOpaquePassThroughReport(registry, cfg)
	status := "passed"
	if reportPayload.Status != "ready" || reportPayload.SchemaVersion != radius.OpaquePassThroughSchemaVersion ||
		reportPayload.Policy.DefaultAction != "drop" || reportPayload.Limits.MaxAttributesPerPacket < 1 ||
		reportPayload.Limits.MaxAttributeBytes > 249 || len(reportPayload.SensitiveTypes) == 0 {
		status = "blocked"
	}
	addProductionCheck(report, productionReadinessCheck{
		Key: "opaque_passthrough", Category: "radius", Label: "Opaque Attribute Pass-through", Status: status,
		Summary: fmt.Sprintf("Opaque pass-through schema %d is %s with default action %s, %d allow rule(s), %d sensitive standard type denylist entries, and %d byte total packet budget.",
			reportPayload.SchemaVersion, reportPayload.Status, reportPayload.Policy.DefaultAction, reportPayload.Summary.RuleCount, len(reportPayload.SensitiveTypes), reportPayload.Limits.MaxTotalBytesPerPacket),
		Recommendation: "Use /api/v1/system/opaque-passthrough to review the effective allowlist; real proxy and device evidence stays in the NAS-0006 release checklist.",
		Dependencies:   []string{"radius.vendor.opaque_pass_through", "internal/radius/opaque_passthrough.go"},
	})
}

func addProductionSecretProviderCheck(report *productionReadinessReport, cfg *config.Config) {
	stored, err := storedSecretSources()
	if err != nil {
		addProductionCheck(report, productionReadinessCheck{
			Key: "secret_providers", Category: "security", Label: "Secret Providers", Status: "blocked",
			Summary:        "Secret provider inventory cannot be read from the database.",
			Recommendation: "Run database migration and inspect /api/v1/system/secret-providers before production sign-off.",
			Dependencies:   []string{"radius_clients.secret_ref"},
		})
		return
	}
	reportPayload := secrets.BuildReport(context.Background(), cfg, stored)
	status := "passed"
	if reportPayload.Status == "blocked" {
		status = "blocked"
	} else if reportPayload.Status == "degraded" {
		status = "degraded"
	}
	addProductionCheck(report, productionReadinessCheck{
		Key: "secret_providers", Category: "security", Label: "Secret Providers", Status: status,
		Summary: fmt.Sprintf("Secret provider schema %d is %s with %d reference(s), %d inline source(s), %d missing reference(s), and %d unsupported provider source(s).",
			reportPayload.SchemaVersion, reportPayload.Status, reportPayload.Summary.ReferenceCount, reportPayload.Summary.InlineCount, reportPayload.Summary.MissingCount, reportPayload.Summary.UnsupportedCount),
		Recommendation: "Move RADIUS, LDAP, integration, and HA secrets to env: or file: refs; keep external secret-manager rollout evidence in the NAS-0007 release checklist.",
		Dependencies:   []string{"security.secrets", "radius_clients.secret_ref", "/api/v1/system/secret-providers"},
	})
}

func addProductionDictionaryReleaseProfileCheck(report *productionReadinessReport, cfg *config.Config) {
	activeID := productconfigs.DefaultDictionaryReleaseProfileID
	if cfg != nil {
		activeID = productconfigs.EffectiveDictionaryReleaseProfileID(cfg.Radius.Vendor.DictionaryRelease)
	}
	profile, ok := productconfigs.DictionaryReleaseProfileByID(activeID)
	if !ok {
		addProductionCheck(report, productionReadinessCheck{
			Key: "dictionary_release_profile", Category: "radius", Label: "Dictionary Release Profile", Status: "blocked",
			Summary:        "The configured dictionary release profile is not embedded in this build.",
			Recommendation: "Use the pinned release profile shipped with this appliance or install a reviewed build for the requested release.",
			Dependencies:   []string{"radius.vendor.dictionary_release"},
		})
		return
	}
	registry, err := productconfigs.BuiltInAttributeRegistry()
	if err != nil {
		addProductionCheck(report, productionReadinessCheck{
			Key: "dictionary_release_profile", Category: "radius", Label: "Dictionary Release Profile", Status: "blocked",
			Summary:        "The dictionary release profile cannot be validated because the attribute registry is unavailable.",
			Recommendation: "Regenerate the pinned registry and rebuild the appliance.",
			Dependencies:   []string{"attribute_registry"},
		})
		return
	}
	if err := productconfigs.ValidateDictionaryReleaseProfile(profile, registry, productconfigs.AegisNASVendorCompatibilityPacks()); err != nil {
		addProductionCheck(report, productionReadinessCheck{
			Key: "dictionary_release_profile", Category: "radius", Label: "Dictionary Release Profile", Status: "blocked",
			Summary:        "The dictionary release profile is inconsistent with the registry or compatibility packs: " + err.Error(),
			Recommendation: "Review the release profile, alias table, firmware scopes, registry hash, and compatibility pack metadata together.",
			Dependencies:   []string{"configs/dictionary_release_profiles.go", "configs/attribute_registry"},
		})
		return
	}
	addProductionCheck(report, productionReadinessCheck{
		Key: "dictionary_release_profile", Category: "radius", Label: "Dictionary Release Profile", Status: "passed",
		Summary: fmt.Sprintf("Active profile %s pins FreeRADIUS %s with %d vendor aliases, %d attribute aliases, and %d firmware scopes.", profile.ID, profile.Release, profile.VendorAliasCount, profile.AttributeAliasCount, profile.FirmwareProfileCount),
	})
}

func addProductionCompatibilityEvidenceCheck(report *productionReadinessReport, cfg *config.Config) {
	compatibility := productconfigs.AegisNASVendorCompatibilityReport()
	if cfg != nil && len(cfg.Radius.Vendor.CompatibilityPacks) > 0 {
		compatibility.ActivePacks = normalizeVendorCompatibilityPackKeys(cfg.Radius.Vendor.CompatibilityPacks)
	}
	if cfg != nil {
		vendor := cfg.Radius.Vendor
		compatibility.Catalog = productconfigs.AegisNASVendorDictionaryCatalogFor(vendor.Name, vendor.ID)
		for index := range compatibility.Packs {
			if compatibility.Packs[index].Key == productconfigs.VendorPackAegisNAS {
				compatibility.Packs[index].VendorName = strings.TrimSpace(vendor.Name)
				compatibility.Packs[index].VendorID = vendor.ID
			}
		}
	}
	importPaths := vendorDictionaryImportPaths(cfg)
	if len(importPaths) > 0 {
		imported := productconfigs.LoadVendorDictionaryCatalog(importPaths)
		compatibility.Catalog = productconfigs.MergeVendorDictionaryCatalogs("built-in AegisNAS, "+imported.Source, compatibility.Catalog, imported)
	}
	evidence := productconfigs.BuildCompatibilityEvidenceReport(compatibility.Catalog, compatibility.Packs, compatibility.ActivePacks)
	if err := productconfigs.ValidateCompatibilityEvidenceReport(evidence); err != nil {
		addProductionCheck(report, productionReadinessCheck{
			Key: "compatibility_evidence", Category: "radius", Label: "Compatibility Evidence Model", Status: "blocked",
			Summary:        "Compatibility evidence could not be validated: " + err.Error(),
			Recommendation: "Review the evidence model, registry, vendor packs, and dictionary release profile before claiming compatibility.",
			Dependencies:   []string{"configs/compatibility_evidence.go", "configs/vendor_packs.go", "configs/attribute_registry"},
		})
		return
	}
	activeBlocked := 0
	for _, record := range evidence.Records {
		if record.Active && record.SoftwareState == productconfigs.EvidenceSoftwareStateBlocked {
			activeBlocked++
		}
	}
	status := "passed"
	if activeBlocked > 0 {
		status = "degraded"
	}
	addProductionCheck(report, productionReadinessCheck{
		Key: "compatibility_evidence", Category: "radius", Label: "Compatibility Evidence Model", Status: status,
		Summary: fmt.Sprintf("Evidence schema %d tracks %d mappings: %d software-ready, %d planned, %d blocked (%d active), %d requiring external certification.",
			evidence.SchemaVersion, evidence.Summary.TotalRecords, evidence.Summary.SoftwareReadyCount, evidence.Summary.SoftwarePlannedCount, evidence.Summary.SoftwareBlockedCount, activeBlocked, evidence.Summary.ExternalRequiredCount),
		Recommendation: "Use /api/v1/system/compatibility-evidence before publishing vendor compatibility claims.",
	})
}

func addProductionRadSecCheck(report *productionReadinessReport, cfg *config.Config) {
	paths := []string{}
	if cfg.Radius.RadSec.Enabled {
		paths = append(paths, cfg.Radius.RadSec.CertificateFile, cfg.Radius.RadSec.PrivateKeyFile)
		if cfg.Radius.RadSec.CAFile != "" {
			paths = append(paths, cfg.Radius.RadSec.CAFile)
		}
		if env := strings.TrimSpace(cfg.Radius.RadSec.PrivateKeyPasswordEnv); env != "" && os.Getenv(env) == "" {
			addProductionCheck(report, productionReadinessCheck{Key: "radsec_key_environment", Category: "security", Label: "RadSec Key Password Environment", Status: "blocked", Summary: "RadSec private key password environment variable " + env + " is not set.", Recommendation: "Set the systemd service environment securely before applying RadSec configuration.", Dependencies: []string{env}})
			return
		}
	}
	peerCount := 0
	pskPeerCount := 0
	pskDependencies := []string{}
	for _, server := range cfg.Radius.Upstream.Servers {
		if !strings.EqualFold(strings.TrimSpace(server.Transport), "radsec") {
			continue
		}
		peerCount++
		if server.RadSec.PSK.Enabled {
			pskPeerCount++
			for _, ref := range []string{server.RadSec.PSK.SecretRef, server.RadSec.PSK.NextSecretRef} {
				ref = strings.TrimSpace(ref)
				if ref == "" {
					continue
				}
				if !secretRefAvailable(ref) {
					pskDependencies = append(pskDependencies, ref)
				}
			}
			continue
		}
		paths = append(paths, server.RadSec.CertificateFile, server.RadSec.PrivateKeyFile)
		if server.RadSec.CAFile != "" {
			paths = append(paths, server.RadSec.CAFile)
		}
		if env := strings.TrimSpace(server.RadSec.PrivateKeyPasswordEnv); env != "" && os.Getenv(env) == "" {
			addProductionCheck(report, productionReadinessCheck{Key: "radsec_key_environment", Category: "security", Label: "RadSec Key Password Environment", Status: "blocked", Summary: "RadSec private key password environment variable " + env + " is not set.", Recommendation: "Set the systemd service environment securely before applying RadSec configuration.", Dependencies: []string{env}})
			return
		}
	}
	if !cfg.Radius.RadSec.Enabled && peerCount == 0 {
		return
	}
	credentialReport := radius.BuildRadSecCredentialReport(cfg)
	if len(pskDependencies) > 0 {
		addProductionCheck(report, productionReadinessCheck{Key: "radsec_psk_secret_refs", Category: "security", Label: "RadSec TLS-PSK Secret References", Status: "blocked", Summary: "RadSec TLS-PSK secret references are unavailable: " + strings.Join(pskDependencies, ", "), Recommendation: "Set referenced environment variables or install referenced files before applying PSK RadSec configuration.", Dependencies: pskDependencies})
		return
	}
	missing := []string{}
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		if info, err := os.Stat(path); err != nil || info.IsDir() {
			missing = append(missing, path)
		}
	}
	if len(missing) > 0 {
		addProductionCheck(report, productionReadinessCheck{Key: "radsec_credentials", Category: "security", Label: "RadSec Credentials", Status: "blocked", Summary: "RadSec certificate, key, or CA files are unavailable: " + strings.Join(missing, ", "), Recommendation: "Install the mTLS identity and trust files with root ownership and least-privilege service access.", Dependencies: missing})
		return
	}
	if credentialReport.Status == "blocked" {
		addProductionCheck(report, productionReadinessCheck{Key: "radsec_credentials", Category: "security", Label: "RadSec Credentials", Status: "blocked", Summary: credentialReport.Message, Recommendation: "Review /api/v1/system/radsec-credentials and fix blocked mTLS or PSK credential state.", Dependencies: credentialReport.Warnings})
		return
	}
	status := "passed"
	if credentialReport.Status == "degraded" {
		status = "degraded"
	}
	addProductionCheck(report, productionReadinessCheck{Key: "radsec_credentials", Category: "security", Label: "RadSec Credentials", Status: status, Summary: fmt.Sprintf("RadSec credentials are configured for %d mTLS endpoint(s) and %d TLS-PSK endpoint(s).", credentialReport.Summary.MTLSEndpoints, credentialReport.Summary.PSKEndpoints), Recommendation: "Use /api/v1/system/radsec-credentials during every RadSec credential rotation."})
}

func secretRefAvailable(ref string) bool {
	scheme, value, ok := strings.Cut(strings.TrimSpace(ref), ":")
	if !ok {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(scheme)) {
	case "env":
		return os.Getenv(strings.TrimSpace(value)) != ""
	case "file":
		info, err := os.Stat(strings.TrimSpace(value))
		return err == nil && !info.IsDir()
	default:
		return false
	}
}

func buildProductionVendorIdentityState(cfg *config.Config) productionVendorIdentityState {
	identity := productconfigs.AegisNASVendorIdentity()
	vendor := cfg.Radius.Vendor
	configuredID := vendor.ID
	idSource := identity.IDSource
	if configuredID != identity.ID {
		idSource = "config:radius.vendor.id"
	}
	importPaths := vendorDictionaryImportPaths(cfg)
	state := productionVendorIdentityState{
		Enabled:                    vendor.Enabled,
		Name:                       strings.TrimSpace(vendor.Name),
		ConfiguredID:               configuredID,
		ConfiguredIDPlaceholder:    configuredID == productconfigs.AegisNASPlaceholderVendorID,
		IDSource:                   idSource,
		DictionaryFilename:         identity.DictionaryFilename,
		DictionaryInstallPath:      productconfigs.AegisNASVendorDictionaryInstallPath(""),
		DictionaryInclude:          identity.IncludeLine,
		DictionaryDetected:         productDictionaryDetected(cfg, importPaths),
		DictionaryImportPaths:      importPaths,
		PENRegistryURL:             identity.RegistryURL,
		PENApplyURL:                identity.ApplyURL,
		ProductCompatibilityActive: normalizedProductionPackSet(vendor.CompatibilityPacks)[productconfigs.VendorPackAegisNAS],
		IdentityMode:               strings.ToLower(strings.TrimSpace(vendor.IdentityMode)),
		AssignedOrganization:       strings.TrimSpace(vendor.AssignedOrganization),
		AssignmentRecordSHA256:     strings.TrimSpace(vendor.AssignmentRecordSHA),
		LegacyIDs:                  append([]int(nil), vendor.LegacyIDs...),
		LegacyAcceptUntil:          strings.TrimSpace(vendor.LegacyAcceptUntil),
	}
	if evidence, err := config.RadiusVendorAssignmentEvidence(vendor); err == nil {
		state.EvidenceValid = evidence.Validate(vendor.ID, vendor.AssignedOrganization) == nil
	}
	if db.DB != nil {
		if assignment, err := db.ActiveVendorIdentityAssignment(db.DB); err == nil && assignment != nil {
			state.AssignmentActive = assignment.PEN == uint32(vendor.ID) && assignment.RecordSHA256 == vendor.AssignmentRecordSHA
		}
	}
	return state
}

func productDictionaryDetected(cfg *config.Config, importPaths []string) bool {
	if cfg == nil || len(importPaths) == 0 {
		return false
	}
	catalog := productconfigs.LoadVendorDictionaryCatalog(importPaths)
	vendor, ok := catalog.VendorByName(cfg.Radius.Vendor.Name)
	return ok && vendor.ID == cfg.Radius.Vendor.ID
}

func vendorProfileSummaryForProductionReadiness(cfg *config.Config) vendorCompatibilityProfileSummary {
	_, summary, err := loadVendorCompatibilityClientProfiles(cfg)
	if err != nil {
		summary.UnknownProfiles = append(summary.UnknownProfiles, "profile-read-error: "+err.Error())
	}
	return summary
}

func vendorRuntimeSummaryForProductionReadiness(report *productionReadinessReport) db.VendorObservabilitySummary {
	summary, err := db.GetVendorObservabilitySummary()
	if err != nil {
		addProductionCheck(report, productionReadinessCheck{
			Key:            "vendor_runtime_read",
			Category:       "observability",
			Label:          "Vendor Runtime Read",
			Status:         "degraded",
			Summary:        "Vendor runtime counters could not be read: " + err.Error(),
			Recommendation: "Check the database connection before using the production readiness report as a sign-off artifact.",
		})
		return db.VendorObservabilitySummary{}
	}
	return summary
}

func addProductionConfigCheck(report *productionReadinessReport, cfg *config.Config) {
	if err := cfg.Validate(); err != nil {
		addProductionCheck(report, productionReadinessCheck{
			Key:            "config_validation",
			Category:       "configuration",
			Label:          "Configuration Validation",
			Status:         "blocked",
			Summary:        err.Error(),
			Recommendation: "Fix configuration validation errors before production deployment.",
		})
		return
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:      "config_validation",
		Category: "configuration",
		Label:    "Configuration Validation",
		Status:   "passed",
		Summary:  "Configuration validation passes.",
	})
}

func addProductionScalingCheck(report *productionReadinessReport) {
	scaling := report.HardwareScaling
	switch {
	case !scaling.HardwareKnown:
		addProductionCheck(report, productionReadinessCheck{
			Key:            "hardware_scaling",
			Category:       "deployment",
			Label:          "Hardware Scaling",
			Status:         "blocked",
			Summary:        "CPU and memory are not declared for this appliance.",
			Recommendation: "Set deployment.hardware.cpu_cores and deployment.hardware.memory_mb before production deployment.",
			Dependencies:   []string{"deployment.hardware.cpu_cores", "deployment.hardware.memory_mb"},
		})
	case !scaling.CanRunSelected:
		addProductionCheck(report, productionReadinessCheck{
			Key:            "hardware_scaling",
			Category:       "deployment",
			Label:          "Hardware Scaling",
			Status:         "blocked",
			Summary:        scaling.Summary,
			Recommendation: "Lower the selected deployment profile or move to hardware that matches the selected profile.",
			Dependencies:   []string{"deployment.profile", "deployment.hardware.memory_mb", "deployment.hardware.cpu_cores", "deployment.hardware.storage_gb"},
		})
	case !scaling.StorageKnown:
		addProductionCheck(report, productionReadinessCheck{
			Key:            "hardware_scaling",
			Category:       "deployment",
			Label:          "Hardware Scaling",
			Status:         "warned",
			Summary:        scaling.Reason,
			Recommendation: "Set deployment.hardware.storage_gb so retention and history features can be sized intentionally.",
			Dependencies:   []string{"deployment.hardware.storage_gb"},
		})
	default:
		addProductionCheck(report, productionReadinessCheck{
			Key:      "hardware_scaling",
			Category: "deployment",
			Label:    "Hardware Scaling",
			Status:   "passed",
			Summary:  scaling.Summary,
		})
	}
}

func addProductionVendorIdentityCheck(report *productionReadinessReport) {
	identity := report.VendorIdentity
	switch {
	case !identity.Enabled:
		addProductionCheck(report, productionReadinessCheck{
			Key:            "vendor_identity",
			Category:       "vendor",
			Label:          "AegisNAS Vendor Identity",
			Status:         "warned",
			Summary:        "AegisNAS product VSAs are disabled; standards-based RADIUS can deploy, but product-vendor mode is not active.",
			Recommendation: "Enable radius.vendor.enabled after receiving an IANA Private Enterprise Number if this appliance should identify as its own vendor.",
			Dependencies:   []string{"radius.vendor.enabled", "radius.vendor.id"},
		})
	case identity.ConfiguredIDPlaceholder:
		addProductionCheck(report, productionReadinessCheck{
			Key:            "vendor_identity",
			Category:       "vendor",
			Label:          "AegisNAS Vendor Identity",
			Status:         "blocked",
			Summary:        fmt.Sprintf("AegisNAS product VSAs are enabled with the lab placeholder vendor ID %d.", productconfigs.AegisNASPlaceholderVendorID),
			Recommendation: "Request an IANA Private Enterprise Number, wait for publication, and use the verified Vendor Identity preview/apply workflow.",
			Dependencies:   []string{"radius.vendor.id", "vendor_identity_assignments"},
		})
	case identity.IdentityMode != "production" || !identity.EvidenceValid || !identity.AssignmentActive:
		addProductionCheck(report, productionReadinessCheck{
			Key:            "vendor_identity",
			Category:       "vendor",
			Label:          "AegisNAS Vendor Identity",
			Status:         "blocked",
			Summary:        fmt.Sprintf("AegisNAS PEN %d does not have matching verified IANA evidence and an active assignment record.", identity.ConfiguredID),
			Recommendation: "Use the Vendor Identity preview/apply workflow after IANA assigns the PEN; do not activate arbitrary non-placeholder values.",
			Dependencies:   []string{"radius.vendor.identity_mode", "vendor_identity_assignments"},
		})
	default:
		addProductionCheck(report, productionReadinessCheck{
			Key:      "vendor_identity",
			Category: "vendor",
			Label:    "AegisNAS Vendor Identity",
			Status:   "passed",
			Summary:  fmt.Sprintf("AegisNAS product PEN %d is verified for %s and matches the active assignment record.", identity.ConfiguredID, identity.AssignedOrganization),
		})
	}
}

func addProductionDictionaryCheck(report *productionReadinessReport) {
	identity := report.VendorIdentity
	if !identity.Enabled {
		return
	}
	if identity.DictionaryDetected {
		addProductionCheck(report, productionReadinessCheck{
			Key:      "product_dictionary",
			Category: "vendor",
			Label:    "Product Dictionary Install",
			Status:   "passed",
			Summary:  "AegisNAS product dictionary was detected in the configured FreeRADIUS dictionary imports.",
		})
		return
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:            "product_dictionary",
		Category:       "vendor",
		Label:          "Product Dictionary Install",
		Status:         "warned",
		Summary:        "AegisNAS product dictionary was not detected in the configured or standard FreeRADIUS dictionary import paths.",
		Recommendation: "Install dictionary.aegisnas and include it from the local FreeRADIUS dictionary before hardware smoke tests.",
		Dependencies:   []string{"radius.vendor.dictionary_paths", identity.DictionaryInstallPath},
	})
}

func addProductionVendorPackCheck(report *productionReadinessReport, cfg *config.Config) {
	packs := normalizedProductionPackSet(cfg.Radius.Vendor.CompatibilityPacks)
	if len(packs) == 0 {
		addProductionCheck(report, productionReadinessCheck{
			Key:            "vendor_packs",
			Category:       "vendor",
			Label:          "Vendor Compatibility Packs",
			Status:         "blocked",
			Summary:        "No valid vendor compatibility packs are configured.",
			Recommendation: "Enable at least the standard pack and every access-device family used by this deployment.",
			Dependencies:   []string{"radius.vendor.compatibility_packs"},
		})
		return
	}
	if cfg.Radius.Vendor.Enabled && !packs[productconfigs.VendorPackAegisNAS] {
		addProductionCheck(report, productionReadinessCheck{
			Key:            "vendor_packs",
			Category:       "vendor",
			Label:          "Vendor Compatibility Packs",
			Status:         "warned",
			Summary:        "Product VSAs are enabled, but the aegisnas compatibility pack is not active.",
			Recommendation: "Add aegisnas to radius.vendor.compatibility_packs when access devices or upstream AAA should consume AegisNAS VSAs.",
			Dependencies:   []string{"radius.vendor.compatibility_packs"},
		})
		return
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:      "vendor_packs",
		Category: "vendor",
		Label:    "Vendor Compatibility Packs",
		Status:   "passed",
		Summary:  fmt.Sprintf("%d valid vendor compatibility pack(s) configured.", len(packs)),
	})
}

func addProductionNASProfileCheck(report *productionReadinessReport) {
	summary := report.NASProfileSummary
	switch {
	case len(summary.UnknownProfiles) > 0:
		addProductionCheck(report, productionReadinessCheck{
			Key:            "nas_profile_coverage",
			Category:       "vendor",
			Label:          "NAS Profile Coverage",
			Status:         "blocked",
			Summary:        "One or more enabled RADIUS clients use unknown NAS profiles: " + strings.Join(summary.UnknownProfiles, ", "),
			Recommendation: "Set each RADIUS client nas_type to a known vendor pack or explicitly use other for standards-only clients.",
			Dependencies:   []string{"radius_clients.nas_type"},
		})
	case summary.EnabledClients == 0:
		addProductionCheck(report, productionReadinessCheck{
			Key:            "nas_profile_coverage",
			Category:       "vendor",
			Label:          "NAS Profile Coverage",
			Status:         "warned",
			Summary:        "No enabled RADIUS clients are present in the appliance database.",
			Recommendation: "Add APs, controllers, switches, or VPN gateways before production smoke testing.",
			Dependencies:   []string{"radius_clients"},
		})
	case summary.GlobalFallbackClientCount > 0:
		addProductionCheck(report, productionReadinessCheck{
			Key:            "nas_profile_coverage",
			Category:       "vendor",
			Label:          "NAS Profile Coverage",
			Status:         "warned",
			Summary:        fmt.Sprintf("%d RADIUS client(s) use global or standards-only compatibility packs.", summary.GlobalFallbackClientCount),
			Recommendation: "Use known vendor NAS profiles for devices that need vendor-specific replies.",
			Dependencies:   []string{"radius_clients.nas_type"},
		})
	default:
		addProductionCheck(report, productionReadinessCheck{
			Key:      "nas_profile_coverage",
			Category: "vendor",
			Label:    "NAS Profile Coverage",
			Status:   "passed",
			Summary:  fmt.Sprintf("%d enabled RADIUS client(s) use known vendor profiles.", summary.EnabledClients),
		})
	}
}

func addProductionFeatureCapabilityCheck(report *productionReadinessReport, cfg *config.Config) {
	capabilities := config.EvaluateFeatureCapabilities(cfg)
	blocked := activeCapabilityLabels(capabilities, config.CapabilityBlocked)
	degraded := activeCapabilityLabels(capabilities, config.CapabilityDegraded)
	warned := activeCapabilityLabels(capabilities, config.CapabilityWarned)

	switch {
	case len(blocked) > 0:
		addProductionCheck(report, productionReadinessCheck{
			Key:            "feature_capabilities",
			Category:       "features",
			Label:          "Feature Capability Gates",
			Status:         "blocked",
			Summary:        "Active features are blocked by deployment, hardware, or integration readiness: " + strings.Join(blocked, ", "),
			Recommendation: "Disable blocked features or satisfy their dependencies before production deployment.",
		})
	case len(degraded) > 0:
		addProductionCheck(report, productionReadinessCheck{
			Key:            "feature_capabilities",
			Category:       "features",
			Label:          "Feature Capability Gates",
			Status:         "degraded",
			Summary:        "Active features are degraded: " + strings.Join(degraded, ", "),
			Recommendation: "Review degraded feature dependencies before treating this node as production-ready.",
		})
	case len(warned) > 0:
		addProductionCheck(report, productionReadinessCheck{
			Key:            "feature_capabilities",
			Category:       "features",
			Label:          "Feature Capability Gates",
			Status:         "warned",
			Summary:        "Active features have production warnings: " + strings.Join(warned, ", "),
			Recommendation: "Review warnings and confirm they match the intended deployment profile.",
		})
	default:
		addProductionCheck(report, productionReadinessCheck{
			Key:      "feature_capabilities",
			Category: "features",
			Label:    "Feature Capability Gates",
			Status:   "passed",
			Summary:  "No active feature capability blockers or warnings were found.",
		})
	}
}

func addProductionControllerCheck(report *productionReadinessReport, cfg *config.Config) {
	if !cfg.Integrations.Controller.Enabled {
		return
	}
	state := buildControllerAdapterConfiguredState(cfg)
	if state.Ready {
		addProductionCheck(report, productionReadinessCheck{
			Key:      "controller_readiness",
			Category: "integrations",
			Label:    "Controller Readiness",
			Status:   "passed",
			Summary:  fmt.Sprintf("%s controller adapter is configured for %s sync.", state.Adapter, state.SyncMode),
		})
		return
	}
	dependencies := []string{"integrations.controller.endpoint", "integrations.controller.api_token_env", "integrations.controller.site"}
	recommendation := "Set endpoint, API token environment variable, and any required site or network identifier."
	if state.Normalized == "cisco" {
		dependencies = []string{"integrations.controller.endpoint", "integrations.controller.api_username_env", "integrations.controller.api_password_env", "integrations.controller.site"}
		recommendation = "Set the Cisco ISE endpoint, API username/password environment variables, and site identifier."
	} else if state.Normalized == "aruba" {
		dependencies = []string{"integrations.controller.endpoint", "integrations.controller.api_token_env", "integrations.controller.site", "integrations.controller.radius_profile"}
		recommendation = "Set the Aruba Central endpoint, API token environment variable, group identifier, and existing RADIUS profile name."
	} else if state.Normalized == "juniper-mist" {
		dependencies = []string{"integrations.controller.endpoint", "integrations.controller.api_token_env", "integrations.controller.site", "integrations.controller.radius_server", "integrations.controller.radius_secret_env"}
		recommendation = "Set the Mist regional API endpoint, API token environment variable, site ID, RADIUS server, and RADIUS shared-secret environment variable."
	} else if state.Normalized == "ruckus" {
		dependencies = []string{"integrations.controller.endpoint", "integrations.controller.api_username_env", "integrations.controller.api_password_env", "integrations.controller.site", "integrations.controller.radius_profile"}
		recommendation = "Set the SmartZone endpoint, API username/password environment variables, zone ID, and existing authentication service name."
	} else if state.Normalized == "fortinet" {
		dependencies = []string{"integrations.controller.endpoint", "integrations.controller.api_token_env", "integrations.controller.site", "integrations.controller.radius_profile"}
		recommendation = "Set the FortiGate endpoint, REST API token environment variable, VDOM, and existing RADIUS profile name."
	} else if state.Normalized == "mikrotik" {
		dependencies = []string{"integrations.controller.endpoint", "integrations.controller.api_username_env", "integrations.controller.api_password_env", "integrations.controller.site", "integrations.controller.radius_server", "integrations.controller.radius_secret_env"}
		recommendation = "Set the RouterOS HTTPS endpoint, API username/password environment variables, managed-site label, RADIUS server, and RADIUS shared-secret environment variable."
	} else if state.Normalized == "unifi" {
		dependencies = []string{"integrations.controller.endpoint", "integrations.controller.api_token_env", "integrations.controller.site", "integrations.controller.radius_profile"}
		recommendation = "Set the UniFi Network integration API base URL, API key environment variable, site ID, and existing RADIUS profile name."
	} else if state.Normalized == "meraki" {
		dependencies = []string{"integrations.controller.endpoint", "integrations.controller.api_token_env", "integrations.controller.site", "integrations.controller.radius_server", "integrations.controller.radius_secret_env"}
		recommendation = "Set the Meraki Dashboard API v1 base URL, API key environment variable, network ID, RADIUS server, and RADIUS shared-secret environment variable."
	} else if state.Normalized == "openwifi" {
		dependencies = []string{"integrations.controller.endpoint", "integrations.controller.api_token_env", "integrations.controller.site", "integrations.controller.radius_server", "integrations.controller.radius_secret_env"}
		recommendation = "Set the OpenWiFi Gateway API v1 base URL, API key environment variable, venue UUID or AP serial number, RADIUS server, and RADIUS shared-secret environment variable."
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:            "controller_readiness",
		Category:       "integrations",
		Label:          "Controller Readiness",
		Status:         "blocked",
		Summary:        "Controller automation is enabled but not ready: " + strings.Join(state.ReadinessWarnings, "; "),
		Recommendation: recommendation,
		Dependencies:   dependencies,
	})
}

func addProductionVendorRuntimeCheck(report *productionReadinessReport) {
	summary := report.VendorRuntime
	switch {
	case summary.TotalVendors == 0:
		addProductionCheck(report, productionReadinessCheck{
			Key:            "vendor_runtime_evidence",
			Category:       "observability",
			Label:          "Vendor Runtime Evidence",
			Status:         "warned",
			Summary:        "No vendor observability counters have been recorded yet.",
			Recommendation: "Run AP/controller authentication, accounting, CoA, and rollback smoke tests before production sign-off.",
		})
	case summary.VSAParseFailureCount > 0 || summary.CoAFailureCount > 0 || summary.DisconnectFailureCount > 0:
		addProductionCheck(report, productionReadinessCheck{
			Key:            "vendor_runtime_evidence",
			Category:       "observability",
			Label:          "Vendor Runtime Evidence",
			Status:         "degraded",
			Summary:        "Vendor runtime counters include VSA parse, CoA, or disconnect failures.",
			Recommendation: "Resolve vendor runtime failures or document a deployment exception before production sign-off.",
		})
	case summary.UnsupportedAttributeCount > 0 || summary.AuthFailureCount > 0:
		addProductionCheck(report, productionReadinessCheck{
			Key:            "vendor_runtime_evidence",
			Category:       "observability",
			Label:          "Vendor Runtime Evidence",
			Status:         "warned",
			Summary:        "Vendor runtime counters include auth failures or unsupported attributes.",
			Recommendation: "Review vendor observability details and confirm failures are expected test cases.",
		})
	default:
		addProductionCheck(report, productionReadinessCheck{
			Key:      "vendor_runtime_evidence",
			Category: "observability",
			Label:    "Vendor Runtime Evidence",
			Status:   "passed",
			Summary:  fmt.Sprintf("%d vendor profile(s) have clean runtime counters.", summary.TotalVendors),
		})
	}
}

func addProductionCheck(report *productionReadinessReport, check productionReadinessCheck) {
	check.Status = strings.ToLower(strings.TrimSpace(check.Status))
	check.Dependencies = uniqueSortedStrings(check.Dependencies)
	report.Checks = append(report.Checks, check)
	switch check.Status {
	case "blocked":
		report.BlockingCount++
	case "degraded":
		report.DegradedCount++
	case "warned":
		report.WarningCount++
	default:
		report.PassingCount++
	}
}

func finalizeProductionReadinessReport(report *productionReadinessReport) {
	switch {
	case report.BlockingCount > 0:
		report.Status = "blocked"
		report.Message = fmt.Sprintf("Production readiness is blocked by %d required check(s).", report.BlockingCount)
	case report.DegradedCount > 0:
		report.Status = "degraded"
		report.Message = fmt.Sprintf("Production readiness has %d degraded check(s) that need review.", report.DegradedCount)
	case report.WarningCount > 0:
		report.Status = "warned"
		report.Message = fmt.Sprintf("Production readiness has %d warning check(s) to review before sign-off.", report.WarningCount)
	default:
		report.Status = "ready"
		report.Message = "Production readiness checks passed."
	}
	report.Ready = report.Status == "ready"
	report.Score = productionReadinessScore(report)
}

func productionReadinessScore(report *productionReadinessReport) int {
	score := 100 - report.BlockingCount*20 - report.DegradedCount*10 - report.WarningCount*5
	if score < 0 {
		return 0
	}
	return score
}

func productionReadinessSummaryFromReport(report productionReadinessReport) productionReadinessSummary {
	return productionReadinessSummary{
		Status:        report.Status,
		Ready:         report.Ready,
		Score:         report.Score,
		Message:       report.Message,
		BlockingCount: report.BlockingCount,
		WarningCount:  report.WarningCount,
		DegradedCount: report.DegradedCount,
		PassingCount:  report.PassingCount,
	}
}

func activeCapabilityLabels(capabilities []config.FeatureCapability, state string) []string {
	var labels []string
	for _, capability := range capabilities {
		if capability.Active && capability.State == state {
			labels = append(labels, capability.Label)
		}
	}
	sort.Strings(labels)
	return labels
}

func normalizedProductionPackSet(keys []string) map[string]bool {
	set := map[string]bool{}
	for _, key := range normalizeVendorCompatibilityPackKeys(keys) {
		set[key] = true
	}
	return set
}

func uniqueSortedStrings(values []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
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

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
