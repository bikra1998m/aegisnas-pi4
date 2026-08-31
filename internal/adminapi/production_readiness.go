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
	"github.com/yourorg/aegisnas-pi4/internal/enforcement"
	"github.com/yourorg/aegisnas-pi4/internal/identity"
	mabpkg "github.com/yourorg/aegisnas-pi4/internal/mab"
	mfapkg "github.com/yourorg/aegisnas-pi4/internal/mfa"
	"github.com/yourorg/aegisnas-pi4/internal/policy"
	"github.com/yourorg/aegisnas-pi4/internal/radius"
	"github.com/yourorg/aegisnas-pi4/internal/secrets"
	"github.com/yourorg/aegisnas-pi4/internal/supplicantprofile"
	"github.com/yourorg/aegisnas-pi4/internal/tacacs"
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
	addProductionOutboundDACClientCheck(&report, cfg)
	addProductionNASCapabilityOwnershipCheck(&report, cfg)
	addProductionDACHandoffCheck(&report, cfg)
	addProductionProxyRoutingCheck(&report, cfg)
	addProductionTransportPolicyCheck(&report, cfg)
	addProductionProxyPolicyCheck(&report, cfg)
	addProductionAccountingSpoolCheck(&report, cfg)
	addProductionAccountingIngestSpoolCheck(&report, cfg)
	addProductionAccountingChargingCheck(&report, cfg)
	addProductionSQLAccountingCheck(&report, cfg)
	addProductionAccountingOrderingCheck(&report, cfg)
	addProductionAccountingCountersCheck(&report, cfg)
	addProductionAccountingIPCheck(&report, cfg)
	addProductionAccountingServicesCheck(&report, cfg)
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
	addProductionACLASTCheck(&report)
	addProductionACLCompilerCheck(&report)
	addProductionRuntimeFirewallCheck(&report)
	addProductionRuntimeQoSCheck(&report, cfg)
	addProductionVLANLifecycleCheck(&report, cfg)
	addProductionSubscriberRouteExportCheck(&report, cfg)
	addProductionAtomicEnforcementCheck(&report, cfg)
	addProductionVLANPolicyCheck(&report, cfg)
	addProductionRoutePolicyCheck(&report, cfg)
	addProductionAddressPolicyCheck(&report, cfg)
	addProductionTranslationPolicyCheck(&report, cfg)
	addProductionRateCompilerCheck(&report)
	addProductionPolicySetGovernanceCheck(&report, cfg)
	addProductionPolicySimulationAnalysisCheck(&report, cfg)
	addProductionSubscriberServiceChainsCheck(&report, cfg)
	addProductionTACACSCheck(&report, cfg)
	addProductionTenantIsolationCheck(&report, cfg)
	addProductionCertificateLifecycleCheck(&report, cfg)
	addProductionSupplicantLifecycleCheck(&report, cfg)
	addProductionMABCheck(&report, cfg)
	addProductionSecretProviderCheck(&report, cfg)
	addProductionDatabaseDataPlaneCheck(&report, cfg)
	addProductionDictionaryReleaseProfileCheck(&report, cfg)
	addProductionCompatibilityEvidenceCheck(&report, cfg)
	addProductionVendorMappingCertificationCheck(&report, cfg)
	addProductionCiscoFamilyPackCheck(&report)
	addProductionArubaFamilyPackCheck(&report)
	addProductionJuniperExtremePackCheck(&report)
	addProductionRuckusICXPackCheck(&report)
	addProductionFortinetPaloAltoPackCheck(&report)
	addProductionCloudControllerPackCheck(&report)
	addProductionAccessVendorPackCheck(&report)
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

func addProductionOutboundDACClientCheck(report *productionReadinessReport, cfg *config.Config) {
	dac := radius.BuildOutboundDACReport(cfg)
	status := "passed"
	switch dac.Status {
	case "blocked":
		status = "blocked"
	case "disabled", "degraded":
		status = "blocked"
	}
	policy := config.EffectiveDynamicAuthConfig(cfg.Radius.DynamicAuth)
	if !policy.OutboundEnabled || !policy.OutboundRequireKnownClient ||
		policy.OutboundDefaultPort < 1 || policy.OutboundTimeoutSeconds < 1 ||
		policy.OutboundHistoryLimit < 1 || policy.OutboundMaxAttributes < 1 ||
		(!policy.OutboundAllowCoA && !policy.OutboundAllowDisconnect) ||
		!policy.OutboundRequireConfirmation || !policy.OutboundQueueEnabled ||
		!policy.OutboundReplayEnabled || policy.OutboundMaxQueueRecords < 1 ||
		policy.OutboundMaxAttempts < 1 || policy.OutboundBatchSize < 1 ||
		policy.OutboundInitialRetrySeconds < 1 ||
		policy.OutboundMaxRetrySeconds < policy.OutboundInitialRetrySeconds ||
		policy.OutboundRecordTTLSeconds < policy.OutboundMaxRetrySeconds ||
		policy.OutboundLockSeconds < 1 || !policy.OutboundProxyEnabled ||
		(!policy.OutboundProxyAllowUDP && !policy.OutboundProxyAllowRadSec) ||
		policy.OutboundProxyMaxHops < 1 || policy.OutboundProxyMaxHops > 32 ||
		strings.TrimSpace(policy.OutboundProxyLoopMarker) == "" ||
		!policy.OutboundVendorActionsEnabled || !policy.OutboundVendorActionsRequirePack {
		status = "blocked"
	}
	if policy.OutboundProxyEnabled {
		switch dac.ProxyRouting.Status {
		case "blocked":
			status = "blocked"
		case "degraded":
			if status == "passed" {
				status = "degraded"
			}
		}
		if dac.ProxyRouting.Summary.RouteCount == 0 || dac.ProxyRouting.Summary.HomeServerCount == 0 {
			status = "blocked"
		}
	}
	switch dac.VendorActions.Status {
	case "blocked":
		status = "blocked"
	case "degraded":
		if status == "passed" {
			status = "degraded"
		}
	}
	if dac.Summary.NAKCount > 0 || dac.Summary.ErrorCount > 0 || dac.Summary.BlockedCount > 0 {
		if status == "passed" {
			status = "degraded"
		}
	}
	if dac.QueueSummary.PoisonCount > 0 || dac.QueueSummary.ErrorCount > 0 || dac.QueueSummary.ExpiredCount > 0 || dac.QueueSummary.QueueUtilization >= 90 {
		if status == "passed" {
			status = "degraded"
		}
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:      "radius_outbound_dac_client",
		Category: "radius",
		Label:    "Outbound CoA And Disconnect Client",
		Status:   status,
		Summary: fmt.Sprintf("Outbound DAC schema %d is %s with %d request(s), %d ACK, %d NAK, %d error, %d blocked, %d immediate attempt(s), %d queued, %d retrying, %d poison, %d%% queue utilization, %d proxy route(s), %d RadSec route(s), %d blocked proxy route(s), and %d active vendor action pack(s).",
			dac.SchemaVersion, dac.Status, dac.Summary.TotalRequests, dac.Summary.ACKCount,
			dac.Summary.NAKCount, dac.Summary.ErrorCount, dac.Summary.BlockedCount, dac.Summary.AttemptCount,
			dac.QueueSummary.QueuedCount, dac.QueueSummary.RetryingCount, dac.QueueSummary.PoisonCount, dac.QueueSummary.QueueUtilization,
			dac.ProxyRouting.Summary.RouteCount, dac.ProxyRouting.Summary.RadSecRouteCount, dac.ProxyRouting.Summary.BlockedRouteCount,
			len(dac.VendorActions.ActivePacks)),
		Recommendation: "Keep radius.dynamic_auth outbound queue, replay, proxy routing, vendor action compiler, NAS ownership checks, HA handoff, confirmation, known-client gates, bounded Proxy-State, and route transport policy enabled; complete the NAS-0042/NAS-0043/NAS-0044/NAS-0045/NAS-0046/NAS-0047 release certification packet-capture and vendor-device checklist before production claims.",
		Dependencies:   []string{"radius.dynamic_auth", "radius.dynamic_auth.outbound_proxy_enabled", "radius.dynamic_auth.outbound_vendor_actions_enabled", "radius.vendor.compatibility_packs", "radius.upstream.routes", "/api/v1/system/dac-client", "/api/v1/system/nas-ownership", "/api/v1/system/dac-handoff", "/api/v1/system/dac-client/preview", "/api/v1/system/dac-client/send", "/api/v1/system/dac-client/enqueue", "/api/v1/system/dac-client/replay", "/api/v1/system/dac-client/history", "radius_outbound_dac_requests", "radius_outbound_dac_attempts", "radius_outbound_dac_queue", "radius_outbound_dac_queue_attempts", "nas_session_ownership", "radius_dac_handoff_leases", "radius_dac_handoff_events", "RFC 5176", "RFC 6614"},
	})
}

func addProductionNASCapabilityOwnershipCheck(report *productionReadinessReport, cfg *config.Config) {
	ownership := radius.BuildNASCapabilityOwnershipReport(cfg)
	status := "passed"
	switch ownership.Status {
	case "blocked":
		status = "blocked"
	case "degraded":
		status = "degraded"
	}
	if db.DB == nil || ownership.Summary.EnabledClients == 0 {
		status = "blocked"
	}
	if ownership.Summary.CapabilityClients == 0 && ownership.Summary.EnabledClients > 0 && status == "passed" {
		status = "degraded"
	}
	if ownership.Summary.StaleSessions > 0 || ownership.Summary.UnknownSessions > 0 {
		if status == "passed" {
			status = "degraded"
		}
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:      "nas_capability_ownership",
		Category: "radius",
		Label:    "NAS Capability And Session Ownership Registry",
		Status:   status,
		Summary: fmt.Sprintf("NAS ownership schema %d is %s with %d enabled client(s), %d capability-backed client(s), %d active session(s), %d owned session(s), %d stale, %d unknown, and %d%% ownership coverage.",
			ownership.SchemaVersion, ownership.Status, ownership.Summary.EnabledClients, ownership.Summary.CapabilityClients,
			ownership.Summary.ActiveSessions, ownership.Summary.OwnedSessions, ownership.Summary.StaleSessions,
			ownership.Summary.UnknownSessions, ownership.Summary.OwnershipCoverage),
		Recommendation: "Keep NAS clients capability-backed, monitor /api/v1/system/nas-ownership before outbound dynamic authorization, reconcile stale ownership rows, and complete the NAS-0046 release certification packet-capture and failover checklist before production claims.",
		Dependencies:   []string{"radius_clients.capabilities_json", "nas_session_ownership", "radius_outbound_dac_requests.ownership_session_id", "radius_outbound_dac_queue.ownership_session_id", "/api/v1/system/nas-ownership", "/api/v1/system/dac-client", "RFC 5176", "RFC 6614"},
	})
}

func addProductionDACHandoffCheck(report *productionReadinessReport, cfg *config.Config) {
	handoff := radius.BuildOutboundDACHandoffReport(cfg)
	status := "passed"
	switch handoff.Status {
	case "blocked":
		status = "blocked"
	case "degraded":
		status = "degraded"
	}
	if db.DB == nil {
		status = "blocked"
	}
	if cfg != nil && cfg.HighAvailability.Enabled {
		if !handoff.Decision.CanSend || !handoff.Decision.CanQueue || !handoff.Decision.CanReplay {
			status = "blocked"
		}
		if !cfg.HighAvailability.SplitBrainProtectionEnabled {
			status = "blocked"
		}
		if strings.TrimSpace(handoff.Decision.LeaseID) == "" || handoff.Summary.TotalLeases == 0 {
			status = "blocked"
		}
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:      "radius_dac_handoff",
		Category: "radius",
		Label:    "HA-Aware CoA Cluster Handoff",
		Status:   status,
		Summary: fmt.Sprintf("Outbound DAC handoff schema %d is %s for node %s role %s effective %s with %d active, %d standby, %d blocked, and %d replay-capable lease(s).",
			handoff.SchemaVersion, handoff.Status, handoff.Decision.NodeID, handoff.Decision.Role,
			handoff.Decision.EffectiveRole, handoff.Summary.ActiveLeases, handoff.Summary.StandbyLeases,
			handoff.Summary.BlockedLeases, handoff.Summary.ReplayCapableLeases),
		Recommendation: "For HA deployments, keep split-brain protection enabled, monitor /api/v1/system/dac-handoff before replay, verify only the effective active node can send or replay DAC, and complete the NAS-0047 release certification failover checklist before production cluster claims.",
		Dependencies:   []string{"high_availability", "high_availability.split_brain_protection_enabled", "/api/v1/system/dac-handoff", "radius_dac_handoff_leases", "radius_dac_handoff_events", "radius_outbound_dac_requests.handoff_decision", "radius_outbound_dac_queue.handoff_decision", "RFC 5176"},
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

func addProductionAccountingIngestSpoolCheck(report *productionReadinessReport, cfg *config.Config) {
	spool := radius.BuildAccountingIngestSpoolReport(cfg)
	status := "passed"
	switch spool.Status {
	case "blocked":
		status = "blocked"
	case "degraded", "disabled":
		status = "blocked"
	}
	if !spool.Enabled || !spool.Policy.ReplayEnabled || spool.Policy.MaxQueueRecords <= 0 || spool.Policy.MaxAttempts <= 0 || spool.Policy.RecordTTLSeconds <= 0 {
		status = "blocked"
	}
	if spool.Summary.QueueUtilization >= 90 || spool.Summary.PoisonCount > 0 || spool.Summary.ExpiredCount > 0 || spool.Summary.LossSLOBreachCount > 0 {
		if status == "passed" {
			status = "degraded"
		}
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:      "radius_accounting_ingest_spool",
		Category: "radius",
		Label:    "Durable Local Accounting Ingest Spool",
		Status:   status,
		Summary: fmt.Sprintf("Accounting ingest spool schema %d is %s with %d queued, %d retrying, %d applied, %d poison, %d expired, %d SLO breach(es), and %d%% queue utilization.",
			spool.SchemaVersion, spool.Status, spool.Summary.QueuedCount, spool.Summary.RetryingCount,
			spool.Summary.AppliedCount, spool.Summary.PoisonCount, spool.Summary.ExpiredCount,
			spool.Summary.LossSLOBreachCount, spool.Summary.QueueUtilization),
		Recommendation: "Keep radius.accounting_ingest_spool enabled with replay enabled, monitor /api/v1/system/accounting-ingest-spool, and complete the NAS-0040 release certification replay, failover, and outage drills.",
		Dependencies:   []string{"radius.accounting_ingest_spool", "/api/v1/system/accounting-ingest-spool", "/api/v1/system/accounting-ingest-spool/replay", "radius_accounting_ingest_spool", "radius_accounting_ingest_spool_attempts", "radius_accounting_events"},
	})
}

func addProductionAccountingChargingCheck(report *productionReadinessReport, cfg *config.Config) {
	charging := radius.BuildAccountingChargingReport(cfg)
	status := "passed"
	switch charging.Status {
	case "blocked":
		status = "blocked"
	case "degraded", "disabled":
		status = "blocked"
	}
	if !charging.Enabled || !charging.Policy.RatingEnabled || !charging.Policy.ExportEnabled ||
		charging.Policy.BatchSize <= 0 || charging.Policy.MaxExportRecords <= 0 ||
		charging.Policy.IntegritySampleLimit <= 0 {
		status = "blocked"
	}
	if charging.Summary.RatingErrorRecords > 0 || charging.Summary.IntegrityErrorRows > 0 {
		if status == "passed" {
			status = "degraded"
		}
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:      "radius_accounting_charging",
		Category: "radius",
		Label:    "Charging Records, Rating, And Export Integrity",
		Status:   status,
		Summary: fmt.Sprintf("Charging schema %d is %s with %d CDR(s), %d closed, %d unrated, %d pending export, %d export batch(es), %d rating error(s), and %d integrity error(s).",
			charging.SchemaVersion, charging.Status, charging.Summary.CDRRows,
			charging.Summary.ClosedRecords, charging.Summary.UnratedRecords,
			charging.Summary.PendingExportRecords, charging.Summary.ExportBatchRows,
			charging.Summary.RatingErrorRecords, charging.Summary.IntegrityErrorRows),
		Recommendation: "Keep radius.accounting_charging enabled with rating and export enabled, reconcile CDRs, verify hash-chain exports, and complete the NAS-0041 release certification billing, packet-capture, and soak checklist before production claims.",
		Dependencies:   []string{"radius.accounting_charging", "/api/v1/system/accounting-charging", "/api/v1/system/accounting-charging/reconcile", "/api/v1/system/accounting-charging/export", "radius_accounting_charging_records", "radius_accounting_charging_exports", "radius_accounting_charging_export_records"},
	})
}

func addProductionSQLAccountingCheck(report *productionReadinessReport, cfg *config.Config) {
	sqlAccounting := radius.BuildSQLAccountingReport(cfg)
	status := "passed"
	switch sqlAccounting.Status {
	case "blocked":
		status = "blocked"
	case "degraded", "disabled":
		status = "blocked"
	}
	if !sqlAccounting.Enabled || !sqlAccounting.Policy.ReconcileEnabled {
		status = "blocked"
	}
	if sqlAccounting.Summary.ErrorRows > 0 || sqlAccounting.Summary.StalePendingRows > 0 {
		if status == "passed" {
			status = "degraded"
		}
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:      "radius_sql_accounting",
		Category: "radius",
		Label:    "FreeRADIUS SQL Accounting Reconciliation",
		Status:   status,
		Summary: fmt.Sprintf("SQL accounting schema %d is %s with %d radacct row(s), %d radpostauth row(s), %d pending, %d stale pending, %d error, and %d reconciled row(s).",
			sqlAccounting.SchemaVersion, sqlAccounting.Status, sqlAccounting.Summary.RadAcctRows,
			sqlAccounting.Summary.PostAuthRows, sqlAccounting.Summary.PendingRows,
			sqlAccounting.Summary.StalePendingRows, sqlAccounting.Summary.ErrorRows,
			sqlAccounting.Summary.ReconciledRows),
		Recommendation: "Keep radius.sql_accounting enabled with automatic reconciliation, monitor /api/v1/system/sql-accounting, run reconcile after FreeRADIUS SQL imports, and complete the NAS-0035 release certification checklist before production claims.",
		Dependencies:   []string{"radius.sql_accounting", "/api/v1/system/sql-accounting", "/api/v1/system/sql-accounting/reconcile", "radacct", "radpostauth", "radius_sql_accounting_reconcile_events"},
	})
}

func addProductionAccountingOrderingCheck(report *productionReadinessReport, cfg *config.Config) {
	ordering := radius.BuildAccountingOrderingReport(cfg)
	status := "passed"
	switch ordering.Status {
	case "blocked":
		status = "blocked"
	case "degraded", "disabled":
		status = "blocked"
	}
	if !ordering.Enabled || !ordering.Policy.ReplayEnabled {
		status = "blocked"
	}
	if ordering.Summary.ErrorEvents > 0 || ordering.Summary.StalePendingEvents > 0 {
		if status == "passed" {
			status = "degraded"
		}
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:      "radius_accounting_ordering",
		Category: "radius",
		Label:    "Accounting Idempotency And Ordering",
		Status:   status,
		Summary: fmt.Sprintf("Accounting ordering schema %d is %s with %d event(s), %d pending, %d stale pending, %d error, %d duplicate, %d reordered, and %d late Stop event(s).",
			ordering.SchemaVersion, ordering.Status, ordering.Summary.TotalEvents,
			ordering.Summary.PendingEvents, ordering.Summary.StalePendingEvents,
			ordering.Summary.ErrorEvents, ordering.Summary.DuplicateEvents,
			ordering.Summary.ReorderedEvents, ordering.Summary.LateStopEvents),
		Recommendation: "Keep radius.accounting_ordering enabled with replay enabled, monitor /api/v1/system/accounting-ordering, replay after imports or failover, and complete the NAS-0036 release certification checklist before production claims.",
		Dependencies:   []string{"radius.accounting_ordering", "/api/v1/system/accounting-ordering", "/api/v1/system/accounting-ordering/replay", "radius_accounting_events"},
	})
}

func addProductionAccountingCountersCheck(report *productionReadinessReport, cfg *config.Config) {
	counters := radius.BuildAccountingCountersReport(cfg)
	status := "passed"
	switch counters.Status {
	case "blocked":
		status = "blocked"
	case "degraded", "disabled":
		status = "blocked"
	}
	if !counters.Enabled || !counters.Policy.GigawordsEnabled || !counters.Policy.ResetDetection || counters.Policy.MaxCounterBits != 64 {
		status = "blocked"
	}
	if counters.Summary.CounterErrorRows > 0 {
		if status == "passed" {
			status = "degraded"
		}
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:      "radius_accounting_counters",
		Category: "radius",
		Label:    "64-bit Accounting Counters And Gigawords",
		Status:   status,
		Summary: fmt.Sprintf("Accounting counters schema %d is %s with %d radacct row(s), %d event(s), %d gigaword row(s), %d rollover event(s), %d reset event(s), %d counter error row(s), max input %s, and max output %s.",
			counters.SchemaVersion, counters.Status, counters.Summary.RadAcctRows, counters.Summary.EventRows,
			counters.Summary.GigawordRows, counters.Summary.RolloverEvents, counters.Summary.ResetEvents,
			counters.Summary.CounterErrorRows, counters.Summary.MaxInputOctets64, counters.Summary.MaxOutputOctets64),
		Recommendation: "Keep radius.accounting_counters enabled with gigawords and reset detection, monitor /api/v1/system/accounting-counters, reconcile after FreeRADIUS SQL imports, and complete the NAS-0037 release certification checklist before production claims.",
		Dependencies:   []string{"radius.accounting_counters", "/api/v1/system/accounting-counters", "Acct-Input-Gigawords", "Acct-Output-Gigawords", "radacct", "radius_accounting_events"},
	})
}

func addProductionAccountingIPCheck(report *productionReadinessReport, cfg *config.Config) {
	accountingIP := radius.BuildAccountingIPReport(cfg)
	status := "passed"
	switch accountingIP.Status {
	case "blocked":
		status = "blocked"
	case "degraded", "disabled":
		status = "blocked"
	}
	if !accountingIP.Enabled || !accountingIP.Policy.IPv6Enabled || !accountingIP.Policy.RouteAccountingEnabled || !accountingIP.Policy.DelegatedPrefixEnabled {
		status = "blocked"
	}
	if accountingIP.Summary.InvalidRows > 0 {
		if status == "passed" {
			status = "degraded"
		}
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:      "radius_accounting_ip",
		Category: "radius",
		Label:    "IPv6, Prefix, And Route Accounting",
		Status:   status,
		Summary: fmt.Sprintf("Accounting IP schema %d is %s with %d assignment row(s), %d IPv6 address row(s), %d delegated prefix row(s), %d IPv4 route row(s), %d IPv6 route row(s), and %d invalid row(s).",
			accountingIP.SchemaVersion, accountingIP.Status, accountingIP.Summary.AssignmentRows,
			accountingIP.Summary.IPv6AddressRows, accountingIP.Summary.DelegatedPrefixRows,
			accountingIP.Summary.IPv4RouteRows, accountingIP.Summary.IPv6RouteRows, accountingIP.Summary.InvalidRows),
		Recommendation: "Keep radius.accounting_ip enabled with IPv6, delegated-prefix, and route accounting; monitor /api/v1/system/accounting-ip; reconcile after FreeRADIUS SQL imports; and complete the NAS-0038 release certification checklist before production claims.",
		Dependencies:   []string{"radius.accounting_ip", "/api/v1/system/accounting-ip", "Framed-IPv6-Address", "Framed-IPv6-Prefix", "Delegated-IPv6-Prefix", "Framed-Route", "Framed-IPv6-Route", "radacct", "radius_accounting_ip_assignments"},
	})
}

func addProductionAccountingServicesCheck(report *productionReadinessReport, cfg *config.Config) {
	services := radius.BuildAccountingServicesReport(cfg)
	status := "passed"
	switch services.Status {
	case "blocked":
		status = "blocked"
	case "degraded", "disabled":
		status = "blocked"
	}
	if !services.Enabled || !services.Policy.CorrelateSubscriberChains || !services.Policy.DeriveFromClass || !services.Policy.DeriveFromAcctMultiSessionID {
		status = "blocked"
	}
	if services.Summary.ConflictCorrelations > 0 {
		status = "degraded"
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:      "radius_accounting_services",
		Category: "radius",
		Label:    "Multi-Service Accounting Correlation",
		Status:   status,
		Summary: fmt.Sprintf("Accounting service schema %d is %s with %d correlation row(s), %d active, %d closed, %d linked subscriber service(s), %d Acct-Multi-Session row(s), %d bearer leg(s), %d call leg(s), and %d conflict(s).",
			services.SchemaVersion, services.Status, services.Summary.CorrelationRows,
			services.Summary.ActiveCorrelations, services.Summary.ClosedCorrelations,
			services.Summary.LinkedSubscriberServices, services.Summary.AcctMultiSessionRows,
			services.Summary.BearerLegRows, services.Summary.CallLegRows,
			services.Summary.ConflictCorrelations),
		Recommendation: "Keep radius.accounting_services enabled, correlate subscriber chains, Class metadata, and Acct-Multi-Session-Id, monitor /api/v1/system/accounting-services, and complete the NAS-0039 release certification checklist before production claims.",
		Dependencies:   []string{"radius.accounting_services", "/api/v1/system/accounting-services", "Acct-Multi-Session-Id", "Acct-Link-Count", "Service-Type", "Class", "subscriber_service_accounting", "radius_accounting_service_correlations"},
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

func addProductionACLASTCheck(report *productionReadinessReport) {
	status := "passed"
	summary := "ACL AST normalization is ready."
	if db.DB == nil {
		addProductionCheck(report, productionReadinessCheck{
			Key:            "acl_ast",
			Category:       "policy",
			Label:          "Lossless Vendor-Neutral ACL AST",
			Status:         "blocked",
			Summary:        "Database is not initialized; ACL AST policy coverage cannot be verified.",
			Recommendation: "Initialize the database before using ACL AST readiness as release evidence.",
			Dependencies:   []string{"acl_policies", "/api/v1/system/acl-ast", "/api/v1/system/acl-ast/normalize", "RFC 2865"},
		})
		return
	}
	policies, err := loadACLASTPolicyStatuses()
	if err != nil {
		status = "blocked"
		summary = "ACL AST policy status failed: " + err.Error()
	} else {
		nonLossless := 0
		diagnostics := 0
		rules := 0
		astRules := 0
		objectGroups := 0
		serviceGroups := 0
		for _, policy := range policies {
			if !policy.Lossless {
				nonLossless++
			}
			diagnostics += len(policy.Diagnostics)
			rules += policy.RuleCount
			astRules += policy.ASTRuleCount
			objectGroups += policy.ObjectGroups
			serviceGroups += policy.ServiceGroups
		}
		if nonLossless > 0 {
			status = "degraded"
		}
		summary = fmt.Sprintf("ACL AST schema %d has %d policy/policies, %d AST rule(s), %d compatibility rule(s), %d object group(s), %d service group(s), %d diagnostic(s), and %d non-lossless policy projection(s).",
			radius.ACLASTSchemaVersion, len(policies), astRules, rules, objectGroups, serviceGroups, diagnostics, nonLossless)
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:            "acl_ast",
		Category:       "policy",
		Label:          "Lossless Vendor-Neutral ACL AST",
		Status:         status,
		Summary:        summary,
		Recommendation: "Use ACL AST as the source of truth for reusable policy intent, keep flat rules as compatibility projections, review diagnostics before vendor export, and complete the NAS-0048 release certification checklist before production parity claims.",
		Dependencies:   []string{"acl_policies.ast_json", "acl_policies.ast_fingerprint", "/api/v1/system/acl-ast", "/api/v1/system/acl-ast/normalize", "/api/v1/system/vendor-reply-preview", "RFC 2865"},
	})
}

func addProductionACLCompilerCheck(report *productionReadinessReport) {
	capabilities := radius.ACLCompilerCapabilities()
	capabilitySummary := summarizeACLCompilerCapabilities(capabilities)
	status := "passed"
	summary := fmt.Sprintf("ACL compiler schema %d has %d software-certified line compiler(s), %d profile-reference compiler(s), %d decompiler(s), and %d unsupported pack(s).",
		radius.ACLCompilerSchemaVersion,
		capabilitySummary["line_rule_compilers"].(int),
		capabilitySummary["profile_reference"].(int),
		capabilitySummary["decompile_supported"].(int),
		capabilitySummary["unsupported"].(int),
	)
	if capabilitySummary["software_certified"].(int) == 0 {
		status = "blocked"
		summary = "No software-certified ACL line compilers are available."
	}
	if db.DB == nil {
		if status == "passed" {
			status = "degraded"
		}
		summary += " Database is not initialized; compiler evidence history cannot be verified."
	} else if evidence, err := db.GetACLCompilerEventSummary(); err != nil {
		status = "blocked"
		summary += " ACL compiler evidence failed: " + err.Error()
	} else {
		if evidence.BlockedCount > 0 || evidence.UnsupportedCount > 0 {
			status = "degraded"
		}
		summary += fmt.Sprintf(" Evidence has %d compile/decompile event(s), %d blocked, %d unsupported, %d degraded, and %d artifact(s).",
			evidence.TotalEvents, evidence.BlockedCount, evidence.UnsupportedCount, evidence.DegradedCount, evidence.ArtifactCount)
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:            "acl_compilers",
		Category:       "policy",
		Label:          "Certified Vendor ACL Compilers And Decompilers",
		Status:         status,
		Summary:        summary,
		Recommendation: "Use /api/v1/system/acl-compilers/compile and /decompile for vendor ACL evidence, block unsupported packs instead of falling back silently, and complete the NAS-0049 release certification checklist before production parity claims.",
		Dependencies:   []string{"acl_compiler_events", "/api/v1/system/acl-compilers", "/api/v1/system/acl-compilers/compile", "/api/v1/system/acl-compilers/decompile", "RFC 2865"},
	})
}

func addProductionRuntimeFirewallCheck(report *productionReadinessReport) {
	status := "passed"
	summary := "Stateful per-session local firewall policy is ready."
	plan, err := enforcement.PreviewRuntimeFirewall()
	if err != nil {
		status = "blocked"
		summary = "Runtime firewall preview failed: " + err.Error()
	} else {
		switch plan.Status {
		case "blocked":
			status = "blocked"
		case "degraded":
			status = "degraded"
		}
		summary = fmt.Sprintf("Runtime firewall schema %d plans %d managed session(s), %d quarantined session(s), %d IPv4 address(es), %d IPv6 address(es), %d ACL rule(s), %d nftable rule(s), and %d diagnostic(s).",
			plan.SchemaVersion, plan.Summary.ManagedSessions, plan.Summary.QuarantineSessions,
			plan.Summary.IPv4Sessions, plan.Summary.IPv6Sessions, plan.Summary.RuleCount,
			plan.Summary.AppliedRuleCount, len(plan.Diagnostics))
	}
	if db.DB == nil {
		status = "blocked"
		summary = "Database is not initialized; runtime firewall snapshots and history cannot be verified."
	} else if evidence, err := db.GetRuntimeFirewallEventSummary(); err != nil {
		status = "blocked"
		summary += " Runtime firewall evidence failed: " + err.Error()
	} else {
		if evidence.FailedCount > 0 || evidence.BlockedCount > 0 {
			status = "degraded"
		}
		summary += fmt.Sprintf(" Evidence has %d event(s), %d applied, %d rolled back, %d failed, active snapshot=%s.",
			evidence.TotalEvents, evidence.AppliedCount, evidence.RolledBackCount, evidence.FailedCount, firstNonEmptyAdminString(evidence.ActiveSnapshotID, "none"))
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:            "stateful_local_firewall",
		Category:       "policy",
		Label:          "Stateful Per-Session Local Firewall Policy",
		Status:         status,
		Summary:        summary,
		Recommendation: "Use /api/v1/system/runtime-firewall/preview before apply, keep ACL policies normalized through ACL AST and compiler checks, retain snapshots for rollback, and complete the NAS-0050 release certification checklist for nftables, HA, packet-capture, and vendor-device proof.",
		Dependencies:   []string{"runtime_firewall_snapshots", "runtime_firewall_events", "/api/v1/system/runtime-firewall", "/api/v1/system/runtime-firewall/preview", "/api/v1/system/runtime-firewall/apply", "/api/v1/system/runtime-firewall/rollback", "nftables", "RFC 2865"},
	})
}

func addProductionRuntimeQoSCheck(report *productionReadinessReport, cfg *config.Config) {
	status := "passed"
	summary := "Hierarchical QoS scheduler model is ready."
	plan, err := enforcement.PreviewRuntimeQoS(cfg)
	if err != nil {
		status = "blocked"
		summary = "Runtime QoS scheduler preview failed: " + err.Error()
	} else {
		switch plan.Status {
		case "blocked":
			status = "blocked"
		case "degraded", "skipped":
			status = "degraded"
		}
		summary = fmt.Sprintf("Runtime QoS schema %d plans %d profile(s), %d class(es), %d shaped session(s), %d unshaped session(s), %d command(s), and %d diagnostic(s) on interface %s.",
			plan.SchemaVersion, plan.Summary.ProfileCount, plan.Summary.ClassCount,
			plan.Summary.ShapedSessions, plan.Summary.UnshapedSessions, plan.Summary.CommandCount,
			len(plan.Diagnostics), firstNonEmptyAdminString(plan.InterfaceName, "unset"))
	}
	if db.DB == nil {
		status = "blocked"
		summary = "Database is not initialized; runtime QoS scheduler snapshots and history cannot be verified."
	} else if evidence, err := db.GetRuntimeQoSEventSummary(); err != nil {
		status = "blocked"
		summary += " Runtime QoS evidence failed: " + err.Error()
	} else {
		if evidence.FailedCount > 0 || evidence.BlockedCount > 0 {
			status = "degraded"
		}
		summary += fmt.Sprintf(" Evidence has %d event(s), %d applied, %d rolled back, %d failed, active snapshot=%s.",
			evidence.TotalEvents, evidence.AppliedCount, evidence.RolledBackCount, evidence.FailedCount, firstNonEmptyAdminString(evidence.ActiveSnapshotID, "none"))
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:            "hierarchical_qos_scheduler",
		Category:       "policy",
		Label:          "Hierarchical QoS And Scheduler Model",
		Status:         status,
		Summary:        summary,
		Recommendation: "Use /api/v1/system/qos-scheduler/preview before apply, store aggregate scheduler overrides in qos_scheduler_profiles, retain snapshots for rollback, and complete the NAS-0051 release certification checklist for tc, controller, packet-capture, HA, and throughput proof.",
		Dependencies:   []string{"bandwidth_profiles", "qos_scheduler_profiles", "runtime_qos_snapshots", "runtime_qos_events", "/api/v1/system/qos-scheduler", "/api/v1/system/qos-scheduler/preview", "/api/v1/system/qos-scheduler/apply", "/api/v1/system/qos-scheduler/rollback", "tc", "ifb", "RFC 2865"},
	})
}

func addProductionVLANLifecycleCheck(report *productionReadinessReport, cfg *config.Config) {
	status := "passed"
	summary := "Dynamic VLAN lifecycle model is ready."
	plan, err := enforcement.PreviewVLANLifecycle(cfg)
	if err != nil {
		status = "blocked"
		summary = "Dynamic VLAN lifecycle preview failed: " + err.Error()
	} else {
		switch plan.Status {
		case "blocked":
			status = "blocked"
		case "degraded", "skipped":
			status = "degraded"
		}
		summary = fmt.Sprintf("VLAN lifecycle schema %d plans %d VLAN(s), %d bridge(s), %d subinterface(s), %d hostapd VLAN entries, %d command(s), and %d diagnostic(s) on interface %s.",
			plan.SchemaVersion, plan.Summary.VLANCount, plan.Summary.BridgeCount,
			plan.Summary.SubinterfaceCount, plan.Summary.HostapdVLANEntryCount, plan.Summary.CommandCount,
			len(plan.Diagnostics), firstNonEmptyAdminString(plan.ParentInterface, "unset"))
	}
	if db.DB == nil {
		status = "blocked"
		summary = "Database is not initialized; dynamic VLAN lifecycle snapshots and history cannot be verified."
	} else if evidence, err := db.GetVLANLifecycleEventSummary(); err != nil {
		status = "blocked"
		summary += " Dynamic VLAN lifecycle evidence failed: " + err.Error()
	} else {
		if evidence.FailedCount > 0 || evidence.BlockedCount > 0 {
			status = "degraded"
		}
		summary += fmt.Sprintf(" Evidence has %d event(s), %d applied, %d rolled back, %d failed, active snapshot=%s.",
			evidence.TotalEvents, evidence.AppliedCount, evidence.RolledBackCount, evidence.FailedCount, firstNonEmptyAdminString(evidence.ActiveSnapshotID, "none"))
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:            "dynamic_vlan_lifecycle",
		Category:       "policy",
		Label:          "Dynamic VLAN Bridge And Subinterface Lifecycle",
		Status:         status,
		Summary:        summary,
		Recommendation: "Use /api/v1/system/vlan-lifecycle/preview before apply, keep VLAN catalog, role VLANs, policy VLANs, and hostapd dynamic VLAN entries in one evidence-backed lifecycle, and complete the NAS-0053 release certification checklist for Linux bridge/VLAN, hostapd, FreeRADIUS, HA, and vendor-device proof.",
		Dependencies:   []string{"vlans", "roles.vlan", "policy_rules.vlan", "wireless.ssids.dynamic_vlan", "vlan_lifecycle_snapshots", "vlan_lifecycle_events", "/api/v1/system/vlan-lifecycle", "/api/v1/system/vlan-lifecycle/preview", "/api/v1/system/vlan-lifecycle/apply", "/api/v1/system/vlan-lifecycle/rollback", "ip link", "hostapd vlan_file", "RFC 2868"},
	})
}

func addProductionSubscriberRouteExportCheck(report *productionReadinessReport, cfg *config.Config) {
	status := "passed"
	summary := "Dynamic BGP/OSPF subscriber route export is ready."
	plan, err := enforcement.PreviewSubscriberRouteExport(cfg)
	if err != nil {
		status = "blocked"
		summary = "Subscriber route export preview failed: " + err.Error()
	} else {
		switch plan.Status {
		case "blocked":
			status = "blocked"
		case "degraded", "skipped":
			status = "degraded"
		}
		summary = fmt.Sprintf("Subscriber route export schema %d plans %d protocol(s), %d active route(s), %d exported route(s), %d suppressed route(s), %d withdrawal(s), %d command(s), and %d diagnostic(s) with driver %s.",
			plan.SchemaVersion,
			plan.Summary.ProtocolCount,
			plan.Summary.RouteCount,
			plan.Summary.ExportedRoutes,
			plan.Summary.SuppressedRoutes,
			plan.Summary.WithdrawRouteCount,
			plan.Summary.CommandCount,
			len(plan.Diagnostics),
			firstNonEmptyAdminString(plan.Driver, "file"))
		if !plan.ApplyEnabled {
			summary += " Live routing apply is gated by config; previews, evidence, and rollback snapshots remain active."
		}
	}
	if db.DB == nil {
		status = "blocked"
		summary = "Database is not initialized; subscriber route export snapshots and history cannot be verified."
	} else if evidence, err := db.GetSubscriberRouteExportSummary(); err != nil {
		status = "blocked"
		summary += " Subscriber route export evidence failed: " + err.Error()
	} else {
		if evidence.FailedCount > 0 || evidence.BlockedCount > 0 {
			status = "degraded"
		}
		summary += fmt.Sprintf(" Evidence has %d event(s), %d applied, %d rolled back, %d skipped, %d failed, active snapshot=%s.",
			evidence.TotalEvents,
			evidence.AppliedCount,
			evidence.RolledBackCount,
			evidence.SkippedCount,
			evidence.FailedCount,
			firstNonEmptyAdminString(evidence.ActiveSnapshotID, "none"))
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:            "dynamic_subscriber_route_export",
		Category:       "policy",
		Label:          "Dynamic Routing Integration For Subscriber Routes",
		Status:         status,
		Summary:        summary,
		Recommendation: "Use /api/v1/system/subscriber-route-export/preview before enabling live apply, retain subscriber_route_export_snapshots and subscriber_route_export_events evidence, keep route ownership withdrawal tied to Accounting Stop, and complete the NAS-0059 release certification checklist for FRR, BGP/OSPF convergence, HA, packet captures, and vendor-device proof.",
		Dependencies:   []string{"radius.route_policy.dynamic_routing", "route_policy_ownership", "subscriber_route_export_snapshots", "subscriber_route_export_events", "/api/v1/system/subscriber-route-export", "/api/v1/system/subscriber-route-export/preview", "/api/v1/system/subscriber-route-export/apply", "/api/v1/system/subscriber-route-export/rollback", "FRRouting", "BGP", "OSPF", "Framed-Route", "Framed-IPv6-Route", "RFC 4271", "RFC 2328", "RFC 5340", "RFC 5176"},
	})
}

func addProductionAtomicEnforcementCheck(report *productionReadinessReport, cfg *config.Config) {
	status := "passed"
	policy := cfg.Policy.EnforcementTransactions
	plan, err := enforcement.BuildAtomicEnforcementPlan(context.Background(), cfg, enforcement.AtomicEnforcementRequest{})
	if err != nil {
		status = "blocked"
	}
	summary := "Atomic enforcement transaction layer is ready."
	if err != nil {
		summary = "Atomic enforcement transaction preview failed: " + err.Error()
	} else {
		switch plan.Status {
		case "blocked":
			status = "blocked"
		case "degraded", "skipped":
			status = "degraded"
		}
		summary = fmt.Sprintf("Atomic enforcement schema %d plans %d target(s), %d ready, %d degraded, %d blocked, %d skipped, %d needing apply, and %d rollbackable target(s).",
			plan.SchemaVersion,
			plan.Summary.TargetCount,
			plan.Summary.ReadyTargets,
			plan.Summary.DegradedTargets,
			plan.Summary.BlockedTargets,
			plan.Summary.SkippedTargets,
			plan.Summary.ApplyRequired,
			plan.Summary.RollbackAvailable)
	}
	if !policy.Enabled || !policy.FailClosed || !policy.RequirePreviewBeforeApply || !policy.AutoRollbackOnFailure || !policy.DriftCheckAfterApply {
		status = "blocked"
		summary += " Required safeguards are not all enabled."
	}
	if db.DB == nil {
		status = "blocked"
		summary = "Database is not initialized; atomic enforcement transactions, steps, and drift history cannot be verified."
	} else if evidence, err := db.GetEnforcementTransactionSummary(); err != nil {
		status = "blocked"
		summary += " Atomic enforcement evidence failed: " + err.Error()
	} else {
		if evidence.FailedCount > 0 || evidence.BlockedCount > 0 || evidence.FailedSteps > 0 || evidence.OpenDriftEvents > 0 {
			status = "degraded"
		}
		summary += fmt.Sprintf(" Evidence has %d transaction(s), %d applied, %d compensated, %d rolled back, %d failed, %d drift event(s), latest=%s/%s.",
			evidence.TotalTransactions,
			evidence.AppliedCount,
			evidence.CompensatedCount,
			evidence.RolledBackCount,
			evidence.FailedCount,
			evidence.DriftEvents,
			firstNonEmptyAdminString(evidence.LastOperation, "none"),
			firstNonEmptyAdminString(evidence.LastStatus, "none"))
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:            "atomic_enforcement_transactions",
		Category:       "policy",
		Label:          "Atomic Enforcement Transactions And Drift Rollback",
		Status:         status,
		Summary:        summary,
		Recommendation: "Keep atomic transactions enabled, fail closed, preview before apply, auto-rollback on failed participant apply, and drift verification after apply. Use /api/v1/system/enforcement-transactions for status, /preview for safe review, /apply for ordered enforcement, /drift for verification, and /rollback for reverse-order compensation; complete the NAS-0058 release checklist for physical device, HA, and soak evidence.",
		Dependencies:   []string{"enforcement_transactions", "enforcement_transaction_steps", "enforcement_drift_events", "runtime_firewall_snapshots", "runtime_qos_snapshots", "vlan_lifecycle_snapshots", "/api/v1/system/enforcement-transactions", "/api/v1/system/enforcement-transactions/preview", "/api/v1/system/enforcement-transactions/apply", "/api/v1/system/enforcement-transactions/drift", "/api/v1/system/enforcement-transactions/rollback", "RFC 5176"},
	})
}

func addProductionVLANPolicyCheck(report *productionReadinessReport, cfg *config.Config) {
	status := "passed"
	compilerReport := radius.BuildVLANPolicyReport(cfg)
	sample := radius.CompileVLANPolicy(cfg, radius.VLANPolicyCompileRequest{
		Role:             firstProductionVLANPolicyRole(cfg),
		VLAN:             firstProductionVLANPolicyFallbackVLAN(cfg),
		CallingStationID: "00:11:22:33:44:55",
		NASIdentifier:    "production-readiness",
		PackKeys:         []string{productconfigs.VendorPackStandard, productconfigs.VendorPackAegisNAS, productconfigs.VendorPackExtreme, productconfigs.VendorPackHP},
	})
	switch sample.Status {
	case "blocked":
		status = "blocked"
	case "degraded":
		status = "degraded"
	}
	summary := fmt.Sprintf("Tagged VLAN policy compiler version %d has %d role policy(s), %d pool(s), %d voice policy(s), %d QinQ policy(s), and compiled %d sample attribute(s) with %d diagnostic(s).",
		compilerReport.CompilerVersion,
		compilerReport.Summary.PolicyCount,
		compilerReport.Summary.PoolCount,
		compilerReport.Summary.VoicePolicyCount,
		compilerReport.Summary.QinQPolicyCount,
		len(sample.Attributes),
		len(sample.Diagnostics))
	if db.DB == nil {
		status = "blocked"
		summary = "Database is not initialized; tagged VLAN policy evidence cannot be verified."
	} else if evidence, err := db.GetVLANPolicyEventSummary(); err != nil {
		status = "blocked"
		summary += " Tagged VLAN policy evidence failed: " + err.Error()
	} else {
		if evidence.FailedCount > 0 || evidence.BlockedCount > 0 {
			status = "degraded"
		}
		summary += fmt.Sprintf(" Evidence has %d compiler event(s), %d compiled, %d decompiled, %d blocked, %d failed.",
			evidence.TotalEvents, evidence.CompiledCount, evidence.DecompiledCount, evidence.BlockedCount, evidence.FailedCount)
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:            "tagged_vlan_qinq_policy",
		Category:       "policy",
		Label:          "Tagged Voice/Data VLAN, QinQ, Pool, And Fallback Policy",
		Status:         status,
		Summary:        summary,
		Recommendation: "Use /api/v1/system/vlan-policy/preview before changing role VLAN intent, keep role pools and fallback/auth-fail VLANs explicit, retain vlan_policy_events evidence, and complete the NAS-0054 release certification checklist for FreeRADIUS packet captures and vendor-device proof.",
		Dependencies:   []string{"radius.vlan_policy", "vlan_policy_events", "/api/v1/system/vlan-policy", "/api/v1/system/vlan-policy/preview", "/api/v1/system/vlan-policy/decompile", "Tunnel-Private-Group-Id", "Egress-VLANID", "Extreme-Netlogin-Extended-Vlan", "AegisNAS-Voice-VLAN", "AegisNAS-QinQ-Outer-VLAN", "RFC 2868", "RFC 4675"},
	})
}

func firstProductionVLANPolicyRole(cfg *config.Config) string {
	if cfg != nil {
		for _, policy := range cfg.Radius.VLANPolicy.RolePolicies {
			if strings.TrimSpace(policy.Role) != "" {
				return strings.TrimSpace(policy.Role)
			}
		}
	}
	return "default"
}

func firstProductionVLANPolicyFallbackVLAN(cfg *config.Config) int {
	if cfg != nil {
		if cfg.Radius.VLANPolicy.DefaultFallbackVLAN > 0 {
			return cfg.Radius.VLANPolicy.DefaultFallbackVLAN
		}
		for _, policy := range cfg.Radius.VLANPolicy.RolePolicies {
			switch {
			case policy.DataVLAN > 0:
				return policy.DataVLAN
			case policy.FallbackVLAN > 0:
				return policy.FallbackVLAN
			}
		}
		for _, pool := range cfg.Radius.VLANPolicy.Pools {
			for _, vlan := range pool.VLANs {
				if vlan > 0 {
					return vlan
				}
			}
		}
	}
	return 10
}

func addProductionRoutePolicyCheck(report *productionReadinessReport, cfg *config.Config) {
	status := "passed"
	compilerReport := radius.BuildRoutePolicyReport(cfg)
	sample := radius.CompileRoutePolicy(cfg, radius.RoutePolicyCompileRequest{
		Role:             firstProductionRoutePolicyRole(cfg),
		SessionID:        "readiness-session",
		CallingStationID: "00:11:22:33:44:55",
		NASIdentifier:    "production-readiness",
		VRF:              compilerReport.DefaultVRF,
		Routes:           firstProductionRoutePolicyFallbackRoutes(cfg),
		PackKeys:         []string{productconfigs.VendorPackStandard, productconfigs.VendorPackAegisNAS, productconfigs.VendorPackCisco, productconfigs.VendorPackJuniper, productconfigs.VendorPackHuawei, productconfigs.VendorPackNokia},
	})
	switch sample.Status {
	case "blocked":
		status = "blocked"
	case "degraded":
		status = "degraded"
	}
	summary := fmt.Sprintf("Route policy compiler version %d has %d role policy(s), %d VRF(s), %d IPv4 route(s), %d IPv6 route(s), and compiled %d sample attribute(s) with %d diagnostic(s).",
		compilerReport.CompilerVersion,
		compilerReport.Summary.PolicyCount,
		compilerReport.Summary.VRFCount,
		compilerReport.Summary.IPv4RouteCount,
		compilerReport.Summary.IPv6RouteCount,
		len(sample.Attributes),
		len(sample.Diagnostics))
	if db.DB == nil {
		status = "blocked"
		summary = "Database is not initialized; route policy evidence cannot be verified."
	} else if evidence, err := db.GetRoutePolicyEventSummary(); err != nil {
		status = "blocked"
		summary += " Route policy evidence failed: " + err.Error()
	} else {
		if evidence.FailedCount > 0 || evidence.BlockedCount > 0 {
			status = "degraded"
		}
		summary += fmt.Sprintf(" Evidence has %d compiler event(s), %d active route(s), %d withdrawn route(s), %d blocked, %d failed.",
			evidence.TotalEvents, evidence.ActiveRoutes, evidence.WithdrawnRoutes, evidence.BlockedCount, evidence.FailedCount)
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:            "per_session_route_vrf_policy",
		Category:       "policy",
		Label:          "Per-Session Route Injection And VRF Ownership",
		Status:         status,
		Summary:        summary,
		Recommendation: "Use /api/v1/system/route-policy/preview before changing route or VRF intent, retain route_policy_events and route_policy_ownership evidence, and complete the NAS-0055 release certification checklist for packet captures, vendor-device route installation, CoA update, Stop withdrawal, HA, and rollback proof.",
		Dependencies:   []string{"radius.route_policy", "route_policy_events", "route_policy_ownership", "/api/v1/system/route-policy", "/api/v1/system/route-policy/preview", "/api/v1/system/route-policy/decompile", "Framed-Route", "Framed-IPv6-Route", "AegisNAS-VRF", "AegisNAS-Route-Owner", "RFC 2865", "RFC 3162", "RFC 5176"},
	})
}

func firstProductionRoutePolicyRole(cfg *config.Config) string {
	if cfg != nil {
		for _, policy := range cfg.Radius.RoutePolicy.RolePolicies {
			if strings.TrimSpace(policy.Role) != "" {
				return strings.TrimSpace(policy.Role)
			}
		}
	}
	return "default"
}

func firstProductionRoutePolicyFallbackRoutes(cfg *config.Config) []radius.RoutePolicyRoute {
	if cfg != nil {
		for _, policy := range cfg.Radius.RoutePolicy.RolePolicies {
			if len(policy.IPv4Routes)+len(policy.IPv6Routes) > 0 {
				return nil
			}
		}
	}
	return []radius.RoutePolicyRoute{{Family: "ipv4", Destination: "198.51.100.0/24", Gateway: "0.0.0.0", Metric: 1, Install: true}}
}

func addProductionAddressPolicyCheck(report *productionReadinessReport, cfg *config.Config) {
	status := "passed"
	compilerReport := radius.BuildAddressPolicyReport(cfg)
	sample := radius.CompileAddressPolicy(cfg, firstProductionAddressPolicySample(cfg))
	switch sample.Status {
	case "blocked":
		status = "blocked"
	case "degraded":
		status = "degraded"
	}
	summary := fmt.Sprintf("Address policy compiler version %d has %d role policy(s), %d pool(s), %d delegated-prefix policy(s), %d RA policy(s), and compiled %d sample attribute(s) with %d diagnostic(s).",
		compilerReport.CompilerVersion,
		compilerReport.Summary.PolicyCount,
		compilerReport.Summary.PoolCount,
		compilerReport.Summary.DelegatedPolicyCount,
		compilerReport.Summary.RAPolicyCount,
		len(sample.Attributes),
		len(sample.Diagnostics))
	if db.DB == nil {
		status = "blocked"
		summary = "Database is not initialized; address policy evidence cannot be verified."
	} else if evidence, err := db.GetAddressPolicyEventSummary(); err != nil {
		status = "blocked"
		summary += " Address policy evidence failed: " + err.Error()
	} else {
		if evidence.FailedCount > 0 || evidence.BlockedCount > 0 {
			status = "degraded"
		}
		summary += fmt.Sprintf(" Evidence has %d compiler event(s), %d active assignment(s), %d withdrawn assignment(s), %d delegated prefix(es), %d RA prefix(es), %d blocked, %d failed.",
			evidence.TotalEvents, evidence.ActiveAssignments, evidence.WithdrawnAssignments, evidence.DelegatedPrefixes, evidence.RAPrefixes, evidence.BlockedCount, evidence.FailedCount)
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:            "ipv4_ipv6_pool_dhcpv6_ra_pd",
		Category:       "policy",
		Label:          "IPv4/IPv6 Pools, DHCPv6, RA, And Prefix Delegation",
		Status:         status,
		Summary:        summary,
		Recommendation: "Use /api/v1/system/address-policy/preview before changing address or prefix intent, retain address_policy_events and address_policy_ownership evidence, and complete the NAS-0056 release certification checklist for FreeRADIUS, DHCPv6, RA, prefix delegation, vendor-device, HA, performance, and rollback proof.",
		Dependencies:   []string{"radius.address_policy", "address_policy_events", "address_policy_ownership", "/api/v1/system/address-policy", "/api/v1/system/address-policy/preview", "/api/v1/system/address-policy/decompile", "Framed-IP-Address", "Framed-Pool", "Framed-IPv6-Address", "Framed-IPv6-Prefix", "Delegated-IPv6-Prefix", "Framed-IPv6-Pool", "RFC 2865", "RFC 3162", "RFC 3633", "RFC 4861", "RFC 4862", "RFC 8415"},
	})
}

func firstProductionAddressPolicySample(cfg *config.Config) radius.AddressPolicyCompileRequest {
	req := radius.AddressPolicyCompileRequest{
		Role:             "default",
		SessionID:        "readiness-session",
		CallingStationID: "00:11:22:33:44:55",
		NASIdentifier:    "production-readiness",
		PackKeys:         []string{productconfigs.VendorPackStandard, productconfigs.VendorPackAegisNAS, productconfigs.VendorPackCisco, productconfigs.VendorPackJuniper, productconfigs.VendorPackHuawei, productconfigs.VendorPackMikroTik, productconfigs.VendorPackNokia},
	}
	if cfg == nil {
		req.IPv4Address = "198.51.100.10"
		req.IPv6Address = "2001:db8:10::10"
		req.DelegatedIPv6Prefix = "2001:db8:100::/56"
		req.RAPrefix = "2001:db8:200::/64"
		return req
	}
	for _, policy := range cfg.Radius.AddressPolicy.RolePolicies {
		if strings.TrimSpace(policy.Role) == "" {
			continue
		}
		req.Role = strings.TrimSpace(policy.Role)
		if addressRolePolicyHasIntent(policy) {
			return req
		}
	}
	req.IPv4Address = "198.51.100.10"
	req.IPv6Address = "2001:db8:10::10"
	req.DelegatedIPv6Prefix = "2001:db8:100::/56"
	req.RAPrefix = "2001:db8:200::/64"
	return req
}

func addressRolePolicyHasIntent(policy config.RadiusAddressRolePolicy) bool {
	for _, value := range []string{
		policy.IPv4Pool, policy.IPv4Address, policy.IPv6Pool, policy.IPv6Address,
		policy.IPv6Prefix, policy.DelegatedIPv6Pool, policy.DelegatedIPv6Prefix,
		policy.RAPrefixPool, policy.RAPrefix,
	} {
		if strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}

func addProductionTranslationPolicyCheck(report *productionReadinessReport, cfg *config.Config) {
	status := "passed"
	compilerReport := radius.BuildTranslationPolicyReport(cfg)
	sample := radius.CompileTranslationPolicy(cfg, firstProductionTranslationPolicySample(cfg))
	switch sample.Status {
	case "blocked":
		status = "blocked"
	case "degraded":
		status = "degraded"
	}
	summary := fmt.Sprintf("Translation policy compiler version %d has %d role policy(s), %d pool(s), %d CGNAT policy(s), %d NAT64 policy(s), %d deterministic port-block policy(s), and compiled %d sample attribute(s) with %d diagnostic(s).",
		compilerReport.CompilerVersion,
		compilerReport.Summary.PolicyCount,
		compilerReport.Summary.PoolCount,
		compilerReport.Summary.CGNATPolicies,
		compilerReport.Summary.NAT64Policies,
		compilerReport.Summary.PortBlockPolicies,
		len(sample.Attributes),
		len(sample.Diagnostics))
	if db.DB == nil {
		status = "blocked"
		summary = "Database is not initialized; translation policy evidence cannot be verified."
	} else if evidence, err := db.GetTranslationPolicyEventSummary(); err != nil {
		status = "blocked"
		summary += " Translation policy evidence failed: " + err.Error()
	} else {
		if evidence.FailedCount > 0 || evidence.BlockedCount > 0 {
			status = "degraded"
		}
		summary += fmt.Sprintf(" Evidence has %d compiler event(s), %d active mapping(s), %d withdrawn mapping(s), %d active port block(s), %d active NAT64 mapping(s), %d blocked, %d failed.",
			evidence.TotalEvents, evidence.ActiveMappings, evidence.WithdrawnMappings, evidence.ActivePortBlocks, evidence.ActiveNAT64Mappings, evidence.BlockedCount, evidence.FailedCount)
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:            "cgnat_nat64_deterministic_translation",
		Category:       "policy",
		Label:          "CGNAT, NAT64, And Deterministic Subscriber Translation",
		Status:         status,
		Summary:        summary,
		Recommendation: "Use /api/v1/system/translation-policy/preview before changing subscriber translation intent, retain translation_policy_events and translation_policy_ownership evidence, and complete the NAS-0057 release certification checklist for FreeRADIUS, vendor-device, CGNAT/NAT64 dataplane, lawful logging, HA, performance, and rollback proof.",
		Dependencies: []string{
			"radius.translation_policy", "translation_policy_events", "translation_policy_ownership",
			"/api/v1/system/translation-policy", "/api/v1/system/translation-policy/preview", "/api/v1/system/translation-policy/decompile",
			"AegisNAS-Translation-Policy", "AegisNAS-Translation-Public-IPv4-Address", "AegisNAS-Translation-Port-Block-Start",
			"Cisco-AVPair", "Juniper-AV-Pair", "Huawei-AVpair", "H3C-Av-Pair", "Nokia-AVPair", "SN-NAT-IP-Address",
			"RFC 2865", "RFC 5176", "RFC 6052", "RFC 6146", "RFC 6888",
		},
	})
}

func firstProductionTranslationPolicySample(cfg *config.Config) radius.TranslationPolicyCompileRequest {
	req := radius.TranslationPolicyCompileRequest{
		Role:                  "default",
		SessionID:             "readiness-session",
		AcctSessionID:         "readiness-acct",
		CallingStationID:      "00:11:22:33:44:55",
		NASIdentifier:         "production-readiness",
		TranslationMode:       "dual-stack",
		PublicIPv4:            "198.51.100.10",
		PrivateIPv4Prefix:     "100.64.0.0/10",
		SubscriberIPv6Prefix:  "2001:db8:57::/64",
		NAT64Prefix:           "64:ff9b::/96",
		PortBlockStart:        10000,
		PortBlockEnd:          10511,
		PortBlockSize:         512,
		LoggingProfile:        "readiness-cgnat",
		AccountingCorrelation: true,
		PackKeys: []string{
			productconfigs.VendorPackAegisNAS,
			productconfigs.VendorPackCisco,
			productconfigs.VendorPackJuniper,
			productconfigs.VendorPackHuawei,
			productconfigs.VendorPackH3C,
			productconfigs.VendorPackNokia,
			productconfigs.VendorPackStarent,
			productconfigs.VendorPackERX,
		},
	}
	if cfg == nil {
		return req
	}
	for _, policy := range cfg.Radius.TranslationPolicy.RolePolicies {
		if strings.TrimSpace(policy.Role) == "" {
			continue
		}
		req.Role = strings.TrimSpace(policy.Role)
		if translationRolePolicyHasIntent(policy) {
			req.TranslationMode = ""
			req.PublicIPv4 = ""
			req.PrivateIPv4Prefix = ""
			req.SubscriberIPv6Prefix = ""
			req.NAT64Prefix = ""
			req.PortBlockStart = 0
			req.PortBlockEnd = 0
			req.PortBlockSize = 0
			req.LoggingProfile = ""
			return req
		}
	}
	return req
}

func translationRolePolicyHasIntent(policy config.RadiusTranslationRolePolicy) bool {
	for _, value := range []string{
		policy.TranslationMode,
		policy.PublicPool,
		policy.PublicIPv4,
		policy.PrivateIPv4Prefix,
		policy.SubscriberIPv6Prefix,
		policy.NAT64Prefix,
		policy.LoggingProfile,
		policy.AccountingKey,
	} {
		if strings.TrimSpace(value) != "" {
			return true
		}
	}
	return policy.PortBlockStart > 0 || policy.PortBlockEnd > 0 || policy.PortBlockSize > 0 || policy.QuotaCorrelation || policy.AccountingCorrelation
}

func addProductionRateCompilerCheck(report *productionReadinessReport) {
	status := "passed"
	compilerReport := radius.BuildRateCompilerReport()
	sample := radius.CompileVendorRates(radius.RateCompilerRequest{
		PackKeys:                   []string{productconfigs.VendorPackMikroTik, productconfigs.VendorPackWISPr, productconfigs.VendorPackUBNT, productconfigs.VendorPackHuawei, productconfigs.VendorPackH3C, productconfigs.VendorPackTPLink, productconfigs.VendorPackZTE},
		DownloadRateKbps:           50000,
		UploadRateKbps:             20000,
		DownloadBurstRateKbps:      80000,
		UploadBurstRateKbps:        30000,
		DownloadBurstThresholdKbps: 40000,
		UploadBurstThresholdKbps:   10000,
		DownloadBurstTimeSeconds:   10,
		UploadBurstTimeSeconds:     10,
		Priority:                   3,
		DownloadMinRateKbps:        10000,
		UploadMinRateKbps:          5000,
	})
	if sample.Status == "blocked" {
		status = "blocked"
	}
	summary := fmt.Sprintf("Rate compiler version %d covers %d vendor unit profile(s) and compiled %d sample attribute(s) with %d diagnostic(s).",
		compilerReport.CompilerVersion, len(compilerReport.Capabilities), sample.AttributeCount, len(sample.Diagnostics))
	if db.DB == nil {
		status = "blocked"
		summary = "Database is not initialized; rate compiler evidence cannot be verified."
	} else if evidence, err := db.GetRateCompilerEventSummary(); err != nil {
		status = "blocked"
		summary += " Rate compiler evidence failed: " + err.Error()
	} else {
		if evidence.FailedCount > 0 || evidence.BlockedCount > 0 {
			status = "degraded"
		}
		summary += fmt.Sprintf(" Evidence has %d compiler event(s), %d compiled, %d decompiled, %d blocked, %d failed.",
			evidence.TotalEvents, evidence.CompiledCount, evidence.DecompiledCount, evidence.BlockedCount, evidence.FailedCount)
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:            "vendor_rate_compiler",
		Category:       "policy",
		Label:          "Dual-stack Shaping And Vendor Rate Compiler",
		Status:         status,
		Summary:        summary,
		Recommendation: "Use /api/v1/system/rate-compiler/compile for vendor-safe kbps, bps, and MikroTik grammar previews, retain rate_compiler_events evidence, and complete the NAS-0052 release certification checklist for packet capture, controller reconciliation, HA, and throughput proof.",
		Dependencies:   []string{"rate_compiler_events", "/api/v1/system/rate-compiler", "/api/v1/system/rate-compiler/compile", "Mikrotik-Rate-Limit", "WISPr-Bandwidth-Max-Down", "UBNT-Data-Rate-DL", "tc flower", "IPv6", "RFC 2865", "RFC 2866", "RFC 5176"},
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

func addProductionSubscriberServiceChainsCheck(report *productionReadinessReport, cfg *config.Config) {
	chainReport, err := buildSubscriberServiceChainsReport(cfg, 0)
	status := "passed"
	message := "Per-service authorization and subscriber chain evidence is ready."
	if err != nil {
		status = "blocked"
		message = fmt.Sprintf("Subscriber service chain report failed: %v", err)
	} else {
		switch chainReport.Status {
		case "blocked":
			status = "blocked"
		case "degraded":
			status = "degraded"
		}
		if cfg.Policy.MaxServiceChainLength < 0 || cfg.Policy.MaxServiceChainLength > policy.MaxServiceChainLength {
			status = "blocked"
		}
		message = fmt.Sprintf("Subscriber service-chain schema %d is %s with max length %d, %d active chain(s), %d rolled back chain(s), %d failed event(s), and %d started accounting record(s).",
			chainReport.SchemaVersion, chainReport.Status, chainReport.Config.MaxServiceChainLength,
			chainReport.Summary.ActiveChains, chainReport.Summary.RolledBackChains,
			chainReport.Summary.FailedEvents, chainReport.Summary.StartedAccounting)
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:            "subscriber_service_chains",
		Category:       "policy",
		Label:          "Per-Service Authorization And Subscriber Chains",
		Status:         status,
		Summary:        message,
		Recommendation: "Model chained services in policy service_chain intents, preview before activation, preserve rollback/accounting evidence, and complete the NAS-0032 release certification checklist for real BRAS, BNG, WLAN, and controller smoke tests.",
		Dependencies:   []string{"policy.max_service_chain_length", "policy_rules.service_chain_json", "subscriber_service_chains", "subscriber_service_events", "subscriber_service_accounting", "/api/v1/system/subscriber-service-chains"},
	})
}

func addProductionTACACSCheck(report *productionReadinessReport, cfg *config.Config) {
	tacacsReport := tacacs.BuildReport(cfg, 0)
	status := "passed"
	switch tacacsReport.Status {
	case "blocked":
		status = "blocked"
	case "disabled", "degraded":
		status = "degraded"
	}
	if cfg.TACACS.Enabled {
		if !strings.EqualFold(strings.TrimSpace(cfg.TACACS.Mode), "enforce") {
			status = maxReadinessStatus(status, "degraded")
		}
		if cfg.TACACS.RequireKnownClient && tacacsReport.Summary.EnabledClients == 0 {
			status = "blocked"
		}
		if strings.TrimSpace(cfg.TACACS.SecretRef) == "" && tacacsReport.Summary.EnabledClients == 0 {
			status = "blocked"
		}
		if cfg.TACACS.AllowUnencrypted {
			status = "blocked"
		}
		if tacacsReport.Summary.EnabledSets == 0 {
			status = "blocked"
		}
		if !cfg.TACACS.AuditEnabled {
			status = maxReadinessStatus(status, "degraded")
		}
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:      "tacacs_command_authorization",
		Category: "policy",
		Label:    "Command Authorization And TACACS+",
		Status:   status,
		Summary: fmt.Sprintf("TACACS+ schema %d is %s with %d enabled client(s), %d effective command set(s), %d authorization event(s), and %d accounting record(s).",
			tacacsReport.SchemaVersion, tacacsReport.Status, tacacsReport.Summary.EnabledClients,
			tacacsReport.Summary.EffectiveSets, tacacsReport.DBSummary.AuthorizationEvents,
			tacacsReport.DBSummary.AccountingRecords),
		Recommendation: "Set tacacs.enabled=true, tacacs.mode=enforce, require known clients, use secret refs, keep encrypted packets only, define command sets, audit accounting evidence, and complete the NAS-0033 release certification checklist with Cisco, Juniper, HPE, Dell, Brocade, Extreme, and Arista devices.",
		Dependencies:   []string{"tacacs", "tacacs_command_sets", "tacacs_authorization_events", "tacacs_accounting_records", "/api/v1/system/tacacs", "RFC 8907"},
	})
}

func addProductionTenantIsolationCheck(report *productionReadinessReport, cfg *config.Config) {
	isolation, err := buildTenantIsolationReport(cfg, 0)
	status := "passed"
	message := "Tenant isolation is enforced with delegated policy ownership."
	if err != nil {
		status = "blocked"
		message = fmt.Sprintf("Tenant isolation report failed: %v", err)
	} else {
		switch isolation.Status {
		case "blocked":
			status = "blocked"
		case "disabled", "degraded":
			status = "degraded"
		}
		if cfg.Governance.MultiTenantEnabled {
			if isolation.Config.IsolationMode != "enforce" ||
				!isolation.Config.FailClosed ||
				!isolation.Config.EnforcePolicySetOwnership ||
				!isolation.Config.EnforceResourceOwnership ||
				!isolation.Config.ResourceAuditEnabled {
				status = "blocked"
			}
			if isolation.Config.TenantProfileRequired && isolation.Summary.ActiveTenantCount == 0 {
				status = "blocked"
			}
		}
		message = fmt.Sprintf("Tenant isolation schema %d is %s with %d active tenant(s), %d owned resource binding(s), %d tenant policy scope(s), and %d denied decision(s).",
			isolation.SchemaVersion, isolation.Status, isolation.Summary.ActiveTenantCount,
			isolation.Summary.ResourceBindingCount, isolation.Summary.PolicySetTenantCount,
			isolation.Summary.DeniedEventCount)
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:            "tenant_isolation",
		Category:       "policy",
		Label:          "Hard Tenant Isolation And Delegated Policy Trees",
		Status:         status,
		Summary:        message,
		Recommendation: "Set governance.multi_tenant_enabled=true, isolation_mode=enforce, fail_closed=true, create active tenant profiles, bind tenant-owned resources, keep decision audit enabled, and complete the NAS-0034 release certification checklist for external tenant-boundary evidence.",
		Dependencies:   []string{"governance.multi_tenant_enabled", "governance.isolation_mode", "tenant_profiles", "tenant_resource_bindings", "tenant_isolation_events", "/api/v1/system/tenant-isolation"},
	})
}

func maxReadinessStatus(current, candidate string) string {
	weight := map[string]int{"passed": 0, "degraded": 1, "blocked": 2}
	if weight[candidate] > weight[current] {
		return candidate
	}
	return current
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

func addProductionVendorMappingCertificationCheck(report *productionReadinessReport, cfg *config.Config) {
	certification, err := buildVendorMappingCertificationForConfig(cfg)
	if err != nil {
		addProductionCheck(report, productionReadinessCheck{
			Key: "vendor_mapping_certification", Category: "radius", Label: "NAS-0060 Vendor Mapping Certification", Status: "blocked",
			Summary:        "Vendor mapping certification report could not be built: " + err.Error(),
			Recommendation: "Regenerate the typed registry and repair the vendor mapping certification report before closing NAS-0060.",
			Dependencies:   []string{"configs/vendor_mapping_certification.go", "configs/attribute_registry/freeradius-3.2.8-vsa-audit.csv"},
		})
		return
	}
	if err := productconfigs.ValidateVendorMappingCertificationReport(certification); err != nil {
		addProductionCheck(report, productionReadinessCheck{
			Key: "vendor_mapping_certification", Category: "radius", Label: "NAS-0060 Vendor Mapping Certification", Status: "blocked",
			Summary:        "NAS-0060 software certification is incomplete: " + err.Error(),
			Recommendation: "Use /api/v1/system/vendor-mapping-certification to inspect blocked dimensions; external certification must remain in the release checklist.",
			Dependencies:   []string{"configs/vendor_mapping_certification.go", "internal/db/vendor_mapping_certification.go", "web/admin-ui/src/pages/VendorCompatibility.tsx"},
		})
		return
	}
	status := "passed"
	if db.DB == nil {
		status = "degraded"
	}
	addProductionCheck(report, productionReadinessCheck{
		Key: "vendor_mapping_certification", Category: "radius", Label: "NAS-0060 Vendor Mapping Certification", Status: status,
		Summary: fmt.Sprintf("NAS-0060 certifies %d/%d audit-source partial mappings in software across %d vendors; %d mappings remain ready for external release certification.",
			certification.Summary.CertifiedMappings,
			certification.Summary.BaselinePartialMappings,
			certification.Summary.VendorCount,
			certification.Summary.ExternalRequiredMappings,
		),
		Recommendation: "Record the current fingerprint with /api/v1/system/vendor-mapping-certification/record, then execute docs/nas-0060-release-certification-checklist.md before publishing hardware-certified claims.",
		Dependencies: []string{
			"/api/v1/system/vendor-mapping-certification",
			"vendor_mapping_certification_events",
			"docs/nas-0060-release-certification-checklist.md",
		},
	})
}

func addProductionCiscoFamilyPackCheck(report *productionReadinessReport) {
	certification, err := buildCiscoFamilyPackForRequest()
	if err != nil {
		addProductionCheck(report, productionReadinessCheck{
			Key: "cisco_family_pack", Category: "radius", Label: "NAS-0061 Cisco Family Pack", Status: "blocked",
			Summary:        "Cisco family pack report could not be built: " + err.Error(),
			Recommendation: "Repair the pinned attribute registry and Cisco-family certification report before closing NAS-0061.",
			Dependencies:   []string{"configs/cisco_family_pack.go", "internal/radius/cisco_avpair.go", "configs/attribute_registry/freeradius-3.2.8-vsa-audit.csv"},
		})
		return
	}
	if err := productconfigs.ValidateCiscoFamilyPackReport(certification); err != nil {
		addProductionCheck(report, productionReadinessCheck{
			Key: "cisco_family_pack", Category: "radius", Label: "NAS-0061 Cisco Family Pack", Status: "blocked",
			Summary:        "NAS-0061 software certification is incomplete: " + err.Error(),
			Recommendation: "Use /api/v1/system/cisco-family-pack to inspect blocked Cisco-family dimensions; external certification must remain in the release checklist.",
			Dependencies:   []string{"configs/cisco_family_pack.go", "internal/radius/cisco_avpair.go", "internal/db/cisco_family_pack.go"},
		})
		return
	}
	status := "passed"
	if db.DB == nil {
		status = "degraded"
	}
	addProductionCheck(report, productionReadinessCheck{
		Key: "cisco_family_pack", Category: "radius", Label: "NAS-0061 Cisco Family Pack", Status: status,
		Summary: fmt.Sprintf("NAS-0061 software-certifies %d/%d Cisco-family dictionary rows across %d vendors, with %d AVPair grammar rules and %d external certification claims.",
			certification.Summary.SoftwareCertifiedMappings,
			certification.Summary.AttributeCount,
			certification.Summary.VendorCount,
			certification.Summary.GrammarRuleCount,
			certification.Summary.ExternalRequiredMappings,
		),
		Recommendation: "Record the current fingerprint with /api/v1/system/cisco-family-pack/record, then execute docs/nas-0061-release-certification-checklist.md before publishing hardware-certified claims.",
		Dependencies: []string{
			"/api/v1/system/cisco-family-pack",
			"cisco_family_pack_events",
			"docs/nas-0061-release-certification-checklist.md",
		},
	})
}

func addProductionArubaFamilyPackCheck(report *productionReadinessReport) {
	certification, err := buildArubaFamilyPackForRequest()
	if err != nil {
		addProductionCheck(report, productionReadinessCheck{
			Key: "aruba_family_pack", Category: "radius", Label: "NAS-0062 Aruba/HPE Family Pack", Status: "blocked",
			Summary:        "Aruba/HPE family pack report could not be built: " + err.Error(),
			Recommendation: "Repair the pinned attribute registry and Aruba/HPE-family certification report before closing NAS-0062.",
			Dependencies:   []string{"configs/aruba_family_pack.go", "internal/radius/aruba_family.go", "configs/attribute_registry/freeradius-3.2.8-vsa-audit.csv"},
		})
		return
	}
	if err := productconfigs.ValidateArubaFamilyPackReport(certification); err != nil {
		addProductionCheck(report, productionReadinessCheck{
			Key: "aruba_family_pack", Category: "radius", Label: "NAS-0062 Aruba/HPE Family Pack", Status: "blocked",
			Summary:        "NAS-0062 software certification is incomplete: " + err.Error(),
			Recommendation: "Use /api/v1/system/aruba-family-pack to inspect blocked Aruba/HPE-family dimensions; external certification must remain in the release checklist.",
			Dependencies:   []string{"configs/aruba_family_pack.go", "internal/radius/aruba_family.go", "internal/db/aruba_family_pack.go"},
		})
		return
	}
	status := "passed"
	if db.DB == nil {
		status = "degraded"
	}
	addProductionCheck(report, productionReadinessCheck{
		Key: "aruba_family_pack", Category: "radius", Label: "NAS-0062 Aruba/HPE Family Pack", Status: status,
		Summary: fmt.Sprintf("NAS-0062 software-certifies %d/%d Aruba/HPE-family dictionary rows across %d vendors, with %d policy grammar rules, %d sensitive redaction mappings, and %d external certification claims.",
			certification.Summary.SoftwareCertifiedMappings,
			certification.Summary.AttributeCount,
			certification.Summary.VendorCount,
			certification.Summary.GrammarRuleCount,
			certification.Summary.SensitiveRedactedMappings,
			certification.Summary.ExternalRequiredMappings,
		),
		Recommendation: "Record the current fingerprint with /api/v1/system/aruba-family-pack/record, then execute docs/nas-0062-release-certification-checklist.md before publishing hardware-certified claims.",
		Dependencies: []string{
			"/api/v1/system/aruba-family-pack",
			"aruba_family_pack_events",
			"docs/nas-0062-release-certification-checklist.md",
		},
	})
}

func addProductionJuniperExtremePackCheck(report *productionReadinessReport) {
	certification, err := buildJuniperExtremePackForRequest()
	if err != nil {
		addProductionCheck(report, productionReadinessCheck{
			Key: "juniper_extreme_pack", Category: "radius", Label: "NAS-0063 Juniper/ERX/Extreme/Mist Pack", Status: "blocked",
			Summary:        "Juniper/ERX/Extreme/Mist pack report could not be built: " + err.Error(),
			Recommendation: "Repair the pinned attribute registry and Juniper/ERX/Extreme/Mist certification report before closing NAS-0063.",
			Dependencies:   []string{"configs/juniper_extreme_pack.go", "internal/radius/juniper_extreme.go", "configs/attribute_registry/freeradius-3.2.8-vsa-audit.csv"},
		})
		return
	}
	if err := productconfigs.ValidateJuniperExtremePackReport(certification); err != nil {
		addProductionCheck(report, productionReadinessCheck{
			Key: "juniper_extreme_pack", Category: "radius", Label: "NAS-0063 Juniper/ERX/Extreme/Mist Pack", Status: "blocked",
			Summary:        "NAS-0063 software certification is incomplete: " + err.Error(),
			Recommendation: "Use /api/v1/system/juniper-extreme-pack to inspect blocked Juniper/ERX/Extreme/Mist dimensions; external certification must remain in the release checklist.",
			Dependencies:   []string{"configs/juniper_extreme_pack.go", "internal/radius/juniper_extreme.go", "internal/db/juniper_extreme_pack.go"},
		})
		return
	}
	status := "passed"
	if db.DB == nil {
		status = "degraded"
	}
	addProductionCheck(report, productionReadinessCheck{
		Key: "juniper_extreme_pack", Category: "radius", Label: "NAS-0063 Juniper/ERX/Extreme/Mist Pack", Status: status,
		Summary: fmt.Sprintf("NAS-0063 software-certifies %d/%d Juniper/ERX/Extreme rows across %d dictionary vendors and %d product scopes, with %d policy grammar rules, %d sensitive redaction mappings, and %d external certification claims.",
			certification.Summary.SoftwareCertifiedMappings,
			certification.Summary.AttributeCount,
			certification.Summary.VendorCount,
			certification.Summary.ProductScopeCount,
			certification.Summary.GrammarRuleCount,
			certification.Summary.SensitiveRedactedMappings,
			certification.Summary.ExternalRequiredMappings,
		),
		Recommendation: "Record the current fingerprint with /api/v1/system/juniper-extreme-pack/record, then execute docs/nas-0063-release-certification-checklist.md before publishing hardware-certified claims.",
		Dependencies: []string{
			"/api/v1/system/juniper-extreme-pack",
			"juniper_extreme_pack_events",
			"docs/nas-0063-release-certification-checklist.md",
		},
	})
}

func addProductionRuckusICXPackCheck(report *productionReadinessReport) {
	certification, err := buildRuckusICXPackForRequest()
	if err != nil {
		addProductionCheck(report, productionReadinessCheck{
			Key: "ruckus_icx_pack", Category: "radius", Label: "NAS-0064 Ruckus/ICX Pack", Status: "blocked",
			Summary:        "Ruckus/ICX pack report could not be built: " + err.Error(),
			Recommendation: "Repair the pinned attribute registry and Ruckus/ICX certification report before closing NAS-0064.",
			Dependencies:   []string{"configs/ruckus_icx_pack.go", "internal/radius/ruckus_icx.go", "configs/attribute_registry/freeradius-3.2.8-vsa-audit.csv"},
		})
		return
	}
	if err := productconfigs.ValidateRuckusICXPackReport(certification); err != nil {
		addProductionCheck(report, productionReadinessCheck{
			Key: "ruckus_icx_pack", Category: "radius", Label: "NAS-0064 Ruckus/ICX Pack", Status: "blocked",
			Summary:        "NAS-0064 software certification is incomplete: " + err.Error(),
			Recommendation: "Use /api/v1/system/ruckus-icx-pack to inspect blocked Ruckus/ICX dimensions; external certification must remain in the release checklist.",
			Dependencies:   []string{"configs/ruckus_icx_pack.go", "internal/radius/ruckus_icx.go", "internal/db/ruckus_icx_pack.go"},
		})
		return
	}
	status := "passed"
	if db.DB == nil {
		status = "degraded"
	}
	addProductionCheck(report, productionReadinessCheck{
		Key: "ruckus_icx_pack", Category: "radius", Label: "NAS-0064 Ruckus/ICX Pack", Status: status,
		Summary: fmt.Sprintf("NAS-0064 software-certifies %d/%d Ruckus/ICX rows across %d dictionary vendors and %d product scopes, with %d policy grammar rules, %d sensitive redaction mappings, and %d external certification claims.",
			certification.Summary.SoftwareCertifiedMappings,
			certification.Summary.AttributeCount,
			certification.Summary.VendorCount,
			certification.Summary.ProductScopeCount,
			certification.Summary.GrammarRuleCount,
			certification.Summary.SensitiveRedactedMappings,
			certification.Summary.ExternalRequiredMappings,
		),
		Recommendation: "Record the current fingerprint with /api/v1/system/ruckus-icx-pack/record, then execute docs/nas-0064-release-certification-checklist.md before publishing hardware-certified claims.",
		Dependencies: []string{
			"/api/v1/system/ruckus-icx-pack",
			"ruckus_icx_pack_events",
			"docs/nas-0064-release-certification-checklist.md",
		},
	})
}

func addProductionFortinetPaloAltoPackCheck(report *productionReadinessReport) {
	certification, err := buildFortinetPaloAltoPackForRequest()
	if err != nil {
		addProductionCheck(report, productionReadinessCheck{
			Key: "fortinet_paloalto_pack", Category: "radius", Label: "NAS-0065 Fortinet/Palo Alto Pack", Status: "blocked",
			Summary:        "Fortinet/Palo Alto pack report could not be built: " + err.Error(),
			Recommendation: "Repair the pinned attribute registry and Fortinet/Palo Alto certification report before closing NAS-0065.",
			Dependencies:   []string{"configs/fortinet_paloalto_pack.go", "internal/radius/fortinet_paloalto.go", "configs/attribute_registry/freeradius-3.2.8-vsa-audit.csv"},
		})
		return
	}
	if err := productconfigs.ValidateFortinetPaloAltoPackReport(certification); err != nil {
		addProductionCheck(report, productionReadinessCheck{
			Key: "fortinet_paloalto_pack", Category: "radius", Label: "NAS-0065 Fortinet/Palo Alto Pack", Status: "blocked",
			Summary:        "NAS-0065 software certification is incomplete: " + err.Error(),
			Recommendation: "Use /api/v1/system/fortinet-paloalto-pack to inspect blocked Fortinet/Palo Alto dimensions; external certification must remain in the release checklist.",
			Dependencies:   []string{"configs/fortinet_paloalto_pack.go", "internal/radius/fortinet_paloalto.go", "internal/db/fortinet_paloalto_pack.go"},
		})
		return
	}
	status := "passed"
	if db.DB == nil {
		status = "degraded"
	}
	addProductionCheck(report, productionReadinessCheck{
		Key: "fortinet_paloalto_pack", Category: "radius", Label: "NAS-0065 Fortinet/Palo Alto Pack", Status: status,
		Summary: fmt.Sprintf("NAS-0065 software-certifies %d/%d Fortinet/Palo Alto rows across %d dictionary vendors and %d product scopes, with %d policy grammar rules, %d sensitive redaction mappings, and %d external certification claims.",
			certification.Summary.SoftwareCertifiedMappings,
			certification.Summary.AttributeCount,
			certification.Summary.VendorCount,
			certification.Summary.ProductScopeCount,
			certification.Summary.GrammarRuleCount,
			certification.Summary.SensitiveRedactedMappings,
			certification.Summary.ExternalRequiredMappings,
		),
		Recommendation: "Record the current fingerprint with /api/v1/system/fortinet-paloalto-pack/record, then execute docs/nas-0065-release-certification-checklist.md before publishing hardware-certified claims.",
		Dependencies: []string{
			"/api/v1/system/fortinet-paloalto-pack",
			"fortinet_paloalto_pack_events",
			"docs/nas-0065-release-certification-checklist.md",
		},
	})
}

func addProductionCloudControllerPackCheck(report *productionReadinessReport) {
	certification, err := buildCloudControllerPackForRequest()
	if err != nil {
		addProductionCheck(report, productionReadinessCheck{
			Key: "cloud_controller_pack", Category: "radius", Label: "NAS-0066 Meraki/UniFi/OpenWiFi Cloud Pack", Status: "blocked",
			Summary:        "Cloud controller pack report could not be built: " + err.Error(),
			Recommendation: "Repair the pinned attribute registry and cloud-controller certification report before closing NAS-0066.",
			Dependencies:   []string{"configs/cloud_controller_pack.go", "internal/radius/vendor.go", "configs/attribute_registry/freeradius-3.2.8-vsa-audit.csv"},
		})
		return
	}
	if err := productconfigs.ValidateCloudControllerPackReport(certification); err != nil {
		addProductionCheck(report, productionReadinessCheck{
			Key: "cloud_controller_pack", Category: "radius", Label: "NAS-0066 Meraki/UniFi/OpenWiFi Cloud Pack", Status: "blocked",
			Summary:        "NAS-0066 software certification is incomplete: " + err.Error(),
			Recommendation: "Use /api/v1/system/cloud-controller-pack to inspect blocked cloud-controller dimensions; external certification must remain in the release checklist.",
			Dependencies:   []string{"configs/cloud_controller_pack.go", "internal/radius/vendor.go", "internal/db/cloud_controller_pack.go"},
		})
		return
	}
	status := "passed"
	if db.DB == nil {
		status = "degraded"
	}
	addProductionCheck(report, productionReadinessCheck{
		Key: "cloud_controller_pack", Category: "radius", Label: "NAS-0066 Meraki/UniFi/OpenWiFi Cloud Pack", Status: status,
		Summary: fmt.Sprintf("NAS-0066 software-certifies %d/%d Meraki, UniFi/UBNT, and OpenWiFi rows across %d dictionary/runtime vendors and %d product scopes, with %d cloud grammar rules and %d external certification claims.",
			certification.Summary.SoftwareCertifiedMappings,
			certification.Summary.AttributeCount,
			certification.Summary.VendorCount,
			certification.Summary.ProductScopeCount,
			certification.Summary.GrammarRuleCount,
			certification.Summary.ExternalRequiredMappings,
		),
		Recommendation: "Record the current fingerprint with /api/v1/system/cloud-controller-pack/record, then execute docs/nas-0066-release-certification-checklist.md before publishing hardware-certified cloud claims.",
		Dependencies: []string{
			"/api/v1/system/cloud-controller-pack",
			"cloud_controller_pack_events",
			"docs/nas-0066-release-certification-checklist.md",
		},
	})
}

func addProductionAccessVendorPackCheck(report *productionReadinessReport) {
	certification, err := buildAccessVendorPackForRequest()
	if err != nil {
		addProductionCheck(report, productionReadinessCheck{
			Key: "access_vendor_pack", Category: "radius", Label: "NAS-0067 Cambium/TP-Link/D-Link Access Pack", Status: "blocked",
			Summary:        "Access vendor pack report could not be built: " + err.Error(),
			Recommendation: "Repair the pinned attribute registry and access-vendor certification report before closing NAS-0067.",
			Dependencies:   []string{"configs/access_vendor_pack.go", "internal/radius/vendor.go", "configs/attribute_registry/freeradius-3.2.8-vsa-audit.csv"},
		})
		return
	}
	if err := productconfigs.ValidateAccessVendorPackReport(certification); err != nil {
		addProductionCheck(report, productionReadinessCheck{
			Key: "access_vendor_pack", Category: "radius", Label: "NAS-0067 Cambium/TP-Link/D-Link Access Pack", Status: "blocked",
			Summary:        "NAS-0067 software certification is incomplete: " + err.Error(),
			Recommendation: "Use /api/v1/system/access-vendor-pack to inspect blocked access-vendor dimensions; external certification must remain in the release checklist.",
			Dependencies:   []string{"configs/access_vendor_pack.go", "internal/radius/vendor.go", "internal/db/access_vendor_pack.go"},
		})
		return
	}
	status := "passed"
	if db.DB == nil {
		status = "degraded"
	}
	addProductionCheck(report, productionReadinessCheck{
		Key: "access_vendor_pack", Category: "radius", Label: "NAS-0067 Cambium/TP-Link/D-Link Access Pack", Status: status,
		Summary: fmt.Sprintf("NAS-0067 software-certifies %d/%d Cambium, TP-Link, and D-Link rows across %d dictionary vendors and %d product scopes, with %d access grammar rules, %d redacted secret mappings, and %d external certification claims.",
			certification.Summary.SoftwareCertifiedMappings,
			certification.Summary.AttributeCount,
			certification.Summary.VendorCount,
			certification.Summary.ProductScopeCount,
			certification.Summary.GrammarRuleCount,
			certification.Summary.SensitiveRedactedMappings,
			certification.Summary.ExternalRequiredMappings,
		),
		Recommendation: "Record the current fingerprint with /api/v1/system/access-vendor-pack/record, then execute docs/nas-0067-release-certification-checklist.md before publishing hardware-certified access-vendor claims.",
		Dependencies: []string{
			"/api/v1/system/access-vendor-pack",
			"access_vendor_pack_events",
			"docs/nas-0067-release-certification-checklist.md",
		},
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
